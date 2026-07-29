package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/cpa"
	"github.com/grok-free-register/grok-reg/internal/egress"
	"github.com/grok-free-register/grok-reg/internal/email"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/inventory"
	"github.com/grok-free-register/grok-reg/internal/logx"
	"github.com/grok-free-register/grok-reg/internal/oauth"
	"github.com/grok-free-register/grok-reg/internal/riskstate"
	"github.com/grok-free-register/grok-reg/internal/signup"
	"github.com/grok-free-register/grok-reg/internal/state"
)

type cancelAfterFirstCheckContext struct {
	checks atomic.Int64
}

func (ctx *cancelAfterFirstCheckContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *cancelAfterFirstCheckContext) Done() <-chan struct{}       { return nil }
func (ctx *cancelAfterFirstCheckContext) Value(any) any               { return nil }
func (ctx *cancelAfterFirstCheckContext) Err() error {
	if ctx.checks.Add(1) > 1 {
		return context.Canceled
	}
	return nil
}

func TestDeriveWorkersSerializesOAuthByDefault(t *testing.T) {
	cfg := config.Defaults()
	_, _, _, oauthWorkers, _ := deriveWorkers(cfg)
	if oauthWorkers != 1 {
		t.Fatalf("expected one OAuth worker, got %d", oauthWorkers)
	}
	// Flow retries stay off by default; invalid_grant fuse allows a few strikes so
	// one Access denied does not abort a multi-account run after real OAuth wins.
	if cfg.OAuthFlowRetries != 0 || cfg.OAuthInvalidGrantLimit != 3 {
		t.Fatalf("unexpected OAuth failure defaults: retries=%d invalid_grant_limit=%d", cfg.OAuthFlowRetries, cfg.OAuthInvalidGrantLimit)
	}
}

func TestDeriveWorkersSerializesBrowserMCP(t *testing.T) {
	cfg := config.Defaults()
	cfg.RegisterMode = "browser-mcp"
	s, p, c, _, phys := deriveWorkers(cfg)
	if s != 0 || p != 1 || c != 1 || phys != 1 {
		t.Fatalf("browser-mcp workers = S%d P%d C%d phys%d", s, p, c, phys)
	}
}

func TestDeriveWorkersClampsOAuthWorkers(t *testing.T) {
	cfg := config.Defaults()
	cfg.OAuthWorkers = 99
	_, _, _, oauthWorkers, _ := deriveWorkers(cfg)
	if oauthWorkers != 4 {
		t.Fatalf("expected OAuth worker cap 4, got %d", oauthWorkers)
	}
}

func TestAccountSessionSurvivesQAndOAuthQueue(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New[string, QItem](1, 1)
	session := newAccountSession(email.Handle{
		Email:    "person@example.com",
		Password: "password",
	}, "http://proxy.example:8080")
	if err := inv.PutQ(ctx, QItem{Session: session}, time.Minute); err != nil {
		t.Fatal(err)
	}
	envelope, err := inv.ClaimQ(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer envelope.Release()
	if envelope.Value.Session != session {
		t.Fatal("inventory changed account session identity")
	}

	session.SSO = "sso-value"
	job := SSOJob{Session: envelope.Value.Session}
	if job.Session != session {
		t.Fatal("OAuth queue changed account session identity")
	}
	if job.Session.Proxy != "http://proxy.example:8080" || job.Session.DiagnosticID == "" {
		t.Fatalf("session affinity lost: proxy=%q id=%q", job.Session.Proxy, job.Session.DiagnosticID)
	}
}

func TestDiagnosticIDsAreOpaqueAndUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for range 64 {
		id := newDiagnosticID()
		if id == "" {
			t.Fatal("empty diagnostic ID")
		}
		if strings.ContainsAny(id, "@/: ") {
			t.Fatalf("diagnostic ID is not filesystem safe: %q", id)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate diagnostic ID: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestCompleteAccountRecordsSynchronousUpload(t *testing.T) {
	root := t.TempDir()
	run := home.RunDirs{
		RunID:     "test-run",
		Root:      root,
		SSO:       filepath.Join(root, "SSO"),
		CPA:       filepath.Join(root, "CPA"),
		Discarded: filepath.Join(root, "discarded"),
		LogPath:   filepath.Join(root, "run.log"),
	}
	for _, dir := range []string{run.SSO, run.CPA, run.Discarded} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		called <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	logger, err := logx.New(run.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.ProbeEnabled = false
	engine := &Engine{
		opt: Options{
			Cfg:    cfg,
			Run:    run,
			Target: 1,
			Log:    logger,
			Store:  state.NewStore(filepath.Join(root, "state.json")),
		},
		start: time.Now(),
		inv:   inventory.New[string, QItem](1, 1),
		uploader: cpa.NewUploader(cpa.UploadConfig{
			Enabled:    true,
			BaseURL:    server.URL,
			Key:        "management-key",
			TimeoutSec: 2,
			Retries:    0,
			Verify:     false,
		}, nil),
	}
	session := &AccountSession{
		DiagnosticID: "attempt-123",
		Proxy:        "http://proxy.example:8080",
		Email:        "person@example.com",
		Password:     "password-sentinel",
	}
	credential := oauth.Credential{
		AccessToken:   "access-token-sentinel",
		RefreshToken:  "refresh-token-sentinel",
		Subject:       "subject-123",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
	}
	if err := engine.completeAccount(context.Background(), session, credential, "test"); err != nil {
		t.Fatalf("completeAccount() error = %v", err)
	}

	select {
	case <-called:
	default:
		t.Fatal("upload had not completed when completeAccount returned")
	}
	if !session.Upload.Attempted || !session.Upload.OK || session.Upload.HTTPStatus != http.StatusOK {
		t.Fatalf("upload status = %+v", session.Upload)
	}
	if engine.done.Load() != 1 {
		t.Fatalf("done = %d", engine.done.Load())
	}

	entries, err := os.ReadDir(run.CPA)
	if err != nil || len(entries) != 1 {
		t.Fatalf("CPA entries = %d, err=%v", len(entries), err)
	}
	raw, err := os.ReadFile(filepath.Join(run.CPA, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"diagnostic_id", "proxy", "password", "upload"} {
		if _, exists := doc[key]; exists {
			t.Fatalf("CPA document contains session-only key %q", key)
		}
	}

	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(run.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	if !strings.Contains(logText, session.DiagnosticID) {
		t.Fatal("log does not contain diagnostic ID")
	}
	for _, secret := range []string{session.Password, credential.AccessToken, credential.RefreshToken} {
		if strings.Contains(logText, secret) {
			t.Fatalf("log leaked secret %q", secret)
		}
	}
}

func TestOAuthRateLimitStateIsRunWide(t *testing.T) {
	engine := &Engine{opt: Options{Cfg: config.Config{OAuthRetrySec: 1}}}
	engine.noteOAuthRateResult(errors.New("rate_limited"))
	if !engine.oauthRateUntil.After(time.Now()) || engine.oauthRateTrips != 1 {
		t.Fatalf("cooldown not tripped: until=%v trips=%d", engine.oauthRateUntil, engine.oauthRateTrips)
	}
	engine.noteOAuthRateResult(errors.New("unrelated error"))
	if engine.oauthRateTrips != 1 {
		t.Fatalf("unrelated error changed cooldown trips: %d", engine.oauthRateTrips)
	}
	engine.noteOAuthRateResult(nil)
	if !engine.oauthRateUntil.IsZero() || engine.oauthRateTrips != 0 {
		t.Fatalf("successful flow did not clear cooldown: until=%v trips=%d", engine.oauthRateUntil, engine.oauthRateTrips)
	}
}

func TestOAuthCooldownClearWakesWaiters(t *testing.T) {
	engine := &Engine{opt: Options{Cfg: config.Config{OAuthRetrySec: 2}}}
	engine.noteOAuthRateResult(errors.New("rate_limited"))
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- engine.waitOAuthRateLimit(context.Background())
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	engine.noteOAuthRateResult(nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitOAuthRateLimit() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("clearing OAuth cooldown did not wake waiter")
	}
}

func TestOAuthInvalidGrantBreakerCountsSameSessionRejections(t *testing.T) {
	root := t.TempDir()
	logger, err := logx.New(filepath.Join(root, "run.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	canceled := false
	engine := &Engine{
		opt: Options{
			Cfg:   config.Config{OAuthInvalidGrantLimit: 3},
			Log:   logger,
			Store: state.NewStore(filepath.Join(root, "state.json")),
		},
		cancel: func() { canceled = true },
	}
	rejected := &oauth.RejectionError{Stage: "token", Code: "invalid_grant", Description: "Access denied"}

	engine.noteOAuthOutcome(rejected)
	engine.noteOAuthOutcome(rejected)
	if canceled {
		t.Fatal("breaker tripped before reaching the limit")
	}
	// A poll timeout or a missing SSO export says nothing about x.ai resuming
	// token issuance, so it must not reset the streak.
	engine.noteOAuthOutcome(errors.New("missing SSO session"))
	if got := engine.oauthInvalidGrantStreak.Load(); got != 2 {
		t.Fatalf("unrelated failure changed streak: %d", got)
	}
	engine.noteOAuthOutcome(rejected)
	if !canceled {
		t.Fatal("breaker did not trip at the configured invalid_grant limit")
	}
	if snapshot := engine.opt.Store.Get(); snapshot.Status != state.StatusError || snapshot.Phase != state.PhaseOAuth {
		t.Fatalf("breaker state = status=%v phase=%v", snapshot.Status, snapshot.Phase)
	}
}

func TestBurntMailboxDomainLeavesRotationBeforeRunWideFuse(t *testing.T) {
	root := t.TempDir()
	logger, err := logx.New(filepath.Join(root, "run.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	provider := email.New(email.Config{
		Mode:         config.EmailCFTemp,
		CFTempAPI:    "http://worker.invalid",
		CFTempDomain: "a.example.com,b.example.com,c.example.com",
	})
	engine := &Engine{
		opt: Options{
			// Run-wide fuse set high so only the per-domain rule can fire here.
			Cfg:   config.Config{OAuthInvalidGrantLimit: 99},
			Log:   logger,
			Store: state.NewStore(filepath.Join(root, "state.json")),
		},
		mail: provider,
	}
	rejected := &oauth.RejectionError{Stage: "token", Code: "invalid_grant", Description: "Access denied"}

	engine.noteOAuthOutcomeFor("one@a.example.com", rejected)
	if got := len(provider.CFTempDomainPool()); got != 3 {
		t.Fatalf("domain retired after a single rejection: pool=%d", got)
	}
	engine.noteOAuthOutcomeFor("two@a.example.com", rejected)
	pool := provider.CFTempDomainPool()
	if len(pool) != 2 {
		t.Fatalf("burnt domain still in rotation: %v", pool)
	}
	for _, domain := range pool {
		if domain == "a.example.com" {
			t.Fatalf("burnt domain still in rotation: %v", pool)
		}
	}

	// A success elsewhere must not resurrect the burnt domain, and per-domain
	// retirement must not trip the run-wide fuse.
	engine.noteOAuthOutcomeFor("three@b.example.com", nil)
	if got := provider.CFTempDomainPool(); len(got) != 2 {
		t.Fatalf("success on another domain resurrected the burnt one: %v", got)
	}
	if engine.opt.Store.Get().Status == state.StatusError {
		t.Fatal("per-domain retirement should not trip the run-wide fuse")
	}
}

func TestMailboxDomainExtraction(t *testing.T) {
	if got := mailboxDomain("Person@A.Example.COM"); got != "a.example.com" {
		t.Fatalf("mailboxDomain() = %q", got)
	}
	if got := mailboxDomain("not-an-address"); got != "" {
		t.Fatalf("mailboxDomain() = %q, want empty", got)
	}
}

func TestOAuthInvalidGrantBreakerResetsOnlyOnSuccess(t *testing.T) {
	engine := &Engine{opt: Options{Cfg: config.Config{OAuthInvalidGrantLimit: 3}}}
	rejected := &oauth.RejectionError{Stage: "token", Code: "invalid_grant"}
	engine.noteOAuthOutcome(rejected)
	engine.noteOAuthOutcome(rejected)
	engine.noteOAuthOutcome(nil)
	if got := engine.oauthInvalidGrantStreak.Load(); got != 0 {
		t.Fatalf("successful exchange did not clear streak: %d", got)
	}
}

func TestCompleteAccountHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	discarded := t.TempDir()
	engine := &Engine{opt: Options{
		Target: 1,
		Run:    home.RunDirs{Discarded: discarded},
	}}
	err := engine.completeAccount(ctx, &AccountSession{DiagnosticID: "canceled"}, oauth.Credential{Subject: "subject-canceled"}, "test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("completeAccount() error = %v, want context canceled", err)
	}
	if got := engine.done.Load(); got != 0 {
		t.Fatalf("done = %d, want 0", got)
	}
	entries, readErr := os.ReadDir(discarded)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("discarded entries = %d, err=%v", len(entries), readErr)
	}
}

func TestCompleteAccountSavesCredentialWhenCanceledAfterGate(t *testing.T) {
	root := t.TempDir()
	discarded := filepath.Join(root, "discarded")
	engine := &Engine{opt: Options{
		Cfg:    config.Config{ProbeEnabled: false},
		Target: 1,
		Run:    home.RunDirs{Discarded: discarded},
		Store:  state.NewStore(filepath.Join(root, "state.json")),
	}}
	ctx := &cancelAfterFirstCheckContext{}
	err := engine.completeAccount(ctx, &AccountSession{DiagnosticID: "canceled-after-gate"}, oauth.Credential{Subject: "subject-after-gate"}, "test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("completeAccount() error = %v, want context canceled", err)
	}
	entries, readErr := os.ReadDir(discarded)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("discarded entries = %d, err=%v", len(entries), readErr)
	}
	if got := engine.done.Load(); got != 0 {
		t.Fatalf("done = %d, want 0", got)
	}
}

func TestCompleteAccountDoesNotExceedTargetDuringSlowUpload(t *testing.T) {
	root := t.TempDir()
	run := home.RunDirs{
		RunID:     "target-test",
		Root:      root,
		SSO:       filepath.Join(root, "SSO"),
		CPA:       filepath.Join(root, "CPA"),
		Discarded: filepath.Join(root, "discarded"),
		LogPath:   filepath.Join(root, "run.log"),
	}
	for _, dir := range []string{run.SSO, run.CPA, run.Discarded} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	var uploadCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	logger, err := logx.New(run.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	cfg := config.Defaults()
	cfg.ProbeEnabled = false
	engine := &Engine{
		opt: Options{
			Cfg:    cfg,
			Run:    run,
			Target: 1,
			Log:    logger,
			Store:  state.NewStore(filepath.Join(root, "state.json")),
		},
		start: time.Now(),
		inv:   inventory.New[string, QItem](1, 1),
		uploader: cpa.NewUploader(cpa.UploadConfig{
			Enabled:    true,
			BaseURL:    server.URL,
			Key:        "management-key",
			TimeoutSec: 2,
			Retries:    0,
			Verify:     false,
		}, nil),
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session := &AccountSession{
				DiagnosticID: fmt.Sprintf("attempt-%d", i),
				Email:        fmt.Sprintf("person-%d@example.com", i),
			}
			credential := oauth.Credential{
				AccessToken:  fmt.Sprintf("access-%d", i),
				RefreshToken: fmt.Sprintf("refresh-%d", i),
				Subject:      fmt.Sprintf("subject-%d", i),
			}
			errs <- engine.completeAccount(context.Background(), session, credential, "test")
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("completeAccount() error = %v", err)
		}
	}

	if got := engine.done.Load(); got != 1 {
		t.Fatalf("done = %d, want 1", got)
	}
	if got := uploadCount.Load(); got != 1 {
		t.Fatalf("uploads = %d, want 1", got)
	}
	if entries, err := os.ReadDir(run.CPA); err != nil || len(entries) != 1 {
		t.Fatalf("CPA entries = %d, err=%v", len(entries), err)
	}
	if entries, err := os.ReadDir(run.Discarded); err != nil || len(entries) != 1 {
		t.Fatalf("discarded entries = %d, err=%v", len(entries), err)
	}
}

func TestBrowserSignupRetryPolicy(t *testing.T) {
	tests := []struct {
		name   string
		result signup.BrowserResult
		err    error
		want   bool
	}{
		{name: "turnstile", result: signup.BrowserResult{Stage: "turnstile_stuck"}, err: errors.New("turnstile_not_passed_after_retries"), want: true},
		{name: "navigation", result: signup.BrowserResult{Stage: "browser_error"}, err: errors.New("navigate_failed: timeout"), want: true},
		{name: "rate limit", result: signup.BrowserResult{Stage: "browser_error"}, err: errors.New("email_code_rate_limited"), want: false},
		{name: "invalid code", result: signup.BrowserResult{Stage: "browser_error"}, err: errors.New("invalid_or_expired_code"), want: false},
		{name: "missing dependency", result: signup.BrowserResult{Stage: "bootstrap_error"}, err: errors.New("Camoufox is not installed"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := browserSignupRetryable(test.result, test.err); got != test.want {
				t.Fatalf("browserSignupRetryable() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRegistrationMetricIsCredentialSafe(t *testing.T) {
	root := t.TempDir()
	engine := &Engine{opt: Options{
		Cfg: config.Config{RegisterMode: "camoufox"},
		Run: home.RunDirs{Root: root},
	}}
	session := &AccountSession{
		DiagnosticID: "diag-123",
		Proxy:        "http://proxy-user:proxy-password@proxy.example:8080",
		Email:        "secret@example.com",
		Password:     "account-password",
		Egress: egress.Profile{
			IP:          "203.0.113.8",
			ASN:         64512,
			ISP:         "Example ISP",
			CountryCode: "US",
		},
	}
	engine.recordRegistrationMetric(session, 2, "registration", "failure", errors.New("turnstile timeout"))
	data, err := os.ReadFile(filepath.Join(root, "registration-metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"secret@example.com", "account-password", "proxy-user", "proxy-password"} {
		if strings.Contains(text, secret) {
			t.Fatalf("metric leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, `"diagnostic_id":"diag-123"`) || !strings.Contains(text, `"asn":64512`) {
		t.Fatalf("metric missing safe dimensions: %s", text)
	}
}

func TestInvalidGrantSwitchesDomainMailToOutlookAndBlocksPair(t *testing.T) {
	root := t.TempDir()
	accountsPath := filepath.Join(root, "outlook-accounts.txt")
	if err := os.WriteFile(
		accountsPath,
		[]byte("fallback@outlook.com----mail-pass----client-id----refresh-token\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	provider := email.New(email.Config{
		Mode:                     config.EmailCustom,
		Domain:                   "domain.example",
		InvalidGrantFallback:     "outlook",
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         filepath.Join(root, "outlook-state.json"),
		OutlookAliasesPerAccount: 3,
	})
	if err := provider.Validate(); err != nil {
		t.Fatal(err)
	}
	registry, err := riskstate.Open(filepath.Join(root, "invalid-grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{
		opt:  Options{Cfg: config.Config{OAuthInvalidGrantLimit: 3}},
		mail: provider,
		risk: registry,
	}
	engine.oauthInvalidGrantStreak.Store(2)
	domainSession := &AccountSession{
		DiagnosticID: "diag-domain",
		Email:        "person@domain.example",
		Handle:       email.Handle{Kind: "custom", Email: "person@domain.example"},
		Proxy:        "http://proxy-user:proxy-pass@p.webshare.io:80",
		Egress:       egress.Profile{IP: "203.0.113.9", ASN: 64512, ISP: "Residential ISP"},
	}
	engine.noteOAuthOutcomeForSession(domainSession, &oauth.RejectionError{Code: "invalid_grant", Description: "Access denied"})

	if !provider.UsingOutlook() {
		t.Fatal("domain invalid_grant did not switch future mailboxes to Outlook")
	}
	if got := engine.oauthInvalidGrantStreak.Load(); got != 0 {
		t.Fatalf("domain fallback should reset the Outlook breaker budget, got %d", got)
	}
	if !registry.EmailBlocked(domainSession.Email) || !registry.IPBlocked(domainSession.Egress.IP) || !registry.FallbackToOutlook() {
		t.Fatal("invalid_grant email/IP/fallback markers were not persisted")
	}
	if engine.accountCandidateAllowed(domainSession) {
		t.Fatal("stale domain mailbox/IP should be rejected after fallback")
	}

	outlookHandle, err := provider.Create()
	if err != nil {
		t.Fatal(err)
	}
	if outlookHandle.Kind != "outlook" {
		t.Fatalf("future allocation kind = %q", outlookHandle.Kind)
	}
	outlookSession := &AccountSession{
		DiagnosticID: "diag-outlook",
		Email:        outlookHandle.Email,
		Handle:       outlookHandle,
		Egress:       egress.Profile{IP: "203.0.113.10"},
	}
	if !engine.accountCandidateAllowed(outlookSession) {
		t.Fatal("fresh Outlook mailbox and IP should be allowed")
	}
	engine.noteOAuthOutcomeForSession(outlookSession, &oauth.RejectionError{Code: "invalid_grant"})
	if got := engine.oauthInvalidGrantStreak.Load(); got != 1 {
		t.Fatalf("Outlook invalid_grant streak = %d, want 1", got)
	}
	if !registry.EmailBlocked(outlookSession.Email) || !registry.IPBlocked(outlookSession.Egress.IP) {
		t.Fatal("Outlook invalid_grant pair was not blocked")
	}
}
