package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/grok-free-register/grok-reg/internal/clearance"
	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/cpa"
	"github.com/grok-free-register/grok-reg/internal/email"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/inventory"
	"github.com/grok-free-register/grok-reg/internal/logx"
	"github.com/grok-free-register/grok-reg/internal/oauth"
	"github.com/grok-free-register/grok-reg/internal/protocol"
	"github.com/grok-free-register/grok-reg/internal/proxypool"
	"github.com/grok-free-register/grok-reg/internal/signup"
	"github.com/grok-free-register/grok-reg/internal/state"
	"github.com/grok-free-register/grok-reg/internal/turnstile"
)

type AccountUploadStatus struct {
	Attempted  bool
	OK         bool
	Name       string
	HTTPStatus int
	Verified   bool
	Error      string
}

type AccountSession struct {
	DiagnosticID string
	Proxy        string

	Email    string
	Password string
	Code     string
	Handle   email.Handle
	SSO      string
	Upload   AccountUploadStatus

	oauthMu     sync.Mutex
	oauthClient *oauth.Client
}

type QItem struct {
	Session *AccountSession
}

type SSOJob struct {
	Session *AccountSession
}

var diagnosticSequence atomic.Uint64

type Options struct {
	Cfg    config.Config
	Paths  home.Paths
	Run    home.RunDirs
	Target int
	Log    *logx.Logger
	Store  *state.Store
}

type Engine struct {
	opt Options

	cm       *clearance.Manager
	xai      *protocol.Client
	mail     *email.Provider
	turn     turnstile.Provider
	signup   signup.Driver
	inv      *inventory.Inventory[string, QItem]
	phys     *inventory.Semaphore
	qPending *inventory.Semaphore

	oauthCh  chan SSOJob
	uploader *cpa.Uploader

	done                    atomic.Int64
	ssoN                    atomic.Int64
	oaN                     atomic.Int64
	fail                    atomic.Int64
	oauthInvalidGrantStreak atomic.Int64

	// Per-mailbox-domain invalid_grant streaks. x.ai stops issuing tokens for a
	// mailbox domain once it has seen too many accounts from it, so a burnt
	// domain is retired from rotation before it drags the whole run down.
	domainStreakMu sync.Mutex
	domainStreak   map[string]int

	start   time.Time
	cancel  context.CancelFunc
	wgReg   sync.WaitGroup // S/P/C
	wgOAuth sync.WaitGroup
	wgAux   sync.WaitGroup // status ticker etc

	// Browser signup pacing (x.ai email-code rate limits).
	signupPaceMu sync.Mutex
	nextSignupAt time.Time

	// Account-scoped OAuth clients retain proxy affinity, while these run-wide
	// gates preserve cross-account cooldown and terminal target accounting.
	oauthExchangeMu  sync.Mutex
	oauthRateMu      sync.Mutex
	oauthRateUntil   time.Time
	oauthRateTrips   int
	oauthRateChanged chan struct{}
	completeOnce     sync.Once
	completeGate     chan struct{}

	// Optional multi-proxy rotation for browser signup.
	proxies *proxypool.Pool
}

func Run(ctx context.Context, opt Options) error {
	e := &Engine{
		opt:     opt,
		oauthCh: make(chan SSOJob, 64),
		start:   time.Now(),
	}
	return e.run(ctx)
}

func newDiagnosticID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), diagnosticSequence.Add(1))
}

func newAccountSession(h email.Handle, proxy string) *AccountSession {
	return &AccountSession{
		DiagnosticID: newDiagnosticID(),
		Proxy:        strings.TrimSpace(proxy),
		Email:        h.Email,
		Password:     h.Password,
		Handle:       h,
	}
}

func (e *Engine) nextAccountProxy() string {
	proxy := strings.TrimSpace(e.opt.Cfg.RegisterProxy)
	if e.proxies != nil && e.proxies.Len() > 0 {
		if selected := strings.TrimSpace(e.proxies.Next()); selected != "" {
			proxy = selected
		}
	}
	return proxy
}

func (e *Engine) buildOAuthClient(session *AccountSession) (*oauth.Client, error) {
	if session == nil {
		return nil, fmt.Errorf("account session required")
	}
	id := strings.TrimSpace(session.DiagnosticID)
	if id == "" {
		id = "startup"
	}
	tracef := func(format string, args ...any) {
		all := append([]any{id}, args...)
		e.opt.Log.Infof("[acct=%s] "+format, all...)
	}
	return oauth.NewClient(
		session.Proxy,
		e.cm,
		time.Duration(e.opt.Cfg.OAuthRetrySec*float64(time.Second)),
		oauth.Options{
			ConfirmMode:          e.opt.Cfg.OAuthConfirmMode,
			BrowserTimeout:       time.Duration(e.opt.Cfg.OAuthBrowserTimeoutSec * float64(time.Second)),
			BrowserDiagnosticDir: filepath.Join(e.opt.Run.Root, "oauth-browser", id),
			Tracef:               tracef,
		},
	)
}

func (e *Engine) oauthFor(session *AccountSession) (*oauth.Client, error) {
	if session == nil {
		return nil, fmt.Errorf("account session required")
	}
	session.oauthMu.Lock()
	defer session.oauthMu.Unlock()
	if session.oauthClient != nil {
		return session.oauthClient, nil
	}
	client, err := e.buildOAuthClient(session)
	if err != nil {
		return nil, err
	}
	session.oauthClient = client
	return client, nil
}

func (session *AccountSession) closeOAuth() {
	if session == nil {
		return
	}
	session.oauthMu.Lock()
	defer session.oauthMu.Unlock()
	if session.oauthClient != nil {
		session.oauthClient.CloseIdleConnections()
		session.oauthClient = nil
	}
}

func (e *Engine) waitOAuthRateLimit(ctx context.Context) error {
	for {
		e.oauthRateMu.Lock()
		wait := time.Until(e.oauthRateUntil)
		if wait <= 0 {
			e.oauthRateMu.Unlock()
			return nil
		}
		if e.oauthRateChanged == nil {
			e.oauthRateChanged = make(chan struct{})
		}
		changed := e.oauthRateChanged
		e.oauthRateMu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
			continue
		case <-timer.C:
		}
	}
}

func (e *Engine) signalOAuthRateChangeLocked() {
	if e.oauthRateChanged != nil {
		close(e.oauthRateChanged)
	}
	e.oauthRateChanged = make(chan struct{})
}

func (e *Engine) noteOAuthRateResult(err error) {
	e.oauthRateMu.Lock()
	defer e.oauthRateMu.Unlock()
	if err == nil {
		if !e.oauthRateUntil.IsZero() || e.oauthRateTrips != 0 {
			e.oauthRateUntil = time.Time{}
			e.oauthRateTrips = 0
			e.signalOAuthRateChangeLocked()
		}
		return
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "rate_limited") && !strings.Contains(message, "rate limited") {
		return
	}
	e.oauthRateTrips++
	cooldown := time.Duration(e.opt.Cfg.OAuthRetrySec * float64(time.Second))
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}
	for i := 1; i < e.oauthRateTrips; i++ {
		cooldown += cooldown / 2
		if cooldown >= 5*time.Minute {
			cooldown = 5 * time.Minute
			break
		}
	}
	until := time.Now().Add(cooldown)
	if until.After(e.oauthRateUntil) {
		e.oauthRateUntil = until
		e.signalOAuthRateChangeLocked()
	}
}

// noteOAuthOutcome tracks consecutive invalid_grant rejections across both the
// same-session and the standalone OAuth paths, and trips the configured circuit
// breaker once the limit is reached.
//
// Only a successful exchange clears the streak. An unrelated failure (poll
// timeout, missing SSO) is not evidence that x.ai resumed issuing tokens, and
// treating it as one is what let an overnight run burn 161 mailboxes: 108
// same-session invalid_grant rejections never reached this counter, and the
// futile standalone retries that followed reset it each time.
func (e *Engine) noteOAuthOutcome(err error) {
	e.noteOAuthOutcomeFor("", err)
}

// noteOAuthOutcomeFor is noteOAuthOutcome with the account's mailbox domain
// attached, so a single burnt domain can be retired from rotation before the
// run-wide fuse blows.
func (e *Engine) noteOAuthOutcomeFor(mailbox string, err error) {
	if err == nil {
		e.oauthInvalidGrantStreak.Store(0)
		e.clearDomainStreak(mailbox)
		return
	}
	if !oauth.IsInvalidGrant(err) {
		return
	}
	e.noteDomainInvalidGrant(mailbox)
	streak := e.oauthInvalidGrantStreak.Add(1)
	limit := int64(e.opt.Cfg.OAuthInvalidGrantLimit)
	if limit <= 0 || streak < limit {
		return
	}
	reason := fmt.Sprintf("OAuth 连续 %d 次 invalid_grant，x.ai 拒绝为新账号签发 token，已自动停止以避免继续消耗邮箱", streak)
	e.opt.Log.Errf("%s", reason)
	_ = e.opt.Store.Set(func(s *state.Snapshot) {
		s.Status = state.StatusError
		s.Phase = state.PhaseOAuth
		s.PhaseDetail = "OAuth 熔断停止"
		s.Error = reason
	})
	if e.cancel != nil {
		e.cancel()
	}
}

// domainInvalidGrantLimit is how many consecutive invalid_grant rejections
// retire a mailbox domain from rotation. It sits below the run-wide fuse so a
// single burnt domain gets dropped before the whole run is stopped.
const domainInvalidGrantLimit = 2

// noteDomainInvalidGrant retires a mailbox domain once x.ai has rejected that
// many of its accounts in a row.
func (e *Engine) noteDomainInvalidGrant(mailbox string) {
	domain := mailboxDomain(mailbox)
	if domain == "" || e.mail == nil {
		return
	}
	e.domainStreakMu.Lock()
	if e.domainStreak == nil {
		e.domainStreak = map[string]int{}
	}
	e.domainStreak[domain]++
	streak := e.domainStreak[domain]
	e.domainStreakMu.Unlock()
	if streak < domainInvalidGrantLimit {
		return
	}
	if !e.mail.BenchDomain(domain) {
		return
	}
	e.domainStreakMu.Lock()
	delete(e.domainStreak, domain)
	e.domainStreakMu.Unlock()
	if e.opt.Log != nil {
		e.opt.Log.Warnf("邮箱域 %s 连续 %d 次 invalid_grant，已退出轮换 (剩余 %v)", domain, streak, e.mail.CFTempDomainPool())
	}
}

// clearDomainStreak forgives a domain's streak after it produces a token.
func (e *Engine) clearDomainStreak(mailbox string) {
	domain := mailboxDomain(mailbox)
	if domain == "" {
		return
	}
	e.domainStreakMu.Lock()
	delete(e.domainStreak, domain)
	e.domainStreakMu.Unlock()
}

func mailboxDomain(mailbox string) string {
	at := strings.LastIndexByte(mailbox, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(mailbox[at+1:]))
}

func (e *Engine) startAccountDeviceFlow(ctx context.Context, client *oauth.Client) (oauth.DeviceFlow, error) {
	if client == nil {
		return oauth.DeviceFlow{}, fmt.Errorf("OAuth client required")
	}
	e.oauthExchangeMu.Lock()
	defer e.oauthExchangeMu.Unlock()
	if err := e.waitOAuthRateLimit(ctx); err != nil {
		return oauth.DeviceFlow{}, err
	}
	flow, err := client.StartDeviceFlow(ctx)
	if err != nil {
		e.noteOAuthRateResult(err)
	}
	return flow, err
}

func (e *Engine) acquireCompletion(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.completeOnce.Do(func() {
		e.completeGate = make(chan struct{}, 1)
		e.completeGate <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.completeGate:
		return nil
	}
}

func (e *Engine) releaseCompletion() {
	e.completeGate <- struct{}{}
}

func (e *Engine) enqueueOAuth(ctx context.Context, session *AccountSession) error {
	if session == nil {
		return fmt.Errorf("account session required")
	}
	job := SSOJob{Session: session}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e.oauthCh <- job:
		return nil
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e.oauthCh <- job:
		return nil
	}
}

func (e *Engine) run(ctx context.Context) error {
	cfg := e.opt.Cfg
	log := e.opt.Log
	st := e.opt.Store

	config.ApplyProxyEnv(cfg)

	sWorkers, pWorkers, cWorkers, oauthWorkers, physCap := deriveWorkers(cfg)
	e.phys = inventory.NewSemaphore(physCap)
	// Pending email codes in flight: cap by target so target=5 doesn't open 12 boxes.
	qPend := cfg.Target
	if qPend <= 0 {
		qPend = 4
	}
	if qPend > 6 {
		qPend = 6
	}
	if qPend < 2 {
		qPend = 2
	}
	// Browser mode: keep at most one staged mailbox so we don't burn codes
	// while the single browser worker is still mid-signup.
	regMode := strings.ToLower(strings.TrimSpace(cfg.RegisterMode))
	if isBrowserRegisterMode(regMode) {
		qPend = 1
	}
	e.qPending = inventory.NewSemaphore(qPend)
	tSlots, qSlots := 4, 4
	if cfg.Target > 0 && cfg.Target < 4 {
		tSlots, qSlots = cfg.Target, cfg.Target
	}
	e.inv = inventory.New[string, QItem](tSlots, qSlots)
	log.Infof("workers S=%d P=%d C=%d OAuth=%d phys=%d q_pending=%d", sWorkers, pWorkers, cWorkers, oauthWorkers, physCap, qPend)

	_ = st.Set(func(s *state.Snapshot) {
		s.Status = state.StatusRunning
		s.RunID = e.opt.Run.RunID
		s.Target = e.opt.Target
		s.Done = 0
		s.Phase = state.PhaseClearance
		s.PhaseDetail = "清障预热中"
		s.Workers = state.Workers{S: sWorkers, P: pWorkers, C: cWorkers, OAuth: oauthWorkers}
		s.PID = os.Getpid()
		s.StartedAt = e.start.UTC().Format(time.RFC3339)
		s.LogPath = e.opt.Run.LogPath
		s.OutputDir = e.opt.Run.Root
		s.Error = ""
	})

	// Clearance
	if cfg.ClearanceEnabled {
		e.cm = clearance.NewManager(cfg.FlareSolverrURL, cfg.ClearanceProxy, cfg.ClearanceURLs)
		msg, err := e.cm.Prewarm()
		if err != nil {
			log.Warnf("clearance: %v (%s)", err, msg)
		} else {
			log.Infof("[clearance] %s", msg)
		}
	} else {
		log.Info("[clearance] 未启用")
	}

	// Build register proxy pool: REGISTER_PROXIES (+ REGISTER_PROXY as fallback entry).
	proxyList := proxypool.ParseList(cfg.RegisterProxies)
	if strings.EqualFold(strings.TrimSpace(cfg.RegisterMode), "browser-mcp") && len(proxyList) > 1 {
		log.Warnf("[proxy] browser-mcp controls an existing Chrome network and cannot rotate per-tab proxies; REGISTER_PROXIES rotation is disabled for this mode")
		proxyList = nil
	}
	if len(proxyList) == 0 && strings.TrimSpace(cfg.RegisterProxy) != "" {
		// No pool configured — single REGISTER_PROXY only.
		proxyList = []string{cfg.RegisterProxy}
	}
	// When REGISTER_PROXIES is set, it is the full rotation list (do NOT silently
	// append REGISTER_PROXY, which used to drag a third gateway back into the pool).
	e.proxies = proxypool.New(proxypool.Options{
		Proxies:      proxyList,
		ProbeTimeout: 12 * time.Second,
		Cooldown:     12 * time.Minute,
		Logf: func(f string, a ...any) {
			log.Infof("[proxy] "+f, a...)
		},
	})
	if e.proxies != nil && e.proxies.Len() > 0 {
		live := e.proxies.ProbeAll(ctx)
		log.Infof("[proxy] pool size=%d live=%d | %s", e.proxies.Len(), live, e.proxies.Snapshot())
		if live == 0 {
			log.Warnf("[proxy] no proxy passed accounts.x.ai probe — will still try (browser may differ from curl)")
		}
		// Prefer a live proxy as the default for non-rotating clients.
		if pxy := e.proxies.Next(); pxy != "" {
			cfg.RegisterProxy = pxy
			e.opt.Cfg.RegisterProxy = pxy
		}
	}

	var err error
	e.xai, err = protocol.NewClient(cfg.RegisterProxy, e.cm)
	if err != nil {
		return err
	}
	outlookAccountsFile := strings.TrimSpace(cfg.OutlookAccountsFile)
	if outlookAccountsFile == "" {
		outlookAccountsFile = e.opt.Paths.OutlookAccounts
	}
	outlookStateFile := strings.TrimSpace(cfg.OutlookStateFile)
	if outlookStateFile == "" {
		outlookStateFile = e.opt.Paths.OutlookState
	}
	e.mail = email.New(email.Config{
		Mode:                     cfg.EmailMode,
		Domain:                   cfg.EmailDomain,
		API:                      cfg.EmailAPI,
		LOLRetries:               cfg.TempmailLOLRetries,
		LOLIntervalMS:            cfg.TempmailLOLIntervalMS,
		CFTempAPI:                cfg.CFTempEmailAPI,
		CFTempAdmin:              cfg.CFTempEmailAdmin,
		CFTempDomain:             cfg.CFTempEmailDomain,
		CFTempAuth:               cfg.CFTempEmailAuth,
		CFTempPrefix:             cfg.CFTempEmailPrefix,
		OutlookAccountsFile:      outlookAccountsFile,
		OutlookStateFile:         outlookStateFile,
		OutlookAliasesPerAccount: cfg.OutlookAliasesPerAccount,
		OutlookPollInterval:      time.Duration(cfg.OutlookPollIntervalSec * float64(time.Second)),
	})
	if err := e.mail.Validate(); err != nil {
		return fmt.Errorf("邮箱配置: %w", err)
	}
	if remaining, ok := e.mail.OutlookRemaining(); ok {
		if remaining < e.opt.Target {
			return fmt.Errorf("Outlook 别名池只剩 %d 个地址，少于本次目标 %d；请导入更多主邮箱或提高 OUTLOOK_ALIASES_PER_ACCOUNT", remaining, e.opt.Target)
		}
		if remaining < e.opt.Target+2 {
			log.Warnf("Outlook 别名池剩余 %d、目标 %d，几乎没有失败重试余量", remaining, e.opt.Target)
		}
	}
	if cfg.EmailMode == config.EmailCFTemp {
		pool := e.mail.CFTempDomainPool()
		domain := strings.Join(pool, ",")
		if domain == "" {
			domain = "(Worker auto)"
		}
		log.Infof("Email mode=cf_temp_email api=%s domains=%s (pool=%d) admin=%v", cfg.CFTempEmailAPI, domain, len(pool), cfg.CFTempEmailAdmin != "")
		if len(pool) == 1 {
			// One domain absorbs the whole run; x.ai's trust in it decays with
			// volume and every account starts coming back invalid_grant.
			log.Warnf("CF_TEMP_EMAIL_DOMAIN 只配了 1 个域名，大批量注册会烧掉它；建议逗号分隔多个域名轮换")
		}
	}
	if cfg.EmailMode == config.EmailOutlook {
		log.Infof("Email mode=outlook accounts=%s aliases_per_account=%d state=%s", outlookAccountsFile, cfg.OutlookAliasesPerAccount, outlookStateFile)
	}
	e.turn = turnstile.New(turnstile.Options{
		Provider: cfg.TurnstileProvider,
		LiteURL:  cfg.LiteSolverURL,
		Proxy:    cfg.RegisterProxy,
		Clear:    e.cm,
	})
	if c, ok := e.turn.(turnstile.Closer); ok {
		defer c.Close()
	}
	regMode = strings.ToLower(strings.TrimSpace(cfg.RegisterMode))
	if regMode == "" {
		regMode = "browser"
	}
	if regMode == "browser" {
		e.signup = signup.NewBrowser(signup.BrowserOptions{
			Proxy:         cfg.RegisterProxy,
			Timeout:       time.Duration(cfg.SignupBrowserTimeoutSec * float64(time.Second)),
			CodeTimeout:   100 * time.Second,
			DiagnosticDir: filepath.Join(e.opt.Run.Root, "signup-browser"),
			Tracef:        log.Infof,
		})
		log.Infof("Register mode=browser script=%s (Castle+Turnstile in-page)", signup.DetectedScript())
	} else if regMode == "browser-mcp" {
		workingDir, _ := os.Getwd()
		e.signup = signup.NewMCPBrowser(signup.MCPBrowserOptions{
			Command:       cfg.BrowserMCPCommand,
			Incognito:     cfg.BrowserMCPIncognito,
			Timeout:       time.Duration(cfg.SignupBrowserTimeoutSec * float64(time.Second)),
			CodeTimeout:   100 * time.Second,
			DiagnosticDir: filepath.Join(e.opt.Run.Root, "signup-browser-mcp"),
			WorkingDir:    workingDir,
			Tracef:        log.Infof,
		})
		log.Infof("Register mode=browser-mcp cli=%s incognito=%v (real Chrome; Castle+Turnstile in-page)", cfg.BrowserMCPCommand, cfg.BrowserMCPIncognito)
	} else {
		log.Infof("Register mode=%s (legacy HTTP; higher bot risk)", regMode)
		log.Infof("Turnstile provider=%s (Playwright mint preferred, chromedp fallback)", e.turn.Name())
		log.Infof("Turnstile mint: python=%s script=%s", turnstile.DetectedPython(), turnstile.DetectedScript())
	}
	e.uploader = cpa.NewUploader(cpa.UploadConfig{
		Enabled:      cfg.CPAUploadEnabled,
		BaseURL:      cfg.CPAManagementBase,
		Key:          cfg.CPAManagementKey,
		TimeoutSec:   cfg.CPAUploadTimeoutSec,
		Retries:      cfg.CPAUploadRetries,
		NameTemplate: cfg.CPAUploadNameTemplate,
		Verify:       cfg.CPAUploadVerify,
		Mode:         cfg.CPAUploadMode,
	}, func(f string, a ...any) {
		log.Infof(f, a...)
	})
	if e.uploader.Enabled() {
		log.Infof("CPA upload enabled base=%s", cfg.CPAManagementBase)
	}
	oauthCheck, err := e.buildOAuthClient(&AccountSession{
		DiagnosticID: "startup",
		Proxy:        cfg.RegisterProxy,
	})
	if err != nil {
		return err
	}
	log.Infof("OAuth confirm mode=%s", oauthCheck.ConfirmMode())

	var scfg protocol.SignupConfig
	regMode = strings.ToLower(strings.TrimSpace(cfg.RegisterMode))
	if regMode == "" {
		regMode = "browser"
	}
	if !isBrowserRegisterMode(regMode) {
		_ = st.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseRegister
			s.PhaseDetail = "获取注册配置"
		})
		log.Info("Fetching signup config...")
		scfg, err = e.xai.FetchConfig()
		if err != nil {
			_ = st.Set(func(s *state.Snapshot) {
				s.Status = state.StatusError
				s.Error = err.Error()
				s.PhaseDetail = "配置获取失败"
			})
			return fmt.Errorf("config fetch: %w", err)
		}
		log.Infof("SITE_KEY=%s ACTION_ID=%s...", scfg.SiteKey, trim(scfg.ActionID, 12))
	} else {
		_ = st.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseRegister
			s.PhaseDetail = "浏览器注册就绪"
		})
	}
	log.OKf("注册服务已启动 | mode=%s | 目标 %d | run=%s", regMode, e.opt.Target, e.opt.Run.RunID)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.cancel = cancel

	// signal
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case <-sigCh:
			log.Warn("收到停止信号，正在退出...")
			cancel()
		case <-ctx.Done():
		}
	}()

	// status ticker
	e.wgAux.Add(1)
	go func() {
		defer e.wgAux.Done()
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.refreshState()
			}
		}
	}()

	if isBrowserRegisterMode(regMode) {
		// Browser signup mints Turnstile/Castle itself; no separate S workers.
		// pWorker still prepares mailboxes, but must NOT pre-send email codes
		// (the browser page triggers CreateEmailValidationCode with Castle).
		for i := 0; i < pWorkers; i++ {
			e.wgReg.Add(1)
			go e.pWorkerBrowser(ctx, i)
		}
		for i := 0; i < cWorkers; i++ {
			e.wgReg.Add(1)
			go e.cWorkerBrowser(ctx, i)
		}
	} else {
		for i := 0; i < sWorkers; i++ {
			e.wgReg.Add(1)
			go e.sWorker(ctx, i, scfg)
		}
		for i := 0; i < pWorkers; i++ {
			e.wgReg.Add(1)
			go e.pWorker(ctx, i)
		}
		for i := 0; i < cWorkers; i++ {
			e.wgReg.Add(1)
			go e.cWorker(ctx, i, scfg)
		}
	}
	for i := 0; i < oauthWorkers; i++ {
		e.wgOAuth.Add(1)
		go e.oauthWorker(ctx, i)
	}

	// wait until target or cancel
	for {
		if int(e.done.Load()) >= e.opt.Target {
			log.OKf("已达目标 %d，停止", e.opt.Target)
			cancel()
			break
		}
		select {
		case <-ctx.Done():
			goto shutdown
		case <-time.After(500 * time.Millisecond):
		}
	}
shutdown:
	// 1) stop S/P/C producers (ctx canceled)
	// 2) wait register workers so no more sends to oauthCh
	// 3) close oauthCh so OAuth workers exit range
	waitGroupTimeout(&e.wgReg, 15*time.Second, log, "register workers")
	close(e.oauthCh)
	waitGroupTimeout(&e.wgOAuth, 30*time.Second, log, "oauth workers")
	waitGroupTimeout(&e.wgAux, 3*time.Second, log, "aux")

	_ = st.Set(func(s *state.Snapshot) {
		if s.Status != state.StatusError {
			s.Status = state.StatusStopped
			s.Phase = state.PhaseIdle
			s.PhaseDetail = fmt.Sprintf("完成 %d/%d", e.done.Load(), e.opt.Target)
		}
		s.Done = int(e.done.Load())
		s.SSOCount = int(e.ssoN.Load())
		s.OAuthCount = int(e.oaN.Load())
		s.FailCount = int(e.fail.Load())
		s.PID = 0
	})
	log.Infof("结束 done=%d sso=%d oauth=%d fail=%d", e.done.Load(), e.ssoN.Load(), e.oaN.Load(), e.fail.Load())
	return nil
}

func (e *Engine) refreshState() {
	elapsed := time.Since(e.start).Minutes()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(e.done.Load()) / elapsed
	}
	t, q := e.inv.Depths()
	_ = e.opt.Store.Set(func(s *state.Snapshot) {
		s.Done = int(e.done.Load())
		s.SSOCount = int(e.ssoN.Load())
		s.OAuthCount = int(e.oaN.Load())
		s.FailCount = int(e.fail.Load())
		s.RatePerMin = rate
		if s.Phase == state.PhaseRegister || s.Phase == "" {
			s.PhaseDetail = fmt.Sprintf("注册中 T=%d Q=%d done=%d/%d", t, q, e.done.Load(), e.opt.Target)
		}
	})
}

func waitGroupTimeout(wg *sync.WaitGroup, d time.Duration, log *logx.Logger, name string) {
	ch := make(chan struct{})
	go func() {
		wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(d):
		log.Warnf("%s 退出超时", name)
	}
}

func (e *Engine) sWorker(ctx context.Context, id int, scfg protocol.SignupConfig) {
	defer e.wgReg.Done()
	log := e.opt.Log
	pageURL := protocol.SiteURL + "/sign-up"
	for {
		if int(e.done.Load()) >= e.opt.Target {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := e.phys.Acquire(ctx); err != nil {
			return
		}
		tok, err := e.turn.Solve(ctx, scfg.SiteKey, pageURL)
		e.phys.Release()
		if err != nil {
			log.Warnf("[S%d] turnstile: %v", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if err := e.inv.PutT(ctx, tok, 5*time.Minute); err != nil {
			return
		}
		log.Infof("[S%d] token ok (len=%d)", id, len(tok))
	}
}

func (e *Engine) pWorker(ctx context.Context, id int) {
	defer e.wgReg.Done()
	log := e.opt.Log
	for {
		if int(e.done.Load()) >= e.opt.Target {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Admission: don't flood tempmail when T is empty or we already have enough Q.
		// remaining CPA slots ≈ target - done; keep at most min(4, remaining) Q ready.
		remaining := e.opt.Target - int(e.done.Load())
		if remaining <= 0 {
			return
		}
		_, qDepth := e.inv.Depths()
		qCap := remaining
		if qCap > 4 {
			qCap = 4
		}
		if qCap < 1 {
			qCap = 1
		}
		if qDepth >= qCap {
			select {
			case <-ctx.Done():
				return
			case <-time.After(800 * time.Millisecond):
			}
			continue
		}

		if err := e.qPending.Acquire(ctx); err != nil {
			return
		}
		h, err := e.mail.Create()
		if err != nil {
			e.qPending.Release()
			log.Debugf("[P%d] create email: %v", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		session := newAccountSession(h, e.opt.Cfg.RegisterProxy)
		if err := e.xai.CreateEmailCode(session.Email); err != nil {
			e.mail.Release(h)
			e.qPending.Release()
			log.Debugf("[P%d] create code %s: %v", id, session.Email, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		code, err := e.mail.PollCode(h, 90*time.Second)
		if err != nil {
			e.qPending.Release()
			log.Debugf("[P%d] poll code: %v", id, err)
			continue
		}
		session.Code = code
		item := QItem{Session: session}
		if err := e.inv.PutQ(ctx, item, 2*time.Minute); err != nil {
			e.qPending.Release()
			return
		}
		e.qPending.Release()
		log.Debugf("[P%d] Q ready %s acct=%s", id, session.Email, session.DiagnosticID)
	}
}

func (e *Engine) cWorker(ctx context.Context, id int, scfg protocol.SignupConfig) {
	defer e.wgReg.Done()
	log := e.opt.Log
	for {
		if int(e.done.Load()) >= e.opt.Target {
			return
		}
		pair, err := e.inv.ClaimPair(ctx)
		if err != nil {
			return
		}
		token := pair.T.Value
		session := pair.Q.Value.Session
		if session == nil {
			pair.Release()
			log.Warnf("[C%d] missing account session", id)
			e.fail.Add(1)
			continue
		}
		_ = e.opt.Store.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseRegister
			s.PhaseDetail = fmt.Sprintf("正在注册 %s", session.Email)
		})
		log.Startf("开始注册 %s acct=%s", session.Email, session.DiagnosticID)

		e.xai.ClearAuthCookies()
		if err := e.xai.VerifyEmailCode(session.Email, session.Code); err != nil {
			log.Warnf("verify fail %s acct=%s: %v", session.Email, session.DiagnosticID, err)
			pair.Release()
			e.fail.Add(1)
			continue
		}
		body := protocol.BuildSignupBody(session.Email, session.Password, session.Code, token)
		text, sso, err := e.xai.SignupServerAction(body, scfg.ActionID, scfg.StateTree)
		if sso == "" {
			sso = protocol.ExtractSSOFromText(text)
		}
		pair.Release()
		if err != nil || sso == "" {
			preview := text
			if len(preview) > 180 {
				preview = preview[:180]
			}
			log.Warnf("signup fail %s acct=%s: err=%v sso=%v body=%q", session.Email, session.DiagnosticID, err, sso != "", preview)
			e.fail.Add(1)
			continue
		}

		session.SSO = strings.TrimSpace(sso)
		accPath := filepath.Join(e.opt.Run.SSO, "accounts.txt")
		if err := cpa.AppendSSO(accPath, session.Email, session.Password, session.SSO); err != nil {
			log.Warnf("write sso: %v", err)
		}
		_ = cpa.AppendAuthSession(filepath.Join(e.opt.Run.SSO, "auth-sessions.jsonl"), session.Email, session.SSO)
		n := e.ssoN.Add(1)
		log.OKf("注册成功 #%d %s acct=%s", n, session.Email, session.DiagnosticID)

		// A brand-new SSO can briefly bounce auth.x.ai device verify back to
		// sign-in. Give the session a short propagation window before OAuth.
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		if err := e.enqueueOAuth(ctx, session); err != nil {
			session.closeOAuth()
			return
		}
	}
}

func (e *Engine) oauthWorker(ctx context.Context, id int) {
	defer e.wgOAuth.Done()
	log := e.opt.Log
	minInterval := time.Duration(e.opt.Cfg.OAuthMinIntervalSec * float64(time.Second))
	if minInterval <= 0 {
		minInterval = 10 * time.Second
	}
	var last time.Time
	for job := range e.oauthCh {
		session := job.Session
		if session == nil {
			log.Warnf("[OAuth%d] missing account session", id)
			e.fail.Add(1)
			continue
		}
		if ctx.Err() != nil || int(e.done.Load()) >= e.opt.Target {
			session.closeOAuth()
			continue
		}
		if !last.IsZero() {
			if d := time.Until(last.Add(minInterval)); d > 0 {
				select {
				case <-ctx.Done():
					session.closeOAuth()
					continue
				case <-time.After(d):
				}
			}
		}
		last = time.Now()
		_ = e.opt.Store.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseOAuth
			s.PhaseDetail = fmt.Sprintf("正在 OAuth (%s)", session.Email)
		})
		log.Startf("OAuth %s acct=%s", session.Email, session.DiagnosticID)
		cred, err := e.exchangeOAuthWithRetry(ctx, session)
		if err != nil {
			session.closeOAuth()
			log.Warnf("OAuth fail %s acct=%s: %v", session.Email, session.DiagnosticID, err)
			_ = cpa.AppendOAuthFailure(
				filepath.Join(e.opt.Run.SSO, "oauth-failures.jsonl"),
				session.Email,
				err.Error(),
				session.DiagnosticID,
			)
			e.fail.Add(1)
			e.noteOAuthOutcomeFor(session.Email, err)
			continue
		}
		e.noteOAuthOutcomeFor(session.Email, nil)
		if err := e.completeAccount(ctx, session, cred, "oauth-worker"); err != nil {
			log.Warnf("CPA finalize fail %s acct=%s: %v", session.Email, session.DiagnosticID, err)
			e.fail.Add(1)
		}
	}
}

func (e *Engine) exchangeOAuthWithRetry(ctx context.Context, session *AccountSession) (oauth.Credential, error) {
	client, err := e.oauthFor(session)
	if err != nil {
		return oauth.Credential{}, err
	}
	retries := e.opt.Cfg.OAuthFlowRetries
	if retries < 0 {
		retries = 0
	}
	delay := time.Duration(e.opt.Cfg.OAuthRetryDelaySec * float64(time.Second))
	if delay <= 0 {
		delay = 30 * time.Second
	}
	var last error
	for attempt := 0; attempt <= retries; attempt++ {
		e.oauthExchangeMu.Lock()
		if err := e.waitOAuthRateLimit(ctx); err != nil {
			e.oauthExchangeMu.Unlock()
			return oauth.Credential{}, err
		}
		cred, exchangeErr := client.ExchangeAccount(ctx, session.SSO, session.Email, session.Password)
		e.noteOAuthRateResult(exchangeErr)
		e.oauthExchangeMu.Unlock()
		if exchangeErr == nil {
			return cred, nil
		}
		last = exchangeErr
		if e.proxies != nil {
			e.proxies.ReportFailure(session.Proxy, exchangeErr)
		}
		if attempt >= retries || !oauth.IsRetryableRejection(exchangeErr) {
			break
		}
		e.opt.Log.Warnf("OAuth %s acct=%s: %v；%s 后用全新 Device Flow 重试 (%d/%d)", session.Email, session.DiagnosticID, exchangeErr, delay, attempt+1, retries)
		select {
		case <-ctx.Done():
			return oauth.Credential{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	return oauth.Credential{}, last
}

func (e *Engine) completeAccount(ctx context.Context, session *AccountSession, cred oauth.Credential, source string) error {
	if session == nil {
		return fmt.Errorf("account session required")
	}
	defer session.closeOAuth()
	e.oaN.Add(1)
	doc := cpa.FromCredential(cred, session.Email)

	// Finalization includes synchronous upload, so serialize the target check and
	// completion increment to prevent slow uploads from overshooting the target.
	if err := e.acquireCompletion(ctx); err != nil {
		path, saveErr := cpa.WriteAtomic(e.opt.Run.Discarded, doc, cpa.DefaultSecret())
		if saveErr != nil {
			return fmt.Errorf("completion canceled (%v); save credential: %w", err, saveErr)
		}
		if e.opt.Log != nil {
			e.opt.Log.Warnf("completion canceled; saved credential acct=%s -> %s", session.DiagnosticID, filepath.Base(path))
		}
		return err
	}
	defer e.releaseCompletion()

	if e.opt.Target > 0 && int(e.done.Load()) >= e.opt.Target {
		path, err := cpa.WriteAtomic(e.opt.Run.Discarded, doc, cpa.DefaultSecret())
		if err != nil {
			return fmt.Errorf("save over-target credential: %w", err)
		}
		e.opt.Log.Warnf("target reached; saved extra credential acct=%s -> %s", session.DiagnosticID, filepath.Base(path))
		return nil
	}
	_ = e.opt.Store.Set(func(s *state.Snapshot) {
		s.Phase = state.PhaseProbe
		s.PhaseDetail = fmt.Sprintf("探活 %s", session.Email)
	})
	if e.opt.Cfg.ProbeEnabled {
		if err := cpa.ProbeContext(ctx, doc, session.Proxy); err != nil {
			_, _ = cpa.WriteAtomic(e.opt.Run.Discarded, doc, cpa.DefaultSecret())
			return fmt.Errorf("probe: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		if _, saveErr := cpa.WriteAtomic(e.opt.Run.Discarded, doc, cpa.DefaultSecret()); saveErr != nil {
			return fmt.Errorf("completion canceled (%v); save credential: %w", err, saveErr)
		}
		return err
	}
	path, err := cpa.WriteAtomic(e.opt.Run.CPA, doc, cpa.DefaultSecret())
	if err != nil {
		return fmt.Errorf("write CPA: %w", err)
	}
	if e.uploader != nil && e.uploader.Enabled() {
		result := e.uploader.UploadDocumentContext(ctx, doc)
		session.Upload = AccountUploadStatus{
			Attempted:  true,
			OK:         result.OK,
			Name:       result.Name,
			HTTPStatus: result.Status,
			Verified:   result.Verified,
		}
		if result.Err != nil {
			session.Upload.Error = trim(result.Err.Error(), 160)
		} else if !result.OK {
			session.Upload.Error = "upload_failed"
		}
		if result.OK {
			e.opt.Log.Infof("CPA upload complete acct=%s name=%s status=%d verified=%v", session.DiagnosticID, result.Name, result.Status, result.Verified)
		} else {
			e.opt.Log.Warnf("CPA upload failed acct=%s name=%s status=%d", session.DiagnosticID, result.Name, result.Status)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := e.done.Add(1)
	e.opt.Log.OKf("OAuth/CPA 完成 #%d/%d %s -> %s (%s acct=%s)", done, e.opt.Target, session.Email, filepath.Base(path), source, session.DiagnosticID)
	e.refreshState()
	return nil
}

// pWorkerBrowser creates mailboxes only. Email codes are requested by the
// accounts.x.ai page itself (with a real Castle token), so we must not call
// CreateEmailCode over raw HTTP here.
func (e *Engine) pWorkerBrowser(ctx context.Context, id int) {
	defer e.wgReg.Done()
	log := e.opt.Log
	for {
		// Target is OAuth/CPA completions (done), not bare SSO count.
		if int(e.done.Load()) >= e.opt.Target {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Allow a small SSO backlog awaiting OAuth so one slow OAuth does not
		// starve the pipeline, but never treat ssoN as "target reached".
		remaining := e.opt.Target - int(e.done.Load())
		if remaining <= 0 {
			return
		}
		// Cap staged mailboxes by remaining completions + 1 in-flight SSO headroom.
		headroom := remaining + 1
		_, qDepth := e.inv.Depths()
		qCap := headroom
		if qCap > 2 {
			qCap = 2
		}
		if qCap < 1 {
			qCap = 1
		}
		if qDepth >= qCap {
			select {
			case <-ctx.Done():
				return
			case <-time.After(800 * time.Millisecond):
			}
			continue
		}
		if err := e.qPending.Acquire(ctx); err != nil {
			return
		}
		h, err := e.mail.Create()
		if err != nil {
			e.qPending.Release()
			log.Debugf("[P%d] create email: %v", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		session := newAccountSession(h, e.nextAccountProxy())
		item := QItem{Session: session}
		if err := e.inv.PutQ(ctx, item, 5*time.Minute); err != nil {
			e.mail.Release(h)
			e.qPending.Release()
			return
		}
		e.qPending.Release()
		log.Debugf("[P%d] mailbox ready %s acct=%s proxy=%s", id, session.Email, session.DiagnosticID, proxypool.Label(session.Proxy))
	}
}

func (e *Engine) waitSignupPace(ctx context.Context, log *logx.Logger) error {
	for {
		e.signupPaceMu.Lock()
		wait := time.Until(e.nextSignupAt)
		e.signupPaceMu.Unlock()
		if wait <= 0 {
			return nil
		}
		if wait > 2*time.Second {
			log.Debugf("signup pace: wait %s before next browser attempt", wait.Round(time.Second))
		}
		_ = e.opt.Store.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseRegister
			s.PhaseDetail = fmt.Sprintf("注册降速等待 %s", wait.Round(time.Second))
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (e *Engine) noteSignupAttempt(rateLimited bool) {
	minGap := time.Duration(e.opt.Cfg.SignupMinIntervalSec * float64(time.Second))
	if minGap <= 0 {
		minGap = 35 * time.Second
	}
	backoff := time.Duration(e.opt.Cfg.SignupRateLimitBackoffSec * float64(time.Second))
	if backoff <= 0 {
		backoff = 90 * time.Second
	}
	gap := minGap
	if rateLimited {
		if backoff > gap {
			gap = backoff
		}
		// Stack a little extra jitter after rate-limit to desync bursts.
		gap += 15 * time.Second
	}
	e.signupPaceMu.Lock()
	next := time.Now().Add(gap)
	if next.After(e.nextSignupAt) {
		e.nextSignupAt = next
	}
	e.signupPaceMu.Unlock()
}

func (e *Engine) cWorkerBrowser(ctx context.Context, id int) {
	defer e.wgReg.Done()
	log := e.opt.Log
	if e.signup == nil {
		log.Errf("[C%d] browser signup client missing", id)
		return
	}
	for {
		// Only OAuth/CPA completion (done) counts toward -t target.
		if int(e.done.Load()) >= e.opt.Target {
			return
		}
		if err := e.waitSignupPace(ctx, log); err != nil {
			return
		}
		env, err := e.inv.ClaimQ(ctx)
		if err != nil {
			return
		}
		session := env.Value.Session
		if session == nil {
			env.Release()
			log.Warnf("[C%d] missing account session", id)
			e.fail.Add(1)
			continue
		}
		_ = e.opt.Store.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseRegister
			s.PhaseDetail = fmt.Sprintf("浏览器注册 %s", session.Email)
		})
		log.Startf("开始浏览器注册 %s acct=%s", session.Email, session.DiagnosticID)

		if err := e.phys.Acquire(ctx); err != nil {
			env.Release()
			return
		}
		e.signup.SetProxy(session.Proxy)
		diagnosticRoot := "signup-browser"
		if e.signup.Name() == "browser-mcp-signup" {
			diagnosticRoot = "signup-browser-mcp"
		}
		e.signup.SetDiagnosticDir(filepath.Join(e.opt.Run.Root, diagnosticRoot, session.DiagnosticID))
		log.Infof("browser acct=%s proxy=%s", session.DiagnosticID, proxypool.Label(session.Proxy))
		_ = e.opt.Store.Set(func(s *state.Snapshot) {
			s.Phase = state.PhaseRegister
			s.PhaseDetail = fmt.Sprintf("浏览器注册 %s @%s", session.Email, proxypool.Label(session.Proxy))
		})

		client, clientErr := e.oauthFor(session)
		if clientErr != nil {
			e.phys.Release()
			env.Release()
			log.Warnf("OAuth client fail %s acct=%s: %v", session.Email, session.DiagnosticID, clientErr)
			e.fail.Add(1)
			e.noteSignupAttempt(false)
			continue
		}

		// Start Device Flow first so the same browser session can approve it
		// immediately after signup (matches manual register→OAuth continuity).
		flow, flowErr := e.startAccountDeviceFlow(ctx, client)
		if flowErr != nil {
			e.phys.Release()
			env.Release()
			session.closeOAuth()
			log.Warnf("device flow start fail %s acct=%s: %v", session.Email, session.DiagnosticID, flowErr)
			if e.proxies != nil {
				e.proxies.ReportFailure(session.Proxy, flowErr)
			}
			e.fail.Add(1)
			e.noteSignupAttempt(false)
			continue
		}

		type pollResult struct {
			cred oauth.Credential
			err  error
		}
		pollCtx, cancelPoll := context.WithCancel(ctx)
		pollCh := make(chan pollResult, 1)
		go func() {
			cred, err := client.PollToken(pollCtx, flow)
			pollCh <- pollResult{cred: cred, err: err}
		}()

		result, regErr := e.signup.RegisterWithOAuth(ctx, session.Email, session.Password, "", "", flow.VerificationURL, func(pctx context.Context) (string, error) {
			_ = pctx
			return e.mail.PollCode(session.Handle, 100*time.Second)
		})
		e.mail.Release(session.Handle)
		e.phys.Release()
		env.Release()
		if regErr != nil || !result.OK {
			cancelPoll()
			session.closeOAuth()
			log.Warnf("browser signup fail %s acct=%s: %v", session.Email, session.DiagnosticID, regErr)
			e.fail.Add(1)
			rateLimited := regErr != nil && (strings.Contains(strings.ToLower(regErr.Error()), "rate limit") ||
				strings.Contains(strings.ToLower(regErr.Error()), "rate_limited") ||
				strings.Contains(strings.ToLower(regErr.Error()), "too many") ||
				strings.Contains(regErr.Error(), "email_code_rate_limited"))
			if rateLimited {
				log.Warnf("email/signup rate-limited — backoff before next attempt")
			}
			if e.proxies != nil && regErr != nil {
				e.proxies.ReportFailure(session.Proxy, regErr)
			}
			e.noteSignupAttempt(rateLimited)
			continue
		}
		if e.proxies != nil {
			e.proxies.ReportSuccess(session.Proxy)
		}
		e.noteSignupAttempt(false)
		session.SSO = strings.TrimSpace(result.SSO)
		accPath := filepath.Join(e.opt.Run.SSO, "accounts.txt")
		if err := cpa.AppendSSO(accPath, session.Email, session.Password, session.SSO); err != nil {
			log.Warnf("write sso: %v", err)
		}
		if session.SSO != "" {
			_ = cpa.AppendAuthSession(filepath.Join(e.opt.Run.SSO, "auth-sessions.jsonl"), session.Email, session.SSO)
		}
		n := e.ssoN.Add(1)
		log.OKf("注册成功 #%d %s (browser oauth_session=%v acct=%s)", n, session.Email, result.OAuthAuthorized, session.DiagnosticID)
		if !result.OAuthAuthorized && session.SSO == "" {
			cancelPoll()
			session.closeOAuth()
			err := fmt.Errorf("browser registration succeeded but same-session OAuth was not authorized and SSO export is disabled")
			log.Warnf("OAuth unavailable %s acct=%s: %v", session.Email, session.DiagnosticID, err)
			_ = cpa.AppendOAuthFailure(filepath.Join(e.opt.Run.SSO, "oauth-failures.jsonl"), session.Email, err.Error(), session.DiagnosticID)
			e.fail.Add(1)
			continue
		}

		if result.OAuthAuthorized {
			_ = e.opt.Store.Set(func(s *state.Snapshot) {
				s.Phase = state.PhaseOAuth
				s.PhaseDetail = fmt.Sprintf("同会话 OAuth (%s)", session.Email)
			})
			var cred oauth.Credential
			var pollErr error
			select {
			case <-ctx.Done():
				cancelPoll()
				session.closeOAuth()
				return
			case pr := <-pollCh:
				cancelPoll()
				cred, pollErr = pr.cred, pr.err
			case <-time.After(2 * time.Minute):
				cancelPoll()
				pollErr = fmt.Errorf("oauth_poll_timeout")
			}
			if pollErr != nil {
				e.noteOAuthRateResult(pollErr)
				// The standalone fallback replays the flow from an SSO cookie.
				// browser-mcp never exports one (the incognito window is wiped
				// and closed), so re-queueing only logs a second guaranteed
				// "missing SSO session" failure per account.
				retryable := session.SSO != ""
				if retryable {
					log.Warnf("OAuth poll fail %s acct=%s: %v；回退独立 OAuth", session.Email, session.DiagnosticID, pollErr)
				} else {
					log.Warnf("OAuth poll fail %s acct=%s: %v（无 SSO 导出，跳过独立 OAuth 回退）", session.Email, session.DiagnosticID, pollErr)
				}
				_ = cpa.AppendOAuthFailure(
					filepath.Join(e.opt.Run.SSO, "oauth-failures.jsonl"),
					session.Email,
					pollErr.Error(),
					session.DiagnosticID,
				)
				if e.proxies != nil {
					e.proxies.ReportFailure(session.Proxy, pollErr)
				}
				if !retryable {
					session.closeOAuth()
					e.fail.Add(1)
					// Same-session invalid_grant is the authoritative verdict
					// here; without it the breaker never sees these rejections.
					e.noteOAuthOutcomeFor(session.Email, pollErr)
					continue
				}
				if err := e.enqueueOAuth(ctx, session); err != nil {
					session.closeOAuth()
					return
				}
				continue
			}
			e.noteOAuthOutcomeFor(session.Email, nil)
			e.noteOAuthRateResult(nil)
			if err := e.completeAccount(ctx, session, cred, "same-session oauth"); err != nil {
				log.Warnf("CPA finalize fail %s acct=%s: %v", session.Email, session.DiagnosticID, err)
				e.fail.Add(1)
			}
			continue
		}

		cancelPoll()
		// Browser approved signup but not the device code — fall back while retaining
		// the account's proxy, diagnostic ID, and OAuth client.
		select {
		case <-ctx.Done():
			session.closeOAuth()
			return
		case <-time.After(2 * time.Second):
		}
		if err := e.enqueueOAuth(ctx, session); err != nil {
			session.closeOAuth()
			return
		}
	}
}

func deriveWorkers(cfg config.Config) (s, p, c, oa, phys int) {
	phys = cfg.PhysicalCap
	if phys <= 0 {
		cpus := runtime.NumCPU()
		phys = cpus
		if phys > 4 {
			phys = 4
		}
		if phys < 2 {
			phys = 2
		}
	}
	regMode := strings.ToLower(strings.TrimSpace(cfg.RegisterMode))
	if regMode == "" {
		regMode = "browser"
	}
	// Browser Turnstile / browser signup: serial-ish (one heavy browser at a time).
	if isBrowserRegisterMode(regMode) || strings.EqualFold(cfg.TurnstileProvider, "browser") || cfg.TurnstileProvider == "" {
		s = 1
		phys = 1
	} else {
		s = phys
	}
	// P workers: don't spawn 8 when target is 5 (was flooding tempmail).
	target := cfg.Target
	if target <= 0 {
		target = 10
	}
	p = target
	if p > 4 {
		p = 4
	}
	if p < 1 {
		p = 1
	}
	c = 2
	if target < 2 {
		c = 1
	}
	// Browser signup itself is the bottleneck; keep one completer and one
	// mailbox preparer so we don't pre-create many addresses / trigger code
	// rate limits while the browser is still working.
	if isBrowserRegisterMode(regMode) {
		s = 0
		c = 1
		p = 1
	}
	oa = cfg.OAuthWorkers
	if oa < 1 {
		oa = 1
	}
	if oa > 4 {
		oa = 4
	}
	// s may be 0 in browser-register mode (no separate Turnstile S workers).
	if s < 0 {
		s = 0
	}
	if !isBrowserRegisterMode(regMode) && s < 1 {
		s = 1
	}
	return
}

func isBrowserRegisterMode(mode string) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	return mode == "" || mode == "browser" || mode == "browser-mcp"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
