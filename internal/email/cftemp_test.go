package email

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
)

func TestCFTempPublicCreateAndPoll(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/new_address", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		if body["name"] == "" || body["domain"] != "example.com" {
			t.Errorf("unexpected create request: %v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address":    "ocfixture@example.com",
			"address_id": 42,
			"jwt":        "address-jwt",
		})
	})
	mux.HandleFunc("/api/parsed_mails", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer address-jwt" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count": 1,
			"results": []any{map[string]any{
				"subject": "Your verification code",
				"text":    "Code: ABC-123",
				"sender":  "noreply@x.ai",
			}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	provider := New(Config{
		Mode:         config.EmailCFTemp,
		CFTempAPI:    server.URL,
		CFTempDomain: "example.com",
		HTTPClient:   server.Client(),
	})
	handle, err := provider.Create()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if handle.Email != "ocfixture@example.com" || handle.Kind != "cftemp" || handle.Token != "address-jwt" {
		t.Fatalf("unexpected handle: kind=%s email=%s has_token=%v", handle.Kind, handle.Email, strings.TrimSpace(handle.Token) != "")
	}
	code, err := provider.PollCode(handle, 2*time.Second)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if code != "ABC123" {
		t.Fatalf("code=%q", code)
	}
}

func TestSplitDomainsBuildsRotationPool(t *testing.T) {
	t.Parallel()
	got := SplitDomains(" a.example.com, b.example.org\nA.EXAMPLE.COM ;; c.example.net ")
	want := []string{"a.example.com", "b.example.org", "c.example.net"}
	if len(got) != len(want) {
		t.Fatalf("pool = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pool = %v, want %v", got, want)
		}
	}
	if pool := SplitDomains("mail.tm, ok.example.com"); len(pool) != 1 || pool[0] != "ok.example.com" {
		t.Fatalf("banned domain survived: %v", pool)
	}
	if pool := SplitDomains("  "); len(pool) != 0 {
		t.Fatalf("empty config produced pool %v", pool)
	}
}

func TestCFTempRotatesAcrossConfiguredDomains(t *testing.T) {
	t.Parallel()
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		domain, _ := body["domain"].(string)
		seen[domain]++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": "ocfixture@" + domain,
			"jwt":     "address-jwt",
		})
	}))
	defer server.Close()

	provider := New(Config{
		Mode:         config.EmailCFTemp,
		CFTempAPI:    server.URL,
		CFTempDomain: "a.example.com,b.example.com,c.example.com",
		HTTPClient:   server.Client(),
	})
	for range 90 {
		if _, err := provider.Create(); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	// A single-domain config is what burned 152 mailboxes; every configured
	// domain must actually take traffic.
	if len(seen) != 3 {
		t.Fatalf("rotation used %d domains: %v", len(seen), seen)
	}
}

func TestProviderStrictlyAlternatesCFTempAndOutlook(t *testing.T) {
	root := t.TempDir()
	accountsPath := filepath.Join(root, "accounts.txt")
	writeOutlookFixture(t, accountsPath, "rotate@outlook.com----mail-pass----client-id----refresh-token")
	created := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		created++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": "cf" + string(rune('a'+created-1)) + "@cf.example.com",
			"jwt":     "address-jwt",
		})
	}))
	defer server.Close()

	provider := New(Config{
		Mode:                     config.EmailCFTemp,
		CFTempAPI:                server.URL,
		CFTempDomain:             "cf.example.com",
		ProviderRotation:         "cf_temp_email,outlook",
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         filepath.Join(root, "outlook-state.json"),
		OutlookAliasesPerAccount: 4,
	})
	if err := provider.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := provider.RequiredOutlookAllocations(5); got != 2 {
		t.Fatalf("required Outlook allocations=%d, want 2", got)
	}

	want := []string{"cftemp", "outlook", "cftemp", "outlook"}
	for i, kind := range want {
		handle, err := provider.Create()
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		if handle.Kind != kind {
			t.Fatalf("allocation %d kind=%q, want %q", i, handle.Kind, kind)
		}
		provider.Release(handle)
	}
}

func TestProviderRotationRetriesSameSourceAfterCreateFailure(t *testing.T) {
	root := t.TempDir()
	accountsPath := filepath.Join(root, "accounts.txt")
	writeOutlookFixture(t, accountsPath, "rotate@outlook.com----mail-pass----client-id----refresh-token")
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": "cf@cf.example.com",
			"jwt":     "address-jwt",
		})
	}))
	defer server.Close()

	provider := New(Config{
		Mode:                     config.EmailCFTemp,
		CFTempAPI:                server.URL,
		CFTempDomain:             "cf.example.com",
		ProviderRotation:         "cf_temp_email,outlook",
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         filepath.Join(root, "outlook-state.json"),
		OutlookAliasesPerAccount: 2,
	})
	if err := provider.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Create(); err == nil {
		t.Fatal("first Cloudflare allocation should fail")
	}
	cloudflare, err := provider.Create()
	if err != nil || cloudflare.Kind != "cftemp" {
		t.Fatalf("retry kind=%q err=%v, want cftemp", cloudflare.Kind, err)
	}
	outlook, err := provider.Create()
	if err != nil || outlook.Kind != "outlook" {
		t.Fatalf("next kind=%q err=%v, want outlook", outlook.Kind, err)
	}
	provider.Release(outlook)
}

func TestProviderRotationRejectsFallbackCombination(t *testing.T) {
	provider := New(Config{
		Mode:                 config.EmailCFTemp,
		CFTempAPI:            "https://mail.example.test",
		ProviderRotation:     "cf_temp_email,outlook",
		InvalidGrantFallback: "outlook",
	})
	if err := provider.Validate(); err == nil || !strings.Contains(err.Error(), "不能同时启用") {
		t.Fatalf("validation error=%v", err)
	}
}

func TestBenchDomainRetiresBurntDomainButKeepsOneLive(t *testing.T) {
	t.Parallel()
	provider := New(Config{
		Mode:         config.EmailCFTemp,
		CFTempAPI:    "http://worker.invalid",
		CFTempDomain: "a.example.com,b.example.com",
	})
	if !provider.BenchDomain("A.EXAMPLE.COM") {
		t.Fatal("first bench should retire the domain")
	}
	if provider.BenchDomain("a.example.com") {
		t.Fatal("re-benching the same domain should be a no-op")
	}
	// Benching the last live domain would empty the pool and silently hand
	// domain choice back to the Worker, undoing the rotation.
	if provider.BenchDomain("b.example.com") {
		t.Fatal("last live domain must not be benched")
	}
	for range 20 {
		if got := provider.nextCFTempDomain(); got != "b.example.com" {
			t.Fatalf("benched domain still selected: %q", got)
		}
	}
}
