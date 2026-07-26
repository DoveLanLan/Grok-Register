package email

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
