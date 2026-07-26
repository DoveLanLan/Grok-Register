package cpa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grok-free-register/grok-reg/internal/oauth"
)

func TestFromCredentialUsesCurrentGrokBuildIdentity(t *testing.T) {
	doc := FromCredential(oauth.Credential{
		AccessToken:   "access",
		RefreshToken:  "refresh",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
	}, "person@example.com")

	if got := doc.Headers["x-grok-client-version"]; got != oauth.ClientVersion {
		t.Fatalf("x-grok-client-version = %q, want %q", got, oauth.ClientVersion)
	}
	if got := doc.Headers["x-grok-client-mode"]; got != "headless" {
		t.Fatalf("x-grok-client-mode = %q, want headless", got)
	}
	wantUserAgent := "grok-shell/" + oauth.ClientVersion + " (linux; x86_64)"
	if got := doc.Headers["User-Agent"]; got != wantUserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, wantUserAgent)
	}
}

func TestProbeUsesExplicitProxy(t *testing.T) {
	seen := make(chan *http.Request, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[]}`))
	}))
	defer proxy.Close()

	doc := Document{
		AccessToken: "access",
		BaseURL:     "http://unreachable.invalid",
	}
	if err := Probe(doc, proxy.URL, 0); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	select {
	case req := <-seen:
		if req.URL.Host != "unreachable.invalid" || req.URL.Path != "/responses" {
			t.Fatalf("proxy request URL = %s", req.URL.String())
		}
		if got := req.Header.Get("Authorization"); got != "Bearer access" {
			t.Fatalf("Authorization = %q", got)
		}
	default:
		t.Fatal("explicit proxy did not receive probe request")
	}
}

func TestProbeWithoutAccountProxyStaysDirect(t *testing.T) {
	client, err := newProbeClient("")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("probe transport = %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("direct account probe must not inherit environment proxies")
	}
}

func TestProbeContextCancelsWarmup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ProbeContext(ctx, Document{}, "", 30)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ProbeContext() error = %v, want context canceled", err)
	}
}

func TestProbeRejectsMalformedProxyWithoutEchoingCredentials(t *testing.T) {
	const secret = "proxy-password-sentinel"
	err := Probe(Document{}, "http://user:"+secret+"@", 0)
	if err == nil {
		t.Fatal("expected malformed proxy error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("proxy secret leaked in error: %v", err)
	}
}

func TestAppendOAuthFailureIncludesDiagnosticID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth-failures.jsonl")
	if err := AppendOAuthFailure(path, "person@example.com", "access denied", "attempt-123"); err != nil {
		t.Fatalf("AppendOAuthFailure() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]string
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode failure record: %v", err)
	}
	if record["diagnostic_id"] != "attempt-123" {
		t.Fatalf("diagnostic_id = %q", record["diagnostic_id"])
	}
	for _, key := range []string{"password", "sso", "proxy", "access_token", "refresh_token"} {
		if _, ok := record[key]; ok {
			t.Fatalf("failure record contains sensitive key %q", key)
		}
	}
}
