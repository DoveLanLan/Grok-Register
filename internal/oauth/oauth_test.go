package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grok-free-register/grok-reg/internal/clearance"
)

func TestNewClientPinsProxyAcrossHTTPAndBrowser(t *testing.T) {
	proxyURL := "http://127.0.0.1:18080"
	diagnosticDir := "/tmp/oauth-attempt-123"
	client, err := NewClient(proxyURL, nil, time.Second, Options{
		ConfirmMode:          "browser",
		BrowserDiagnosticDir: diagnosticDir,
	})
	if err != nil {
		t.Fatal(err)
	}

	target, _ := url.Parse("https://auth.x.ai/oauth2/device/code")
	assertProxy := func(name string, httpClient *http.Client) {
		t.Helper()
		transport, ok := httpClient.Transport.(*http.Transport)
		if !ok || transport.Proxy == nil {
			t.Fatalf("%s transport has no explicit proxy", name)
		}
		got, err := transport.Proxy(&http.Request{URL: target})
		if err != nil {
			t.Fatalf("%s proxy lookup: %v", name, err)
		}
		if got == nil || got.String() != proxyURL {
			t.Fatalf("%s proxy = %v, want %s", name, got, proxyURL)
		}
	}
	assertProxy("shared", client.http)
	assertProxy("fresh", client.newHTTPClient())

	approver, ok := client.browser.(*cloakBrowserApprover)
	if !ok {
		t.Fatalf("browser approver = %T", client.browser)
	}
	if approver.proxy != proxyURL || approver.diagnosticDir != diagnosticDir {
		t.Fatalf("browser affinity proxy=%q diagnostic=%q", approver.proxy, approver.diagnosticDir)
	}
}

func TestExchangeReportsInvalidGrantDescription(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"device_authorization_endpoint": server.URL + "/device",
				"token_endpoint":                server.URL + "/token",
			})
		case "/device":
			writeJSON(t, w, map[string]any{
				"device_code":               "device-1",
				"user_code":                 "user-1",
				"verification_uri_complete": server.URL + "/verify-page?user_code=user-1",
				"expires_in":                1800,
				"interval":                  5,
			})
		case "/verify":
			http.Redirect(w, r, "/oauth2/device/consent?user_code=user-1", http.StatusSeeOther)
		case "/approve":
			http.Redirect(w, r, "/oauth2/device/done", http.StatusSeeOther)
		case "/token":
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(t, w, map[string]any{"error": "invalid_grant", "error_description": "Access denied"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	_, err := c.Exchange(context.Background(), "sso-value")
	if !IsInvalidGrant(err) {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
	if !strings.Contains(err.Error(), "Access denied") {
		t.Fatalf("expected safe error description, got %v", err)
	}
}

func TestDeviceFlowMatchesCurrentGrokBuildContract(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"device_authorization_endpoint": server.URL + "/device",
				"token_endpoint":                server.URL + "/token",
			})
		case "/device":
			assertDeviceFlowHeaders(t, r)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse device form: %v", err)
			}
			if r.PostForm.Get("client_id") != ClientID || r.PostForm.Get("scope") != Scope || r.PostForm.Get("referrer") != "grok-build" {
				t.Fatalf("unexpected device form: %v", r.PostForm)
			}
			writeJSON(t, w, map[string]any{
				"device_code":               "device-contract",
				"user_code":                 "user-contract",
				"verification_uri_complete": "https://accounts.x.ai/oauth2/device?user_code=user-contract",
				"expires_in":                1800,
				"interval":                  1,
			})
		case "/token":
			assertDeviceFlowHeaders(t, r)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.PostForm.Get("device_code") != "device-contract" || r.PostForm.Get("client_id") != ClientID {
				t.Fatalf("unexpected token form: %v", r.PostForm)
			}
			writeJSON(t, w, map[string]any{
				"access_token":  "access-contract",
				"refresh_token": "refresh-contract",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	flow, err := c.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("start device flow: %v", err)
	}
	credential, err := c.PollToken(context.Background(), flow)
	if err != nil {
		t.Fatalf("poll token: %v", err)
	}
	if credential.AccessToken != "access-contract" || credential.RefreshToken != "refresh-contract" {
		t.Fatalf("unexpected credential: %+v", credential)
	}
}

func TestRefreshUsesRefreshGrantAndPreservesUnrotatedToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		responseRefresh string
		wantRefresh     string
	}{
		{name: "rotated", responseRefresh: "refresh-new", wantRefresh: "refresh-new"},
		{name: "not rotated", wantRefresh: "refresh-old"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					writeJSON(t, w, map[string]any{
						"device_authorization_endpoint": server.URL + "/device",
						"token_endpoint":                server.URL + "/token",
					})
				case "/token":
					if got := r.Header.Get("x-grok-client-version"); got != "" {
						t.Errorf("refresh request unexpectedly has x-grok-client-version=%q", got)
					}
					if got := r.Header.Get("x-grok-client-surface"); got != "" {
						t.Errorf("refresh request unexpectedly has x-grok-client-surface=%q", got)
					}
					if err := r.ParseForm(); err != nil {
						t.Fatalf("parse refresh form: %v", err)
					}
					if got := r.PostForm.Get("grant_type"); got != "refresh_token" {
						t.Errorf("grant_type=%q", got)
					}
					if got := r.PostForm.Get("client_id"); got != ClientID {
						t.Errorf("client_id=%q", got)
					}
					if got := r.PostForm.Get("refresh_token"); got != "refresh-old" {
						t.Errorf("refresh_token=%q", got)
					}
					doc := map[string]any{
						"access_token": "access-new",
						"token_type":   "Bearer",
						"expires_in":   3600,
					}
					if tc.responseRefresh != "" {
						doc["refresh_token"] = tc.responseRefresh
					}
					writeJSON(t, w, doc)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			credential, err := newTestClient(t, server.URL).Refresh(context.Background(), "refresh-old")
			if err != nil {
				t.Fatalf("refresh failed: %v", err)
			}
			if credential.AccessToken != "access-new" || credential.RefreshToken != tc.wantRefresh {
				t.Fatalf("unexpected credential: %+v", credential)
			}
		})
	}
}

func TestExchangeUsesFreshCookieJarPerAccount(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	deviceRequests := 0
	var leakedCookie string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"device_authorization_endpoint": server.URL + "/device",
				"token_endpoint":                server.URL + "/token",
			})
		case "/device":
			mu.Lock()
			deviceRequests++
			n := deviceRequests
			if n == 2 {
				leakedCookie = r.Header.Get("Cookie")
			}
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "flow", Value: "flow-cookie", Path: "/"})
			writeJSON(t, w, map[string]any{
				"device_code":               "device",
				"user_code":                 "user",
				"verification_uri_complete": server.URL + "/verify-page?user_code=user",
				"expires_in":                1800,
				"interval":                  5,
			})
		case "/verify":
			http.Redirect(w, r, "/oauth2/device/consent?user_code=user", http.StatusSeeOther)
		case "/approve":
			http.Redirect(w, r, "/oauth2/device/done", http.StatusSeeOther)
		case "/token":
			writeJSON(t, w, map[string]any{
				"access_token":  "access",
				"refresh_token": "refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	for _, sso := range []string{"sso-one", "sso-two"} {
		if _, err := c.Exchange(context.Background(), sso); err != nil {
			t.Fatalf("exchange failed: %v", err)
		}
	}
	if leakedCookie != "" {
		t.Fatalf("second device flow inherited cookies: %q", leakedCookie)
	}
}

func TestExchangeUsesConsentFieldsWithoutClearanceCookies(t *testing.T) {
	t.Parallel()

	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"status": "ok",
			"solution": map[string]any{
				"url":       "https://accounts.x.ai",
				"status":    200,
				"userAgent": "test-browser",
				"cookies": []map[string]any{
					{"name": "cf_clearance", "value": "must-not-leak", "domain": ".x.ai", "path": "/"},
					{"name": "__cf_bm", "value": "must-not-leak-either", "domain": ".x.ai", "path": "/"},
				},
			},
		})
	}))
	defer fs.Close()
	cm := clearance.NewManager(fs.URL, "", "https://accounts.x.ai")
	if _, err := cm.Prewarm(); err != nil {
		t.Fatalf("prewarm clearance fixture: %v", err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertNoClearanceCookie(t, r)
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"device_authorization_endpoint": server.URL + "/device",
				"token_endpoint":                server.URL + "/token",
			})
		case "/device":
			writeJSON(t, w, map[string]any{
				"device_code":               "device-consent",
				"user_code":                 "user-consent",
				"verification_uri_complete": server.URL + "/verify-page?user_code=user-consent",
				"expires_in":                1800,
				"interval":                  1,
			})
		case "/verify-page":
			if !strings.Contains(r.Header.Get("Cookie"), "sso=sso-value") {
				t.Errorf("verification warmup missing SSO: %q", r.Header.Get("Cookie"))
			}
			w.WriteHeader(http.StatusOK)
		case "/verify":
			http.SetCookie(w, &http.Cookie{Name: "device_session", Value: "session-one", Path: "/"})
			http.Redirect(w, r, "/oauth2/device/consent?user_code=user-consent", http.StatusSeeOther)
		case "/oauth2/device/consent":
			if !strings.Contains(r.Header.Get("Cookie"), "device_session=session-one") {
				t.Errorf("consent request missing merged session cookie: %q", r.Header.Get("Cookie"))
			}
			http.SetCookie(w, &http.Cookie{Name: "consent_session", Value: "session-two", Path: "/"})
			_, _ = w.Write([]byte(`<form><input type="hidden" name="principal_id" value="principal-from-form"><input value="csrf&amp;value" name="csrf"><input name="action" value="deny"></form>`))
		case "/approve":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse approve form: %v", err)
			}
			if got := r.Form.Get("principal_id"); got != "principal-from-form" {
				t.Errorf("principal_id=%q", got)
			}
			if got := r.Form.Get("csrf"); got != "csrf&value" {
				t.Errorf("csrf=%q", got)
			}
			if got := r.Form.Get("action"); got != "allow" {
				t.Errorf("action=%q", got)
			}
			if !strings.Contains(r.Header.Get("Cookie"), "consent_session=session-two") {
				t.Errorf("approve request missing consent cookie: %q", r.Header.Get("Cookie"))
			}
			http.Redirect(w, r, "/oauth2/device/done", http.StatusSeeOther)
		case "/token":
			writeJSON(t, w, map[string]any{
				"access_token":  "access",
				"refresh_token": "refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, err := NewClient("", cm, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.discoveryURL = server.URL + "/.well-known/openid-configuration"
	c.accountsURL = server.URL
	c.verifyURL = server.URL + "/verify"
	c.approveURL = server.URL + "/approve"
	if _, err := c.Exchange(context.Background(), "sso-value"); err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
}

func TestConfirmHTTPRejectsSignInRedirect(t *testing.T) {
	t.Parallel()
	approveCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify-page":
			w.WriteHeader(http.StatusOK)
		case "/verify":
			http.Redirect(w, r, "/sign-in", http.StatusSeeOther)
		case "/approve":
			approveCalls++
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	err := c.ConfirmHTTP(context.Background(), "sso-value", DeviceFlow{
		UserCode:        "user-code",
		VerificationURL: server.URL + "/verify-page",
	})
	if err == nil || !strings.Contains(err.Error(), "sso_rejected") {
		t.Fatalf("expected sso_rejected, got %v", err)
	}
	if approveCalls != 0 {
		t.Fatalf("approve called %d times after sign-in redirect", approveCalls)
	}
}

func TestConfirmHTTPRejectsIncompleteApproveRedirect(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify-page":
			w.WriteHeader(http.StatusOK)
		case "/verify":
			http.Redirect(w, r, "/oauth2/device/consent?user_code=secret-user-code", http.StatusSeeOther)
		case "/oauth2/device/consent":
			_, _ = w.Write([]byte(`<form></form>`))
		case "/approve":
			http.Redirect(w, r, "/ordinary-success?user_code=must-not-appear-in-error", http.StatusSeeOther)
		case "/ordinary-success":
			_, _ = w.Write([]byte("ordinary page without an authorization marker"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	err := c.ConfirmHTTP(context.Background(), "sso-value", DeviceFlow{
		UserCode:        "secret-user-code",
		VerificationURL: server.URL + "/verify-page",
	})
	if err == nil || !strings.Contains(err.Error(), "device_approve_incomplete") {
		t.Fatalf("expected incomplete approval, got %v", err)
	}
	if strings.Contains(err.Error(), "must-not-appear") || strings.Contains(err.Error(), "secret-user-code") {
		t.Fatalf("OAuth error leaked a user code: %v", err)
	}
}

func TestPrincipalFromSSO(t *testing.T) {
	t.Parallel()
	if got := principalFromSSO(testJWT(t, map[string]any{"sub": "top-level"})); got != "top-level" {
		t.Fatalf("top-level principal=%q", got)
	}
	if got := principalFromSSO(testJWT(t, map[string]any{"user": map[string]any{"id": "nested"}})); got != "nested" {
		t.Fatalf("nested principal=%q", got)
	}
}

func TestIsDeviceDoneChecksPathOnly(t *testing.T) {
	t.Parallel()
	if !isDeviceDone("https://auth.x.ai/oauth2/device/done") {
		t.Fatal("done path not detected")
	}
	if isDeviceDone("https://auth.x.ai/consent?next=/oauth2/device/done") {
		t.Fatal("done marker in query must not be accepted")
	}
}

func TestExchangeAccountUsesBrowserApprover(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"device_authorization_endpoint": server.URL + "/device",
				"token_endpoint":                server.URL + "/token",
			})
		case "/device":
			writeJSON(t, w, map[string]any{
				"device_code":               "browser-device",
				"user_code":                 "browser-user",
				"verification_uri_complete": "https://accounts.x.ai/oauth2/device?user_code=browser-user",
				"expires_in":                1800,
				"interval":                  1,
			})
		case "/token":
			writeJSON(t, w, map[string]any{
				"access_token":  "access",
				"refresh_token": "refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/verify", "/approve":
			t.Errorf("legacy HTTP confirm endpoint called in browser mode: %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, err := NewClient("", nil, time.Second, Options{ConfirmMode: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	c.discoveryURL = server.URL + "/.well-known/openid-configuration"
	c.verifyURL = server.URL + "/verify"
	c.approveURL = server.URL + "/approve"
	fake := &fakeBrowserApprover{}
	c.browser = fake
	if _, err := c.ExchangeAccount(context.Background(), "sso-secret", "person@example.com", "password-secret"); err != nil {
		t.Fatalf("browser exchange failed: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("browser approver calls=%d", fake.calls)
	}
	if fake.approval.SSO != "sso-secret" || fake.approval.Email != "person@example.com" || fake.approval.Password != "password-secret" {
		t.Fatalf("browser approver did not receive account context")
	}
	if fake.approval.Flow.DeviceCode != "browser-device" || !strings.Contains(fake.approval.Flow.VerificationURL, "accounts.x.ai") {
		t.Fatalf("browser approver flow=%+v", fake.approval.Flow)
	}
}

func TestNewClientRejectsUnknownConfirmMode(t *testing.T) {
	t.Parallel()
	if _, err := NewClient("", nil, time.Second, Options{ConfirmMode: "magic"}); err == nil {
		t.Fatal("unknown OAuth confirm mode unexpectedly accepted")
	}
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient("", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.discoveryURL = baseURL + "/.well-known/openid-configuration"
	c.accountsURL = baseURL
	c.verifyURL = baseURL + "/verify"
	c.approveURL = baseURL + "/approve"
	return c
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func assertNoClearanceCookie(t *testing.T, r *http.Request) {
	t.Helper()
	cookie := r.Header.Get("Cookie")
	if strings.Contains(cookie, "cf_clearance") || strings.Contains(cookie, "__cf_bm") || strings.Contains(cookie, "must-not-leak") {
		t.Errorf("clearance cookie leaked to OAuth request %s: %q", r.URL.Path, cookie)
	}
}

func assertDeviceFlowHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("x-grok-client-version"); got != ClientVersion {
		t.Fatalf("x-grok-client-version = %q, want %q", got, ClientVersion)
	}
	if got := r.Header.Get("x-grok-client-surface"); got != deviceClientSurface {
		t.Fatalf("x-grok-client-surface = %q, want %q", got, deviceClientSurface)
	}
}

func testJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}

type fakeBrowserApprover struct {
	calls    int
	approval browserApproval
	err      error
}

func (f *fakeBrowserApprover) Name() string { return "fake" }

func (f *fakeBrowserApprover) Approve(_ context.Context, approval browserApproval) error {
	f.calls++
	f.approval = approval
	return f.err
}
