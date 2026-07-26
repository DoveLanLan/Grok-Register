package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/grok-free-register/grok-reg/internal/clearance"
)

const (
	DiscoveryURL        = "https://auth.x.ai/.well-known/openid-configuration"
	AccountsURL         = "https://accounts.x.ai"
	ClientID            = "b1a00492-073a-47ea-816f-4c329264a828"
	ClientVersion       = "0.2.111"
	Scope               = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
	VerifyURL           = "https://auth.x.ai/oauth2/device/verify"
	ApproveURL          = "https://auth.x.ai/oauth2/device/approve"
	DefaultUA           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	deviceClientSurface = "ui"
)

type DeviceFlow struct {
	DeviceCode      string
	UserCode        string
	VerificationURL string
	ExpiresIn       int
	Interval        float64
	TokenEndpoint   string
}

type Credential struct {
	AccessToken   string
	RefreshToken  string
	IDToken       string
	TokenType     string
	ExpiresIn     int
	ExpiresAt     string
	LastRefresh   string
	Subject       string
	TokenEndpoint string
	Email         string
}

// Options selects how the user-facing Device Flow approval is completed.
// ConfirmMode is "browser" for the accounts.x.ai Web UI or "http" for the
// legacy auth.x.ai form posts (kept for diagnostics and tests).
type Options struct {
	ConfirmMode          string
	BrowserTimeout       time.Duration
	BrowserDiagnosticDir string
	Tracef               func(string, ...any)
}

type Client struct {
	http         *http.Client
	proxyURL     *url.URL
	ua           string
	clear        *clearance.Manager
	discoveryURL string
	accountsURL  string
	verifyURL    string
	approveURL   string
	exchangeMu   sync.Mutex
	confirmMode  string
	browser      deviceBrowserApprover

	// rate limit gate
	mu         sync.Mutex
	trippedAt  time.Time
	nextProbe  time.Time
	cooldown   time.Duration
	baseCool   time.Duration
	trips      int
	probeToken int
	probeSeq   int
}

func NewClient(proxy string, cm *clearance.Manager, baseCooldown time.Duration, options ...Options) (*Client, error) {
	var proxyURL *url.URL
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		proxyURL = u
	}
	if baseCooldown <= 0 {
		baseCooldown = 60 * time.Second
	}
	opt := Options{ConfirmMode: "http"}
	if len(options) > 0 {
		opt = options[0]
	}
	mode := strings.ToLower(strings.TrimSpace(opt.ConfirmMode))
	if mode == "" {
		mode = "http"
	}
	if mode != "http" && mode != "browser" {
		return nil, fmt.Errorf("unsupported OAuth confirm mode %q", mode)
	}
	c := &Client{
		proxyURL:     proxyURL,
		ua:           DefaultUA,
		clear:        cm,
		discoveryURL: DiscoveryURL,
		accountsURL:  AccountsURL,
		verifyURL:    VerifyURL,
		approveURL:   ApproveURL,
		confirmMode:  mode,
		baseCool:     baseCooldown,
		cooldown:     baseCooldown,
	}
	c.http = c.newHTTPClient()
	if mode == "browser" {
		c.browser = newCloakBrowserApprover(proxy, opt)
	}
	if cm != nil {
		c.ua = cm.UserAgent()
	}
	return c, nil
}

func (c *Client) ConfirmMode() string { return c.confirmMode }

// CloseIdleConnections releases account-scoped keep-alive sockets once a flow
// reaches a terminal state.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *Client) newHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{}
	if c.proxyURL != nil {
		tr.Proxy = http.ProxyURL(c.proxyURL)
	}
	return &http.Client{
		Timeout:   45 * time.Second,
		Jar:       jar,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// RejectionError preserves the OAuth endpoint's safe error metadata without
// logging device codes, cookies, or tokens.
type RejectionError struct {
	Stage       string
	Code        string
	Description string
	Status      int
}

func (e *RejectionError) Error() string {
	msg := "oauth_rejected"
	if e.Code != "" {
		msg += ": " + e.Code
	} else if e.Status != 0 {
		msg += fmt.Sprintf(" status=%d", e.Status)
	}
	if e.Description != "" {
		msg += " (" + e.Description + ")"
	}
	return msg
}

func ErrorCode(err error) string {
	var rejected *RejectionError
	if errors.As(err, &rejected) {
		return rejected.Code
	}
	return ""
}

func IsInvalidGrant(err error) bool {
	return ErrorCode(err) == "invalid_grant"
}

func IsRetryableRejection(err error) bool {
	switch ErrorCode(err) {
	case "invalid_grant", "temporarily_unavailable", "server_error":
		return true
	default:
		return false
	}
}

func safeOAuthDescription(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func (c *Client) WaitRateLimit(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.trippedAt.IsZero() {
			c.mu.Unlock()
			return nil
		}
		now := time.Now()
		if now.Before(c.nextProbe) {
			wait := time.Until(c.nextProbe)
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
				continue
			}
		}
		// allow one probe
		c.probeSeq++
		c.probeToken = c.probeSeq
		c.mu.Unlock()
		return nil
	}
}

func (c *Client) TripRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.trippedAt.IsZero() {
		c.trippedAt = now
		c.trips = 1
	} else {
		c.trips++
	}
	// growth 1.5^n capped 300s
	cool := float64(c.baseCool) * pow15(c.trips-1)
	if cool > float64(300*time.Second) {
		cool = float64(300 * time.Second)
	}
	c.cooldown = time.Duration(cool)
	c.nextProbe = now.Add(c.cooldown)
}

func (c *Client) ClearRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trippedAt = time.Time{}
	c.nextProbe = time.Time{}
	c.trips = 0
	c.cooldown = c.baseCool
}

func pow15(n int) float64 {
	v := 1.0
	for i := 0; i < n; i++ {
		v *= 1.5
	}
	return v
}

func (c *Client) StartDeviceFlow(ctx context.Context) (DeviceFlow, error) {
	return c.startDeviceFlow(ctx, c.http)
}

func (c *Client) startDeviceFlow(ctx context.Context, client *http.Client) (DeviceFlow, error) {
	devEP, tokEP, err := c.discover(ctx, client)
	if err != nil {
		return DeviceFlow{}, err
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("scope", Scope)
	form.Set("referrer", "grok-build")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, devEP, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceFlow{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	applyDeviceFlowHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return DeviceFlow{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil && resp.StatusCode/100 == 2 {
		return DeviceFlow{}, err
	}
	if resp.StatusCode/100 != 2 {
		code, _ := doc["error"].(string)
		description, _ := doc["error_description"].(string)
		description = safeOAuthDescription(description)
		return DeviceFlow{}, &RejectionError{Stage: "device_authorization", Code: code, Description: description, Status: resp.StatusCode}
	}
	dc, _ := doc["device_code"].(string)
	uc, _ := doc["user_code"].(string)
	baseURL, _ := doc["verification_uri"].(string)
	if baseURL == "" {
		baseURL, _ = doc["verification_url"].(string)
	}
	exp, _ := doc["expires_in"].(float64)
	interval, _ := doc["interval"].(float64)
	if interval <= 0 {
		interval = 5
	}
	vurl, _ := doc["verification_uri_complete"].(string)
	if vurl == "" {
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		vurl = baseURL + sep + "user_code=" + url.QueryEscape(uc)
	}
	return DeviceFlow{
		DeviceCode:      dc,
		UserCode:        uc,
		VerificationURL: vurl,
		ExpiresIn:       int(exp),
		Interval:        interval,
		TokenEndpoint:   tokEP,
	}, nil
}

func (c *Client) discover(ctx context.Context, client *http.Client) (deviceEP, tokenEP string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", c.ua)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("discovery rejected")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", err
	}
	deviceEP, _ = doc["device_authorization_endpoint"].(string)
	tokenEP, _ = doc["token_endpoint"].(string)
	if deviceEP == "" || tokenEP == "" {
		return "", "", fmt.Errorf("discovery missing endpoints")
	}
	return deviceEP, tokenEP, nil
}

// ConfirmHTTP posts verify + approve with SSO cookie (no browser).
func (c *Client) ConfirmHTTP(ctx context.Context, sso string, flow DeviceFlow) error {
	return c.confirmHTTP(ctx, c.http, sso, flow)
}

func (c *Client) confirmHTTP(ctx context.Context, client *http.Client, sso string, flow DeviceFlow) error {
	sso = strings.TrimSpace(sso)
	if sso == "" {
		return fmt.Errorf("login_required")
	}
	cookie := "sso=" + sso

	// Warm the verification page with only this account's SSO session. This is
	// best-effort; the authoritative checks below are verify/approve responses.
	if flow.VerificationURL != "" {
		_, _, _, _ = c.getWithCookie(ctx, client, flow.VerificationURL, cookie)
	}

	// verify
	form := url.Values{"user_code": {flow.UserCode}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	c.setFormHeaders(req, flow.VerificationURL, cookie)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	vbody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	cookie = mergeSetCookies(cookie, resp.Header)
	if err := locationError(loc); err != nil {
		if err.Error() == "rate_limited" {
			c.TripRateLimit()
		}
		return err
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("challenge")
	}
	if isSignInRedirect(loc) {
		return fmt.Errorf("sso_rejected: verify redirected to sign-in")
	}
	if isDeviceDone(loc) {
		c.ClearRateLimit()
		return nil
	}
	if authorizedBody(string(vbody)) && isRedirect(resp.StatusCode) {
		c.ClearRateLimit()
		return nil
	}
	// A bare success page is not proof that the device was authorized. Treating
	// it as success was the source of false-positive confirm + invalid_grant.
	if !isRedirect(resp.StatusCode) && loc == "" {
		return fmt.Errorf("device_verify_failed status=%d", resp.StatusCode)
	}

	// approve
	consentRef := absoluteURL(c.accountsURL, loc)
	if consentRef == "" {
		consentRef = strings.TrimRight(c.accountsURL, "/") + "/oauth2/device/consent?user_code=" + url.QueryEscape(flow.UserCode)
	}
	if isSignInRedirect(consentRef) {
		return fmt.Errorf("sso_rejected: verify redirected to sign-in")
	}

	// Start with the known core fields, then overlay non-empty hidden fields
	// (principal_id, CSRF, etc.) from the live consent form.
	aform := url.Values{
		"user_code":      {flow.UserCode},
		"action":         {"allow"},
		"principal_type": {"User"},
		"principal_id":   {""},
	}
	if principal := principalFromSSO(sso); principal != "" {
		aform.Set("principal_id", principal)
	}
	if fields, consentCookie := c.loadConsentForm(ctx, client, consentRef, cookie); len(fields) > 0 {
		cookie = consentCookie
		for key, values := range fields {
			if key == "action" || len(values) == 0 || values[0] == "" {
				continue
			}
			aform.Set(key, values[0])
		}
		aform.Set("action", "allow")
		if aform.Get("user_code") == "" {
			aform.Set("user_code", flow.UserCode)
		}
		if aform.Get("principal_type") == "" {
			aform.Set("principal_type", "User")
		}
	}

	// First try the complete consent form. If the page supplied extra fields
	// and x.ai rejects them, retry once with only the known core fields.
	forms := []url.Values{aform}
	if len(aform) > 4 {
		forms = append(forms, url.Values{
			"user_code":      {flow.UserCode},
			"action":         {"allow"},
			"principal_type": {"User"},
			"principal_id":   {aform.Get("principal_id")},
		})
	}
	for attempt, approveForm := range forms {
		req2, err := http.NewRequestWithContext(ctx, http.MethodPost, c.approveURL, strings.NewReader(approveForm.Encode()))
		if err != nil {
			return err
		}
		c.setFormHeaders(req2, consentRef, cookie)
		resp2, err := client.Do(req2)
		if err != nil {
			return err
		}
		aloc := resp2.Header.Get("Location")
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
		_ = resp2.Body.Close()
		cookie = mergeSetCookies(cookie, resp2.Header)
		if err := locationError(aloc); err != nil {
			if err.Error() == "rate_limited" {
				c.TripRateLimit()
			}
			return fmt.Errorf("device_approve: %w", err)
		}
		if isSignInRedirect(aloc) {
			return fmt.Errorf("sso_rejected: approve redirected to sign-in")
		}
		if authorizedBody(string(body)) || isDeviceDone(aloc) {
			c.ClearRateLimit()
			return nil
		}
		if isRedirect(resp2.StatusCode) && aloc != "" {
			next := absoluteURL(originOf(c.approveURL), aloc)
			if isDeviceDone(next) {
				c.ClearRateLimit()
				return nil
			}
			if isSignInRedirect(next) {
				return fmt.Errorf("sso_rejected: approve redirect led to sign-in")
			}
			if _, nextBody, _, getErr := c.getWithCookie(ctx, client, next, cookie); getErr == nil && authorizedBody(nextBody) {
				c.ClearRateLimit()
				return nil
			}
			if attempt+1 < len(forms) {
				continue
			}
			return fmt.Errorf("device_approve_incomplete status=%d loc=%q", resp2.StatusCode, safeLocation(aloc))
		}
		if resp2.StatusCode == 403 {
			return fmt.Errorf("challenge")
		}
		if strings.Contains(strings.ToLower(string(body)), "invalid action") && attempt+1 < len(forms) {
			continue
		}
		if attempt+1 < len(forms) {
			continue
		}
		return fmt.Errorf("unknown_page status=%d loc=%q", resp2.StatusCode, safeLocation(aloc))
	}
	return fmt.Errorf("device_approve_failed")
}

func principalFromSSO(sso string) string {
	for _, key := range []string{"sub", "user_id", "userId", "uid", "id", "principal_id", "principalId"} {
		if value := jwtClaim(sso, key); value != "" {
			return value
		}
	}
	payload := jwtPayload(sso)
	for _, nested := range []string{"user", "account", "identity", "profile"} {
		child, _ := payload[nested].(map[string]any)
		for _, key := range []string{"sub", "id", "user_id", "userId", "uid"} {
			if value, _ := child[key].(string); value != "" {
				return value
			}
		}
	}
	return ""
}

func jwtPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload := parts[1]
		switch len(payload) % 4 {
		case 2:
			payload += "=="
		case 3:
			payload += "="
		}
		raw, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return nil
		}
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	return payload
}

func isDeviceDone(location string) bool {
	if location == "" {
		return false
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return strings.Contains(location, "/oauth2/device/done")
	}
	return strings.Contains(parsed.Path, "/oauth2/device/done") || strings.HasSuffix(parsed.Path, "/device/done")
}

func isSignInRedirect(location string) bool {
	location = strings.ToLower(location)
	return strings.Contains(location, "/sign-in") ||
		strings.Contains(location, "/login") ||
		strings.Contains(location, "signin") ||
		strings.Contains(location, "login_required")
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther ||
		status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func authorizedBody(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "device authorized") ||
		strings.Contains(body, "设备已授权") ||
		strings.Contains(lower, "you have authorized") ||
		strings.Contains(lower, "device is authorized")
}

func absoluteURL(base, location string) string {
	if location == "" {
		return ""
	}
	ref, err := url.Parse(location)
	if err != nil {
		return location
	}
	if ref.IsAbs() {
		return ref.String()
	}
	baseURL, err := url.Parse(strings.TrimRight(base, "/") + "/")
	if err != nil {
		return location
	}
	return baseURL.ResolveReference(ref).String()
}

func originOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}
	return parsed.Scheme + "://" + parsed.Host
}

func mergeSetCookies(cookie string, headers http.Header) string {
	parts := strings.Split(cookie, "; ")
	for _, setCookie := range headers.Values("Set-Cookie") {
		pair := strings.SplitN(setCookie, ";", 2)[0]
		name, _, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			continue
		}
		replaced := false
		for i, existing := range parts {
			if strings.HasPrefix(existing, name+"=") {
				parts[i] = pair
				replaced = true
				break
			}
		}
		if !replaced {
			parts = append(parts, pair)
		}
	}
	return strings.Join(parts, "; ")
}

func (c *Client) getWithCookie(ctx context.Context, client *http.Client, rawURL, cookie string) (int, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	c.setSessionNavigationHeaders(req, cookie)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), resp.Header.Clone(), nil
}

func (c *Client) loadConsentForm(ctx context.Context, client *http.Client, consentURL, cookie string) (url.Values, string) {
	status, body, headers, err := c.getWithCookie(ctx, client, consentURL, cookie)
	if err != nil || status >= 400 {
		return nil, cookie
	}
	return parseHTMLFormFields(body), mergeSetCookies(cookie, headers)
}

func parseHTMLFormFields(body string) url.Values {
	values := url.Values{}
	lower := strings.ToLower(body)
	for offset := 0; offset < len(body); {
		start := strings.Index(lower[offset:], "<input")
		if start < 0 {
			break
		}
		start += offset
		end := strings.IndexByte(body[start:], '>')
		if end < 0 {
			break
		}
		tag := body[start : start+end]
		offset = start + end + 1
		name := attrValue(tag, "name")
		if name != "" {
			values.Set(name, attrValue(tag, "value"))
		}
	}
	return values
}

func attrValue(tag, attribute string) string {
	lower := strings.ToLower(tag)
	key := strings.ToLower(attribute) + "="
	start := strings.Index(lower, key)
	if start < 0 {
		return ""
	}
	rest := strings.TrimLeft(tag[start+len(key):], " \t")
	if rest == "" {
		return ""
	}
	quote := rest[0]
	if quote == '\'' || quote == '"' {
		rest = rest[1:]
		end := strings.IndexByte(rest, quote)
		if end < 0 {
			return ""
		}
		return html.UnescapeString(rest[:end])
	}
	if end := strings.IndexAny(rest, " \t>/"); end >= 0 {
		rest = rest[:end]
	}
	return html.UnescapeString(rest)
}

func safeLocation(value string) string {
	if parsed, err := url.Parse(value); err == nil {
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		value = parsed.String()
	} else if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	return safeText(value, 160)
}

func safeText(value string, limit int) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func locationError(loc string) error {
	if loc == "" {
		return nil
	}
	u, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	e := u.Query().Get("error")
	if e == "" {
		return nil
	}
	return fmt.Errorf("%s", e)
}

func (c *Client) setFormHeaders(req *http.Request, referer, cookie string) {
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://accounts.x.ai")
	req.Header.Set("Referer", referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setSessionNavigationHeaders(req, cookie)
}

func (c *Client) setSessionNavigationHeaders(req *http.Request, cookie string) {
	// OAuth verify/consent/approve must carry only the account SSO/session
	// cookies. FlareSolverr cf_clearance/__cf_bm can poison the auth.x.ai
	// session and produce false-looking confirmation followed by invalid_grant.
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (c *Client) PollToken(ctx context.Context, flow DeviceFlow) (Credential, error) {
	return c.pollToken(ctx, c.http, flow)
}

func (c *Client) pollToken(ctx context.Context, client *http.Client, flow DeviceFlow) (Credential, error) {
	deadline := time.Now().Add(time.Duration(flow.ExpiresIn) * time.Second)
	if flow.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := time.Duration(flow.Interval * float64(time.Second))
	if interval < time.Second {
		interval = 5 * time.Second
	}
	for time.Now().Before(deadline) {
		form := url.Values{}
		form.Set("client_id", ClientID)
		form.Set("device_code", flow.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, flow.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return Credential{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.ua)
		applyDeviceFlowHeaders(req)
		resp, err := client.Do(req)
		if err != nil {
			return Credential{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		if resp.StatusCode/100 == 2 {
			return credentialFrom(doc, flow.TokenEndpoint)
		}
		errCode, _ := doc["error"].(string)
		description, _ := doc["error_description"].(string)
		description = safeOAuthDescription(description)
		switch errCode {
		case "authorization_pending":
			// continue
		case "slow_down":
			interval += time.Second
		case "access_denied":
			return Credential{}, &RejectionError{Stage: "token", Code: errCode, Description: description, Status: resp.StatusCode}
		case "expired_token":
			return Credential{}, fmt.Errorf("oauth_expired")
		default:
			return Credential{}, &RejectionError{Stage: "token", Code: errCode, Description: description, Status: resp.StatusCode}
		}
		select {
		case <-ctx.Done():
			return Credential{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return Credential{}, fmt.Errorf("oauth_expired")
}

func applyDeviceFlowHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("x-grok-client-version", ClientVersion)
	req.Header.Set("x-grok-client-surface", deviceClientSurface)
}

func credentialFrom(doc map[string]any, endpoint string) (Credential, error) {
	at, _ := doc["access_token"].(string)
	rt, _ := doc["refresh_token"].(string)
	if at == "" || rt == "" {
		return Credential{}, fmt.Errorf("oauth_rejected: missing tokens")
	}
	id, _ := doc["id_token"].(string)
	tt, _ := doc["token_type"].(string)
	expF, _ := doc["expires_in"].(float64)
	exp := int(expF)
	if exp <= 0 {
		exp = 3600
	}
	now := time.Now().UTC()
	sub := jwtClaim(id, "sub")
	if sub == "" {
		sub = jwtClaim(at, "sub")
	}
	email := jwtClaim(id, "email")
	if email == "" {
		email = jwtClaim(at, "email")
	}
	return Credential{
		AccessToken:   at,
		RefreshToken:  rt,
		IDToken:       id,
		TokenType:     tt,
		ExpiresIn:     exp,
		ExpiresAt:     now.Add(time.Duration(exp) * time.Second).Format(time.RFC3339),
		LastRefresh:   now.Format(time.RFC3339),
		Subject:       sub,
		TokenEndpoint: endpoint,
		Email:         email,
	}, nil
}

func jwtClaim(token, key string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// Refresh exchanges a refresh token for a current access-token pair without
// starting a new Device Flow. x.ai may omit a rotated refresh_token; in that
// case the existing one remains valid and is carried forward.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return Credential{}, fmt.Errorf("refresh_token empty")
	}
	if err := c.WaitRateLimit(ctx); err != nil {
		return Credential{}, err
	}
	_, tokenEndpoint, err := c.discover(ctx, c.http)
	if err != nil {
		return Credential{}, err
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return Credential{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	if resp.StatusCode/100 == 2 {
		if rotated, _ := doc["refresh_token"].(string); strings.TrimSpace(rotated) == "" {
			doc["refresh_token"] = refreshToken
		}
		return credentialFrom(doc, tokenEndpoint)
	}
	code, _ := doc["error"].(string)
	description, _ := doc["error_description"].(string)
	description = safeOAuthDescription(description)
	if code == "" {
		preview := strings.TrimSpace(string(body))
		if len(preview) > 120 {
			preview = preview[:120]
		}
		return Credential{}, fmt.Errorf("refresh_rejected status=%d body=%s", resp.StatusCode, preview)
	}
	return Credential{}, &RejectionError{
		Stage:       "refresh",
		Code:        code,
		Description: description,
		Status:      resp.StatusCode,
	}
}

// Exchange performs an OAuth flow with SSO only. Production registration
// should use ExchangeAccount so the browser can log in if the SSO cookie is
// rejected by accounts.x.ai.
func (c *Client) Exchange(ctx context.Context, sso string) (Credential, error) {
	return c.exchange(ctx, browserApproval{SSO: sso})
}

func (c *Client) ExchangeAccount(ctx context.Context, sso, email, password string) (Credential, error) {
	return c.exchange(ctx, browserApproval{SSO: sso, Email: email, Password: password})
}

func (c *Client) exchange(ctx context.Context, approval browserApproval) (Credential, error) {
	// A device flow is stateful. Serialize exchanges and give every account a
	// fresh cookie jar so concurrent accounts cannot contaminate one another.
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	client := c.newHTTPClient()
	defer client.CloseIdleConnections()

	if err := c.WaitRateLimit(ctx); err != nil {
		return Credential{}, err
	}
	flow, err := c.startDeviceFlow(ctx, client)
	if err != nil {
		return Credential{}, err
	}
	approval.Flow = flow
	switch c.confirmMode {
	case "browser":
		if c.browser == nil {
			return Credential{}, fmt.Errorf("oauth_browser_unavailable")
		}
		// Poll during Web approval, as prescribed by RFC 8628. Keeping the
		// accounts.x.ai browser session alive while the token endpoint observes
		// authorization also avoids relying on state after the browser closes.
		type pollResult struct {
			credential Credential
			err        error
		}
		pollCtx, cancelPoll := context.WithCancel(ctx)
		pollCh := make(chan pollResult, 1)
		go func() {
			credential, err := c.pollToken(pollCtx, client, flow)
			pollCh <- pollResult{credential: credential, err: err}
		}()
		if err := c.browser.Approve(ctx, approval); err != nil {
			cancelPoll()
			return Credential{}, err
		}
		select {
		case <-ctx.Done():
			cancelPoll()
			return Credential{}, ctx.Err()
		case result := <-pollCh:
			cancelPoll()
			return result.credential, result.err
		}
	case "http":
		if err := c.confirmHTTP(ctx, client, approval.SSO, flow); err != nil {
			return Credential{}, err
		}
	default:
		return Credential{}, fmt.Errorf("unsupported OAuth confirm mode %q", c.confirmMode)
	}
	return c.pollToken(ctx, client, flow)
}
