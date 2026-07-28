// Package mcpreg implements Grok account registration via the browser-mcp
// extension bridge.  It drives the real Chrome browser already connected to
// the bridge at ws://127.0.0.1:18768, which means Cloudflare Turnstile is
// solved by the user's own browser profile rather than a headless instance.
package mcpreg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/cpa"
	"github.com/grok-free-register/grok-reg/internal/email"
	"github.com/grok-free-register/grok-reg/internal/oauth"
)

const (
	signupURL       = "https://accounts.x.ai/sign-up?redirect=grok-com"
	turnstileInputQ = `document.querySelector('input[name="cf-turnstile-response"]')?.value?.length > 20`
	turnstileTO     = 60 * time.Second
	codeWaitMax     = 90 * time.Second
)

// Options configures a single mcp-register run.
type Options struct {
	// Email provider
	EmailProvider *email.Provider

	// OAuth client (must be in "http" confirm mode; we handle browser approval ourselves)
	OAuthClient *oauth.Client

	// Output directory for CPA JSON files
	CPADir string

	// CPASecret for filename HMAC
	CPASecret []byte

	// CPA accounts.txt path (for SSO record)
	AccountsPath string

	// Tracef for progress logging; may be nil
	Tracef func(string, ...any)

	// BridgeSessionID for this run (optional; auto-generated if empty)
	BridgeSessionID string

	// Password to use for the new account; auto-generated if empty
	Password string
}

// Result holds the output of a successful registration.
type Result struct {
	Email      string
	Password   string
	SSO        string
	Credential oauth.Credential
	CPAPath    string
}

// Register performs one complete account registration via the browser-mcp bridge.
func Register(ctx context.Context, opts Options) (Result, error) {
	tracef := opts.Tracef
	if tracef == nil {
		tracef = func(string, ...any) {}
	}

	sessionID := opts.BridgeSessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("grok-reg-%d", time.Now().UnixNano())
	}

	// ── Connect to browser-mcp bridge ────────────────────────────────────────
	tracef("[mcpreg] connecting to browser-mcp bridge …")
	bc, err := NewBridgeClient(sessionID)
	if err != nil {
		return Result{}, fmt.Errorf("bridge connect: %w", err)
	}
	defer bc.Close()
	tracef("[mcpreg] bridge connected (session=%s)", sessionID)

	// ── Create temp email ────────────────────────────────────────────────────
	tracef("[mcpreg] creating temp email …")
	handle, err := opts.EmailProvider.Create()
	if err != nil {
		return Result{}, fmt.Errorf("email create: %w", err)
	}
	defer opts.EmailProvider.Release(handle)
	tracef("[mcpreg] email: %s", handle.Email)

	password := opts.Password
	if password == "" {
		password = handle.Password
	}

	// ── Open tab ────────────────────────────────────────────────────────────
	// NOTE: incognito requires the browser-mcp extension to have incognito
	// permission enabled in Chrome. If not available, use a normal tab.
	tracef("[mcpreg] opening registration tab …")
	tabID, err := bc.OpenTab(signupURL, false)
	if err != nil {
		return Result{}, fmt.Errorf("open tab: %w", err)
	}
	tracef("[mcpreg] tab_id=%s", tabID)
	defer func() {
		_ = bc.CloseTab(tabID)
	}()

	// Give the page time to load and pass Cloudflare if needed
	tracef("[mcpreg] waiting for page to be ready …")
	if err := waitForPageReady(ctx, bc, tabID, 30*time.Second); err != nil {
		return Result{}, fmt.Errorf("page load: %w", err)
	}

	// ── Accept cookies if banner present ────────────────────────────────────
	_ = clickByText(ctx, bc, tabID, "Accept All", 3*time.Second)
	_ = clickByText(ctx, bc, tabID, "接受所有", 2*time.Second)

	// ── Click "Sign up with email" ───────────────────────────────────────────
	tracef("[mcpreg] clicking 'Sign up with email' …")
	clicked := false
	for _, text := range []string{"Sign up with email", "使用邮箱注册", "邮箱", "email"} {
		if err := clickByText(ctx, bc, tabID, text, 5*time.Second); err == nil {
			clicked = true
			break
		}
	}
	if !clicked {
		return Result{}, fmt.Errorf("click sign-up-with-email: button not found (tried EN/CN)")
	}
	if err := sleepCtx(ctx, 1500*time.Millisecond); err != nil {
		return Result{}, err
	}

	// ── Fill email ───────────────────────────────────────────────────────────
	tracef("[mcpreg] filling email …")
	if err := fillByType(ctx, bc, tabID, "email", handle.Email); err != nil {
		return Result{}, fmt.Errorf("fill email: %w", err)
	}
	if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
		return Result{}, err
	}

	// ── Submit email form ────────────────────────────────────────────────────
	tracef("[mcpreg] submitting email …")
	if err := clickSubmit(ctx, bc, tabID); err != nil {
		return Result{}, fmt.Errorf("submit email: %w", err)
	}

	// ── Poll mailbox for verification code ───────────────────────────────────
	tracef("[mcpreg] waiting for verification code …")
	code, err := opts.EmailProvider.PollCode(handle, codeWaitMax)
	if err != nil {
		return Result{}, fmt.Errorf("poll code: %w", err)
	}
	tracef("[mcpreg] verification code received")

	// ── Fill verification code ───────────────────────────────────────────────
	tracef("[mcpreg] filling verification code …")
	if err := sleepCtx(ctx, 1*time.Second); err != nil {
		return Result{}, err
	}
	if err := fillCodeFields(ctx, bc, tabID, code); err != nil {
		return Result{}, fmt.Errorf("fill code: %w", err)
	}
	if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
		return Result{}, err
	}
	// submit code
	if err := clickSubmit(ctx, bc, tabID); err != nil {
		_ = err // might auto-submit on last digit
	}

	// ── Wait for credentials form ─────────────────────────────────────────────
	tracef("[mcpreg] waiting for credentials form …")
	if err := waitForCredentialsForm(ctx, bc, tabID, 30*time.Second); err != nil {
		return Result{}, fmt.Errorf("credentials form: %w", err)
	}
	if err := sleepCtx(ctx, 1*time.Second); err != nil {
		return Result{}, err
	}

	// ── Fill given name, family name, password ────────────────────────────────
	tracef("[mcpreg] filling name + password …")
	givenName, familyName := randomName()
	if err := fillCredentials(ctx, bc, tabID, givenName, familyName, password); err != nil {
		return Result{}, fmt.Errorf("fill credentials: %w", err)
	}

	// ── Wait for Turnstile ───────────────────────────────────────────────────
	tracef("[mcpreg] waiting for Turnstile …")
	if err := waitForTurnstile(ctx, bc, tabID); err != nil {
		return Result{}, fmt.Errorf("turnstile timeout: %w", err)
	}
	tracef("[mcpreg] Turnstile passed")

	// ── Click "Create account" ───────────────────────────────────────────────
	tracef("[mcpreg] clicking 'Create account' …")
	if err := clickSubmit(ctx, bc, tabID); err != nil {
		return Result{}, fmt.Errorf("submit create-account: %w", err)
	}

	// ── Wait for SSO cookie ──────────────────────────────────────────────────
	tracef("[mcpreg] waiting for SSO cookie …")
	sso, err := waitForSSO(ctx, bc, tabID, 60*time.Second)
	if err != nil {
		return Result{}, fmt.Errorf("wait sso: %w", err)
	}
	tracef("[mcpreg] SSO cookie acquired")

	// ── OAuth Device Flow ─────────────────────────────────────────────────────
	tracef("[mcpreg] starting OAuth device flow …")
	flow, err := opts.OAuthClient.StartDeviceFlow(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("device flow: %w", err)
	}
	tracef("[mcpreg] verification_url: %s", flow.VerificationURL)

	// Navigate the same incognito tab to the verification URL.
	if err := bc.Navigate(tabID, flow.VerificationURL); err != nil {
		return Result{}, fmt.Errorf("navigate verification_url: %w", err)
	}
	if err := sleepCtx(ctx, 2*time.Second); err != nil {
		return Result{}, err
	}

	// Click the allow/approve button on the consent page.
	tracef("[mcpreg] approving OAuth consent …")
	if err := clickOAuthApprove(ctx, bc, tabID, 20*time.Second); err != nil {
		return Result{}, fmt.Errorf("oauth approve: %w", err)
	}

	// ── Poll token endpoint ───────────────────────────────────────────────────
	tracef("[mcpreg] polling for token …")
	cred, err := opts.OAuthClient.PollToken(ctx, flow)
	if err != nil {
		return Result{}, fmt.Errorf("poll token: %w", err)
	}
	tracef("[mcpreg] token received sub=%s", cred.Subject)

	// ── Write CPA JSON ────────────────────────────────────────────────────────
	doc := cpa.FromCredential(cred, handle.Email)
	secret := opts.CPASecret
	if len(secret) == 0 {
		secret = cpa.DefaultSecret()
	}
	cpaPath, err := cpa.WriteAtomic(opts.CPADir, doc, secret)
	if err != nil {
		return Result{}, fmt.Errorf("write cpa: %w", err)
	}
	tracef("[mcpreg] CPA written: %s", cpaPath)

	// Append to accounts.txt if configured.
	if opts.AccountsPath != "" {
		_ = cpa.AppendSSO(opts.AccountsPath, handle.Email, password, sso)
	}

	return Result{
		Email:      handle.Email,
		Password:   password,
		SSO:        sso,
		Credential: cred,
		CPAPath:    cpaPath,
	}, nil
}

// ── Page interaction helpers ──────────────────────────────────────────────────

// clickByText finds a button / link whose visible text contains substr and clicks it.
// It retries until the element appears or the deadline is reached.
func clickByText(ctx context.Context, bc *BridgeClient, tabID, substr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := bc.Scan(tabID)
		if err != nil {
			_ = sleepCtx(ctx, 500*time.Millisecond)
			continue
		}
		ref, ok := findRefByText(raw, substr)
		if !ok {
			_ = sleepCtx(ctx, 800*time.Millisecond)
			continue
		}
		return bc.ClickRef(tabID, ref)
	}
	return fmt.Errorf("clickByText %q: element not found within %s", substr, timeout)
}

// fillByType fills the first input whose type attribute matches inputType.
func fillByType(ctx context.Context, bc *BridgeClient, tabID, inputType, value string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := bc.Scan(tabID)
		if err != nil {
			_ = sleepCtx(ctx, 500*time.Millisecond)
			continue
		}
		ref, ok := findInputRefByType(raw, inputType)
		if !ok {
			_ = sleepCtx(ctx, 800*time.Millisecond)
			continue
		}
		return bc.FillRef(tabID, ref, value)
	}
	return fmt.Errorf("fillByType %q: input not found within 15s", inputType)
}

// fillByName fills an input whose name attribute matches.
func fillByName(ctx context.Context, bc *BridgeClient, tabID, name, value string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := bc.Scan(tabID)
		if err != nil {
			_ = sleepCtx(ctx, 500*time.Millisecond)
			continue
		}
		ref, ok := findInputRefByAttr(raw, "name", name)
		if !ok {
			_ = sleepCtx(ctx, 800*time.Millisecond)
			continue
		}
		return bc.FillRef(tabID, ref, value)
	}
	return fmt.Errorf("fillByName %q: input not found within 15s", name)
}

// clickSubmit clicks the first submit button on the page.
func clickSubmit(ctx context.Context, bc *BridgeClient, tabID string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := bc.Scan(tabID)
		if err != nil {
			_ = sleepCtx(ctx, 500*time.Millisecond)
			continue
		}
		ref, ok := findSubmitRef(raw)
		if !ok {
			_ = sleepCtx(ctx, 500*time.Millisecond)
			continue
		}
		return bc.ClickRef(tabID, ref)
	}
	return fmt.Errorf("clickSubmit: submit button not found within 10s")
}

// fillCodeFields handles both a single 6-digit input and a series of individual
// digit inputs (some UIs split the OTP into 6 single-character inputs).
func fillCodeFields(ctx context.Context, bc *BridgeClient, tabID, code string) error {
	digits := strings.ReplaceAll(code, "-", "")
	raw, err := bc.Scan(tabID)
	if err != nil {
		return err
	}

	// Try single OTP input first.
	if ref, ok := findInputRefByType(raw, "text"); ok {
		return bc.FillRef(tabID, ref, digits)
	}

	// Try split digit inputs via JS — fill each digit input in order.
	script := fmt.Sprintf(`
		(function(){
			var inputs = Array.from(document.querySelectorAll('input[maxlength="1"]'));
			if(!inputs.length) return false;
			var code = %q;
			for(var i=0;i<inputs.length&&i<code.length;i++){
				var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
				nativeInputValueSetter.call(inputs[i], code[i]);
				inputs[i].dispatchEvent(new Event('input', {bubbles:true}));
				inputs[i].dispatchEvent(new Event('change', {bubbles:true}));
			}
			return true;
		})()`, digits)
	ok, err := bc.ExecuteJSBool(tabID, script)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("fillCodeFields: no code inputs found on page")
	}
	return nil
}

// waitForCredentialsForm polls until a password input appears, indicating the
// registration flow has progressed to the name+password step.
func waitForCredentialsForm(ctx context.Context, bc *BridgeClient, tabID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := bc.ExecuteJSBool(tabID, `!!document.querySelector('input[type="password"]')`)
		if err == nil && ok {
			return nil
		}
		_ = sleepCtx(ctx, 1*time.Second)
	}
	return fmt.Errorf("credentials form did not appear within %s", timeout)
}

// fillCredentials fills given name, family name and password fields.
func fillCredentials(ctx context.Context, bc *BridgeClient, tabID, given, family, password string) error {
	// Try name inputs by autocomplete attribute, then by placeholder text.
	if err := fillFieldBest(ctx, bc, tabID, "given-name", given); err != nil {
		return fmt.Errorf("given name: %w", err)
	}
	if err := fillFieldBest(ctx, bc, tabID, "family-name", family); err != nil {
		return fmt.Errorf("family name: %w", err)
	}
	// Password field
	if err := fillByType(ctx, bc, tabID, "password", password); err != nil {
		return fmt.Errorf("password: %w", err)
	}
	return nil
}

// fillFieldBest tries autocomplete, then name, then first text input.
func fillFieldBest(ctx context.Context, bc *BridgeClient, tabID, autocomplete, value string) error {
	raw, _ := bc.Scan(tabID)
	if raw != nil {
		if ref, ok := findInputRefByAttr(raw, "autocomplete", autocomplete); ok {
			return bc.FillRef(tabID, ref, value)
		}
		if ref, ok := findInputRefByAttr(raw, "name", autocomplete); ok {
			return bc.FillRef(tabID, ref, value)
		}
	}
	// Fallback: use JS to fill by autocomplete
	script := fmt.Sprintf(`
		(function(){
			var el = document.querySelector('input[autocomplete=%q]') ||
			         document.querySelector('input[name=%q]');
			if(!el) return false;
			var nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
			nativeInputValueSetter.call(el, %q);
			el.dispatchEvent(new Event('input',{bubbles:true}));
			el.dispatchEvent(new Event('change',{bubbles:true}));
			return true;
		})()`, autocomplete, autocomplete, value)
	ok, err := bc.ExecuteJSBool(tabID, script)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("field %q not found", autocomplete)
	}
	return nil
}

// waitForPageReady waits until the page is past Cloudflare challenge and shows
// registration content (looks for signup-related text on the page).
func waitForPageReady(ctx context.Context, bc *BridgeClient, tabID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Check if page has real content (not CF challenge)
		ok, _ := bc.ExecuteJSBool(tabID, `
			(function() {
				var body = document.body ? document.body.innerText || '' : '';
				var title = document.title || '';
				var all = body + ' ' + title;
				return all.indexOf('Sign up') >= 0 || all.indexOf('Create') >= 0 ||
				       all.indexOf('注册') >= 0 || all.indexOf('Grok') >= 0 ||
				       all.indexOf('email') >= 0 || all.indexOf('邮箱') >= 0 ||
				       document.querySelectorAll('button').length > 2;
			})()
		`)
		if ok {
			return nil
		}
		_ = sleepCtx(ctx, 1500*time.Millisecond)
	}
	return fmt.Errorf("page did not become ready within %s (may be stuck on CF challenge)", timeout)
}

// waitForTurnstile polls until cf-turnstile-response input has a non-trivial
// value (> 20 chars), indicating the Turnstile widget has completed.
func waitForTurnstile(ctx context.Context, bc *BridgeClient, tabID string) error {
	deadline := time.Now().Add(turnstileTO)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := bc.ExecuteJSBool(tabID, turnstileInputQ)
		if err == nil && ok {
			return nil
		}
		_ = sleepCtx(ctx, 1500*time.Millisecond)
	}
	return fmt.Errorf("turnstile did not complete within %s", turnstileTO)
}

// waitForSSO polls the tab's cookies for the "sso" cookie on .x.ai.
func waitForSSO(ctx context.Context, bc *BridgeClient, tabID string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		cookies, err := bc.GetCookies(tabID)
		if err == nil {
			for _, c := range cookies {
				name, _ := c["name"].(string)
				if name == "sso" {
					if val, _ := c["value"].(string); val != "" {
						return val, nil
					}
				}
			}
		}
		// Also try extracting via JS in case GetCookies misses it
		raw, jsErr := bc.ExecuteJS(tabID, `document.cookie`)
		if jsErr == nil {
			var cookieStr string
			if json.Unmarshal(raw, &cookieStr) == nil {
				for _, part := range strings.Split(cookieStr, ";") {
					kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
					if len(kv) == 2 && kv[0] == "sso" && kv[1] != "" {
						return kv[1], nil
					}
				}
			}
		}
		_ = sleepCtx(ctx, 1*time.Second)
	}
	return "", fmt.Errorf("SSO cookie not found within %s", timeout)
}

// clickOAuthApprove looks for approve/allow/authorize buttons on the OAuth consent page.
func clickOAuthApprove(ctx context.Context, bc *BridgeClient, tabID string, timeout time.Duration) error {
	keywords := []string{"allow", "approve", "authorize", "confirm", "continue"}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := bc.Scan(tabID)
		if err != nil {
			_ = sleepCtx(ctx, 500*time.Millisecond)
			continue
		}
		for _, kw := range keywords {
			if ref, ok := findRefByText(raw, kw); ok {
				return bc.ClickRef(tabID, ref)
			}
		}
		// fallback: click submit
		if ref, ok := findSubmitRef(raw); ok {
			return bc.ClickRef(tabID, ref)
		}
		_ = sleepCtx(ctx, 800*time.Millisecond)
	}
	return fmt.Errorf("OAuth approve button not found within %s", timeout)
}

// ── Scan result parsing ───────────────────────────────────────────────────────

// scan element shape from browser-mcp (subset of what the extension returns)
type scanElement struct {
	Ref         string `json:"ref"`
	Type        string `json:"type"`       // "button","input","a", …
	InputType   string `json:"input_type"` // for inputs: "text","email","password","submit"
	Name        string `json:"name"`
	Value       string `json:"value"`
	Text        string `json:"text"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Autocomplete string `json:"autocomplete"`
	AriaLabel   string `json:"aria_label"`
}

func parseScanElements(raw json.RawMessage) []scanElement {
	if raw == nil {
		return nil
	}
	// The scan result may be {"elements":[...]} or [...] directly.
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err == nil {
		if elems, ok := wrapper["elements"]; ok {
			raw = elems
		}
	}
	var elements []scanElement
	_ = json.Unmarshal(raw, &elements)
	return elements
}

func findRefByText(raw json.RawMessage, substr string) (string, bool) {
	lower := strings.ToLower(substr)
	for _, el := range parseScanElements(raw) {
		if strings.Contains(strings.ToLower(el.Text), lower) ||
			strings.Contains(strings.ToLower(el.Label), lower) ||
			strings.Contains(strings.ToLower(el.AriaLabel), lower) ||
			strings.Contains(strings.ToLower(el.Value), lower) {
			if el.Ref != "" {
				return el.Ref, true
			}
		}
	}
	return "", false
}

func findInputRefByType(raw json.RawMessage, inputType string) (string, bool) {
	for _, el := range parseScanElements(raw) {
		if el.Type == "input" && strings.EqualFold(el.InputType, inputType) {
			if el.Ref != "" {
				return el.Ref, true
			}
		}
	}
	return "", false
}

func findInputRefByAttr(raw json.RawMessage, attr, value string) (string, bool) {
	lower := strings.ToLower(value)
	for _, el := range parseScanElements(raw) {
		if el.Type != "input" {
			continue
		}
		var attrVal string
		switch strings.ToLower(attr) {
		case "name":
			attrVal = el.Name
		case "autocomplete":
			attrVal = el.Autocomplete
		}
		if strings.EqualFold(attrVal, lower) && el.Ref != "" {
			return el.Ref, true
		}
	}
	return "", false
}

func findSubmitRef(raw json.RawMessage) (string, bool) {
	for _, el := range parseScanElements(raw) {
		if (el.Type == "input" && strings.EqualFold(el.InputType, "submit")) ||
			(el.Type == "button" && (el.InputType == "" || strings.EqualFold(el.InputType, "submit"))) {
			if el.Ref != "" {
				return el.Ref, true
			}
		}
	}
	return "", false
}

// ── Misc helpers ─────────────────────────────────────────────────────────────

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// randomName returns a plausible given + family name pair for form filling.
func randomName() (string, string) {
	given := []string{
		"Alex", "Jordan", "Morgan", "Casey", "Riley",
		"Taylor", "Cameron", "Parker", "Quinn", "Avery",
	}
	family := []string{
		"Smith", "Johnson", "Brown", "Davis", "Wilson",
		"Moore", "Anderson", "Thomas", "Jackson", "White",
	}
	// Use time-based selection (not crypto-random; only for display names)
	ns := time.Now().UnixNano()
	g := given[ns%int64(len(given))]
	f := family[(ns/int64(len(given)))%int64(len(family))]
	return g, f
}
