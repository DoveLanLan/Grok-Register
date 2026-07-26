package signup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/grok-free-register/grok-reg/internal/browsermcp"
)

const mcpSignupURL = "https://accounts.x.ai/sign-up?redirect=grok-com"
const mcpBlankURL = "about:blank"

// mcpHandoffPlan bounds the wait for the post-signup redirect to grok.com.
//
// Approving the Device Flow before that redirect finishes leaves the account
// half-initialized and the token poll comes back invalid_grant, so Settle also
// gives grok.com room to commit its cookies before the tab navigates away.
type mcpHandoffPlan struct {
	Timeout time.Duration
	Poll    time.Duration
	Settle  time.Duration
}

var defaultMCPHandoffPlan = mcpHandoffPlan{
	Timeout: 60 * time.Second,
	Poll:    time.Second,
	Settle:  3 * time.Second,
}

type MCPBrowserOptions struct {
	Command       string
	CommandArgs   []string
	Incognito     bool
	Timeout       time.Duration
	CodeTimeout   time.Duration
	DiagnosticDir string
	WorkingDir    string
	Tracef        func(string, ...any)
}

type mcpRPC interface {
	Start(context.Context) error
	Call(context.Context, string, map[string]any, any) error
	Close() error
}

type MCPBrowser struct {
	opt MCPBrowserOptions

	mu        sync.Mutex
	proxy     string
	newClient func(browsermcp.Options) mcpRPC
}

type mcpNavigateResult struct {
	TabID     string `json:"tab_id"`
	URL       string `json:"url"`
	Title     string `json:"title"`
	Incognito bool   `json:"incognito"`
}

type mcpScanResult struct {
	Page struct {
		Title string `json:"title"`
		URL   string `json:"url"`
	} `json:"page"`
	Regions []struct {
		Name string `json:"name"`
		Text string `json:"text"`
	} `json:"regions"`
	Frames []struct {
		Src  string `json:"src"`
		Name string `json:"name"`
	} `json:"frames"`
	Signals struct {
		HasEmail             bool `json:"has_email"`
		HasCode              bool `json:"has_code"`
		HasPassword          bool `json:"has_password"`
		TurnstileTokenLength int  `json:"turnstile_token_length"`
		ChallengePresent     bool `json:"challenge_present"`
		SubmitEnabled        bool `json:"submit_enabled"`
	} `json:"signals"`
	Actions     []mcpAction `json:"actions"`
	TabRevision int         `json:"tab_revision"`
}

type mcpAction struct {
	Ref         string `json:"ref"`
	Tag         string `json:"tag"`
	Role        string `json:"role"`
	Label       string `json:"label"`
	Text        string `json:"text"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
	Disabled    bool   `json:"disabled"`
}

type mcpPageState struct {
	URL                  string `json:"url"`
	Title                string `json:"title"`
	Text                 string `json:"text"`
	HasEmail             bool   `json:"has_email"`
	HasCode              bool   `json:"has_code"`
	HasPassword          bool   `json:"has_password"`
	TurnstileTokenLength int    `json:"turnstile_token_length"`
	ChallengePresent     bool   `json:"challenge_present"`
	SubmitEnabled        bool   `json:"submit_enabled"`
}

type mcpClearCookiesResult struct {
	Removed int `json:"removed"`
	Failed  int `json:"failed"`
}

func NewMCPBrowser(opt MCPBrowserOptions) *MCPBrowser {
	if opt.Timeout <= 0 {
		opt.Timeout = 180 * time.Second
	}
	if opt.CodeTimeout <= 0 {
		opt.CodeTimeout = 100 * time.Second
	}
	b := &MCPBrowser{opt: opt}
	b.newClient = func(clientOpt browsermcp.Options) mcpRPC { return browsermcp.New(clientOpt) }
	return b
}

func (b *MCPBrowser) Name() string { return "browser-mcp-signup" }

func (b *MCPBrowser) SetProxy(proxy string) { b.proxy = strings.TrimSpace(proxy) }
func (b *MCPBrowser) Proxy() string         { return b.proxy }
func (b *MCPBrowser) SetDiagnosticDir(path string) {
	b.opt.DiagnosticDir = strings.TrimSpace(path)
}
func (b *MCPBrowser) DiagnosticDir() string { return b.opt.DiagnosticDir }

func (b *MCPBrowser) Register(ctx context.Context, email, password, given, family string, pollCode func(context.Context) (string, error)) (BrowserResult, error) {
	return b.RegisterWithOAuth(ctx, email, password, given, family, "", pollCode)
}

func (b *MCPBrowser) RegisterWithOAuth(ctx context.Context, email, password, given, family, verificationURL string, pollCode func(context.Context) (string, error)) (BrowserResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return BrowserResult{}, fmt.Errorf("browser_mcp_signup_invalid: email/password required")
	}
	if pollCode == nil {
		return BrowserResult{}, fmt.Errorf("browser_mcp_signup_invalid: pollCode required")
	}
	if !b.opt.Incognito {
		return BrowserResult{}, fmt.Errorf("browser_mcp_signup_unsafe: incognito is required so account cookies cannot leak into the next registration")
	}
	if given == "" || family == "" {
		defaultGiven, defaultFamily := mcpRandomName()
		if given == "" {
			given = defaultGiven
		}
		if family == "" {
			family = defaultFamily
		}
	}

	runBudget := b.opt.Timeout + b.opt.CodeTimeout + 45*time.Second
	if strings.TrimSpace(verificationURL) != "" {
		runBudget += 2 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, runBudget)
	defer cancel()

	sessionID := "grok-reg-" + mcpSessionSuffix()
	client := b.newClient(browsermcp.Options{
		Command:      b.opt.Command,
		Args:         b.opt.CommandArgs,
		SessionID:    sessionID,
		SessionLabel: "Grok registration",
		WorkingDir:   b.opt.WorkingDir,
		Tracef:       b.tracef,
	})
	if err := client.Start(runCtx); err != nil {
		return BrowserResult{}, fmt.Errorf("browser_mcp_start: %w", err)
	}
	defer client.Close()

	if b.proxy != "" {
		b.tracef("Browser MCP controls the current Chrome network; REGISTER_PROXY=%s applies only to Go HTTP/OAuth calls", safeProxyLabel(b.proxy))
	}

	var nav mcpNavigateResult
	if err := client.Call(runCtx, "navigate", map[string]any{
		"url":       mcpBlankURL,
		"incognito": b.opt.Incognito,
		"timeout":   30,
	}, &nav); err != nil {
		return BrowserResult{}, fmt.Errorf("browser_mcp_navigate: %w", err)
	}
	if nav.TabID == "" {
		return BrowserResult{}, fmt.Errorf("browser_mcp_navigate: missing tab_id")
	}
	tabID := nav.TabID
	defer b.closeAccountTab(client, tabID)
	if !nav.Incognito {
		return BrowserResult{}, fmt.Errorf("browser_mcp_navigate: Chrome did not create an incognito tab")
	}
	if _, err := b.clearAccountCookies(runCtx, client, tabID); err != nil {
		return BrowserResult{}, fmt.Errorf("browser_mcp_session_reset: %w", err)
	}
	if err := client.Call(runCtx, "navigate", map[string]any{
		"tab_id":  tabID,
		"url":     mcpSignupURL,
		"timeout": 30,
	}, &nav); err != nil {
		return BrowserResult{}, fmt.Errorf("browser_mcp_signup_navigate: %w", err)
	}

	actions := []string{"browser:opened"}

	if err := b.waitPage(runCtx, client, tabID, 35*time.Second, func(s mcpPageState) bool {
		return s.HasEmail || strings.Contains(strings.ToLower(s.Text), "sign up") || strings.Contains(s.Text, "注册")
	}); err != nil {
		return mcpFailure("page_ready", actions, err)
	}
	_ = b.clickOptional(runCtx, client, tabID, []string{"accept all", "accept cookies", "接受所有"}, 3*time.Second)
	if clicked, err := b.clickText(runCtx, client, tabID, []string{"sign up with email", "使用邮箱注册", "邮箱注册"}, 12*time.Second); err == nil {
		actions = append(actions, "click:"+clicked)
	}

	if err := b.fillMatching(runCtx, client, tabID, email, func(a mcpAction) bool {
		text := actionText(a)
		return strings.EqualFold(a.Type, "email") || strings.EqualFold(a.Name, "email") || strings.Contains(text, "email") || strings.Contains(text, "邮箱")
	}, nil); err != nil {
		return mcpFailure("email_fill", actions, err)
	}
	actions = append(actions, "fill:email")
	if clicked, err := b.clickText(runCtx, client, tabID, []string{"sign up", "continue", "next", "注册", "继续", "下一步"}, 12*time.Second); err != nil {
		return mcpFailure("email_submit", actions, err)
	} else {
		actions = append(actions, "submit:email:"+clicked)
	}

	if err := b.waitPage(runCtx, client, tabID, 55*time.Second, func(s mcpPageState) bool { return s.HasCode }); err != nil {
		state, _ := b.pageState(runCtx, client, tabID)
		if pageHasRateLimit(state.Text) {
			err = fmt.Errorf("email_code_rate_limited")
		}
		return mcpFailure("awaiting_code_field", actions, err)
	}
	codeCtx, codeCancel := context.WithTimeout(runCtx, b.opt.CodeTimeout)
	code, err := pollCode(codeCtx)
	codeCancel()
	if err != nil {
		return mcpFailure("code_poll", actions, err)
	}
	if err := b.fillVerificationCode(runCtx, client, tabID, code); err != nil {
		return mcpFailure("code_fill", actions, err)
	}
	actions = append(actions, "fill:code")
	if clicked, clickErr := b.clickText(runCtx, client, tabID, []string{"confirm email", "confirm", "continue", "verify", "确认", "继续"}, 10*time.Second); clickErr == nil {
		actions = append(actions, "submit:code:"+clicked)
	}

	if err := b.waitPage(runCtx, client, tabID, 40*time.Second, func(s mcpPageState) bool { return s.HasPassword }); err != nil {
		return mcpFailure("credentials_form", actions, err)
	}
	if err := b.fillCredentials(runCtx, client, tabID, given, family, password); err != nil {
		return mcpFailure("credentials_fill", actions, err)
	}
	actions = append(actions, "fill:credentials")

	advanced, turnstileAction, err := b.waitTurnstile(runCtx, client, tabID, 75*time.Second)
	if turnstileAction != "" {
		actions = append(actions, turnstileAction)
	}
	if err != nil {
		return mcpFailure("turnstile", actions, err)
	}
	if !advanced {
		clicked, clickErr := b.clickText(runCtx, client, tabID, []string{
			"complete sign up", "create account", "create", "finish", "完成注册", "创建账户", "创建账号",
		}, 20*time.Second)
		if clickErr != nil {
			return mcpFailure("credentials_submit", actions, clickErr)
		}
		actions = append(actions, "submit:credentials:"+clicked)
	}

	if err := b.waitRegistration(runCtx, client, tabID, 70*time.Second); err != nil {
		return mcpFailure("registration", actions, err)
	}
	actions = append(actions, "registered")

	// accounts.x.ai redirects to grok.com to finish provisioning the account.
	// OAuth consent must not start until that landing page is loaded.
	handoffAction, handoffErr := b.waitGrokHandoff(runCtx, client, tabID, defaultMCPHandoffPlan)
	if handoffAction != "" {
		actions = append(actions, handoffAction)
	}
	if handoffErr != nil {
		return mcpFailure("grok_handoff", actions, handoffErr)
	}

	oauthOK := false
	if strings.TrimSpace(verificationURL) != "" {
		oauthOK, err = b.approveOAuth(runCtx, client, tabID, verificationURL, email, password, 100*time.Second)
		if err != nil {
			actions = append(actions, "oauth:error")
			b.tracef("browser-mcp OAuth approval failed: %v", err)
		} else if oauthOK {
			actions = append(actions, "oauth:authorized")
		}
	}

	stage := "registered"
	if oauthOK {
		stage = "registered_oauth"
	}
	return BrowserResult{
		OK:              true,
		Stage:           stage,
		OAuthAuthorized: oauthOK,
		URL:             verificationURL,
		Actions:         tailActions(actions, 24),
		Email:           email,
		GivenName:       given,
		FamilyName:      family,
	}, nil
}

func (b *MCPBrowser) tracef(format string, args ...any) {
	if b.opt.Tracef != nil {
		b.opt.Tracef(format, args...)
	}
}

func (b *MCPBrowser) scan(ctx context.Context, client mcpRPC, tabID string) (mcpScanResult, error) {
	var result mcpScanResult
	err := client.Call(ctx, "scan", map[string]any{
		"tab_id":        tabID,
		"max_actions":   80,
		"summary_chars": 1600,
		"timeout":       15,
	}, &result)
	return result, err
}

func (b *MCPBrowser) pageState(ctx context.Context, client mcpRPC, tabID string) (mcpPageState, error) {
	scan, err := b.scan(ctx, client, tabID)
	if err != nil {
		return mcpPageState{}, err
	}
	state := mcpPageState{
		URL:                  scan.Page.URL,
		Title:                scan.Page.Title,
		HasEmail:             scan.Signals.HasEmail,
		HasCode:              scan.Signals.HasCode,
		HasPassword:          scan.Signals.HasPassword,
		TurnstileTokenLength: scan.Signals.TurnstileTokenLength,
		ChallengePresent:     scan.Signals.ChallengePresent,
		SubmitEnabled:        scan.Signals.SubmitEnabled,
	}
	texts := make([]string, 0, len(scan.Regions))
	for _, region := range scan.Regions {
		if text := strings.TrimSpace(region.Text); text != "" {
			texts = append(texts, text)
		}
	}
	state.Text = strings.Join(texts, " | ")

	// Compatibility fallbacks for an older browser-mcp extension which does
	// not yet include scan.signals. All interactions still use native scan
	// refs; this only derives read-only state from the same snapshot.
	for _, action := range scan.Actions {
		if !isInputAction(action) {
			continue
		}
		text := actionText(action)
		state.HasEmail = state.HasEmail || strings.EqualFold(action.Type, "email") || strings.EqualFold(action.Name, "email") || strings.Contains(text, "email") || strings.Contains(text, "邮箱")
		state.HasPassword = state.HasPassword || strings.EqualFold(action.Type, "password")
		state.HasCode = state.HasCode || strings.EqualFold(action.Name, "code") || strings.EqualFold(action.Name, "otp") || strings.Contains(text, "verification") || strings.Contains(text, "code") || strings.Contains(text, "验证码")
	}
	for _, frame := range scan.Frames {
		frameID := strings.ToLower(frame.Src + " " + frame.Name)
		if strings.Contains(frameID, "challenges.cloudflare.com") || strings.Contains(frameID, "turnstile") {
			state.ChallengePresent = true
		}
	}
	return state, nil
}

func (b *MCPBrowser) waitPage(ctx context.Context, client mcpRPC, tabID string, timeout time.Duration, ready func(mcpPageState) bool) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := b.pageState(ctx, client, tabID)
		if err == nil && ready(state) {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		if err := sleepMCP(ctx, 900*time.Millisecond); err != nil {
			return err
		}
	}
	if lastErr != nil {
		return fmt.Errorf("page wait timeout (%s): %w", timeout, lastErr)
	}
	return fmt.Errorf("page wait timeout (%s)", timeout)
}

func (b *MCPBrowser) clickOptional(ctx context.Context, client mcpRPC, tabID string, keywords []string, timeout time.Duration) error {
	_, err := b.clickText(ctx, client, tabID, keywords, timeout)
	return err
}

func (b *MCPBrowser) clickText(ctx context.Context, client mcpRPC, tabID string, keywords []string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		scan, err := b.scan(ctx, client, tabID)
		if err == nil {
			if action, ok := findAction(scan.Actions, func(a mcpAction) bool {
				if a.Disabled || (a.Role != "button" && a.Tag != "button" && a.Role != "link" && a.Tag != "a" && a.Type != "submit") {
					return false
				}
				text := actionText(a)
				for _, keyword := range keywords {
					if strings.Contains(text, strings.ToLower(keyword)) {
						return true
					}
				}
				return false
			}); ok {
				var result map[string]any
				err = client.Call(ctx, "click_ref", map[string]any{
					"tab_id":            tabID,
					"ref":               action.Ref,
					"seen_tab_revision": scan.TabRevision,
					"timeout":           12,
				}, &result)
				if err == nil {
					return firstNonEmpty(action.Label, action.Text, action.Name, action.Ref), nil
				}
				lastErr = err
			}
		} else {
			lastErr = err
		}
		if err := sleepMCP(ctx, 650*time.Millisecond); err != nil {
			return "", err
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("button action failed (%s): %w", strings.Join(keywords, "/"), lastErr)
	}
	return "", fmt.Errorf("button not found: %s", strings.Join(keywords, "/"))
}

func (b *MCPBrowser) fillMatching(ctx context.Context, client mcpRPC, tabID, value string, match func(mcpAction) bool, fallback func([]mcpAction) (mcpAction, bool)) error {
	deadline := time.Now().Add(18 * time.Second)
	for time.Now().Before(deadline) {
		scan, err := b.scan(ctx, client, tabID)
		if err == nil {
			action, ok := findAction(scan.Actions, func(a mcpAction) bool {
				return isInputAction(a) && match(a)
			})
			if !ok && fallback != nil {
				action, ok = fallback(scan.Actions)
			}
			if ok {
				var result map[string]any
				if err := client.Call(ctx, "fill_ref", map[string]any{
					"tab_id":            tabID,
					"ref":               action.Ref,
					"value":             value,
					"seen_tab_revision": scan.TabRevision,
					"timeout":           12,
				}, &result); err == nil {
					return nil
				}
			}
		}
		if err := sleepMCP(ctx, 600*time.Millisecond); err != nil {
			return err
		}
	}
	return fmt.Errorf("matching input not found")
}

func (b *MCPBrowser) fillVerificationCode(ctx context.Context, client mcpRPC, tabID, code string) error {
	code = strings.TrimSpace(code)
	compact := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, code)
	scan, err := b.scan(ctx, client, tabID)
	if err != nil {
		return err
	}
	fields := filterActions(scan.Actions, func(a mcpAction) bool {
		if !isInputAction(a) || strings.EqualFold(a.Type, "email") || strings.EqualFold(a.Type, "password") {
			return false
		}
		text := actionText(a)
		return strings.Contains(text, "code") || strings.Contains(text, "verification") || strings.Contains(text, "otp") || strings.Contains(text, "验证码") || strings.EqualFold(a.Name, "code")
	})
	if len(fields) == 0 {
		fields = filterActions(scan.Actions, func(a mcpAction) bool {
			return isInputAction(a) && !strings.EqualFold(a.Type, "email") && !strings.EqualFold(a.Type, "password")
		})
	}
	if len(fields) >= len(compact) && len(compact) >= 4 {
		for i, digit := range compact {
			current, scanErr := b.scan(ctx, client, tabID)
			if scanErr != nil {
				return scanErr
			}
			currentFields := filterActions(current.Actions, func(a mcpAction) bool {
				return isInputAction(a) && !strings.EqualFold(a.Type, "email") && !strings.EqualFold(a.Type, "password")
			})
			if i >= len(currentFields) {
				return fmt.Errorf("verification digit input disappeared at %d", i)
			}
			var result map[string]any
			if err := client.Call(ctx, "fill_ref", map[string]any{
				"tab_id":            tabID,
				"ref":               currentFields[i].Ref,
				"value":             string(digit),
				"seen_tab_revision": current.TabRevision,
				"timeout":           10,
			}, &result); err != nil {
				return err
			}
		}
		return nil
	}
	return b.fillMatching(ctx, client, tabID, code, func(a mcpAction) bool {
		text := actionText(a)
		return strings.Contains(text, "code") || strings.Contains(text, "verification") || strings.Contains(text, "otp") || strings.Contains(text, "验证码") || strings.EqualFold(a.Name, "code")
	}, func(actions []mcpAction) (mcpAction, bool) {
		return findAction(actions, func(a mcpAction) bool {
			return isInputAction(a) && !strings.EqualFold(a.Type, "email") && !strings.EqualFold(a.Type, "password")
		})
	})
}

func (b *MCPBrowser) fillCredentials(ctx context.Context, client mcpRPC, tabID, given, family, password string) error {
	textFallback := func(index int) func([]mcpAction) (mcpAction, bool) {
		return func(actions []mcpAction) (mcpAction, bool) {
			inputs := filterActions(actions, func(a mcpAction) bool {
				return isInputAction(a) && !strings.EqualFold(a.Type, "password") && !strings.EqualFold(a.Type, "email") && strings.TrimSpace(a.Value) == ""
			})
			if index < len(inputs) {
				return inputs[index], true
			}
			return mcpAction{}, false
		}
	}
	if err := b.fillMatching(ctx, client, tabID, given, func(a mcpAction) bool {
		text := actionText(a)
		return strings.Contains(text, "first") || strings.Contains(text, "given") || strings.EqualFold(a.Name, "givenName") || strings.Contains(text, "名")
	}, textFallback(0)); err != nil {
		return fmt.Errorf("given name: %w", err)
	}
	if err := b.fillMatching(ctx, client, tabID, family, func(a mcpAction) bool {
		text := actionText(a)
		return strings.Contains(text, "last") || strings.Contains(text, "family") || strings.EqualFold(a.Name, "familyName") || strings.Contains(text, "姓")
	}, textFallback(0)); err != nil {
		return fmt.Errorf("family name: %w", err)
	}
	if err := b.fillMatching(ctx, client, tabID, password, func(a mcpAction) bool {
		return strings.EqualFold(a.Type, "password")
	}, nil); err != nil {
		return fmt.Errorf("password: %w", err)
	}
	return nil
}

func (b *MCPBrowser) waitTurnstile(ctx context.Context, client mcpRPC, tabID string, timeout time.Duration) (advanced bool, action string, err error) {
	deadline := time.Now().Add(timeout)
	started := time.Now()
	seenChallenge := false
	for time.Now().Before(deadline) {
		state, stateErr := b.pageState(ctx, client, tabID)
		if stateErr == nil {
			seenChallenge = seenChallenge || state.ChallengePresent
			if !state.HasPassword {
				return true, "turnstile:navigated_away", nil
			}
			if state.TurnstileTokenLength > 20 {
				b.tracef("browser-mcp Cloudflare passed (response length=%d)", state.TurnstileTokenLength)
				return false, "turnstile:token_ready", nil
			}
			if state.SubmitEnabled && ((seenChallenge && !state.ChallengePresent) || time.Since(started) > 20*time.Second) {
				b.tracef("browser-mcp Cloudflare appears ready (submit enabled; token field not exposed)")
				return false, "turnstile:submit_enabled", nil
			}
			if time.Since(started) > 25*time.Second && state.ChallengePresent {
				b.tracef("browser-mcp Cloudflare is still visible; complete it in the real Chrome window if interaction is requested")
			}
		}
		if err := sleepMCP(ctx, 1200*time.Millisecond); err != nil {
			return false, "", err
		}
	}
	state, _ := b.pageState(ctx, client, tabID)
	if state.SubmitEnabled {
		return false, "turnstile:timeout_submit_enabled", nil
	}
	return false, "turnstile:timeout", fmt.Errorf("Cloudflare did not expose a response or enable submit within %s", timeout)
}

func (b *MCPBrowser) waitRegistration(ctx context.Context, client mcpRPC, tabID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	advanced := 0
	lastSubmit := time.Now()
	for time.Now().Before(deadline) {
		state, err := b.pageState(ctx, client, tabID)
		if err == nil {
			if pageHasRateLimit(state.Text) {
				return fmt.Errorf("signup_rate_limited")
			}
			lower := strings.ToLower(state.Text)
			if strings.Contains(lower, "invalid") && strings.Contains(lower, "password") {
				return fmt.Errorf("signup_password_rejected")
			}
			if !state.HasPassword {
				advanced++
				if advanced >= 2 {
					return nil
				}
			} else {
				advanced = 0
				if state.SubmitEnabled && time.Since(lastSubmit) >= 8*time.Second {
					if _, clickErr := b.clickText(ctx, client, tabID, []string{
						"complete sign up", "create account", "create", "finish", "完成注册", "创建账户", "创建账号",
					}, 4*time.Second); clickErr == nil {
						lastSubmit = time.Now()
					}
				}
			}
		}
		if err := sleepMCP(ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("credentials form remained visible after submit")
}

// waitGrokHandoff blocks until the post-signup redirect to grok.com has landed.
//
// x.ai finishes provisioning the account on that hop: accounts.x.ai issues the
// session, grok.com exchanges it and sets its own cookies. Overnight logs showed
// 108 device-token polls returning invalid_grant (Access denied) because consent
// was requested while the tab was still mid-handoff. Waiting here is what makes
// the automated run match a manual register → OAuth sequence.
func (b *MCPBrowser) waitGrokHandoff(ctx context.Context, client mcpRPC, tabID string, plan mcpHandoffPlan) (string, error) {
	deadline := time.Now().Add(plan.Timeout)
	lastURL := ""
	for time.Now().Before(deadline) {
		state, err := b.pageState(ctx, client, tabID)
		if err == nil {
			if state.URL != lastURL {
				b.tracef("browser-mcp post-signup page url=%s", safeMCPLocation(state.URL))
				lastURL = state.URL
			}
			if isGrokHandoffURL(state.URL) {
				b.tracef("browser-mcp grok.com handoff loaded; settling %s before OAuth", plan.Settle)
				if err := sleepMCP(ctx, plan.Settle); err != nil {
					return "", err
				}
				return "handoff:grok_loaded", nil
			}
		}
		if err := sleepMCP(ctx, plan.Poll); err != nil {
			return "", err
		}
	}
	// The account exists and SSO is live; a missed redirect should degrade to a
	// best-effort OAuth attempt rather than discarding a good registration.
	b.tracef("browser-mcp grok.com handoff not observed within %s; continuing to OAuth", plan.Timeout)
	return "handoff:timeout", nil
}

// isGrokHandoffURL reports whether the tab has landed on the grok.com app that
// accounts.x.ai redirects to once signup completes.
func isGrokHandoffURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "grok.com" || strings.HasSuffix(host, ".grok.com")
}

func (b *MCPBrowser) closeAccountTab(client mcpRPC, tabID string) {
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cleanupCancel()
	cleanup := func(target mcpRPC) error {
		_, clearErr := b.clearAccountCookies(cleanupCtx, target, tabID)
		var closed map[string]any
		closeErr := target.Call(cleanupCtx, "close_tab", map[string]any{
			"tab_id":  tabID,
			"timeout": 8,
		}, &closed)
		if clearErr != nil && closeErr != nil {
			return fmt.Errorf("clear cookies: %v; close tab: %w", clearErr, closeErr)
		}
		if clearErr != nil {
			return fmt.Errorf("clear cookies: %w", clearErr)
		}
		return closeErr
	}
	if err := cleanup(client); err == nil {
		b.tracef("browser-mcp account incognito window closed; session cookies discarded tab=%s", tabID)
		return
	} else {
		b.tracef("browser-mcp primary cleanup connection unavailable tab=%s: %v", tabID, err)
	}

	// A registration deadline can terminate the original CLI. Rejoin with a
	// short-lived peer so the owned Incognito window is still destroyed.
	fallback := b.newClient(browsermcp.Options{
		Command:      b.opt.Command,
		Args:         b.opt.CommandArgs,
		SessionID:    "grok-cleanup-" + mcpSessionSuffix(),
		SessionLabel: "Grok registration cleanup",
		WorkingDir:   b.opt.WorkingDir,
		Tracef:       b.tracef,
	})
	if err := fallback.Start(cleanupCtx); err != nil {
		b.tracef("browser-mcp cleanup peer start failed tab=%s: %v", tabID, err)
		return
	}
	defer fallback.Close()
	if err := cleanup(fallback); err != nil {
		b.tracef("browser-mcp cleanup peer failed tab=%s: %v", tabID, err)
		return
	}
	b.tracef("browser-mcp account incognito window closed by cleanup peer; session cookies discarded tab=%s", tabID)
}

func (b *MCPBrowser) clearAccountCookies(ctx context.Context, client mcpRPC, tabID string) (mcpClearCookiesResult, error) {
	var result mcpClearCookiesResult
	err := client.Call(ctx, "clear_cookies", map[string]any{
		"tab_id":  tabID,
		"domains": []string{"x.ai", "grok.com"},
		"timeout": 10,
	}, &result)
	if err != nil {
		return mcpClearCookiesResult{}, err
	}
	if result.Failed > 0 {
		return result, fmt.Errorf("%d account cookies could not be removed", result.Failed)
	}
	b.tracef("browser-mcp account cookies cleared (count=%d tab=%s)", result.Removed, tabID)
	return result, nil
}

func (b *MCPBrowser) approveOAuth(ctx context.Context, client mcpRPC, tabID, verificationURL, email, password string, timeout time.Duration) (bool, error) {
	var nav mcpNavigateResult
	if err := client.Call(ctx, "navigate", map[string]any{
		"tab_id":  tabID,
		"url":     verificationURL,
		"timeout": 30,
	}, &nav); err != nil {
		return false, err
	}
	deadline := time.Now().Add(timeout)
	lastClick := time.Time{}
	lastPage := ""
	for time.Now().Before(deadline) {
		consentPage := false
		state, err := b.pageState(ctx, client, tabID)
		if err == nil {
			lowerURL := strings.ToLower(state.URL)
			lowerText := strings.ToLower(state.Text)
			consentPage = strings.Contains(lowerURL, "/oauth2/device/consent") || strings.Contains(lowerURL, "/device/consent")
			pageKey := lowerURL + "|" + strings.ToLower(state.Title)
			if pageKey != lastPage {
				b.tracef("browser-mcp OAuth page url=%s title=%s", safeMCPLocation(state.URL), safeMCPText(state.Title, 100))
				lastPage = pageKey
			}
			if strings.Contains(lowerURL, "/oauth2/device/done") || strings.Contains(lowerURL, "/device/done") ||
				strings.Contains(lowerText, "device authorized") || strings.Contains(lowerText, "you have authorized") ||
				strings.Contains(lowerText, "authorization successful") || strings.Contains(lowerText, "successfully authorized") ||
				strings.Contains(state.Text, "设备已授权") || strings.Contains(state.Text, "授权成功") {
				return true, nil
			}
			if state.HasEmail {
				_ = b.fillMatching(ctx, client, tabID, email, func(a mcpAction) bool {
					return strings.EqualFold(a.Type, "email") || strings.Contains(actionText(a), "email") || strings.Contains(actionText(a), "邮箱")
				}, nil)
				_, _ = b.clickText(ctx, client, tabID, []string{"continue", "next", "sign in", "继续", "下一步", "登录"}, 4*time.Second)
			}
			if state.HasPassword {
				_ = b.fillMatching(ctx, client, tabID, password, func(a mcpAction) bool { return strings.EqualFold(a.Type, "password") }, nil)
				_, _ = b.clickText(ctx, client, tabID, []string{"continue", "sign in", "log in", "继续", "登录"}, 4*time.Second)
			}
		}
		if time.Since(lastClick) > 2*time.Second {
			clickTimeout := 4 * time.Second
			if consentPage {
				clickTimeout = 12 * time.Second
			}
			if clicked, clickErr := b.clickText(ctx, client, tabID, []string{"allow", "approve", "authorize", "confirm", "continue", "允许", "授权", "确认", "继续"}, clickTimeout); clickErr == nil {
				lastClick = time.Now()
				b.tracef("browser-mcp OAuth clicked %s", safeMCPText(clicked, 100))
				// A successful native click on an approval-specific control is
				// enough to hand control back to the Device Flow poller. The poller
				// remains the authoritative proof that authorization succeeded; the
				// browser does not have to redirect to a particular completion URL.
				if isOAuthApprovalClick(clicked, consentPage) {
					return true, nil
				}
			} else if consentPage {
				b.tracef("browser-mcp OAuth consent click pending: %v", clickErr)
			}
		}
		if err := sleepMCP(ctx, 850*time.Millisecond); err != nil {
			return false, err
		}
	}
	return false, fmt.Errorf("OAuth approval did not reach device/done within %s", timeout)
}

func isOAuthApprovalClick(label string, consentPage bool) bool {
	lower := strings.ToLower(strings.TrimSpace(label))
	if strings.Contains(lower, "allow") || strings.Contains(lower, "approve") || strings.Contains(lower, "authorize") ||
		strings.Contains(label, "允许") || strings.Contains(label, "授权") {
		return true
	}
	return consentPage && (strings.Contains(lower, "confirm") || strings.Contains(lower, "continue") ||
		strings.Contains(label, "确认") || strings.Contains(label, "继续"))
}

func safeMCPText(value string, limit int) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if limit > 0 && len(value) > limit {
		return value[:limit]
	}
	return value
}

func safeMCPLocation(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexByte(value, '?'); index >= 0 {
		return value[:index]
	}
	return safeMCPText(value, 160)
}

func actionText(a mcpAction) string {
	return strings.ToLower(strings.Join([]string{a.Label, a.Text, a.Name, a.Placeholder, a.Role, a.Type}, " "))
}

func isInputAction(a mcpAction) bool {
	return a.Tag == "input" || a.Tag == "textarea" || a.Role == "textbox"
}

func findAction(actions []mcpAction, match func(mcpAction) bool) (mcpAction, bool) {
	for _, action := range actions {
		if action.Ref != "" && match(action) {
			return action, true
		}
	}
	return mcpAction{}, false
}

func filterActions(actions []mcpAction, match func(mcpAction) bool) []mcpAction {
	out := make([]mcpAction, 0, len(actions))
	for _, action := range actions {
		if action.Ref != "" && match(action) {
			out = append(out, action)
		}
	}
	return out
}

func pageHasRateLimit(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "rate limit") || strings.Contains(lower, "too many") || strings.Contains(lower, "try again later") || strings.Contains(lower, "请求过多")
}

func mcpFailure(stage string, actions []string, err error) (BrowserResult, error) {
	result := BrowserResult{OK: false, Stage: stage, Actions: tailActions(actions, 24)}
	if err != nil {
		result.Error = err.Error()
	}
	return result, fmt.Errorf("browser_mcp_signup_failed stage=%s: %w", stage, err)
}

func tailActions(actions []string, limit int) []string {
	if len(actions) <= limit {
		return append([]string{}, actions...)
	}
	return append([]string{}, actions[len(actions)-limit:]...)
}

func sleepMCP(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func mcpSessionSuffix() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func mcpRandomName() (string, string) {
	given := []string{"Alex", "Jordan", "Morgan", "Casey", "Riley", "Taylor", "Cameron", "Parker"}
	family := []string{"Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Anderson", "Thomas"}
	now := time.Now().UnixNano()
	return given[now%int64(len(given))], family[(now/int64(len(given)))%int64(len(family))]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "action"
}

func safeProxyLabel(raw string) string {
	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		return "***@" + parts[1]
	}
	return raw
}
