package signup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/grok-free-register/grok-reg/internal/browsermcp"
)

type fakeMCPRPC struct {
	states     []mcpPageState
	closeErr   error
	closedTabs []string
	methods    []string
	started    bool
}

func (f *fakeMCPRPC) Start(context.Context) error {
	f.started = true
	return nil
}

func (f *fakeMCPRPC) Close() error { return nil }

func (f *fakeMCPRPC) Call(_ context.Context, method string, params map[string]any, out any) error {
	f.methods = append(f.methods, method)
	switch method {
	case "scan":
		if len(f.states) == 0 {
			return errors.New("no state")
		}
		state := f.states[0]
		if len(f.states) > 1 {
			f.states = f.states[1:]
		}
		var scan mcpScanResult
		scan.Page.URL = state.URL
		scan.Page.Title = state.Title
		scan.Regions = append(scan.Regions, struct {
			Name string `json:"name"`
			Text string `json:"text"`
		}{Name: "body", Text: state.Text})
		scan.Signals.HasEmail = state.HasEmail
		scan.Signals.HasCode = state.HasCode
		scan.Signals.HasPassword = state.HasPassword
		scan.Signals.TurnstileTokenLength = state.TurnstileTokenLength
		scan.Signals.ChallengePresent = state.ChallengePresent
		scan.Signals.SubmitEnabled = state.SubmitEnabled
		raw, _ := json.Marshal(scan)
		return json.Unmarshal(raw, out)
	case "close_tab":
		if f.closeErr != nil {
			return f.closeErr
		}
		f.closedTabs = append(f.closedTabs, params["tab_id"].(string))
		return nil
	default:
		return nil
	}
}

func TestMCPBrowserDetectsTurnstileTokenWithoutReturningIt(t *testing.T) {
	fake := &fakeMCPRPC{states: []mcpPageState{{
		HasPassword:          true,
		TurnstileTokenLength: 128,
	}}}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	advanced, action, err := browser.waitTurnstile(context.Background(), fake, "7", time.Second)
	if err != nil || advanced || action != "turnstile:token_ready" {
		t.Fatalf("waitTurnstile() = advanced=%v action=%q err=%v", advanced, action, err)
	}
}

func TestMCPBrowserDetectsTurnstileChallengeCompletion(t *testing.T) {
	fake := &fakeMCPRPC{states: []mcpPageState{
		{HasPassword: true, ChallengePresent: true},
		{HasPassword: true, SubmitEnabled: true},
	}}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	advanced, action, err := browser.waitTurnstile(context.Background(), fake, "7", 3*time.Second)
	if err != nil || advanced || action != "turnstile:submit_enabled" {
		t.Fatalf("waitTurnstile() = advanced=%v action=%q err=%v", advanced, action, err)
	}
}

func TestMCPBrowserCleanupUsesFallbackPeer(t *testing.T) {
	primary := &fakeMCPRPC{closeErr: errors.New("original cli stopped")}
	fallback := &fakeMCPRPC{}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	browser.newClient = func(browsermcp.Options) mcpRPC { return fallback }
	browser.closeAccountTab(primary, "88")
	if !fallback.started {
		t.Fatal("cleanup fallback was not started")
	}
	if len(fallback.closedTabs) != 1 || fallback.closedTabs[0] != "88" {
		t.Fatalf("fallback closed tabs = %v", fallback.closedTabs)
	}
	if got := strings.Join(fallback.methods, ","); got != "clear_cookies,close_tab" {
		t.Fatalf("fallback cleanup methods = %s", got)
	}
}

func TestMCPBrowserCleanupClearsCookiesBeforeClosingTab(t *testing.T) {
	primary := &fakeMCPRPC{}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	browser.closeAccountTab(primary, "91")
	if got := strings.Join(primary.methods, ","); got != "clear_cookies,close_tab" {
		t.Fatalf("cleanup methods = %s", got)
	}
}

func TestMCPBrowserRequiresIncognito(t *testing.T) {
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: false})
	_, err := browser.RegisterWithOAuth(
		context.Background(),
		"person@example.test",
		"password",
		"Alex",
		"Smith",
		"",
		func(context.Context) (string, error) { return "ABC-123", nil },
	)
	if err == nil || !strings.Contains(err.Error(), "incognito is required") {
		t.Fatalf("expected incognito safety error, got %v", err)
	}
}

func TestMCPScanActionShapeMatchesExtension(t *testing.T) {
	actions := []mcpAction{
		{Ref: "e1", Tag: "input", Role: "textbox", Type: "email", Label: "Email"},
		{Ref: "e2", Tag: "button", Role: "button", Text: "Sign up"},
	}
	input, ok := findAction(actions, func(action mcpAction) bool {
		return isInputAction(action) && action.Type == "email"
	})
	if !ok || input.Ref != "e1" {
		t.Fatalf("email action = %+v, ok=%v", input, ok)
	}
}

func TestMCPPageStateUsesScanInsteadOfEval(t *testing.T) {
	fake := &fakeMCPRPC{states: []mcpPageState{{
		URL:              "https://accounts.x.ai/sign-up",
		Title:            "Create account",
		Text:             "Complete sign up",
		HasPassword:      true,
		ChallengePresent: true,
		SubmitEnabled:    true,
	}}}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	state, err := browser.pageState(context.Background(), fake, "7")
	if err != nil {
		t.Fatal(err)
	}
	if !state.HasPassword || !state.ChallengePresent || !state.SubmitEnabled {
		t.Fatalf("page state = %+v", state)
	}
	if got := strings.Join(fake.methods, ","); got != "scan" {
		t.Fatalf("page state methods = %s", got)
	}
}

func TestWaitGrokHandoffBlocksUntilRedirectLands(t *testing.T) {
	fake := &fakeMCPRPC{states: []mcpPageState{
		{URL: "https://accounts.x.ai/sign-up?redirect=grok-com"},
		{URL: "https://accounts.x.ai/sso/redirect"},
		{URL: "https://grok.com/?ref=signup"},
	}}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	action, err := browser.waitGrokHandoff(context.Background(), fake, "7", mcpHandoffPlan{
		Timeout: 5 * time.Second,
		Poll:    time.Millisecond,
		Settle:  10 * time.Millisecond,
	})
	if err != nil || action != "handoff:grok_loaded" {
		t.Fatalf("waitGrokHandoff() = %q, err=%v", action, err)
	}
	// The consent page must not be opened before grok.com is observed.
	if len(fake.states) != 1 || fake.states[0].URL != "https://grok.com/?ref=signup" {
		t.Fatalf("handoff returned before consuming the redirect chain: %+v", fake.states)
	}
}

func TestWaitGrokHandoffDegradesToBestEffortOnTimeout(t *testing.T) {
	fake := &fakeMCPRPC{states: []mcpPageState{{URL: "https://accounts.x.ai/sign-up"}}}
	browser := NewMCPBrowser(MCPBrowserOptions{Incognito: true})
	// A missed redirect must not discard an otherwise good registration.
	action, err := browser.waitGrokHandoff(context.Background(), fake, "7", mcpHandoffPlan{
		Timeout: 50 * time.Millisecond,
		Poll:    time.Millisecond,
		Settle:  time.Millisecond,
	})
	if err != nil || action != "handoff:timeout" {
		t.Fatalf("waitGrokHandoff() = %q, err=%v", action, err)
	}
}

func TestGrokHandoffURLDetection(t *testing.T) {
	for _, url := range []string{"https://grok.com/", "https://grok.com/?ref=signup", "https://www.grok.com/chat"} {
		if !isGrokHandoffURL(url) {
			t.Fatalf("grok.com landing not detected: %q", url)
		}
	}
	for _, url := range []string{"", "about:blank", "https://accounts.x.ai/sign-up", "https://notgrok.com/", "https://grok.com.evil.test/"} {
		if isGrokHandoffURL(url) {
			t.Fatalf("non-handoff URL treated as grok.com: %q", url)
		}
	}
}

func TestOAuthApprovalClickDetection(t *testing.T) {
	for _, label := range []string{"Authorize", "Allow access", "Approve", "授权", "允许"} {
		if !isOAuthApprovalClick(label, false) {
			t.Fatalf("approval label not detected: %q", label)
		}
	}
	if !isOAuthApprovalClick("Continue", true) {
		t.Fatal("consent-page Continue should count as approval submission")
	}
	if isOAuthApprovalClick("Continue", false) {
		t.Fatal("login-page Continue must not count as approval submission")
	}
}
