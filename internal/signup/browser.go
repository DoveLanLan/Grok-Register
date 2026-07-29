package signup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/grok-free-register/grok-reg/internal/egress"
	"github.com/grok-free-register/grok-reg/internal/turnstile"
)

// BrowserResult is the safe subset returned by scripts/signup_browser.py.
type BrowserResult struct {
	OK              bool            `json:"ok"`
	Stage           string          `json:"stage"`
	SSO             string          `json:"sso"`
	OAuthAuthorized bool            `json:"oauth_authorized"`
	Cookies         []BrowserCookie `json:"cookies"`
	URL             string          `json:"url"`
	Title           string          `json:"title"`
	Actions         []string        `json:"actions"`
	Screenshot      string          `json:"screenshot"`
	Error           string          `json:"error"`
	Email           string          `json:"email"`
	GivenName       string          `json:"given_name"`
	FamilyName      string          `json:"family_name"`
}

// BrowserCookie is a subset of Playwright cookie fields used to rehydrate a
// session for diagnostics / secondary flows.
type BrowserCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite"`
}

// BrowserOptions configures one CloakBrowser or Camoufox signup attempt.
type BrowserOptions struct {
	Proxy                   string
	Engine                  string // chromium (CloakBrowser) or camoufox
	Timeout                 time.Duration
	CodeTimeout             time.Duration
	DiagnosticDir           string
	Chrome                  string
	TurnstileInjectFallback bool
	TurnstileInjectAfter    time.Duration
	Tracef                  func(string, ...any)
}

// Driver is the browser-signup boundary consumed by the pipeline. Both the
// bundled CloakBrowser runner and the browser-mcp real-Chrome driver implement
// it, so mailbox/OAuth/CPA orchestration stays independent of browser control.
type Driver interface {
	Name() string
	SetProxy(string)
	Proxy() string
	SetEgress(egress.Profile)
	SetDiagnosticDir(string)
	DiagnosticDir() string
	Register(context.Context, string, string, string, string, func(context.Context) (string, error)) (BrowserResult, error)
	RegisterWithOAuth(context.Context, string, string, string, string, string, func(context.Context) (string, error)) (BrowserResult, error)
}

// Browser drives accounts.x.ai signup in a real browser so Castle/Turnstile
// tokens are minted by page JS instead of empty HTTP placeholders.
type Browser struct {
	python string
	script string
	opt    BrowserOptions
	egress egress.Profile

	// One signup browser at a time — CloakBrowser + proxy is heavy and serial
	// behaviour matches human-ish traffic better than parallel mints.
	mu sync.Mutex
}

type browserInput struct {
	Email                   string         `json:"email"`
	Password                string         `json:"password"`
	GivenName               string         `json:"given_name,omitempty"`
	FamilyName              string         `json:"family_name,omitempty"`
	Proxy                   string         `json:"proxy,omitempty"`
	Chrome                  string         `json:"chrome,omitempty"`
	TimeoutSec              float64        `json:"timeout_sec"`
	CodeTimeoutSec          float64        `json:"code_timeout_sec"`
	OAuthTimeoutSec         float64        `json:"oauth_timeout_sec,omitempty"`
	CodeFile                string         `json:"code_file,omitempty"`
	Code                    string         `json:"code,omitempty"`
	Headless                bool           `json:"headless"`
	DiagnosticDir           string         `json:"diagnostic_dir,omitempty"`
	URL                     string         `json:"url,omitempty"`
	VerificationURL         string         `json:"verification_url,omitempty"`
	Engine                  string         `json:"engine,omitempty"`
	Egress                  egress.Profile `json:"egress,omitempty"`
	TurnstileInjectFallback bool           `json:"turnstile_inject_fallback,omitempty"`
	TurnstileInjectAfterSec float64        `json:"turnstile_inject_after_sec,omitempty"`
}

func NewBrowser(opt BrowserOptions) *Browser {
	if opt.Timeout <= 0 {
		opt.Timeout = 180 * time.Second
	}
	if opt.CodeTimeout <= 0 {
		opt.CodeTimeout = 100 * time.Second
	}
	if strings.TrimSpace(opt.Engine) == "" {
		opt.Engine = "chromium"
	}
	if opt.TurnstileInjectAfter <= 0 {
		opt.TurnstileInjectAfter = 35 * time.Second
	}
	chrome := strings.TrimSpace(opt.Chrome)
	if chrome == "" {
		chrome = strings.TrimSpace(os.Getenv("CHROME_PATH"))
	}
	opt.Chrome = chrome
	return &Browser{
		python: turnstile.DetectedPython(),
		script: findSignupBrowserScript(),
		opt:    opt,
	}
}

// NewCamoufoxBrowser uses the same audited signup flow with Camoufox as the
// browser engine. It remains opt-in so existing installs without Camoufox keep
// working.
func NewCamoufoxBrowser(opt BrowserOptions) *Browser {
	opt.Engine = "camoufox"
	return NewBrowser(opt)
}

func (b *Browser) Name() string {
	if strings.EqualFold(b.opt.Engine, "camoufox") {
		return "camoufox-signup"
	}
	return "cloakbrowser-signup"
}

// SetProxy updates the proxy used by the next Register call.
// Safe for serial browser workers (phys=1 / c=1).
func (b *Browser) SetProxy(proxy string) {
	b.opt.Proxy = strings.TrimSpace(proxy)
}

// Proxy returns the currently configured proxy URL.
func (b *Browser) Proxy() string { return b.opt.Proxy }

// SetEgress supplies the public identity resolved through Proxy. The Python
// driver uses it to align locale, timezone, geolocation, and WebRTC policy.
func (b *Browser) SetEgress(profile egress.Profile) { b.egress = profile }

// SetDiagnosticDir scopes browser artifacts to the next account attempt.
// Safe for serial browser workers (phys=1 / c=1).
func (b *Browser) SetDiagnosticDir(path string) {
	b.opt.DiagnosticDir = strings.TrimSpace(path)
}

// DiagnosticDir returns the currently configured artifact directory.
func (b *Browser) DiagnosticDir() string { return b.opt.DiagnosticDir }

// Register opens accounts.x.ai, submits email (Castle runs in-page), waits for
// pollCode to return a verification code, completes credentials, and returns SSO.
func (b *Browser) Register(ctx context.Context, email, password, given, family string, pollCode func(context.Context) (string, error)) (BrowserResult, error) {
	return b.RegisterWithOAuth(ctx, email, password, given, family, "", pollCode)
}

// RegisterWithOAuth is Register plus optional same-session Device Flow approval.
// When verificationURL is non-empty the browser navigates to it after signup and
// clicks allow/continue without opening a second profile (manual-like continuity).
func (b *Browser) RegisterWithOAuth(ctx context.Context, email, password, given, family, verificationURL string, pollCode func(context.Context) (string, error)) (BrowserResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.python == "" {
		return BrowserResult{}, fmt.Errorf("signup_browser_unavailable: Python not found (set GROK_PYTHON)")
	}
	if b.script == "" {
		return BrowserResult{}, fmt.Errorf("signup_browser_unavailable: signup_browser.py not found (set GROK_SIGNUP_BROWSER_SCRIPT)")
	}
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return BrowserResult{}, fmt.Errorf("signup_browser_invalid: email/password required")
	}
	if pollCode == nil {
		return BrowserResult{}, fmt.Errorf("signup_browser_invalid: pollCode required")
	}

	workDir, err := os.MkdirTemp("", "grok-signup-*")
	if err != nil {
		return BrowserResult{}, fmt.Errorf("signup_browser_temp: %w", err)
	}
	defer os.RemoveAll(workDir)
	_ = os.Chmod(workDir, 0o700)

	codeFile := filepath.Join(workDir, "code.txt")
	if b.opt.DiagnosticDir != "" {
		_ = os.MkdirAll(b.opt.DiagnosticDir, 0o700)
		_ = os.Chmod(b.opt.DiagnosticDir, 0o700)
	}

	// Poll mailbox only after the browser signals that the code field is visible
	// (code_file.ready). Starting earlier wastes the mailbox poll budget before
	// x.ai has even sent the message.
	pollCtx, cancelPoll := context.WithCancel(ctx)
	defer cancelPoll()
	go func() {
		readyPath := codeFile + ".ready"
		deadline := time.Now().Add(b.opt.Timeout)
		for time.Now().Before(deadline) {
			select {
			case <-pollCtx.Done():
				return
			default:
			}
			if st, err := os.Stat(readyPath); err == nil && !st.IsDir() {
				break
			}
			time.Sleep(400 * time.Millisecond)
		}
		code, err := pollCode(pollCtx)
		if err != nil || strings.TrimSpace(code) == "" {
			return
		}
		code = strings.ToUpper(strings.TrimSpace(code))
		_ = os.WriteFile(codeFile, []byte(code), 0o600)
	}()

	// Display policy (never steal the user's real desktop focus by default):
	//   GROK_SIGNUP_BROWSER_HEADLESS=1  -> pure Chromium headless
	//   GROK_SIGNUP_BROWSER_HEADED=1    -> real DISPLAY window (debug only)
	//   default                        -> xvfb virtual display when available,
	//                                    else pure headless
	commandName := b.python
	commandArgs := []string{b.script, "--stdin-json"}
	headless, commandName, commandArgs := resolveBrowserDisplay(commandName, commandArgs, signupDisplayMode())

	payload, err := json.Marshal(browserInput{
		Email:                   email,
		Password:                password,
		GivenName:               given,
		FamilyName:              family,
		Proxy:                   b.opt.Proxy,
		Chrome:                  b.opt.Chrome,
		TimeoutSec:              b.opt.Timeout.Seconds(),
		CodeTimeoutSec:          b.opt.CodeTimeout.Seconds(),
		OAuthTimeoutSec:         100,
		CodeFile:                codeFile,
		Headless:                headless,
		DiagnosticDir:           b.opt.DiagnosticDir,
		URL:                     "https://accounts.x.ai/sign-up?redirect=grok-com",
		VerificationURL:         strings.TrimSpace(verificationURL),
		Engine:                  strings.ToLower(strings.TrimSpace(b.opt.Engine)),
		Egress:                  b.egress,
		TurnstileInjectFallback: b.opt.TurnstileInjectFallback,
		TurnstileInjectAfterSec: b.opt.TurnstileInjectAfter.Seconds(),
	})
	if err != nil {
		return BrowserResult{}, fmt.Errorf("signup_browser_config: %w", err)
	}

	runBudget := b.opt.Timeout + b.opt.CodeTimeout + 30*time.Second
	if strings.TrimSpace(verificationURL) != "" {
		runBudget += 2 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, runBudget)
	defer cancel()
	cmd := exec.Command(commandName, commandArgs...)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(os.Environ(), "CLOAKBROWSER_SUPPRESS_FONT_WARNING=1")
	// Own process group so we can SIGKILL xvfb-run + Chromium together.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Start()
	if runErr == nil {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case runErr = <-done:
		case <-runCtx.Done():
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			select {
			case runErr = <-done:
			case <-time.After(3 * time.Second):
				runErr = runCtx.Err()
			}
		}
	}
	cancelPoll()

	var result BrowserResult
	decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result)
	if runCtx.Err() != nil {
		// Report the real process budget (Timeout+CodeTimeout+slack[+oauth]), not
		// just TimeoutSec — overnight logs showed ~8m kills while the message said 3m.
		return BrowserResult{}, fmt.Errorf(
			"signup_browser_timeout after %s (budget %s; often turnstile stuck on credentials)",
			b.opt.Timeout.Round(time.Second),
			runBudget.Round(time.Second),
		)
	}
	if decodeErr != nil {
		detail := safeText(stderr.String(), 240)
		if detail == "" && runErr != nil {
			detail = safeText(runErr.Error(), 120)
		}
		return BrowserResult{}, fmt.Errorf("signup_browser_protocol: invalid result (%s)", detail)
	}
	if result.OK && strings.TrimSpace(result.SSO) != "" && runErr == nil {
		if b.opt.Tracef != nil {
			b.opt.Tracef(
				"Signup browser ok stage=%s oauth=%v url=%s actions=%s",
				safeText(result.Stage, 40),
				result.OAuthAuthorized,
				safeText(result.URL, 120),
				safeText(strings.Join(result.Actions, " → "), 160),
			)
		}
		return result, nil
	}
	parts := []string{"signup_browser_failed"}
	if result.Stage != "" {
		parts = append(parts, "stage="+safeText(result.Stage, 40))
	}
	if result.URL != "" {
		parts = append(parts, "url="+safeText(result.URL, 120))
	}
	if result.Title != "" {
		parts = append(parts, "title="+safeText(result.Title, 80))
	}
	if result.Error != "" {
		parts = append(parts, "error="+safeText(result.Error, 180))
	}
	if len(result.Actions) > 0 {
		parts = append(parts, "actions="+safeText(strings.Join(result.Actions, " → "), 160))
	}
	if result.Screenshot != "" {
		parts = append(parts, "screenshot="+safeText(result.Screenshot, 200))
	}
	if result.OK && strings.TrimSpace(result.SSO) == "" {
		parts = append(parts, "error=missing_sso")
	}
	return result, fmt.Errorf("%s", strings.Join(parts, " "))
}

// displayMode selects how Chromium is shown.
// headless = pure --headless (no GUI).
// virtual  = headed Chromium under Xvfb (best anti-detect without focus steal).
// real     = headed on the user's real DISPLAY (steals focus; debug only).
type displayMode string

const (
	displayHeadless displayMode = "headless"
	displayVirtual  displayMode = "virtual"
	displayReal     displayMode = "real"
)

func signupDisplayMode() displayMode {
	// Explicit headed wins only when headless is not forced.
	if envTruthy("GROK_SIGNUP_BROWSER_HEADLESS") {
		return displayHeadless
	}
	if envTruthy("GROK_SIGNUP_BROWSER_HEADED") {
		return displayReal
	}
	// Legacy: HEADLESS=0/false used to mean "show a window". Keep that as real
	// headed only when the user also has a DISPLAY; otherwise fall through.
	if envFalsey("GROK_SIGNUP_BROWSER_HEADLESS") && hasDisplay() {
		return displayReal
	}
	return displayVirtual
}

func resolveBrowserDisplay(python string, scriptArgs []string, mode displayMode) (headless bool, commandName string, commandArgs []string) {
	commandName = python
	commandArgs = append([]string{}, scriptArgs...)
	switch mode {
	case displayReal:
		// Real desktop window — only when the user asked for it.
		if hasDisplay() {
			return false, commandName, commandArgs
		}
		// No DISPLAY: degrade to virtual/headless rather than fail.
		fallthrough
	case displayVirtual:
		if xvfb, err := exec.LookPath("xvfb-run"); err == nil {
			// Headed Chromium on a private X server — no focus steal.
			return false, xvfb, append([]string{"-a", python}, scriptArgs...)
		}
		return true, commandName, commandArgs
	default:
		return true, commandName, commandArgs
	}
}

func envTruthy(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envFalsey(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "0" || value == "false" || value == "no" || value == "off"
}

func hasDisplay() bool {
	return strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != ""
}

func findSignupBrowserScript() string {
	if configured := strings.TrimSpace(os.Getenv("GROK_SIGNUP_BROWSER_SCRIPT")); fileExists(configured) {
		return configured
	}
	var candidates []string
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "signup_browser.py"),
			filepath.Join(dir, "signup_browser.py"),
			filepath.Join(dir, "..", "scripts", "signup_browser.py"),
		)
	}
	if workdir, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(workdir, "scripts", "signup_browser.py"),
			filepath.Join(workdir, "Grok-Register", "scripts", "signup_browser.py"),
		)
	}
	candidates = append(candidates,
		"/opt/Grok-Register/scripts/signup_browser.py",
		"/usr/local/share/grok-reg/signup_browser.py",
	)
	for _, candidate := range candidates {
		if !fileExists(candidate) {
			continue
		}
		if absolute, err := filepath.Abs(candidate); err == nil {
			return absolute
		}
		return candidate
	}
	return ""
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func safeText(value string, limit int) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// DetectedScript exposes the resolved signup script path for startup logs.
func DetectedScript() string { return findSignupBrowserScript() }
