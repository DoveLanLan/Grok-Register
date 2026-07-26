package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/turnstile"
)

type browserApproval struct {
	Flow     DeviceFlow
	SSO      string
	Email    string
	Password string
}

type deviceBrowserApprover interface {
	Approve(context.Context, browserApproval) error
	Name() string
}

type cloakBrowserApprover struct {
	python        string
	script        string
	proxy         string
	chrome        string
	timeout       time.Duration
	diagnosticDir string
	tracef        func(string, ...any)
}

type browserInput struct {
	VerificationURL string  `json:"verification_url"`
	SSO             string  `json:"sso"`
	Email           string  `json:"email,omitempty"`
	Password        string  `json:"password,omitempty"`
	Proxy           string  `json:"proxy,omitempty"`
	Chrome          string  `json:"chrome,omitempty"`
	TimeoutSec      float64 `json:"timeout_sec"`
	Headless        bool    `json:"headless"`
	DiagnosticDir   string  `json:"diagnostic_dir,omitempty"`
	CaptureSuccess  bool    `json:"capture_success,omitempty"`
}

type browserResult struct {
	OK         bool     `json:"ok"`
	Stage      string   `json:"stage"`
	URL        string   `json:"url"`
	Title      string   `json:"title"`
	Actions    []string `json:"actions"`
	Screenshot string   `json:"screenshot"`
	Error      string   `json:"error"`
}

func newCloakBrowserApprover(proxy string, opt Options) *cloakBrowserApprover {
	timeout := opt.BrowserTimeout
	if timeout <= 0 {
		timeout = 150 * time.Second
	}
	return &cloakBrowserApprover{
		python:        turnstile.DetectedPython(),
		script:        findOAuthBrowserScript(),
		proxy:         proxy,
		chrome:        strings.TrimSpace(os.Getenv("CHROME_PATH")),
		timeout:       timeout,
		diagnosticDir: strings.TrimSpace(opt.BrowserDiagnosticDir),
		tracef:        opt.Tracef,
	}
}

func (a *cloakBrowserApprover) Name() string { return "cloakbrowser" }

func (a *cloakBrowserApprover) Approve(ctx context.Context, approval browserApproval) error {
	if a.python == "" {
		return fmt.Errorf("oauth_browser_unavailable: Python not found (set GROK_PYTHON)")
	}
	if a.script == "" {
		return fmt.Errorf("oauth_browser_unavailable: oauth_approve.py not found (set GROK_OAUTH_BROWSER_SCRIPT)")
	}
	if approval.Flow.VerificationURL == "" {
		return fmt.Errorf("oauth_browser_invalid_flow: missing verification URL")
	}
	if a.diagnosticDir != "" {
		if err := os.MkdirAll(a.diagnosticDir, 0o700); err != nil {
			return fmt.Errorf("oauth_browser_diagnostic_dir: %w", err)
		}
		_ = os.Chmod(a.diagnosticDir, 0o700)
	}

	// Same display policy as signup: default = xvfb virtual (no focus steal).
	// GROK_OAUTH_BROWSER_HEADLESS=1 -> pure headless
	// GROK_OAUTH_BROWSER_HEADED=1   -> real desktop window
	commandName := a.python
	commandArgs := []string{a.script, "--stdin-json"}
	headless, commandName, commandArgs := resolveOAuthBrowserDisplay(commandName, commandArgs, oauthDisplayMode())

	payload, err := json.Marshal(browserInput{
		VerificationURL: approval.Flow.VerificationURL,
		SSO:             approval.SSO,
		Email:           approval.Email,
		Password:        approval.Password,
		Proxy:           a.proxy,
		Chrome:          a.chrome,
		TimeoutSec:      a.timeout.Seconds(),
		Headless:        headless,
		DiagnosticDir:   a.diagnosticDir,
		CaptureSuccess:  browserCaptureSuccess(),
	})
	if err != nil {
		return fmt.Errorf("oauth_browser_config: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, a.timeout+15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, commandName, commandArgs...)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(os.Environ(), "CLOAKBROWSER_SUPPRESS_FONT_WARNING=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var result browserResult
	decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result)
	if runCtx.Err() != nil {
		return fmt.Errorf("oauth_browser_timeout after %s", a.timeout)
	}
	if decodeErr != nil {
		detail := safeBrowserText(stderr.String(), 240)
		if detail == "" && runErr != nil {
			detail = safeBrowserText(runErr.Error(), 120)
		}
		return fmt.Errorf("oauth_browser_protocol: invalid result (%s)", detail)
	}
	if result.OK && runErr == nil {
		if a.tracef != nil {
			a.tracef(
				"OAuth browser approved stage=%s url=%s actions=%s",
				safeBrowserText(result.Stage, 40),
				safeLocation(result.URL),
				safeBrowserText(strings.Join(result.Actions, " → "), 160),
			)
			if result.Screenshot != "" {
				a.tracef("OAuth browser diagnostic screenshot=%s", safeBrowserText(result.Screenshot, 200))
			}
		}
		return nil
	}
	parts := []string{"oauth_browser_failed"}
	if result.Stage != "" {
		parts = append(parts, "stage="+safeBrowserText(result.Stage, 40))
	}
	if result.URL != "" {
		parts = append(parts, "url="+safeLocation(result.URL))
	}
	if result.Title != "" {
		parts = append(parts, "title="+safeBrowserText(result.Title, 80))
	}
	if result.Error != "" {
		parts = append(parts, "error="+safeBrowserText(result.Error, 180))
	}
	if len(result.Actions) > 0 {
		parts = append(parts, "actions="+safeBrowserText(strings.Join(result.Actions, " → "), 160))
	}
	if result.Screenshot != "" {
		parts = append(parts, "screenshot="+safeBrowserText(result.Screenshot, 200))
	}
	return fmt.Errorf("%s", strings.Join(parts, " "))
}

func oauthDisplayMode() displayModeOAuth {
	if envTruthyOAuth("GROK_OAUTH_BROWSER_HEADLESS") {
		return displayOAuthHeadless
	}
	if envTruthyOAuth("GROK_OAUTH_BROWSER_HEADED") {
		return displayOAuthReal
	}
	if envFalseyOAuth("GROK_OAUTH_BROWSER_HEADLESS") && hasDisplay() {
		return displayOAuthReal
	}
	return displayOAuthVirtual
}

type displayModeOAuth string

const (
	displayOAuthHeadless displayModeOAuth = "headless"
	displayOAuthVirtual  displayModeOAuth = "virtual"
	displayOAuthReal     displayModeOAuth = "real"
)

func resolveOAuthBrowserDisplay(python string, scriptArgs []string, mode displayModeOAuth) (headless bool, commandName string, commandArgs []string) {
	commandName = python
	commandArgs = append([]string{}, scriptArgs...)
	switch mode {
	case displayOAuthReal:
		if hasDisplay() {
			return false, commandName, commandArgs
		}
		fallthrough
	case displayOAuthVirtual:
		if xvfb, err := exec.LookPath("xvfb-run"); err == nil {
			return false, xvfb, append([]string{"-a", python}, scriptArgs...)
		}
		return true, commandName, commandArgs
	default:
		return true, commandName, commandArgs
	}
}

func envTruthyOAuth(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envFalseyOAuth(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "0" || value == "false" || value == "no" || value == "off"
}

func browserHeadlessForced() bool {
	return envTruthyOAuth("GROK_OAUTH_BROWSER_HEADLESS")
}

func browserCaptureSuccess() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("GROK_OAUTH_BROWSER_CAPTURE_SUCCESS")))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func hasDisplay() bool {
	return strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != ""
}

func findOAuthBrowserScript() string {
	if configured := strings.TrimSpace(os.Getenv("GROK_OAUTH_BROWSER_SCRIPT")); fileExists(configured) {
		return configured
	}
	var candidates []string
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "oauth_approve.py"),
			filepath.Join(dir, "oauth_approve.py"),
			filepath.Join(dir, "..", "scripts", "oauth_approve.py"),
		)
	}
	if workdir, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(workdir, "scripts", "oauth_approve.py"),
			filepath.Join(workdir, "Grok-Register", "scripts", "oauth_approve.py"),
		)
	}
	candidates = append(candidates,
		"/opt/Grok-Register/scripts/oauth_approve.py",
		"/usr/local/share/grok-reg/oauth_approve.py",
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

func safeBrowserText(value string, limit int) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
