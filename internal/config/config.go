package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type EmailMode string

const (
	EmailTempmail EmailMode = "tempmail"
	EmailCustom   EmailMode = "custom"
	// EmailCFTemp connects to a self-hosted dreamhunter2333/cloudflare_temp_email Worker.
	EmailCFTemp EmailMode = "cf_temp_email"
	// EmailOutlook uses imported Microsoft mailboxes and their plus-address aliases.
	EmailOutlook EmailMode = "outlook"
)

type Config struct {
	EmailMode   EmailMode
	EmailDomain string
	EmailAPI    string

	CFTempEmailAPI    string
	CFTempEmailAdmin  string
	CFTempEmailDomain string
	CFTempEmailAuth   string
	CFTempEmailPrefix bool

	OutlookAccountsFile      string
	OutlookStateFile         string
	OutlookAliasesPerAccount int
	OutlookPollIntervalSec   float64

	ClearanceEnabled bool
	RegisterProxy    string
	// RegisterProxies is a comma/newline list of HTTP proxies for rotation.
	// When set, browser signup picks the next healthy proxy per attempt.
	RegisterProxies string
	FlareSolverrURL string
	ClearanceProxy  string
	ClearanceURLs   string

	Target      int
	PhysicalCap int

	TurnstileProvider string
	LiteSolverURL     string

	// RegisterMode: browser (CloakBrowser), browser-mcp (real user Chrome), or http (legacy).
	RegisterMode string
	// BrowserMCPCommand is the browser-mcp JSONL CLI executable. Incognito keeps
	// cleanup scoped away from the normal profile; the driver also clears the
	// account domains in that Incognito cookie store before and after each run.
	BrowserMCPCommand   string
	BrowserMCPIncognito bool

	ProtocolHTTP bool
	HTTPPoolSize int

	TempmailLOLRetries    int
	TempmailLOLIntervalMS int

	OAuthWorkers            int
	OAuthMinIntervalSec     float64
	OAuthRetrySec           float64
	OAuthFlowRetries        int
	OAuthRetryDelaySec      float64
	OAuthInvalidGrantLimit  int
	OAuthConfirmMode        string
	OAuthBrowserTimeoutSec  float64
	SignupBrowserTimeoutSec float64
	// Browser signup pacing: min gap between attempts; longer after rate-limit.
	SignupMinIntervalSec      float64
	SignupRateLimitBackoffSec float64
	ProbeEnabled              bool

	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string

	// CPA Management upload
	CPAUploadEnabled      bool
	CPAManagementBase     string
	CPAManagementKey      string
	CPAUploadTimeoutSec   int
	CPAUploadRetries      int
	CPAUploadNameTemplate string
	CPAUploadVerify       bool
	CPAUploadMode         string // multipart | json
}

func Defaults() Config {
	return Config{
		EmailMode:                 EmailTempmail,
		EmailAPI:                  "http://127.0.0.1:8080",
		CFTempEmailPrefix:         true,
		OutlookAliasesPerAccount:  5,
		OutlookPollIntervalSec:    5,
		ClearanceEnabled:          true,
		RegisterProxy:             "http://127.0.0.1:40080",
		FlareSolverrURL:           "http://127.0.0.1:8191",
		ClearanceProxy:            "http://privoxy:8118",
		ClearanceURLs:             "https://accounts.x.ai,https://x.ai,https://status.x.ai,https://console.x.ai,https://auth.x.ai",
		Target:                    10,
		PhysicalCap:               0,
		TurnstileProvider:         "browser",
		LiteSolverURL:             "http://127.0.0.1:5072",
		RegisterMode:              "browser",
		BrowserMCPCommand:         "browser-mcp-cli",
		BrowserMCPIncognito:       true,
		ProtocolHTTP:              true,
		HTTPPoolSize:              8,
		TempmailLOLRetries:        30,
		TempmailLOLIntervalMS:     1500,
		OAuthWorkers:              1,
		OAuthMinIntervalSec:       15,
		OAuthRetrySec:             60,
		OAuthFlowRetries:          0,
		OAuthRetryDelaySec:        30,
		OAuthInvalidGrantLimit:    3,
		OAuthConfirmMode:          "browser",
		OAuthBrowserTimeoutSec:    150,
		SignupBrowserTimeoutSec:   180,
		SignupMinIntervalSec:      35,
		SignupRateLimitBackoffSec: 90,
		ProbeEnabled:              true,
		HTTPProxy:                 "http://127.0.0.1:40080",
		HTTPSProxy:                "http://127.0.0.1:40080",
		NoProxy:                   "127.0.0.1,localhost",
		CPAUploadEnabled:          false,
		CPAManagementBase:         "http://localhost:8317/v0/management",
		CPAUploadTimeoutSec:       30,
		CPAUploadRetries:          2,
		CPAUploadNameTemplate:     "{email}.json",
		CPAUploadVerify:           true,
		CPAUploadMode:             "multipart",
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	env := parseEnvFile(string(data))
	applyMap(&cfg, env)
	return cfg, nil
}

func Save(path string, cfg Config) error {
	var b strings.Builder
	b.WriteString("# grok-reg config\n")
	b.WriteString(fmt.Sprintf("EMAIL_MODE=%s\n", cfg.EmailMode))
	if cfg.EmailDomain != "" {
		b.WriteString(fmt.Sprintf("EMAIL_DOMAIN=%s\n", cfg.EmailDomain))
	}
	if cfg.EmailAPI != "" {
		b.WriteString(fmt.Sprintf("EMAIL_API=%s\n", cfg.EmailAPI))
	}
	if cfg.CFTempEmailAPI != "" {
		b.WriteString(fmt.Sprintf("CF_TEMP_EMAIL_API=%s\n", cfg.CFTempEmailAPI))
	}
	if cfg.CFTempEmailDomain != "" {
		b.WriteString(fmt.Sprintf("CF_TEMP_EMAIL_DOMAIN=%s\n", cfg.CFTempEmailDomain))
	}
	b.WriteString(fmt.Sprintf("CF_TEMP_EMAIL_PREFIX=%s\n", bool01(cfg.CFTempEmailPrefix)))
	if cfg.OutlookAccountsFile != "" {
		b.WriteString(fmt.Sprintf("OUTLOOK_ACCOUNTS_FILE=%s\n", cfg.OutlookAccountsFile))
	}
	if cfg.OutlookStateFile != "" {
		b.WriteString(fmt.Sprintf("OUTLOOK_STATE_FILE=%s\n", cfg.OutlookStateFile))
	}
	b.WriteString(fmt.Sprintf("OUTLOOK_ALIASES_PER_ACCOUNT=%d\n", cfg.OutlookAliasesPerAccount))
	b.WriteString(fmt.Sprintf("OUTLOOK_POLL_INTERVAL_SEC=%g\n", cfg.OutlookPollIntervalSec))
	b.WriteString(fmt.Sprintf("CLEARANCE_ENABLED=%s\n", bool01(cfg.ClearanceEnabled)))
	b.WriteString(fmt.Sprintf("REGISTER_PROXY=%s\n", cfg.RegisterProxy))
	b.WriteString(fmt.Sprintf("REGISTER_PROXIES=%s\n", cfg.RegisterProxies))
	b.WriteString(fmt.Sprintf("FLARESOLVERR_URL=%s\n", cfg.FlareSolverrURL))
	b.WriteString(fmt.Sprintf("CLEARANCE_PROXY=%s\n", cfg.ClearanceProxy))
	b.WriteString(fmt.Sprintf("CLEARANCE_URLS=%s\n", cfg.ClearanceURLs))
	b.WriteString(fmt.Sprintf("TURNSTILE_PROVIDER=%s\n", cfg.TurnstileProvider))
	if cfg.LiteSolverURL != "" {
		b.WriteString(fmt.Sprintf("LITE_SOLVER_URL=%s\n", cfg.LiteSolverURL))
	}
	b.WriteString(fmt.Sprintf("REGISTER_MODE=%s\n", cfg.RegisterMode))
	b.WriteString(fmt.Sprintf("BROWSER_MCP_CLI=%s\n", cfg.BrowserMCPCommand))
	b.WriteString(fmt.Sprintf("BROWSER_MCP_INCOGNITO=%s\n", bool01(cfg.BrowserMCPIncognito)))
	b.WriteString(fmt.Sprintf("PROTOCOL_HTTP=%s\n", bool01(cfg.ProtocolHTTP)))
	b.WriteString(fmt.Sprintf("HTTP_POOL_SIZE=%d\n", cfg.HTTPPoolSize))
	b.WriteString(fmt.Sprintf("TEMPMAIL_LOL_RETRIES=%d\n", cfg.TempmailLOLRetries))
	b.WriteString(fmt.Sprintf("TEMPMAIL_LOL_MIN_INTERVAL_MS=%d\n", cfg.TempmailLOLIntervalMS))
	b.WriteString(fmt.Sprintf("OAUTH_WORKERS=%d\n", cfg.OAuthWorkers))
	b.WriteString(fmt.Sprintf("OAUTH_MIN_INTERVAL_SEC=%g\n", cfg.OAuthMinIntervalSec))
	b.WriteString(fmt.Sprintf("OAUTH_RETRY_SEC=%g\n", cfg.OAuthRetrySec))
	b.WriteString(fmt.Sprintf("OAUTH_FLOW_RETRIES=%d\n", cfg.OAuthFlowRetries))
	b.WriteString(fmt.Sprintf("OAUTH_RETRY_DELAY_SEC=%g\n", cfg.OAuthRetryDelaySec))
	b.WriteString(fmt.Sprintf("OAUTH_INVALID_GRANT_LIMIT=%d\n", cfg.OAuthInvalidGrantLimit))
	b.WriteString(fmt.Sprintf("OAUTH_CONFIRM_MODE=%s\n", cfg.OAuthConfirmMode))
	b.WriteString(fmt.Sprintf("OAUTH_BROWSER_TIMEOUT_SEC=%g\n", cfg.OAuthBrowserTimeoutSec))
	b.WriteString(fmt.Sprintf("SIGNUP_BROWSER_TIMEOUT_SEC=%g\n", cfg.SignupBrowserTimeoutSec))
	b.WriteString(fmt.Sprintf("SIGNUP_MIN_INTERVAL_SEC=%g\n", cfg.SignupMinIntervalSec))
	b.WriteString(fmt.Sprintf("SIGNUP_RATE_LIMIT_BACKOFF_SEC=%g\n", cfg.SignupRateLimitBackoffSec))
	b.WriteString(fmt.Sprintf("HTTPS_PROXY=%s\n", cfg.HTTPSProxy))
	b.WriteString(fmt.Sprintf("HTTP_PROXY=%s\n", cfg.HTTPProxy))
	b.WriteString(fmt.Sprintf("NO_PROXY=%s\n", cfg.NoProxy))
	b.WriteString(fmt.Sprintf("PROBE_ENABLED=%s\n", bool01(cfg.ProbeEnabled)))
	b.WriteString(fmt.Sprintf("PHYSICAL_CAP=%d\n", cfg.PhysicalCap))
	b.WriteString(fmt.Sprintf("CPA_UPLOAD_ENABLED=%s\n", bool01(cfg.CPAUploadEnabled)))
	b.WriteString(fmt.Sprintf("CPA_MANAGEMENT_BASE=%s\n", cfg.CPAManagementBase))
	// CPA_MANAGEMENT_KEY: never auto-written (set manually in config.env)
	b.WriteString(fmt.Sprintf("CPA_UPLOAD_TIMEOUT_SEC=%d\n", cfg.CPAUploadTimeoutSec))
	b.WriteString(fmt.Sprintf("CPA_UPLOAD_RETRIES=%d\n", cfg.CPAUploadRetries))
	b.WriteString(fmt.Sprintf("CPA_UPLOAD_NAME_TEMPLATE=%s\n", cfg.CPAUploadNameTemplate))
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func InteractiveSetup(path string) (Config, error) {
	cfg := Defaults()
	fmt.Println()
	fmt.Println("选择邮箱模式:")
	fmt.Println("  [1] 免费临时邮箱           (默认 · 零配置 · 直接回车)")
	fmt.Println("  [2] 自建域名邮箱 webhook   (需 Cloudflare Email Routing + 本地 webhook)")
	fmt.Println("  [3] cloudflare_temp_email  (自建 Worker API)")
	fmt.Println("  [4] Outlook 别名池          (先用 grok outlook import 导入账号)")
	fmt.Print("输入 1 / 2 / 3 / 4 [1]: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "2" {
		cfg.EmailMode = EmailCustom
		fmt.Print("  你的域名 (如 example.com): ")
		dom, _ := reader.ReadString('\n')
		cfg.EmailDomain = strings.TrimSpace(dom)
		fmt.Print("  webhook 地址 [http://127.0.0.1:8080]: ")
		api, _ := reader.ReadString('\n')
		api = strings.TrimSpace(api)
		if api == "" {
			api = "http://127.0.0.1:8080"
		}
		cfg.EmailAPI = api
	} else if line == "3" {
		cfg.EmailMode = EmailCFTemp
		fmt.Print("  Worker API 根地址 (如 https://mail-api.example.com): ")
		api, _ := reader.ReadString('\n')
		cfg.CFTempEmailAPI = strings.TrimRight(strings.TrimSpace(api), "/")
		fmt.Print("  固定邮箱域名 (如 example.com): ")
		dom, _ := reader.ReadString('\n')
		cfg.CFTempEmailDomain = strings.TrimSpace(dom)
		fmt.Print("  Admin 密钥 (公共建号已启用可留空): ")
		admin, _ := reader.ReadString('\n')
		cfg.CFTempEmailAdmin = strings.TrimSpace(admin)
	} else if line == "4" {
		cfg.EmailMode = EmailOutlook
		fmt.Print("  每个主邮箱生成几个随机 plus-tag 地址 [5]: ")
		aliases, _ := reader.ReadString('\n')
		if n, err := strconv.Atoi(strings.TrimSpace(aliases)); err == nil && n > 0 {
			cfg.OutlookAliasesPerAccount = n
		}
	} else {
		cfg.EmailMode = EmailTempmail
	}
	if err := Save(path, cfg); err != nil {
		return cfg, err
	}
	fmt.Printf("[*] 已写入 %s\n", path)
	return cfg, nil
}

func ClampTarget(n int) (int, error) {
	if n < 1 {
		return 0, fmt.Errorf("target must be >= 1, got %d", n)
	}
	if n > 10000 {
		return 0, fmt.Errorf("target max is 10000, got %d", n)
	}
	return n, nil
}

func parseEnvFile(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		v = strings.Trim(v, `"'`)
		out[k] = v
	}
	return out
}

func applyMap(cfg *Config, env map[string]string) {
	if v, ok := env["EMAIL_MODE"]; ok {
		mode := strings.ToLower(strings.TrimSpace(v))
		switch mode {
		case "cf_temp", "cf-temp", "cftemp", "cloudflare_temp_email", "cloudflare-temp-email":
			cfg.EmailMode = EmailCFTemp
		case "outlook", "hotmail", "microsoft", "ms":
			cfg.EmailMode = EmailOutlook
		default:
			cfg.EmailMode = EmailMode(mode)
		}
	}
	if v, ok := env["EMAIL_DOMAIN"]; ok {
		cfg.EmailDomain = v
	}
	if v, ok := env["EMAIL_API"]; ok {
		cfg.EmailAPI = v
	}
	if v, ok := env["CF_TEMP_EMAIL_API"]; ok {
		cfg.CFTempEmailAPI = strings.TrimRight(strings.TrimSpace(v), "/")
	} else if v, ok := env["CFTEMP_API"]; ok {
		cfg.CFTempEmailAPI = strings.TrimRight(strings.TrimSpace(v), "/")
	}
	if v, ok := env["CF_TEMP_EMAIL_ADMIN"]; ok {
		cfg.CFTempEmailAdmin = v
	} else if v, ok := env["CFTEMP_ADMIN"]; ok {
		cfg.CFTempEmailAdmin = v
	}
	if v, ok := env["CF_TEMP_EMAIL_DOMAIN"]; ok {
		cfg.CFTempEmailDomain = strings.TrimSpace(v)
	} else if v, ok := env["CFTEMP_DOMAIN"]; ok {
		cfg.CFTempEmailDomain = strings.TrimSpace(v)
	}
	if v, ok := env["CF_TEMP_EMAIL_AUTH"]; ok {
		cfg.CFTempEmailAuth = v
	} else if v, ok := env["CFTEMP_AUTH"]; ok {
		cfg.CFTempEmailAuth = v
	}
	if v, ok := env["CF_TEMP_EMAIL_PREFIX"]; ok {
		cfg.CFTempEmailPrefix = truthy(v)
	}
	if v, ok := env["OUTLOOK_ACCOUNTS_FILE"]; ok {
		cfg.OutlookAccountsFile = strings.TrimSpace(v)
	}
	if v, ok := env["OUTLOOK_STATE_FILE"]; ok {
		cfg.OutlookStateFile = strings.TrimSpace(v)
	}
	if v, ok := env["OUTLOOK_ALIASES_PER_ACCOUNT"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.OutlookAliasesPerAccount = n
		}
	}
	if v, ok := env["OUTLOOK_POLL_INTERVAL_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			cfg.OutlookPollIntervalSec = n
		}
	}
	if v, ok := env["CLEARANCE_ENABLED"]; ok {
		cfg.ClearanceEnabled = truthy(v)
	}
	if v, ok := env["REGISTER_PROXY"]; ok {
		cfg.RegisterProxy = v
	}
	if v, ok := env["REGISTER_PROXIES"]; ok {
		cfg.RegisterProxies = v
	}
	if v, ok := env["FLARESOLVERR_URL"]; ok {
		cfg.FlareSolverrURL = v
	}
	if v, ok := env["CLEARANCE_PROXY"]; ok {
		cfg.ClearanceProxy = v
	}
	if v, ok := env["CLEARANCE_URLS"]; ok {
		cfg.ClearanceURLs = v
	}
	if v, ok := env["TURNSTILE_PROVIDER"]; ok {
		cfg.TurnstileProvider = v
	}
	if v, ok := env["LITE_SOLVER_URL"]; ok {
		cfg.LiteSolverURL = v
	}
	if v, ok := env["REGISTER_MODE"]; ok {
		mode := strings.ToLower(strings.TrimSpace(v))
		switch mode {
		case "browser", "ui", "web":
			cfg.RegisterMode = "browser"
		case "browser-mcp", "browser_mcp", "mcp", "real-browser", "real_chrome":
			cfg.RegisterMode = "browser-mcp"
		case "http", "protocol", "api", "legacy":
			cfg.RegisterMode = "http"
		default:
			if mode != "" {
				cfg.RegisterMode = mode
			}
		}
	}
	if v, ok := env["BROWSER_MCP_CLI"]; ok {
		if command := strings.TrimSpace(v); command != "" {
			cfg.BrowserMCPCommand = command
		}
	}
	if v, ok := env["BROWSER_MCP_INCOGNITO"]; ok {
		cfg.BrowserMCPIncognito = truthy(v)
	}
	if v, ok := env["PROTOCOL_HTTP"]; ok {
		cfg.ProtocolHTTP = truthy(v)
	}
	if v, ok := env["HTTP_POOL_SIZE"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.HTTPPoolSize = n
		}
	}
	if v, ok := env["TEMPMAIL_LOL_RETRIES"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TempmailLOLRetries = n
		}
	}
	if v, ok := env["TEMPMAIL_LOL_MIN_INTERVAL_MS"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TempmailLOLIntervalMS = n
		}
	}
	if v, ok := env["OAUTH_WORKERS"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.OAuthWorkers = n
		}
	}
	if v, ok := env["OAUTH_MIN_INTERVAL_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.OAuthMinIntervalSec = n
		}
	}
	if v, ok := env["OAUTH_RETRY_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.OAuthRetrySec = n
		}
	}
	if v, ok := env["OAUTH_FLOW_RETRIES"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.OAuthFlowRetries = n
		}
	}
	if v, ok := env["OAUTH_RETRY_DELAY_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.OAuthRetryDelaySec = n
		}
	}
	if v, ok := env["OAUTH_INVALID_GRANT_LIMIT"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.OAuthInvalidGrantLimit = n
		}
	}
	if v, ok := env["OAUTH_CONFIRM_MODE"]; ok {
		cfg.OAuthConfirmMode = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := env["OAUTH_BROWSER_TIMEOUT_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.OAuthBrowserTimeoutSec = n
		}
	}
	if v, ok := env["SIGNUP_BROWSER_TIMEOUT_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.SignupBrowserTimeoutSec = n
		}
	}
	if v, ok := env["SIGNUP_MIN_INTERVAL_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.SignupMinIntervalSec = n
		}
	}
	if v, ok := env["SIGNUP_RATE_LIMIT_BACKOFF_SEC"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.SignupRateLimitBackoffSec = n
		}
	}
	if v, ok := env["HTTPS_PROXY"]; ok {
		cfg.HTTPSProxy = v
	}
	if v, ok := env["HTTP_PROXY"]; ok {
		cfg.HTTPProxy = v
	}
	if v, ok := env["NO_PROXY"]; ok {
		cfg.NoProxy = v
	}
	if v, ok := env["PROBE_ENABLED"]; ok {
		cfg.ProbeEnabled = truthy(v)
	}
	if v, ok := env["PHYSICAL_CAP"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PhysicalCap = n
		}
	}
	if v, ok := env["CPA_UPLOAD_ENABLED"]; ok {
		cfg.CPAUploadEnabled = truthy(v)
	}
	if v, ok := env["CPA_MANAGEMENT_BASE"]; ok {
		cfg.CPAManagementBase = v
	}
	if v, ok := env["CPA_MANAGEMENT_KEY"]; ok {
		cfg.CPAManagementKey = v
	}
	if v, ok := env["CPA_UPLOAD_TIMEOUT_SEC"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CPAUploadTimeoutSec = n
		}
	}
	if v, ok := env["CPA_UPLOAD_RETRIES"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CPAUploadRetries = n
		}
	}
	if v, ok := env["CPA_UPLOAD_NAME_TEMPLATE"]; ok {
		cfg.CPAUploadNameTemplate = v
	}
	if v, ok := env["CPA_UPLOAD_VERIFY"]; ok {
		cfg.CPAUploadVerify = truthy(v)
	}
	if v, ok := env["CPA_UPLOAD_MODE"]; ok {
		cfg.CPAUploadMode = v
	}
}

func truthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func bool01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ApplyProxyEnv sets process proxy env for outbound HTTP (tempmail etc).
func ApplyProxyEnv(cfg Config) {
	if cfg.HTTPProxy != "" {
		_ = os.Setenv("HTTP_PROXY", cfg.HTTPProxy)
		_ = os.Setenv("http_proxy", cfg.HTTPProxy)
	}
	if cfg.HTTPSProxy != "" {
		_ = os.Setenv("HTTPS_PROXY", cfg.HTTPSProxy)
		_ = os.Setenv("https_proxy", cfg.HTTPSProxy)
	}
	if cfg.NoProxy != "" {
		_ = os.Setenv("NO_PROXY", cfg.NoProxy)
		_ = os.Setenv("no_proxy", cfg.NoProxy)
	}
}
