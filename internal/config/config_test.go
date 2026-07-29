package config

import "testing"

func TestCFTempAliasesAndFields(t *testing.T) {
	t.Parallel()
	for _, alias := range []string{"cf_temp_email", "cf_temp", "cf-temp", "cftemp", "cloudflare_temp_email"} {
		cfg := Defaults()
		applyMap(&cfg, map[string]string{
			"EMAIL_MODE":           alias,
			"CF_TEMP_EMAIL_API":    "https://api.example.test/",
			"CF_TEMP_EMAIL_DOMAIN": "example.test",
			"CF_TEMP_EMAIL_PREFIX": "0",
		})
		if cfg.EmailMode != EmailCFTemp {
			t.Fatalf("alias %q produced mode %q", alias, cfg.EmailMode)
		}
		if cfg.CFTempEmailAPI != "https://api.example.test" || cfg.CFTempEmailDomain != "example.test" || cfg.CFTempEmailPrefix {
			t.Fatalf("unexpected config for %q: %+v", alias, cfg)
		}
	}
}

func TestBrowserMCPConfig(t *testing.T) {
	cfg := Defaults()
	applyMap(&cfg, map[string]string{
		"REGISTER_MODE":         "mcp",
		"BROWSER_MCP_CLI":       "/opt/browser-mcp/bin/browser-mcp-cli",
		"BROWSER_MCP_INCOGNITO": "0",
	})
	if cfg.RegisterMode != "browser-mcp" {
		t.Fatalf("RegisterMode = %q", cfg.RegisterMode)
	}
	if cfg.BrowserMCPCommand != "/opt/browser-mcp/bin/browser-mcp-cli" {
		t.Fatalf("BrowserMCPCommand = %q", cfg.BrowserMCPCommand)
	}
	if cfg.BrowserMCPIncognito {
		t.Fatal("BrowserMCPIncognito should honor explicit false")
	}
}

func TestCamoufoxEgressAndTurnstileConfig(t *testing.T) {
	cfg := Defaults()
	applyMap(&cfg, map[string]string{
		"REGISTER_MODE":              "camou",
		"EGRESS_STRICT":              "1",
		"EGRESS_REJECT_HOSTING":      "true",
		"EGRESS_BLOCKED_ASNS":        "AS7922,AS123",
		"EGRESS_BLOCKED_ISPS":        "example cable,bad transit",
		"EGRESS_PROBE_TIMEOUT_SEC":   "9.5",
		"TURNSTILE_INJECT_FALLBACK":  "1",
		"TURNSTILE_INJECT_AFTER_SEC": "42",
		"SIGNUP_MAX_ATTEMPTS":        "3",
	})
	if cfg.RegisterMode != "camoufox" || !cfg.EgressStrict || !cfg.EgressRejectHosting {
		t.Fatalf("unexpected browser/egress config: %+v", cfg)
	}
	if cfg.EgressProbeTimeout != 9.5 || cfg.EgressBlockedASNs == "" || cfg.EgressBlockedISPs == "" {
		t.Fatalf("unexpected egress policy: %+v", cfg)
	}
	if !cfg.TurnstileInjectFallback || cfg.TurnstileInjectAfterSec != 42 || cfg.SignupMaxAttempts != 3 {
		t.Fatalf("unexpected retry/turnstile config: %+v", cfg)
	}
}

func TestOutlookConfigAliasesAndLimits(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"outlook", "hotmail", "microsoft", "ms"} {
		cfg := Defaults()
		applyMap(&cfg, map[string]string{
			"EMAIL_MODE":                  mode,
			"OUTLOOK_ACCOUNTS_FILE":       "/secure/accounts.txt",
			"OUTLOOK_STATE_FILE":          "/secure/state.json",
			"OUTLOOK_ALIASES_PER_ACCOUNT": "8",
			"OUTLOOK_POLL_INTERVAL_SEC":   "2.5",
		})
		if cfg.EmailMode != EmailOutlook || cfg.OutlookAliasesPerAccount != 8 || cfg.OutlookPollIntervalSec != 2.5 {
			t.Fatalf("mode %q produced %+v", mode, cfg)
		}
		if cfg.OutlookAccountsFile != "/secure/accounts.txt" || cfg.OutlookStateFile != "/secure/state.json" {
			t.Fatalf("paths not loaded for %q: %+v", mode, cfg)
		}
	}
}

func TestInvalidGrantFallbackAndWebshareConfig(t *testing.T) {
	cfg := Defaults()
	applyMap(&cfg, map[string]string{
		"EMAIL_INVALID_GRANT_FALLBACK":  "Outlook",
		"INVALID_GRANT_STATE_FILE":      "/secure/invalid-grants.json",
		"REGISTER_PROXY_PROVIDER":       "WebShare",
		"WEBSHARE_PROXY_TEMPLATE":       "http://user-{session}:pass@p.webshare.io:80",
		"WEBSHARE_MAX_SESSION_ATTEMPTS": "12",
	})
	if cfg.EmailInvalidGrantFallback != "outlook" {
		t.Fatalf("EmailInvalidGrantFallback = %q", cfg.EmailInvalidGrantFallback)
	}
	if cfg.InvalidGrantStateFile != "/secure/invalid-grants.json" {
		t.Fatalf("InvalidGrantStateFile = %q", cfg.InvalidGrantStateFile)
	}
	if cfg.RegisterProxyProvider != "webshare" || cfg.WebshareMaxSessionAttempts != 12 {
		t.Fatalf("unexpected Webshare config: %+v", cfg)
	}
	if cfg.WebshareProxyTemplate != "http://user-{session}:pass@p.webshare.io:80" {
		t.Fatalf("WebshareProxyTemplate = %q", cfg.WebshareProxyTemplate)
	}
}

func TestWebshareTemplateSelectsProviderImplicitly(t *testing.T) {
	cfg := Defaults()
	applyMap(&cfg, map[string]string{
		"WEBSHARE_PROXY_TEMPLATE": "http://user-{session}:pass@p.webshare.io:80",
	})
	if cfg.RegisterProxyProvider != "webshare" {
		t.Fatalf("RegisterProxyProvider = %q", cfg.RegisterProxyProvider)
	}
}
