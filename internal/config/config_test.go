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
