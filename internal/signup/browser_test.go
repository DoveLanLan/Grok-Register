package signup

import (
	"testing"

	"github.com/grok-free-register/grok-reg/internal/egress"
)

func TestBrowserAttemptSettings(t *testing.T) {
	browser := NewBrowser(BrowserOptions{})
	browser.SetProxy("  http://proxy.example:8080  ")
	browser.SetDiagnosticDir("  /tmp/grok-attempt-123  ")
	browser.SetEgress(egress.Profile{IP: "203.0.113.8", ASN: 64512, Timezone: "America/Los_Angeles"})

	if got := browser.Proxy(); got != "http://proxy.example:8080" {
		t.Fatalf("Proxy() = %q", got)
	}
	if got := browser.DiagnosticDir(); got != "/tmp/grok-attempt-123" {
		t.Fatalf("DiagnosticDir() = %q", got)
	}
}

func TestCamoufoxBrowserMode(t *testing.T) {
	browser := NewCamoufoxBrowser(BrowserOptions{})
	if browser.Name() != "camoufox-signup" || browser.opt.Engine != "camoufox" {
		t.Fatalf("browser = name=%q engine=%q", browser.Name(), browser.opt.Engine)
	}
}
