package signup

import "testing"

func TestBrowserAttemptSettings(t *testing.T) {
	browser := NewBrowser(BrowserOptions{})
	browser.SetProxy("  http://proxy.example:8080  ")
	browser.SetDiagnosticDir("  /tmp/grok-attempt-123  ")

	if got := browser.Proxy(); got != "http://proxy.example:8080" {
		t.Fatalf("Proxy() = %q", got)
	}
	if got := browser.DiagnosticDir(); got != "/tmp/grok-attempt-123" {
		t.Fatalf("DiagnosticDir() = %q", got)
	}
}
