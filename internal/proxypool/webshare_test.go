package proxypool

import (
	"strings"
	"testing"
)

func TestWebshareSessionsExpandUniqueCredentialWithoutLeakingLabel(t *testing.T) {
	sessions, err := NewWebshareSessions("http://customer-{session}:super-secret@p.webshare.io:80")
	if err != nil {
		t.Fatal(err)
	}
	first, firstID, err := sessions.Next()
	if err != nil {
		t.Fatal(err)
	}
	second, secondID, err := sessions.Next()
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID || first == second || strings.Contains(first, "{session}") {
		t.Fatalf("sessions were not expanded uniquely: %q %q", firstID, secondID)
	}
	if got := sessions.Label(); got != "p.webshare.io:80" || strings.Contains(got, "secret") {
		t.Fatalf("label = %q", got)
	}
}

func TestWebshareSessionsRequirePlaceholder(t *testing.T) {
	if _, err := NewWebshareSessions("http://customer:password@p.webshare.io:80"); err == nil {
		t.Fatal("missing {session} should fail")
	}
}
