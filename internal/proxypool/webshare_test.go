package proxypool

import (
	"net/url"
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

func TestWebshareSessionsRotateEntryGateways(t *testing.T) {
	sessions, err := NewWebshareSessionsWithGateways(
		"socks5h://customer-{session}:secret@original.example:80",
		"192.0.2.10,192.0.2.11:1080",
	)
	if err != nil {
		t.Fatal(err)
	}
	for index, expectedHost := range []string{"192.0.2.10:80", "192.0.2.11:1080", "192.0.2.10:80"} {
		raw, sessionID, nextErr := sessions.Next()
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if parsed.Host != expectedHost {
			t.Fatalf("item %d host=%q, want %q", index, parsed.Host, expectedHost)
		}
		if parsed.User == nil || !strings.Contains(parsed.User.Username(), sessionID) {
			t.Fatalf("item %d did not preserve expanded session username", index)
		}
	}
	if got := sessions.Label(); got != "192.0.2.10:80 (+1 gateways)" {
		t.Fatalf("label=%q", got)
	}
}

func TestWebshareSessionsRequirePlaceholder(t *testing.T) {
	if _, err := NewWebshareSessions("http://customer:password@p.webshare.io:80"); err == nil {
		t.Fatal("missing {session} should fail")
	}
}
