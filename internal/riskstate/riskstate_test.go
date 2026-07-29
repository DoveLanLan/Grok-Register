package riskstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryPersistsInvalidGrantPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-grants.json")
	registry, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	err = registry.RecordInvalidGrant(InvalidGrantRecord{
		DiagnosticID: "diag-1",
		Email:        "Person@Example.COM",
		MailboxKind:  "cftemp",
		IP:           "203.0.113.9",
		ASN:          64512,
		Proxy:        "p.webshare.io:80",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.EmailBlocked("person@example.com") || !reloaded.IPBlocked("203.0.113.9") || !reloaded.FallbackToOutlook() {
		t.Fatal("persisted risk markers were not restored")
	}
	emails, ips, records := reloaded.Counts()
	if emails != 1 || ips != 1 || records != 1 {
		t.Fatalf("counts = %d/%d/%d", emails, ips, records)
	}
}

func TestOpenTightensExistingStatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-grants.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"blocked_emails":{},"blocked_ips":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}
