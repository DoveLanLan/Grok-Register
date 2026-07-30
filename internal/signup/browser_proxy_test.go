package signup

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestBridgeBrowserProxyPassesHTTPThrough(t *testing.T) {
	t.Parallel()
	const raw = "http://user:pass@proxy.example:8080"
	got, bridge, err := bridgeBrowserProxy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != raw || bridge != nil {
		t.Fatalf("got=%q bridge=%v", got, bridge)
	}
}

func TestBridgeBrowserProxyWrapsAuthenticatedSOCKS5(t *testing.T) {
	t.Parallel()
	got, bridge, err := bridgeBrowserProxy("socks5h://user:pass@127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if bridge == nil {
		t.Fatal("SOCKS5 proxy was not bridged")
	}
	defer bridge.Close()
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "http" || parsed.User != nil {
		t.Fatalf("unsafe bridge URL: %s", got)
	}
	if ip := net.ParseIP(parsed.Hostname()); ip == nil || !ip.IsLoopback() {
		t.Fatalf("bridge is not loopback-only: %s", got)
	}
	if strings.Contains(got, "user") || strings.Contains(got, "pass") {
		t.Fatalf("bridge URL leaked credentials: %s", got)
	}
}
