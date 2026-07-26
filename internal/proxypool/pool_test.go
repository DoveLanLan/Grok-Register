package proxypool

import "testing"

func TestParseListAndLabel(t *testing.T) {
	list := ParseList("http://u:p@a:1\nhttp://b:2, http://c:3")
	if len(list) != 3 {
		t.Fatalf("len=%d %v", len(list), list)
	}
	if Label("http://user:pass@1.2.3.4:8080") != "1.2.3.4:8080" {
		t.Fatalf("label=%s", Label("http://user:pass@1.2.3.4:8080"))
	}
	p := New(Options{Proxies: list, Cooldown: 0})
	if p.Len() != 3 {
		t.Fatalf("pool len %d", p.Len())
	}
	a := p.Next()
	b := p.Next()
	if a == "" || b == "" || a == b {
		// with 3 items round-robin should differ for first two
		t.Fatalf("next a=%q b=%q", a, b)
	}
}
