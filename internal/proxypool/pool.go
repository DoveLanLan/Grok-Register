// Package proxypool rotates outbound proxies for browser signup.
// Dead exits (CONNECT reset / auth fail) are cooled down so a single
// bad ISP does not block the whole run when a fallback still works.
package proxypool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Pool is a small round-robin proxy list with health + cooldown.
type Pool struct {
	mu      sync.Mutex
	items   []item
	next    int
	probeTo time.Duration
	cool    time.Duration
	logf    func(string, ...any)
}

type item struct {
	raw       string
	label     string
	fails     int
	successes int
	coolUntil time.Time
	lastErr   string
	healthy   bool
	checked   bool
}

// Options configures a Pool.
type Options struct {
	// Proxies is an ordered list (primary first). Empty entries ignored.
	Proxies []string
	// ProbeTimeout for startup / on-demand health checks.
	ProbeTimeout time.Duration
	// Cooldown after a hard failure before the proxy is tried again.
	Cooldown time.Duration
	// Logf optional debug/info logger.
	Logf func(string, ...any)
}

// New builds a pool. Returns nil if no proxies were provided.
func New(opt Options) *Pool {
	var items []item
	seen := map[string]struct{}{}
	for _, raw := range opt.Proxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		items = append(items, item{raw: raw, label: Label(raw), healthy: true})
	}
	if len(items) == 0 {
		return nil
	}
	to := opt.ProbeTimeout
	if to <= 0 {
		to = 12 * time.Second
	}
	cool := opt.Cooldown
	if cool <= 0 {
		cool = 10 * time.Minute
	}
	return &Pool{items: items, probeTo: to, cool: cool, logf: opt.Logf}
}

// Len returns configured proxy count.
func (p *Pool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.items)
}

// Label redacts userinfo for logs.
func Label(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// host:port or other forms
		if i := strings.LastIndex(raw, "@"); i >= 0 {
			return raw[i+1:]
		}
		return raw
	}
	return u.Host
}

// Snapshot returns "host(healthy/cool)" summaries for logs.
func (p *Pool) Snapshot() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	parts := make([]string, 0, len(p.items))
	now := time.Now()
	for _, it := range p.items {
		state := "ok"
		if !it.checked {
			state = "unprobed"
		} else if !it.healthy {
			state = "bad"
		}
		if now.Before(it.coolUntil) {
			state = fmt.Sprintf("cool%ds", int(it.coolUntil.Sub(now).Seconds()))
		}
		parts = append(parts, fmt.Sprintf("%s(%s,ok=%d,fail=%d)", it.label, state, it.successes, it.fails))
	}
	return strings.Join(parts, ", ")
}

// Primary returns the first configured proxy (may be cooling).
func (p *Pool) Primary() string {
	if p == nil || len(p.items) == 0 {
		return ""
	}
	return p.items[0].raw
}

// ProbeAll checks each proxy against accounts.x.ai (any HTTP response counts as
// reachable — CF 403 is fine; dial/reset/timeout is not).
func (p *Pool) ProbeAll(ctx context.Context) (live int) {
	if p == nil {
		return 0
	}
	for i := range p.items {
		ok, err := p.probeOne(ctx, p.items[i].raw)
		p.mu.Lock()
		p.items[i].checked = true
		p.items[i].healthy = ok
		if ok {
			live++
			p.items[i].lastErr = ""
			if p.logf != nil {
				p.logf("proxy probe ok %s", p.items[i].label)
			}
		} else {
			p.items[i].lastErr = errString(err)
			p.items[i].coolUntil = time.Now().Add(p.cool)
			if p.logf != nil {
				p.logf("proxy probe FAIL %s: %v", p.items[i].label, err)
			}
		}
		p.mu.Unlock()
	}
	return live
}

// Next returns the next usable proxy. If all are cooling, returns the soonest
// available one anyway (better than hard-failing the run).
func (p *Pool) Next() string {
	if p == nil || len(p.items) == 0 {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	n := len(p.items)
	// Prefer healthy & not cooling.
	for i := 0; i < n; i++ {
		idx := (p.next + i) % n
		it := &p.items[idx]
		if now.Before(it.coolUntil) {
			continue
		}
		if it.checked && !it.healthy && it.fails > 0 {
			// skip known-bad until cooldown expires (already handled)
			continue
		}
		p.next = (idx + 1) % n
		return it.raw
	}
	// All cooling: pick least-failed / soonest ready.
	best := 0
	for i := 1; i < n; i++ {
		if p.items[i].coolUntil.Before(p.items[best].coolUntil) {
			best = i
		}
	}
	p.next = (best + 1) % n
	return p.items[best].raw
}

// ReportSuccess clears cooldown for this proxy.
func (p *Pool) ReportSuccess(raw string) {
	if p == nil || raw == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if it := p.find(raw); it != nil {
		it.successes++
		it.healthy = true
		it.checked = true
		it.coolUntil = time.Time{}
		it.lastErr = ""
	}
}

// ReportFailure marks a proxy bad for Cooldown when the error looks like a
// transport/proxy problem (not app-level rate limits).
func (p *Pool) ReportFailure(raw string, err error) {
	if p == nil || raw == "" || err == nil {
		return
	}
	if !isTransportErr(err) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if it := p.find(raw); it != nil {
		it.fails++
		it.healthy = false
		it.checked = true
		it.lastErr = errString(err)
		it.coolUntil = time.Now().Add(p.cool)
		if p.logf != nil {
			p.logf("proxy cooldown %s for %s (%s)", it.label, p.cool, it.lastErr)
		}
	}
}

func (p *Pool) find(raw string) *item {
	for i := range p.items {
		if p.items[i].raw == raw {
			return &p.items[i]
		}
	}
	// match by host label
	want := Label(raw)
	for i := range p.items {
		if p.items[i].label == want {
			return &p.items[i]
		}
	}
	return nil
}

func (p *Pool) probeOne(ctx context.Context, raw string) (bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, err
	}
	if u.Scheme == "" {
		u, err = url.Parse("http://" + raw)
		if err != nil {
			return false, err
		}
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
		DialContext: (&net.Dialer{
			Timeout:   p.probeTo,
			KeepAlive: 0,
		}).DialContext,
		TLSHandshakeTimeout:   p.probeTo,
		ResponseHeaderTimeout: p.probeTo,
		// Don't verify carefully — we only care that the tunnel works.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   p.probeTo,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://accounts.x.ai/sign-up", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; grok-reg-proxy-probe/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	// Any HTTP status means CONNECT + TLS worked.
	return true, nil
}

func isTransportErr(err error) bool {
	msg := strings.ToLower(err.Error())
	keys := []string{
		"proxy",
		"connection reset",
		"connection refused",
		"i/o timeout",
		"timed out",
		"timeout",
		"eof",
		"no such host",
		"tunnel",
		"407",
		"502",
		"503",
		"err_proxy",
		"err_tunnel",
		"err_connection",
		"navigate_failed",
		"net::err_",
		"signup_browser_timeout",
		"turnstile_stuck",
		"turnstile_not_passed",
	}
	for _, k := range keys {
		if strings.Contains(msg, k) {
			return true
		}
	}
	return false
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// ParseList splits comma / semicolon / newline separated proxy URLs.
func ParseList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// normalize separators
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, ";", "\n")
	s = strings.ReplaceAll(s, ",", "\n")
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
