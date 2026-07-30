package proxypool

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

const webshareSessionPlaceholder = "{session}"

// WebshareSessions expands a Webshare proxy URL template into a fresh sticky
// session credential for each account. Example:
// http://username-{session}:password@p.webshare.io:80
type WebshareSessions struct {
	template  string
	gateways  []string
	nextEntry atomic.Uint64
}

func NewWebshareSessions(template string) (*WebshareSessions, error) {
	return NewWebshareSessionsWithGateways(template, "")
}

// NewWebshareSessionsWithGateways adds round-robin entry gateway selection to
// the sticky-session template. Gateway entries may be hostnames/IPs with an
// optional port; a missing port inherits the template port.
func NewWebshareSessionsWithGateways(template, rawGateways string) (*WebshareSessions, error) {
	template = strings.TrimSpace(template)
	if template == "" {
		return nil, fmt.Errorf("WEBSHARE_PROXY_TEMPLATE is required")
	}
	if !strings.Contains(template, webshareSessionPlaceholder) {
		return nil, fmt.Errorf("WEBSHARE_PROXY_TEMPLATE must contain %s", webshareSessionPlaceholder)
	}
	probe := strings.ReplaceAll(template, webshareSessionPlaceholder, "123456789012")
	u, err := url.Parse(probe)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid WEBSHARE_PROXY_TEMPLATE")
	}
	if u.User == nil || strings.TrimSpace(u.User.Username()) == "" {
		return nil, fmt.Errorf("WEBSHARE_PROXY_TEMPLATE must include proxy authentication")
	}
	gateways := make([]string, 0)
	for _, rawGateway := range ParseList(rawGateways) {
		gateway, normalizeErr := normalizeWebshareGateway(rawGateway, u.Port())
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		gateways = append(gateways, gateway)
	}
	return &WebshareSessions{template: template, gateways: gateways}, nil
}

func (w *WebshareSessions) Next() (proxyURL, sessionID string, err error) {
	if w == nil {
		return "", "", fmt.Errorf("Webshare session generator is nil")
	}
	sessionID, err = randomNumericSession(12)
	if err != nil {
		return "", "", err
	}
	expanded := strings.ReplaceAll(w.template, webshareSessionPlaceholder, sessionID)
	if len(w.gateways) > 0 {
		parsed, parseErr := url.Parse(expanded)
		if parseErr != nil {
			return "", "", fmt.Errorf("expand Webshare proxy template: %w", parseErr)
		}
		index := (w.nextEntry.Add(1) - 1) % uint64(len(w.gateways))
		parsed.Host = w.gateways[index]
		expanded = parsed.String()
	}
	return expanded, sessionID, nil
}

func (w *WebshareSessions) Label() string {
	if w == nil {
		return ""
	}
	if len(w.gateways) > 0 {
		return fmt.Sprintf("%s (+%d gateways)", w.gateways[0], len(w.gateways)-1)
	}
	return Label(strings.ReplaceAll(w.template, webshareSessionPlaceholder, "session"))
}

func normalizeWebshareGateway(raw, defaultPort string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("WEBSHARE_GATEWAYS contains an empty gateway")
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" {
			return "", fmt.Errorf("invalid Webshare gateway %q", raw)
		}
		raw = parsed.Host
	}
	if strings.ContainsAny(raw, "/?#@") {
		return "", fmt.Errorf("invalid Webshare gateway %q", raw)
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("invalid Webshare gateway %q", raw)
		}
		parsedPort, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || parsedPort == 0 {
			return "", fmt.Errorf("invalid Webshare gateway port %q", port)
		}
		return net.JoinHostPort(host, port), nil
	}
	if defaultPort == "" {
		return "", fmt.Errorf("Webshare gateway %q requires a port", raw)
	}
	if ip := net.ParseIP(strings.Trim(raw, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), defaultPort), nil
	}
	if strings.Contains(raw, ":") || strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("invalid Webshare gateway %q", raw)
	}
	return net.JoinHostPort(raw, defaultPort), nil
}

func randomNumericSession(length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("session length must be positive")
	}
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, value := range raw {
		out[i] = '0' + value%10
	}
	return string(out), nil
}
