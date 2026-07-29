package proxypool

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
)

const webshareSessionPlaceholder = "{session}"

// WebshareSessions expands a Webshare proxy URL template into a fresh sticky
// session credential for each account. Example:
// http://username-{session}:password@p.webshare.io:80
type WebshareSessions struct {
	template string
}

func NewWebshareSessions(template string) (*WebshareSessions, error) {
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
	return &WebshareSessions{template: template}, nil
}

func (w *WebshareSessions) Next() (proxyURL, sessionID string, err error) {
	if w == nil {
		return "", "", fmt.Errorf("Webshare session generator is nil")
	}
	sessionID, err = randomNumericSession(12)
	if err != nil {
		return "", "", err
	}
	return strings.ReplaceAll(w.template, webshareSessionPlaceholder, sessionID), sessionID, nil
}

func (w *WebshareSessions) Label() string {
	if w == nil {
		return ""
	}
	return Label(strings.ReplaceAll(w.template, webshareSessionPlaceholder, "session"))
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
