package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/proxypool"
	"github.com/grok-free-register/grok-reg/internal/state"
)

// registrationMetric deliberately excludes mailbox addresses, passwords,
// tokens, cookies, and proxy credentials.
type registrationMetric struct {
	Timestamp    string `json:"timestamp"`
	DiagnosticID string `json:"diagnostic_id"`
	Attempt      int    `json:"attempt,omitempty"`
	Engine       string `json:"engine"`
	Stage        string `json:"stage"`
	Outcome      string `json:"outcome"`
	Reason       string `json:"reason,omitempty"`
	Proxy        string `json:"proxy,omitempty"`
	IP           string `json:"ip,omitempty"`
	ASN          int    `json:"asn,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Country      string `json:"country,omitempty"`
}

func (e *Engine) recordRegistrationMetric(session *AccountSession, attempt int, stage, outcome string, err error) {
	if e == nil || session == nil || strings.TrimSpace(e.opt.Run.Root) == "" {
		return
	}
	engine := strings.ToLower(strings.TrimSpace(e.opt.Cfg.RegisterMode))
	if e.signup != nil {
		engine = e.signup.Name()
	}
	if engine == "" {
		engine = "browser"
	}
	reason := ""
	if err != nil {
		reason = metricReason(err)
	}
	metric := registrationMetric{
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		DiagnosticID: session.DiagnosticID,
		Attempt:      attempt,
		Engine:       engine,
		Stage:        strings.TrimSpace(stage),
		Outcome:      strings.TrimSpace(outcome),
		Reason:       reason,
		Proxy:        proxypool.Label(session.Proxy),
		IP:           session.Egress.IP,
		ASN:          session.Egress.ASN,
		ISP:          session.Egress.ISP,
		Country:      session.Egress.CountryCode,
	}
	line, marshalErr := json.Marshal(metric)
	if marshalErr != nil {
		return
	}

	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()
	path := filepath.Join(e.opt.Run.Root, "registration-metrics.jsonl")
	file, openErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if openErr != nil {
		return
	}
	_, _ = file.Write(append(line, '\n'))
	_ = file.Close()
}

func metricReason(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	classifications := []struct {
		name  string
		terms []string
	}{
		{name: "rate_limited", terms: []string{"rate_limited", "rate limit", "too many"}},
		{name: "turnstile", terms: []string{"turnstile"}},
		{name: "invalid_code", terms: []string{"invalid_or_expired_code", "invalid code", "expired code"}},
		{name: "email_rejected", terms: []string{"email_rejected", "invalid email", "email_invalid"}},
		{name: "navigate_failed", terms: []string{"navigate_failed", "navigate:"}},
		{name: "timeout", terms: []string{"timeout", "deadline exceeded"}},
		{name: "invalid_grant", terms: []string{"invalid_grant", "access denied"}},
		{name: "proxy_transport", terms: []string{"proxy", "connection reset", "connection refused", "tunnel", "no such host"}},
		{name: "dependency_missing", terms: []string{"not installed", "executable not found", "unavailable"}},
		{name: "canceled", terms: []string{"context canceled", "cancelled"}},
	}
	for _, classification := range classifications {
		for _, term := range classification.terms {
			if strings.Contains(message, term) {
				return classification.name
			}
		}
	}
	return "other_error"
}

func (e *Engine) funnelSnapshot() state.Funnel {
	return state.Funnel{
		AccountsStarted:        int(e.accountsStarted.Load()),
		Attempts:               int(e.signupAttempts.Load()),
		AttemptFailures:        int(e.signupAttemptFailures.Load()),
		FirstPassRegistrations: int(e.firstPassRegistrations.Load()),
		RetryRegistrations:     int(e.retryRegistrations.Load()),
		Registrations:          int(e.registrationN.Load()),
		SSO:                    int(e.ssoN.Load()),
		OAuth:                  int(e.oaN.Load()),
		CPA:                    int(e.done.Load()),
	}
}
