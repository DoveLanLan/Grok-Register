// Package riskstate persists invalid_grant mailbox/exit pairs so later runs do
// not silently reuse an email or residential IP that x.ai already rejected.
package riskstate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const stateVersion = 1

type InvalidGrantRecord struct {
	Timestamp    string `json:"timestamp"`
	DiagnosticID string `json:"diagnostic_id,omitempty"`
	Email        string `json:"email"`
	MailboxKind  string `json:"mailbox_kind,omitempty"`
	IP           string `json:"ip,omitempty"`
	ASN          int    `json:"asn,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Proxy        string `json:"proxy,omitempty"`
}

type fileState struct {
	Version           int                  `json:"version"`
	FallbackToOutlook bool                 `json:"fallback_to_outlook"`
	BlockedEmails     map[string]string    `json:"blocked_emails"`
	BlockedIPs        map[string]string    `json:"blocked_ips"`
	InvalidGrants     []InvalidGrantRecord `json:"invalid_grants"`
}

type Registry struct {
	mu   sync.Mutex
	path string
	data fileState
}

func Open(path string) (*Registry, error) {
	r := &Registry{
		path: strings.TrimSpace(path),
		data: fileState{
			Version:       stateVersion,
			BlockedEmails: map[string]string{},
			BlockedIPs:    map[string]string{},
		},
	}
	if r.path == "" {
		return r, nil
	}
	raw, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("read invalid-grant state: %w", err)
	}
	if err := json.Unmarshal(raw, &r.data); err != nil {
		return nil, fmt.Errorf("parse invalid-grant state: %w", err)
	}
	if err := os.Chmod(r.path, 0o600); err != nil {
		return nil, fmt.Errorf("secure invalid-grant state: %w", err)
	}
	r.data.Version = stateVersion
	if r.data.BlockedEmails == nil {
		r.data.BlockedEmails = map[string]string{}
	}
	if r.data.BlockedIPs == nil {
		r.data.BlockedIPs = map[string]string{}
	}
	return r, nil
}

func (r *Registry) RecordInvalidGrant(record InvalidGrantRecord, fallbackToOutlook bool) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if strings.TrimSpace(record.Timestamp) == "" {
		record.Timestamp = now
	}
	record.Email = strings.ToLower(strings.TrimSpace(record.Email))
	record.IP = strings.TrimSpace(record.IP)
	if record.Email != "" {
		r.data.BlockedEmails[record.Email] = record.Timestamp
	}
	if record.IP != "" {
		r.data.BlockedIPs[record.IP] = record.Timestamp
	}
	if fallbackToOutlook {
		r.data.FallbackToOutlook = true
	}
	r.data.InvalidGrants = append(r.data.InvalidGrants, record)
	if len(r.data.InvalidGrants) > 1000 {
		r.data.InvalidGrants = append([]InvalidGrantRecord(nil), r.data.InvalidGrants[len(r.data.InvalidGrants)-1000:]...)
	}
	return r.saveLocked()
}

func (r *Registry) EmailBlocked(email string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, blocked := r.data.BlockedEmails[strings.ToLower(strings.TrimSpace(email))]
	return blocked
}

func (r *Registry) IPBlocked(ip string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, blocked := r.data.BlockedIPs[strings.TrimSpace(ip)]
	return blocked
}

func (r *Registry) FallbackToOutlook() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.data.FallbackToOutlook
}

func (r *Registry) Counts() (emails, ips, records int) {
	if r == nil {
		return 0, 0, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.data.BlockedEmails), len(r.data.BlockedIPs), len(r.data.InvalidGrants)
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, r.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
