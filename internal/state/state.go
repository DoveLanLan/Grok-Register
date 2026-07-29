package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Status string

const (
	StatusStopped Status = "stopped"
	StatusRunning Status = "running"
	StatusError   Status = "error"
)

type Phase string

const (
	PhaseIdle      Phase = "idle"
	PhaseClearance Phase = "clearance"
	PhaseRegister  Phase = "register"
	PhaseOAuth     Phase = "oauth"
	PhaseProbe     Phase = "probe"
)

type Workers struct {
	S     int `json:"s"`
	P     int `json:"p"`
	C     int `json:"c"`
	OAuth int `json:"oauth"`
}

// Funnel exposes each material conversion boundary independently.
type Funnel struct {
	AccountsStarted        int `json:"accounts_started"`
	Attempts               int `json:"attempts"`
	AttemptFailures        int `json:"attempt_failures"`
	FirstPassRegistrations int `json:"first_pass_registrations"`
	RetryRegistrations     int `json:"retry_registrations"`
	Registrations          int `json:"registrations"`
	SSO                    int `json:"sso"`
	OAuth                  int `json:"oauth"`
	CPA                    int `json:"cpa"`
}

// Snapshot is written atomically for `grok status`.
type Snapshot struct {
	Status      Status  `json:"status"`
	RunID       string  `json:"run_id"`
	Target      int     `json:"target"`
	Done        int     `json:"done"`
	SSOCount    int     `json:"sso_count"`
	OAuthCount  int     `json:"oauth_count"`
	FailCount   int     `json:"fail_count"`
	Funnel      Funnel  `json:"funnel"`
	Phase       Phase   `json:"phase"`
	PhaseDetail string  `json:"phase_detail"`
	Workers     Workers `json:"workers"`
	PID         int     `json:"pid"`
	StartedAt   string  `json:"started_at"`
	UpdatedAt   string  `json:"updated_at"`
	Error       string  `json:"error"`
	LogPath     string  `json:"log_path"`
	OutputDir   string  `json:"output_dir"`
	RatePerMin  float64 `json:"rate_per_min"`
}

type Store struct {
	path string
	mu   sync.Mutex
	cur  Snapshot
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Path() string { return s.path }

func (s *Store) Get() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *Store) Set(fn func(*Snapshot)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cur)
	s.cur.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return s.writeLocked()
}

func (s *Store) Load() (Snapshot, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return Snapshot{Status: StatusStopped}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{Status: StatusStopped}, err
	}
	s.mu.Lock()
	s.cur = snap
	s.mu.Unlock()
	return snap, nil
}

func (s *Store) writeLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.cur, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
