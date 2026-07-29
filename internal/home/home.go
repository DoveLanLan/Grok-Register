package home

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	EnvHome = "GROK_HOME"
	DirName = ".grok"
)

// Paths holds all filesystem locations under GROK_HOME.
type Paths struct {
	Root              string
	Config            string
	PID               string
	Lock              string
	State             string
	LogsDir           string
	Outputs           string
	OutlookAccounts   string
	OutlookState      string
	InvalidGrantState string
	Clearance         string // optional: bundled compose path override
}

func Resolve() (Paths, error) {
	root := os.Getenv(EnvHome)
	if root == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, err
		}
		root = filepath.Join(h, DirName)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Paths{}, err
	}
	p := Paths{
		Root:              root,
		Config:            filepath.Join(root, "config.env"),
		PID:               filepath.Join(root, "run.pid"),
		Lock:              filepath.Join(root, "run.lock"),
		State:             filepath.Join(root, "state.json"),
		LogsDir:           filepath.Join(root, "logs"),
		Outputs:           filepath.Join(root, "outputs"),
		OutlookAccounts:   filepath.Join(root, "outlook-accounts.txt"),
		OutlookState:      filepath.Join(root, "outlook-state.json"),
		InvalidGrantState: filepath.Join(root, "invalid-grants.json"),
	}
	return p, nil
}

func (p Paths) EnsureBase() error {
	for _, d := range []string{p.Root, p.LogsDir, p.Outputs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// NewRunID returns yyyymmdd-HHMMSS in local time.
func NewRunID() string {
	return time.Now().Format("20060102-150405")
}

// RunDirs is created before the first credential file is written.
type RunDirs struct {
	RunID     string
	Root      string
	SSO       string
	CPA       string
	Discarded string
	LogPath   string
}

func (p Paths) PrepareRun(runID string) (RunDirs, error) {
	if runID == "" {
		runID = NewRunID()
	}
	root := filepath.Join(p.Outputs, runID)
	rd := RunDirs{
		RunID:     runID,
		Root:      root,
		SSO:       filepath.Join(root, "SSO"),
		CPA:       filepath.Join(root, "CPA"),
		Discarded: filepath.Join(root, "discarded"),
		LogPath:   filepath.Join(p.LogsDir, fmt.Sprintf("run-%s.log", runID)),
	}
	for _, d := range []string{rd.Root, rd.SSO, rd.CPA, rd.Discarded} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return RunDirs{}, err
		}
	}
	return rd, nil
}
