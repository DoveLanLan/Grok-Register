package cpa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type UploadConfig struct {
	Enabled      bool
	BaseURL      string // e.g. http://localhost:8317/v0/management
	Key          string
	TimeoutSec   int
	Retries      int
	NameTemplate string // {email}.json or {provider}-{email}.json
	Verify       bool   // GET /auth-files after upload
	Mode         string // multipart | json (default multipart)
}

func DefaultUploadConfig() UploadConfig {
	return UploadConfig{
		Enabled:      false,
		BaseURL:      "http://localhost:8317/v0/management",
		TimeoutSec:   30,
		Retries:      2,
		NameTemplate: "{email}.json",
		Verify:       true,
		Mode:         "multipart",
	}
}

type UploadResult struct {
	OK       bool
	Name     string
	Status   int
	Body     string
	Verified bool
	Err      error
}

type Uploader struct {
	cfg    UploadConfig
	client *http.Client
	logf   func(string, ...any)
}

func NewUploader(cfg UploadConfig, logf func(string, ...any)) *Uploader {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	to := time.Duration(cfg.TimeoutSec) * time.Second
	if to <= 0 {
		to = 30 * time.Second
	}
	cfg.BaseURL = NormalizeManagementBase(cfg.BaseURL)
	return &Uploader{
		cfg: cfg,
		client: &http.Client{
			Timeout: to,
			// CPA is usually localhost — do not inherit system HTTPS proxy.
			Transport: &http.Transport{Proxy: nil},
		},
		logf: logf,
	}
}

// NormalizeManagementBase rewrites Docker-only hostnames for host-side grok,
// and ensures the path ends with /v0/management (upload appends /auth-files).
//
// Examples:
//
//	http://cli-proxy-api:8317          → http://127.0.0.1:8317/v0/management
//	http://localhost:8317             → http://localhost:8317/v0/management
//	http://127.0.0.1:8317/v0/management → unchanged
func NormalizeManagementBase(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	// Docker compose service names are not resolvable from the host.
	for _, host := range []string{
		"cli-proxy-api",
		"cpa-public-proxy",
		"cpa-manager-plus",
		"cpa-helper",
	} {
		// http://host:port... or http://host/...
		s = strings.ReplaceAll(s, "://"+host+":", "://127.0.0.1:")
		s = strings.ReplaceAll(s, "://"+host+"/", "://127.0.0.1/")
		if strings.HasSuffix(s, "://"+host) {
			s = strings.TrimSuffix(s, host) + "127.0.0.1"
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(s, "/")
	}
	path := strings.TrimRight(u.Path, "/")
	if path == "" || path == "/" {
		u.Path = "/v0/management"
	} else if !strings.HasSuffix(path, "/v0/management") && !strings.Contains(path, "/management") {
		// base is host:port only or unknown path — append management prefix
		if path == "" {
			u.Path = "/v0/management"
		} else {
			u.Path = path + "/v0/management"
		}
	} else {
		u.Path = path
	}
	return strings.TrimRight(u.String(), "/")
}

func (u *Uploader) Enabled() bool {
	if !u.cfg.Enabled {
		return false
	}
	if strings.TrimSpace(u.cfg.Key) == "" {
		u.logf("[cpa] CPA_UPLOAD_ENABLED=1 but CPA_MANAGEMENT_KEY empty; skip")
		return false
	}
	if strings.TrimSpace(u.cfg.BaseURL) == "" {
		u.logf("[cpa] CPA_MANAGEMENT_BASE empty; skip")
		return false
	}
	return true
}

func UploadName(doc Document, tmpl string) string {
	if tmpl == "" {
		tmpl = "{email}.json"
	}
	email := strings.TrimSpace(doc.Email)
	if email == "" {
		email = "unknown"
	}
	// sanitize for filename
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '@' || r == '.' || r == '_' || r == '-':
			return r
		default:
			return '_'
		}
	}, email)
	provider := "xai"
	name := tmpl
	name = strings.ReplaceAll(name, "{email}", safe)
	name = strings.ReplaceAll(name, "{provider}", provider)
	name = strings.ReplaceAll(name, "{sub}", sanitizePart(doc.Sub))
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	return name
}

func sanitizePart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "na"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// UploadFile uploads a local *.json path.
func (u *Uploader) UploadFile(path string) UploadResult {
	raw, err := os.ReadFile(path)
	if err != nil {
		return UploadResult{Err: err}
	}
	name := filepath.Base(path)
	var doc Document
	_ = json.Unmarshal(raw, &doc)
	if doc.Email != "" {
		name = UploadName(doc, u.cfg.NameTemplate)
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	return u.UploadBytes(name, raw)
}

// UploadDocument marshals doc and uploads.
func (u *Uploader) UploadDocument(doc Document) UploadResult {
	return u.UploadDocumentContext(context.Background(), doc)
}

// UploadDocumentContext is UploadDocument with cancellation support.
func (u *Uploader) UploadDocumentContext(ctx context.Context, doc Document) UploadResult {
	name := UploadName(doc, u.cfg.NameTemplate)
	raw, err := json.Marshal(doc)
	if err != nil {
		return UploadResult{Name: name, Err: err}
	}
	return u.UploadBytesContext(ctx, name, raw)
}

// UploadBytes uploads raw JSON with given filename (must end with .json).
func (u *Uploader) UploadBytes(name string, raw []byte) UploadResult {
	return u.UploadBytesContext(context.Background(), name, raw)
}

// UploadBytesContext is UploadBytes with cancellation support.
func (u *Uploader) UploadBytesContext(ctx context.Context, name string, raw []byte) UploadResult {
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	res := UploadResult{Name: name}
	if !u.Enabled() {
		res.Err = fmt.Errorf("upload disabled")
		return res
	}
	retries := u.cfg.Retries
	if retries < 0 {
		retries = 0
	}
	var last UploadResult
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return UploadResult{Name: name, Err: err}
		}
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * 400 * time.Millisecond
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return UploadResult{Name: name, Err: ctx.Err()}
			case <-timer.C:
			}
		}
		mode := strings.ToLower(strings.TrimSpace(u.cfg.Mode))
		if mode == "" {
			mode = "multipart"
		}
		var r UploadResult
		if mode == "json" || mode == "raw" {
			r = u.doJSON(ctx, name, raw)
		} else {
			r = u.doMultipart(ctx, name, raw)
			// fallback to raw json once if multipart fails with 4xx (except 401/403)
			if !r.OK && r.Status >= 400 && r.Status < 500 && r.Status != 401 && r.Status != 403 {
				r2 := u.doJSON(ctx, name, raw)
				if r2.OK {
					r = r2
				}
			}
		}
		last = r
		if r.OK {
			if u.cfg.Verify {
				ok, err := u.verifyListed(ctx, name)
				last.Verified = ok
				if err != nil {
					u.logf("[cpa] verify list failed %s: %v", name, err)
				} else if !ok {
					u.logf("[cpa] uploaded %s ok but not yet listed", name)
				}
			}
			u.logf("[cpa] uploaded %s ok", name)
			return last
		}
	}
	if last.Err != nil {
		u.logf("[cpa] upload failed %s err=%v", name, last.Err)
	} else {
		u.logf("[cpa] upload failed %s status=%d body=%s", name, last.Status, truncate(last.Body, 200))
	}
	return last
}

func (u *Uploader) authHeaders(req *http.Request) {
	key := strings.TrimSpace(u.cfg.Key)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Management-Key", key)
}

func (u *Uploader) endpoint() string {
	return strings.TrimRight(u.cfg.BaseURL, "/") + "/auth-files"
}

func (u *Uploader) doMultipart(ctx context.Context, name string, raw []byte) UploadResult {
	res := UploadResult{Name: name}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		res.Err = err
		return res
	}
	if _, err := part.Write(raw); err != nil {
		res.Err = err
		return res
	}
	_ = w.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint(), &body)
	if err != nil {
		res.Err = err
		return res
	}
	u.authHeaders(req)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return u.do(req, res)
}

func (u *Uploader) doJSON(ctx context.Context, name string, raw []byte) UploadResult {
	res := UploadResult{Name: name}
	ep := u.endpoint() + "?name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(raw))
	if err != nil {
		res.Err = err
		return res
	}
	u.authHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	return u.do(req, res)
}

func (u *Uploader) do(req *http.Request, res UploadResult) UploadResult {
	resp, err := u.client.Do(req)
	if err != nil {
		res.Err = err
		return res
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	res.Status = resp.StatusCode
	res.Body = string(b)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// optional {"status":"ok"}
		res.OK = true
		return res
	}
	res.OK = false
	return res
}

func (u *Uploader) verifyListed(ctx context.Context, name string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.endpoint(), nil)
	if err != nil {
		return false, err
	}
	u.authHeaders(req)
	resp, err := u.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("list status=%d body=%s", resp.StatusCode, truncate(string(b), 120))
	}
	// response may be array of names or objects
	s := string(b)
	if strings.Contains(s, name) {
		return true, nil
	}
	// also try without path noise
	base := filepath.Base(name)
	return strings.Contains(s, base), nil
}

// ListRunDirs returns up to limit newest run dirs under outputs (name = yyyymmdd-HHMMSS).
func ListRunDirs(outputsRoot string, limit int) ([]string, error) {
	entries, err := os.ReadDir(outputsRoot)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// rough filter yyyymmdd-HHMMSS
		n := e.Name()
		if len(n) < 15 {
			continue
		}
		names = append(names, n)
	}
	// sort descending by name (timestamp format sorts lexicographically)
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] > names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}
	var full []string
	for _, n := range names {
		full = append(full, filepath.Join(outputsRoot, n))
	}
	return full, nil
}

// CollectCPAJSON lists *.json under runDir/CPA.
func CollectCPAJSON(runDir string) ([]string, error) {
	cpaDir := filepath.Join(runDir, "CPA")
	entries, err := os.ReadDir(cpaDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			out = append(out, filepath.Join(cpaDir, e.Name()))
		}
	}
	return out, nil
}
