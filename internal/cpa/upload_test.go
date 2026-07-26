package cpa

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"

	"strings"
	"testing"
)

func TestNormalizeManagementBase(t *testing.T) {
	cases := map[string]string{
		"http://cli-proxy-api:8317":               "http://127.0.0.1:8317/v0/management",
		"http://cli-proxy-api:8317/":              "http://127.0.0.1:8317/v0/management",
		"http://cli-proxy-api:8317/v0/management": "http://127.0.0.1:8317/v0/management",
		"http://127.0.0.1:8317":                   "http://127.0.0.1:8317/v0/management",
		"http://127.0.0.1:8317/v0/management":     "http://127.0.0.1:8317/v0/management",
		"http://localhost:8317/v0/management":     "http://localhost:8317/v0/management",
	}
	for in, want := range cases {
		got := NormalizeManagementBase(in)
		if got != want {
			t.Fatalf("NormalizeManagementBase(%q)=%q want %q", in, got, want)
		}
	}
}

func TestUploadName(t *testing.T) {
	doc := Document{Email: "a@b.com", Sub: "sub1"}
	n := UploadName(doc, "{email}.json")
	if n != "a@b.com.json" {
		t.Fatalf("name=%s", n)
	}
	n2 := UploadName(doc, "{provider}-{email}.json")
	if n2 != "xai-a@b.com.json" {
		t.Fatalf("name=%s", n2)
	}
	n3 := UploadName(Document{Email: "x"}, "")
	if !strings.HasSuffix(n3, ".json") {
		t.Fatalf("suffix: %s", n3)
	}
}

func TestUploadMultipart(t *testing.T) {
	var gotName string
	var gotBody []byte
	var gotAuth string
	var gotXKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/auth-files" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]string{gotName})
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotXKey = r.Header.Get("X-Management-Key")
		ct := r.Header.Get("Content-Type")
		media, params, err := mime.ParseMediaType(ct)
		if err != nil || !strings.HasPrefix(media, "multipart/") {
			http.Error(w, "want multipart", 400)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if part.FormName() == "file" {
				gotName = part.FileName()
				gotBody, _ = io.ReadAll(part)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u := NewUploader(UploadConfig{
		Enabled:      true,
		BaseURL:      srv.URL + "/v0/management",
		Key:          "test-key",
		TimeoutSec:   5,
		Retries:      0,
		NameTemplate: "{email}.json",
		Verify:       true,
		Mode:         "multipart",
	}, func(string, ...any) {})

	doc := Document{
		Type:        "xai",
		AccessToken: "at",
		Email:       "u@test.com",
		BaseURL:     CliproxyBase,
		AuthKind:    "oauth",
	}
	res := u.UploadDocument(doc)
	if !res.OK {
		t.Fatalf("upload failed status=%d body=%s err=%v", res.Status, res.Body, res.Err)
	}
	if gotName != "u@test.com.json" {
		t.Fatalf("filename=%s", gotName)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth=%s", gotAuth)
	}
	if gotXKey != "test-key" {
		t.Fatalf("xkey=%s", gotXKey)
	}
	if !strings.Contains(string(gotBody), "access_token") {
		t.Fatalf("body missing token")
	}
	if !res.Verified {
		t.Fatal("expected verified")
	}
}

func TestUploadJSONRaw(t *testing.T) {
	var gotCT string
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		gotCT = r.Header.Get("Content-Type")
		gotQuery = r.URL.RawQuery
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u := NewUploader(UploadConfig{
		Enabled:    true,
		BaseURL:    srv.URL + "/v0/management",
		Key:        "k",
		TimeoutSec: 5,
		Mode:       "json",
		Verify:     false,
	}, nil)
	res := u.UploadBytes("acc.json", []byte(`{"type":"xai"}`))
	if !res.OK {
		t.Fatalf("fail %v %s", res.Err, res.Body)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Fatalf("ct=%s", gotCT)
	}
	if !strings.Contains(gotQuery, "name=acc.json") {
		t.Fatalf("query=%s", gotQuery)
	}
}

func TestUploadDocumentContextHonorsCancellation(t *testing.T) {
	uploader := NewUploader(UploadConfig{
		Enabled: true,
		BaseURL: "http://127.0.0.1:1",
		Key:     "key",
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := uploader.UploadDocumentContext(ctx, Document{Email: "person@example.com"})
	if !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("upload error = %v, want context canceled", result.Err)
	}
}

func TestUploaderTransportRemainsDirect(t *testing.T) {
	uploader := NewUploader(UploadConfig{}, nil)
	transport, ok := uploader.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("uploader transport = %T", uploader.client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("CPA management uploader must not inherit account or environment proxies")
	}
}

func TestUploadDisabled(t *testing.T) {
	u := NewUploader(UploadConfig{Enabled: false}, nil)
	res := u.UploadBytes("a.json", []byte(`{}`))
	if res.OK {
		t.Fatal("should skip")
	}
}

func TestUploadEmptyKeySkips(t *testing.T) {
	var logs []string
	u := NewUploader(UploadConfig{
		Enabled: true,
		BaseURL: "http://127.0.0.1:1",
		Key:     "",
	}, func(f string, a ...any) {
		logs = append(logs, f)
	})
	if u.Enabled() {
		t.Fatal("should be disabled without key")
	}
	if len(logs) == 0 {
		t.Fatal("expected warning log")
	}
}
