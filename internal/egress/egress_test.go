package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInspectBuildsConsistentProfile(t *testing.T) {
	t.Parallel()
	trace := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("fl=test\nip=203.0.113.42\nloc=US\ntls=TLSv1.3\n"))
	}))
	defer trace.Close()
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/203.0.113.42") {
			t.Fatalf("metadata path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"success":true,"country":"United States","country_code":"US","region":"California","city":"Los Angeles","latitude":34.05,"longitude":-118.24,"timezone":{"id":"America/Los_Angeles"},"connection":{"asn":64512,"org":"Example Org","isp":"Example ISP"}}`))
	}))
	defer meta.Close()

	inspector := NewInspector(Options{
		Timeout:     time.Second,
		TraceURL:    trace.URL,
		MetadataURL: meta.URL + "/{ip}",
	})
	profile, err := inspector.Inspect(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if profile.IP != "203.0.113.42" || profile.ASN != 64512 || profile.Timezone != "America/Los_Angeles" || profile.Locale != "en-US" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestInspectRejectsConfiguredASN(t *testing.T) {
	t.Parallel()
	trace := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ip=198.51.100.9\nloc=GB\n"))
	}))
	defer trace.Close()
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"country_code":"GB","timezone":{"id":"Europe/London"},"connection":{"asn":7922,"isp":"Blocked ISP"}}`))
	}))
	defer meta.Close()

	inspector := NewInspector(Options{
		TraceURL:    trace.URL,
		MetadataURL: meta.URL + "/{ip}",
		BlockedASNs: "AS7922, 123",
	})
	profile, err := inspector.Inspect(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "AS7922") {
		t.Fatalf("profile=%+v err=%v", profile, err)
	}
}

func TestInspectRequiresMetadataWhenPolicyIsConfigured(t *testing.T) {
	t.Parallel()
	trace := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ip=192.0.2.44\nloc=US\n"))
	}))
	defer trace.Close()
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer meta.Close()

	inspector := NewInspector(Options{
		TraceURL:    trace.URL,
		MetadataURL: meta.URL + "/{ip}",
		BlockedISPs: "bad transit",
	})
	_, err := inspector.Inspect(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "metadata required by policy") {
		t.Fatalf("err = %v", err)
	}
}
