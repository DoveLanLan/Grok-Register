package proxybridge

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBridgeCarriesHTTPAndHTTPSOverAuthenticatedSOCKS5(t *testing.T) {
	t.Parallel()
	plainOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain:"+r.URL.Path)
	}))
	defer plainOrigin.Close()
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls:"+r.URL.Path)
	}))
	defer tlsOrigin.Close()

	upstream := startFakeSOCKS5(t, "bridge-user", "bridge-pass")
	defer upstream.Close()
	bridge, err := Start("socks5h://bridge-user:bridge-pass@" + upstream.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	bridgeURL, err := url.Parse(bridge.URL())
	if err != nil {
		t.Fatal(err)
	}
	if host := net.ParseIP(bridgeURL.Hostname()); host == nil || !host.IsLoopback() {
		t.Fatalf("bridge did not bind loopback: %s", bridge.URL())
	}
	if bridgeURL.User != nil {
		t.Fatalf("bridge URL leaked credentials: %s", bridge.URL())
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(bridgeURL),
		// The origin is an httptest TLS server with an ephemeral certificate.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	for _, test := range []struct {
		url  string
		want string
	}{
		{url: plainOrigin.URL + "/plain", want: "plain:/plain"},
		{url: tlsOrigin.URL + "/secure", want: "tls:/secure"},
	} {
		response, requestErr := client.Get(test.url)
		if requestErr != nil {
			t.Fatalf("GET %s: %v", test.url, requestErr)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(body) != test.want {
			t.Fatalf("GET %s body=%q, want %q", test.url, body, test.want)
		}
	}
	if upstream.Authenticated() < 2 {
		t.Fatalf("authenticated SOCKS5 connections=%d, want at least 2", upstream.Authenticated())
	}
}

func TestBridgeRejectsNonSOCKSUpstream(t *testing.T) {
	t.Parallel()
	if _, err := Start("http://proxy.example:8080"); err == nil {
		t.Fatal("HTTP upstream should not be accepted by the SOCKS5 bridge")
	}
}

func TestChromiumBackgroundHostsAreBlockedLocally(t *testing.T) {
	t.Parallel()
	for _, authority := range []string{
		"clients2.google.com",
		"clients2.google.com:80",
		"www.google.com:443",
		"accounts.google.com:443",
	} {
		if !isChromiumBackgroundHost(authority) {
			t.Fatalf("background host %q was not blocked", authority)
		}
	}
	if isChromiumBackgroundHost("accounts.x.ai:443") {
		t.Fatal("accounts.x.ai must not be blocked")
	}
}

type fakeSOCKS5 struct {
	listener      net.Listener
	username      string
	password      string
	authenticated atomic.Int32
	closeOnce     sync.Once
	wg            sync.WaitGroup
}

func startFakeSOCKS5(t *testing.T, username, password string) *fakeSOCKS5 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &fakeSOCKS5{listener: listener, username: username, password: password}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				server.handle(conn)
			}()
		}
	}()
	return server
}

func (s *fakeSOCKS5) Address() string { return s.listener.Addr().String() }

func (s *fakeSOCKS5) Authenticated() int { return int(s.authenticated.Load()) }

func (s *fakeSOCKS5) Close() {
	s.closeOnce.Do(func() { _ = s.listener.Close() })
	s.wg.Wait()
}

func (s *fakeSOCKS5) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting[0] != 0x05 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if s.username != "" || s.password != "" {
		if len(methods) != 2 || methods[0] != 0x00 || methods[1] != 0x02 {
			// Authenticated clients must advertise the same compatible method
			// set and order as Go's standard SOCKS5 implementation.
			_, _ = client.Write([]byte{0x05, 0xff})
			return
		}
	}
	if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
		return
	}
	var authHeader [2]byte
	if _, err := io.ReadFull(client, authHeader[:]); err != nil || authHeader[0] != 0x01 {
		return
	}
	username := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(client, username); err != nil {
		return
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(client, passwordLength[:]); err != nil {
		return
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(client, password); err != nil {
		return
	}
	if string(username) != s.username || string(password) != s.password {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	s.authenticated.Add(1)
	if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
		return
	}

	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil || request[0] != 0x05 || request[1] != 0x01 {
		return
	}
	host, err := readSOCKS5Host(client, request[3])
	if err != nil {
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, stringPort(binary.BigEndian.Uint16(portBytes[:])))
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go copyTunnel(upstream, client, done)
	go copyTunnel(client, upstream, done)
	<-done
}

func readSOCKS5Host(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 0x01:
		address := make([]byte, net.IPv4len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 0x04:
		address := make([]byte, net.IPv6len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", err
		}
		host := make([]byte, int(length[0]))
		_, err := io.ReadFull(reader, host)
		return string(host), err
	default:
		return "", io.ErrUnexpectedEOF
	}
}

func stringPort(port uint16) string {
	return strconv.Itoa(int(port))
}
