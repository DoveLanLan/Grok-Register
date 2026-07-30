// Package proxybridge exposes a loopback-only HTTP proxy whose outbound
// connections are carried by an authenticated SOCKS5 upstream. It lets
// Chromium/Playwright use proxy providers that require SOCKS5 authentication,
// which Chromium does not support directly.
package proxybridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const socksHandshakeTimeout = 15 * time.Second

// Bridge is a loopback HTTP/CONNECT proxy backed by one SOCKS5 credential.
type Bridge struct {
	listener  net.Listener
	server    *http.Server
	transport *http.Transport
	url       string
	closeOnce sync.Once
	errorMu   sync.Mutex
	lastErr   error
}

// Start creates a loopback-only HTTP proxy backed by upstreamProxy. Supported
// upstream schemes are socks5 and socks5h; both resolve destination hostnames
// through the upstream proxy.
func Start(upstreamProxy string) (*Bridge, error) {
	dialer, err := newSOCKS5Dialer(upstreamProxy)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start browser proxy bridge: %w", err)
	}
	bridge := &Bridge{listener: listener}
	bridge.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	bridge.server = &http.Server{
		Handler:           bridge,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	bridge.url = "http://" + listener.Addr().String()
	go func() {
		_ = bridge.server.Serve(listener)
	}()
	return bridge, nil
}

// URL returns the credential-free loopback HTTP proxy URL.
func (b *Bridge) URL() string {
	if b == nil {
		return ""
	}
	return b.url
}

// Close terminates the listener and all idle upstream connections.
func (b *Bridge) Close() error {
	if b == nil {
		return nil
	}
	var closeErr error
	b.closeOnce.Do(func() {
		if b.transport != nil {
			b.transport.CloseIdleConnections()
		}
		if b.server != nil {
			closeErr = b.server.Close()
		} else if b.listener != nil {
			closeErr = b.listener.Close()
		}
		if errors.Is(closeErr, http.ErrServerClosed) || errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
	})
	return closeErr
}

func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isChromiumBackgroundHost(r.Host) {
		// Chrome performs connectivity/update checks even when Playwright is
		// launched with background networking disabled. They are unrelated to
		// signup and can exhaust a residential gateway's connection budget.
		if r.Method == http.MethodConnect {
			http.Error(w, "background request blocked", http.StatusBadGateway)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if r.Method == http.MethodConnect {
		b.serveConnect(w, r)
		return
	}
	b.serveHTTP(w, r)
}

func isChromiumBackgroundHost(authority string) bool {
	host := strings.TrimSpace(authority)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return host == "google.com" || strings.HasSuffix(host, ".google.com")
}

func (b *Bridge) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.Host)
	if target == "" {
		http.Error(w, "missing CONNECT target", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	upstream, err := b.transport.DialContext(r.Context(), "tcp", target)
	if err != nil {
		b.recordError(fmt.Errorf("CONNECT %s: %w", target, err))
		http.Error(w, "upstream proxy connection failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "CONNECT hijacking unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	if buffered.Reader.Buffered() > 0 {
		if _, err := io.CopyN(upstream, buffered.Reader, int64(buffered.Reader.Buffered())); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go copyTunnel(upstream, client, done)
	go copyTunnel(client, upstream, done)
	<-done
}

func copyTunnel(dst io.Writer, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	done <- struct{}{}
}

func (b *Bridge) serveHTTP(w http.ResponseWriter, r *http.Request) {
	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	if outbound.URL.Scheme == "" {
		outbound.URL.Scheme = "http"
	}
	if outbound.URL.Host == "" {
		outbound.URL.Host = r.Host
	}
	removeHopHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Authorization")
	response, err := b.transport.RoundTrip(outbound)
	if err != nil {
		b.recordError(fmt.Errorf("HTTP %s: %w", outbound.URL.Host, err))
		http.Error(w, "upstream proxy request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (b *Bridge) recordError(err error) {
	if b == nil || err == nil {
		return
	}
	b.errorMu.Lock()
	// Chromium cancels background Google connections while a page navigation
	// is failing. Preserve the first substantive upstream error instead of
	// overwriting it with that shutdown noise.
	if b.lastErr == nil || isCanceledError(b.lastErr) {
		if !isCanceledError(err) || b.lastErr == nil {
			b.lastErr = err
		}
	}
	b.errorMu.Unlock()
}

func isCanceledError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return errors.Is(err, context.Canceled) || strings.Contains(message, "operation was canceled") || strings.Contains(message, "context canceled")
}

// lastError is intentionally unexported. External smoke tests in this package
// can surface a credential-free SOCKS failure without changing browser-facing
// responses or logging proxy URLs in production.
func (b *Bridge) lastError() error {
	if b == nil {
		return nil
	}
	b.errorMu.Lock()
	defer b.errorMu.Unlock()
	return b.lastErr
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, key := range hopHeaders {
		header.Del(key)
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

type socks5Dialer struct {
	proxyAddress string
	username     string
	password     string
	base         net.Dialer
}

func newSOCKS5Dialer(raw string) (*socks5Dialer, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse SOCKS5 browser proxy: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "socks5" && scheme != "socks5h" {
		return nil, fmt.Errorf("browser proxy bridge requires socks5 or socks5h upstream")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("SOCKS5 browser proxy requires host and port")
	}
	dialer := &socks5Dialer{
		proxyAddress: net.JoinHostPort(host, port),
		base:         net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
	}
	if parsed.User != nil {
		dialer.username = parsed.User.Username()
		dialer.password, _ = parsed.User.Password()
	}
	if len(dialer.username) > 255 || len(dialer.password) > 255 {
		return nil, fmt.Errorf("SOCKS5 username/password exceeds protocol limit")
	}
	return dialer, nil
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("SOCKS5 browser proxy does not support network %s", network)
	}
	conn, err := d.base.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect SOCKS5 browser proxy: %w", err)
	}
	deadline := time.Now().Add(socksHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	if err := d.negotiate(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *socks5Dialer) negotiate(conn net.Conn, target string) error {
	hasCredentials := d.username != "" || d.password != ""
	methods := []byte{0x00}
	if hasCredentials {
		// Match Go's standard SOCKS5 client: authenticated proxies are
		// offered both no-auth and username/password. Some providers (notably
		// Webshare residential gateways) reject a greeting containing only
		// username/password even though they subsequently select it.
		methods = append(methods, 0x02)
	}
	greetingRequest := append([]byte{0x05, byte(len(methods))}, methods...)
	if err := writeFull(conn, greetingRequest); err != nil {
		return fmt.Errorf("SOCKS5 greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fmt.Errorf("SOCKS5 greeting response: %w", err)
	}
	if greeting[0] != 0x05 {
		return fmt.Errorf("SOCKS5 greeting has invalid version %d", greeting[0])
	}
	if greeting[1] == 0xff {
		return fmt.Errorf("SOCKS5 proxy rejected authentication method")
	}
	switch greeting[1] {
	case 0x00:
		// No authentication selected. This is valid even when credentials were
		// offered and is how the Go standard library handles the response.
	case 0x02:
		if !hasCredentials {
			return fmt.Errorf("SOCKS5 proxy selected username/password without credentials")
		}
		packet := make([]byte, 0, 3+len(d.username)+len(d.password))
		packet = append(packet, 0x01, byte(len(d.username)))
		packet = append(packet, d.username...)
		packet = append(packet, byte(len(d.password)))
		packet = append(packet, d.password...)
		if err := writeFull(conn, packet); err != nil {
			return fmt.Errorf("SOCKS5 authentication: %w", err)
		}
		var authResponse [2]byte
		if _, err := io.ReadFull(conn, authResponse[:]); err != nil {
			return fmt.Errorf("SOCKS5 authentication response: %w", err)
		}
		if authResponse[0] != 0x01 || authResponse[1] != 0x00 {
			return fmt.Errorf("SOCKS5 proxy authentication failed")
		}
	default:
		return fmt.Errorf("SOCKS5 proxy selected unsupported authentication method %d", greeting[1])
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("parse SOCKS5 target: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid SOCKS5 target port")
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("invalid SOCKS5 target hostname")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], uint16(port))
	request = append(request, encodedPort[:]...)
	if err := writeFull(conn, request); err != nil {
		return fmt.Errorf("SOCKS5 connect request: %w", err)
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return fmt.Errorf("SOCKS5 connect response: %w", err)
	}
	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect rejected (code %d)", response[1])
	}
	if err := discardSOCKS5Address(conn, response[3]); err != nil {
		return err
	}
	return nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func discardSOCKS5Address(reader io.Reader, addressType byte) error {
	var addressBytes int
	switch addressType {
	case 0x01:
		addressBytes = net.IPv4len
	case 0x04:
		addressBytes = net.IPv6len
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return fmt.Errorf("SOCKS5 response hostname: %w", err)
		}
		addressBytes = int(length[0])
	default:
		return fmt.Errorf("SOCKS5 response has invalid address type %d", addressType)
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressBytes+2)); err != nil {
		return fmt.Errorf("SOCKS5 response address: %w", err)
	}
	return nil
}
