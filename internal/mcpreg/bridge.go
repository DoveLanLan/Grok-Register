// Package mcpreg provides browser-driven registration via the browser-mcp
// extension bridge WebSocket.  This file implements the peer-side client that
// speaks the shared-bridge peer protocol documented in
// browser_mcp/shared_bridge.py and extension_bridge.py.
package mcpreg

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bridgeAddr          = "127.0.0.1:18768"
	bridgeTokenEnv      = "BROWSER_MCP_BRIDGE_TOKEN"
	bridgeTokenFileEnv  = "BROWSER_MCP_BRIDGE_TOKEN_FILE"
	bridgeHandshakeTO   = 5 * time.Second
	bridgeCommandTO     = 45 * time.Second
)

// BridgeClient is a peer-side WebSocket client for the browser-mcp extension
// bridge.  It speaks the shared-bridge protocol (client_ready handshake,
// peer_command envelopes, peer_result / peer_error responses).
type BridgeClient struct {
	conn     net.Conn
	mu       sync.Mutex
	seq      atomic.Int64
	sessionID string

	pendingMu sync.Mutex
	pending   map[string]chan bridgeReply

	closed chan struct{}
	once   sync.Once
}

type bridgeReply struct {
	data json.RawMessage
	err  error
}

// NewBridgeClient connects to the browser-mcp bridge at 127.0.0.1:18768 and
// completes the client_ready peer handshake.  Close() must be called when done.
func NewBridgeClient(sessionID string) (*BridgeClient, error) {
	token, err := readBridgeToken()
	if err != nil {
		return nil, fmt.Errorf("bridge token: %w", err)
	}

	// HTTP Upgrade to WebSocket using the standard library only.
	conn, _, err := wsDialRaw(bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("bridge dial: %w", err)
	}

	bc := &BridgeClient{
		conn:      conn,
		sessionID: sessionID,
		pending:   make(map[string]chan bridgeReply),
		closed:    make(chan struct{}),
	}

	// Handshake: send client_ready
	hello := map[string]any{
		"type":              "client_ready",
		"client_session_id": sessionID,
		"client_name":       "grok-reg",
		"client_label":      "mcp-register",
		"working_dir":       "",
		"auth": map[string]string{
			"scheme": "bridge_token",
			"token":  token,
		},
	}
	if err := bc.writeJSON(hello); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bridge handshake send: %w", err)
	}

	// Expect client_ready_ack within 5 s
	_ = conn.SetReadDeadline(time.Now().Add(bridgeHandshakeTO))
	raw, err := wsReadFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bridge handshake recv: %w", err)
	}
	var ack map[string]any
	if err := json.Unmarshal(raw, &ack); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bridge handshake bad json: %w", err)
	}
	if t, _ := ack["type"].(string); t != "client_ready_ack" {
		_ = conn.Close()
		msg, _ := ack["error"].(map[string]any)
		reason := ""
		if msg != nil {
			reason, _ = msg["message"].(string)
		}
		if reason == "" {
			reason = fmt.Sprintf("type=%s", t)
		}
		return nil, fmt.Errorf("bridge handshake rejected: %s", reason)
	}

	go bc.readLoop()
	return bc, nil
}

// Close shuts down the bridge connection.
func (bc *BridgeClient) Close() {
	bc.once.Do(func() {
		close(bc.closed)
		_ = bc.conn.Close()
		bc.pendingMu.Lock()
		for _, ch := range bc.pending {
			select {
			case ch <- bridgeReply{err: fmt.Errorf("bridge closed")}:
			default:
			}
		}
		bc.pending = make(map[string]chan bridgeReply)
		bc.pendingMu.Unlock()
	})
}

// SendCommand sends a peer_command to the bridge and waits for the result.
// category follows the shared bridge routing rules (shared_read,
// serialized_page, time_dependent_serialized).
func (bc *BridgeClient) SendCommand(command, tabID, category string, payload map[string]any, timeout time.Duration) (json.RawMessage, error) {
	if timeout <= 0 {
		timeout = bridgeCommandTO
	}
	bc.seq.Add(1)
	reqID := fmt.Sprintf("peer-req-%d", bc.seq.Load())

	envelope := map[string]any{
		"type":              "peer_command",
		"id":                reqID,
		"client_session_id": bc.sessionID,
		"command":           command,
		"category":          category,
		"payload":           payload,
		"timeout_ms":        int(timeout.Milliseconds()),
	}
	if tabID != "" {
		envelope["tab_id"] = tabID
	}

	ch := make(chan bridgeReply, 1)
	bc.pendingMu.Lock()
	bc.pending[reqID] = ch
	bc.pendingMu.Unlock()

	defer func() {
		bc.pendingMu.Lock()
		delete(bc.pending, reqID)
		bc.pendingMu.Unlock()
	}()

	if err := bc.writeJSON(envelope); err != nil {
		return nil, err
	}

	select {
	case reply := <-ch:
		return reply.data, reply.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("bridge command %q timed out after %s", command, timeout)
	case <-bc.closed:
		return nil, fmt.Errorf("bridge closed")
	}
}

func (bc *BridgeClient) readLoop() {
	defer bc.Close()
	for {
		raw, err := wsReadFrame(bc.conn)
		if err != nil {
			return
		}
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		var msgType string
		if t, ok := msg["type"]; ok {
			_ = json.Unmarshal(t, &msgType)
		}
		var reqID string
		if id, ok := msg["id"]; ok {
			_ = json.Unmarshal(id, &reqID)
		}

		switch msgType {
		case "peer_result":
			bc.pendingMu.Lock()
			ch := bc.pending[reqID]
			bc.pendingMu.Unlock()
			if ch != nil {
				data := msg["data"]
				select {
				case ch <- bridgeReply{data: data}:
				default:
				}
			}
		case "peer_error":
			bc.pendingMu.Lock()
			ch := bc.pending[reqID]
			bc.pendingMu.Unlock()
			if ch != nil {
				errMsg := "peer command failed"
				if errObj, ok := msg["error"]; ok {
					var e map[string]string
					if json.Unmarshal(errObj, &e) == nil {
						if m := e["message"]; m != "" {
							errMsg = m
						}
					}
				}
				select {
				case ch <- bridgeReply{err: fmt.Errorf("%s", errMsg)}:
				default:
				}
			}
		case "pong":
			// ignore
		}
	}
}

func (bc *BridgeClient) writeJSON(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return wsWriteFrame(bc.conn, raw)
}

// ── Convenience wrappers ──────────────────────────────────────────────────────

// OpenTab opens an incognito tab to the given URL and returns the tab_id string.
func (bc *BridgeClient) OpenTab(url string, incognito bool) (string, error) {
	payload := map[string]any{
		"url":      url,
		"incognito": incognito,
	}
	raw, err := bc.SendCommand("open_tab", "", "serialized_page", payload, 30*time.Second)
	if err != nil {
		return "", err
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("open_tab bad json: %w", err)
	}
	tabID, _ := result["tab_id"].(string)
	if tabID == "" {
		// try float64 (JSON numbers)
		if n, ok := result["tab_id"].(float64); ok {
			tabID = fmt.Sprintf("%v", int(n))
		}
	}
	if tabID == "" {
		return "", fmt.Errorf("open_tab: no tab_id in response: %s", raw)
	}
	return tabID, nil
}

// CloseTab closes the given tab.
func (bc *BridgeClient) CloseTab(tabID string) error {
	_, err := bc.SendCommand("close_tab", tabID, "serialized_page", nil, 15*time.Second)
	return err
}

// Navigate navigates the tab to url.
func (bc *BridgeClient) Navigate(tabID, url string) error {
	payload := map[string]any{"url": url}
	_, err := bc.SendCommand("navigate", tabID, "serialized_page", payload, 30*time.Second)
	return err
}

// ExecuteJS runs script in the tab and returns the raw result value.
func (bc *BridgeClient) ExecuteJS(tabID, script string) (json.RawMessage, error) {
	payload := map[string]any{"script": script}
	raw, err := bc.SendCommand("execute_js", tabID, "serialized_page", payload, 30*time.Second)
	if err != nil {
		return nil, err
	}
	// result may be wrapped in {"result": ...}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(raw, &wrapper) == nil {
		if r, ok := wrapper["result"]; ok {
			return r, nil
		}
	}
	return raw, nil
}

// ExecuteJSBool runs script and interprets the result as a boolean.
func (bc *BridgeClient) ExecuteJSBool(tabID, script string) (bool, error) {
	raw, err := bc.ExecuteJS(tabID, script)
	if err != nil {
		return false, err
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	// truthy strings
	s := strings.TrimSpace(strings.Trim(string(raw), `"`))
	return s == "true" || s == "1", nil
}

// Scan returns the interactive elements on the page.
func (bc *BridgeClient) Scan(tabID string) (json.RawMessage, error) {
	payload := map[string]any{"mode": "interactive"}
	return bc.SendCommand("scan", tabID, "shared_read", payload, 30*time.Second)
}

// ClickRef clicks an element by its action ref.
func (bc *BridgeClient) ClickRef(tabID, ref string) error {
	payload := map[string]any{"ref": ref}
	_, err := bc.SendCommand("click_ref", tabID, "serialized_page", payload, 15*time.Second)
	return err
}

// FillRef fills an input by its action ref.
func (bc *BridgeClient) FillRef(tabID, ref, value string) error {
	payload := map[string]any{"ref": ref, "value": value}
	_, err := bc.SendCommand("fill_ref", tabID, "serialized_page", payload, 15*time.Second)
	return err
}

// WaitFor waits until the CSS selector appears.
func (bc *BridgeClient) WaitFor(tabID, selector string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	payload := map[string]any{
		"selector": selector,
		"timeout":  int(timeout.Milliseconds()),
	}
	_, err := bc.SendCommand("wait_for", tabID, "time_dependent_serialized", payload, timeout+5*time.Second)
	return err
}

// GetCookies returns all cookies for the tab.
func (bc *BridgeClient) GetCookies(tabID string) ([]map[string]any, error) {
	raw, err := bc.SendCommand("get_cookies", tabID, "shared_read", nil, 15*time.Second)
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	cookiesRaw, ok := result["cookies"]
	if !ok {
		return nil, nil
	}
	var cookies []map[string]any
	if err := json.Unmarshal(cookiesRaw, &cookies); err != nil {
		return nil, err
	}
	return cookies, nil
}

// ── Bridge token ──────────────────────────────────────────────────────────────

func readBridgeToken() (string, error) {
	if t := os.Getenv(bridgeTokenEnv); t != "" {
		return t, nil
	}
	path := os.Getenv(bridgeTokenFileEnv)
	if path == "" {
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			stateHome = filepath.Join(home, ".local", "state")
		}
		path = filepath.Join(stateHome, "browser-mcp", "bridge-token")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read bridge token file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// ── Minimal RFC 6455 WebSocket over net.Conn ─────────────────────────────────

// wsDialRaw performs an HTTP/1.1 WebSocket upgrade and returns the raw TCP
// connection.  We avoid importing a WebSocket library at the cost of a minimal
// hand-rolled upgrade; gobwas/ws is available in the module but brings in
// async complexity — the simple synchronous framing below is sufficient for
// our sequential command/response pattern.
func wsDialRaw(addr string) (net.Conn, *http.Response, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}

	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n",
		addr,
	)
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	// Read and validate the upgrade response (101 Switching Protocols).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ws upgrade read: %w", err)
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "101") {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ws upgrade failed: %s", strings.TrimSpace(resp))
	}

	return conn, nil, nil
}

// wsWriteFrame writes a single text frame.  op=0x81 (FIN + text).
// Frames sent by a client MUST be masked per RFC 6455 § 5.3.
func wsWriteFrame(conn net.Conn, payload []byte) error {
	length := len(payload)
	var header []byte
	header = append(header, 0x81) // FIN + opcode=text
	switch {
	case length <= 125:
		header = append(header, byte(0x80|length))
	case length <= 65535:
		header = append(header, 0x80|126, byte(length>>8), byte(length))
	default:
		header = append(header,
			0x80|127,
			byte(length>>56), byte(length>>48), byte(length>>40), byte(length>>32),
			byte(length>>24), byte(length>>16), byte(length>>8), byte(length),
		)
	}
	// masking key (all zeros — still valid per RFC 6455)
	mask := [4]byte{0x00, 0x00, 0x00, 0x00}
	header = append(header, mask[:]...)

	out := make([]byte, len(header)+length)
	copy(out, header)
	copy(out[len(header):], payload)
	// XOR with zero mask = no-op, but included for protocol compliance

	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := conn.Write(out)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// wsReadFrame reads one WebSocket frame and returns its payload.
// Only handles FIN frames; fragmented messages are not expected from this server.
func wsReadFrame(conn net.Conn) ([]byte, error) {
	// Read 2-byte base header
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	// hdr[0]: FIN(1) + RSV(3) + opcode(4)
	opcode := hdr[0] & 0x0F
	if opcode == 0x08 {
		return nil, io.EOF // close frame
	}
	// hdr[1]: MASK(1) + payload_len(7)
	masked := (hdr[1] & 0x80) != 0
	payLen := int(hdr[1] & 0x7F)

	switch payLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payLen = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payLen = 0
		for _, b := range ext {
			payLen = payLen<<8 | int(b)
		}
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(conn, maskKey[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return payload, nil
}
