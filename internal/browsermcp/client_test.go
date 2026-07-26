package browsermcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClientLongLivedJSONL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := New(Options{
		Command:   os.Args[0],
		Args:      []string{"-test.run=TestBrowserMCPHelperProcess", "--"},
		SessionID: "test-session",
	})
	t.Setenv("GO_WANT_BROWSER_MCP_HELPER", "1")
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	var nav struct {
		TabID     string `json:"tab_id"`
		Incognito bool   `json:"incognito"`
	}
	if err := client.Call(ctx, "navigate", map[string]any{
		"url":       "https://example.test",
		"incognito": true,
	}, &nav); err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if nav.TabID != "77" || !nav.Incognito {
		t.Fatalf("navigate result = %+v", nav)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestClientReturnsRemoteError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := New(Options{
		Command: os.Args[0],
		Args:    []string{"-test.run=TestBrowserMCPHelperProcess", "--"},
	})
	t.Setenv("GO_WANT_BROWSER_MCP_HELPER", "1")
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err := client.Call(ctx, "fail", map[string]any{}, nil)
	remote, ok := err.(*RemoteError)
	if !ok || remote.Code != "synthetic_failure" {
		t.Fatalf("error = %#v", err)
	}
}

func TestBrowserMCPHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_BROWSER_MCP_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req struct {
			ID     string         `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			os.Exit(2)
		}
		var response any
		switch req.Method {
		case "hello":
			response = map[string]any{"id": req.ID, "ok": true, "result": map[string]any{"protocol_version": 1}}
		case "navigate":
			response = map[string]any{"id": req.ID, "ok": true, "result": map[string]any{"tab_id": "77", "incognito": req.Params["incognito"]}}
		case "fail":
			response = map[string]any{"id": req.ID, "ok": false, "error": map[string]any{"code": "synthetic_failure", "message": "expected"}}
		default:
			fmt.Fprintln(os.Stderr, "unexpected method: "+strings.TrimSpace(req.Method))
			os.Exit(3)
		}
		if err := encoder.Encode(response); err != nil {
			os.Exit(4)
		}
	}
	os.Exit(0)
}
