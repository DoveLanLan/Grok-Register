// Package browsermcp implements the long-lived JSONL client used to control
// the browser-mcp CLI without reimplementing its shared bridge protocol.
package browsermcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Options struct {
	Command      string
	Args         []string
	SessionID    string
	SessionLabel string
	WorkingDir   string
	Tracef       func(string, ...any)
}

type Client struct {
	opt Options

	mu      sync.Mutex
	seq     uint64
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	waitCh  chan error
	started bool
}

type rpcResponse struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  *RemoteError    `json:"error"`
}

type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RemoteError) Error() string {
	if e == nil {
		return "browser-mcp command failed"
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

func New(opt Options) *Client {
	if strings.TrimSpace(opt.Command) == "" {
		opt.Command = "browser-mcp-cli"
	}
	if strings.TrimSpace(opt.SessionLabel) == "" {
		opt.SessionLabel = "grok-register"
	}
	return &Client{opt: opt}
}

func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	args := append([]string{}, c.opt.Args...)
	args = append(args, "rpc")
	if c.opt.SessionID != "" {
		args = append(args, "--session-id", c.opt.SessionID)
	}
	args = append(args, "--session-label", c.opt.SessionLabel)
	if c.opt.WorkingDir != "" {
		args = append(args, "--working-dir", c.opt.WorkingDir)
	}
	cmd := exec.CommandContext(ctx, c.opt.Command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("browser_mcp_cli_stdin: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("browser_mcp_cli_stdout: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("browser_mcp_cli_stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("browser_mcp_cli_start: %w", err)
	}

	c.cmd = cmd
	c.stdin = stdin
	c.stdout = bufio.NewReaderSize(stdoutPipe, 64<<10)
	c.waitCh = make(chan error, 1)
	c.started = true
	go func() { c.waitCh <- cmd.Wait() }()
	go c.readStderr(stderrPipe)

	var hello struct {
		ProtocolVersion int `json:"protocol_version"`
	}
	if err := c.callLocked(ctx, "hello", map[string]any{}, &hello); err != nil {
		c.stopLocked()
		return fmt.Errorf("browser_mcp_cli_hello: %w", err)
	}
	if hello.ProtocolVersion != 1 {
		c.stopLocked()
		return fmt.Errorf("browser_mcp_cli_protocol: got=%d want=1", hello.ProtocolVersion)
	}
	return nil
}

func (c *Client) Call(ctx context.Context, method string, params map[string]any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return fmt.Errorf("browser_mcp_cli_not_started")
	}
	return c.callLocked(ctx, method, params, out)
}

func (c *Client) callLocked(ctx context.Context, method string, params map[string]any, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.seq++
	id := fmt.Sprintf("grok-%d", c.seq)
	request := map[string]any{
		"id":     id,
		"method": method,
		"params": params,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if _, err := c.stdin.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("browser_mcp_cli_write: %w", err)
	}

	type readResult struct {
		line string
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		line, readErr := c.stdout.ReadString('\n')
		readCh <- readResult{line: line, err: readErr}
	}()

	var line string
	select {
	case <-ctx.Done():
		c.stopLocked()
		return ctx.Err()
	case result := <-readCh:
		if result.err != nil {
			if errors.Is(result.err, io.EOF) {
				return fmt.Errorf("browser_mcp_cli_closed")
			}
			return fmt.Errorf("browser_mcp_cli_read: %w", result.err)
		}
		line = result.line
	}

	var response rpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &response); err != nil {
		return fmt.Errorf("browser_mcp_cli_protocol: %w", err)
	}
	if response.ID != id {
		return fmt.Errorf("browser_mcp_cli_protocol: response id=%q want=%q", response.ID, id)
	}
	if !response.OK {
		if response.Error == nil {
			return fmt.Errorf("browser_mcp_cli_command_failed")
		}
		return response.Error
	}
	if out != nil && len(response.Result) > 0 && string(response.Result) != "null" {
		if err := json.Unmarshal(response.Result, out); err != nil {
			return fmt.Errorf("browser_mcp_cli_result: %w", err)
		}
	}
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	select {
	case err := <-c.waitCh:
		c.clearLocked()
		return err
	case <-time.After(3 * time.Second):
		c.stopLocked()
		return fmt.Errorf("browser_mcp_cli_exit_timeout")
	}
}

func (c *Client) stopLocked() {
	if c.cmd != nil && c.cmd.Process != nil {
		_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
	}
	c.clearLocked()
}

func (c *Client) clearLocked() {
	c.started = false
	c.cmd = nil
	c.stdin = nil
	c.stdout = nil
	c.waitCh = nil
}

func (c *Client) readStderr(r io.Reader) {
	if c.opt.Tracef == nil {
		_, _ = io.Copy(io.Discard, r)
		return
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			c.opt.Tracef("browser-mcp-cli: %s", line)
		}
	}
}
