package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/daemon"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/logx"
	"github.com/grok-free-register/grok-reg/internal/pipeline"
)

type testEmailArgs struct {
	Email string
	Help  bool
}

func cmdTestEmail(args []string) error {
	parsed, err := parseTestEmailArgs(args)
	if err != nil {
		return err
	}
	if parsed.Help {
		printTestEmailHelp()
		return nil
	}
	if err := validateTestEmail(parsed.Email); err != nil {
		return err
	}

	p, err := paths()
	if err != nil {
		return err
	}
	if pid, readErr := daemon.ReadPID(p.PID); readErr == nil && daemon.PIDAlive(pid) {
		return fmt.Errorf("后台注册机正在运行 (PID %d)，请先执行 grok stop", pid)
	}
	unlock, err := daemon.TryLock(p.Lock)
	if err != nil {
		return err
	}
	defer unlock()

	cfg, err := config.Load(p.Config)
	if err != nil {
		return err
	}
	runID := "test-" + home.NewRunID()
	run, err := p.PrepareRun(runID)
	if err != nil {
		return err
	}
	log, err := logx.New(run.LogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	fmt.Printf("前台单邮箱测试\n")
	fmt.Printf("  邮箱: %s\n", parsed.Email)
	fmt.Printf("  Run:  %s\n", run.RunID)
	fmt.Printf("  日志: %s\n", run.LogPath)
	fmt.Printf("  输出: %s\n", run.Root)
	fmt.Println("  提示: 请使用尚未注册过 x.ai 的真实邮箱；无需提供邮箱密码。")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result, err := pipeline.RunSingleEmail(ctx, pipeline.SingleEmailOptions{
		Cfg:      cfg,
		Paths:    p,
		Run:      run,
		Email:    parsed.Email,
		ReadCode: terminalCodeReader(os.Stdin, os.Stdout),
		Log:      log,
	})
	if err != nil {
		return fmt.Errorf("测试未通过（产物保留在 %s）: %w", run.Root, err)
	}

	if result.Probed {
		fmt.Printf("\n[✓] 测试通过：注册、OAuth 和 CPA 探活均成功\n")
	} else {
		fmt.Printf("\n[✓] 注册和 OAuth 成功，CPA 已生成（PROBE_ENABLED=0，未探活）\n")
	}
	fmt.Printf("    邮箱: %s\n", result.Email)
	fmt.Printf("    CPA:  %s\n", result.CPAPath)
	return nil
}

func parseTestEmailArgs(args []string) (testEmailArgs, error) {
	var parsed testEmailArgs
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			parsed.Help = true
		case a == "-e" || a == "--email":
			if i+1 >= len(args) {
				return parsed, fmt.Errorf("%s 需要邮箱参数", a)
			}
			if parsed.Email != "" {
				return parsed, fmt.Errorf("--email 只能指定一次")
			}
			parsed.Email = strings.TrimSpace(args[i+1])
			i++
		case strings.HasPrefix(a, "--email="):
			if parsed.Email != "" {
				return parsed, fmt.Errorf("--email 只能指定一次")
			}
			parsed.Email = strings.TrimSpace(strings.TrimPrefix(a, "--email="))
		default:
			return parsed, fmt.Errorf("未知参数: %s", a)
		}
	}
	if !parsed.Help && parsed.Email == "" {
		return parsed, fmt.Errorf("缺少 --email，例如: grok test-email --email user@outlook.com")
	}
	return parsed, nil
}

func validateTestEmail(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("邮箱格式无效")
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(addr.Address, value) || !strings.Contains(value, "@") {
		return fmt.Errorf("邮箱格式无效: %s", value)
	}
	return nil
}

func terminalCodeReader(in io.Reader, out io.Writer) func(context.Context) (string, error) {
	reader := bufio.NewReader(in)
	return func(ctx context.Context) (string, error) {
		fmt.Fprintln(out, "\n验证码已发送。请打开邮箱查看 x.ai 邮件。")
		fmt.Fprint(out, "输入 6 位验证码（如 ABC-123）: ")
		type readResult struct {
			value string
			err   error
		}
		ch := make(chan readResult, 1)
		go func() {
			line, err := reader.ReadString('\n')
			if err == io.EOF && strings.TrimSpace(line) != "" {
				err = nil
			}
			ch <- readResult{value: strings.TrimSpace(line), err: err}
		}()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case result := <-ch:
			return result.value, result.err
		}
	}
}

func printTestEmailHelp() {
	fmt.Print(`用法:
  grok test-email --email user@outlook.com

说明:
  向指定邮箱发送一次 x.ai 验证码，并在当前终端等待输入。
  随后依次执行注册、OAuth Device Flow、CPA 探活和本地写入。
  请使用尚未注册过 x.ai 的真实邮箱；不会读取或保存邮箱密码。
`)
}
