package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/daemon"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/logx"
	"github.com/grok-free-register/grok-reg/internal/pipeline"
	"github.com/grok-free-register/grok-reg/internal/state"
)

// cmdMCPRegister runs the normal one-account pipeline in browser-mcp mode. It
// intentionally does not own a second registration/OAuth/CPA implementation.
func cmdMCPRegister(args []string) error {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Print(`grok mcp-register — 通过 browser-mcp 真实 Chrome 注册一个账号

用法:
  grok mcp-register

需要:
  - browser-mcp bridge/扩展已连接
  - browser-mcp-cli 已安装，或在 config.env 配置 BROWSER_MCP_CLI
  - Chrome 扩展已启用 Allow in Incognito

行为:
  使用完整 pipeline 创建邮箱、注册、同会话 OAuth、CPA 探活/上传。
  每个账号使用无痕窗口；注册前及关窗前清除 x.ai/Grok 登录 Cookie。
`)
			return nil
		}
		return fmt.Errorf("未知参数: %s", arg)
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

	if _, statErr := os.Stat(p.Config); os.IsNotExist(statErr) {
		if _, setupErr := config.InteractiveSetup(p.Config); setupErr != nil {
			return setupErr
		}
	}
	cfg, err := config.Load(p.Config)
	if err != nil {
		return err
	}
	cfg.RegisterMode = "browser-mcp"
	cfg.Target = 1

	runID := "mcp-" + home.NewRunID()
	run, err := p.PrepareRun(runID)
	if err != nil {
		return err
	}
	log, err := logx.New(run.LogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	store := state.NewStore(p.State)

	fmt.Printf("browser-mcp 前台注册\n")
	fmt.Printf("  Run:        %s\n", run.RunID)
	fmt.Printf("  CLI:        %s\n", cfg.BrowserMCPCommand)
	fmt.Printf("  Incognito:  %v\n", cfg.BrowserMCPIncognito)
	fmt.Printf("  日志:       %s\n", run.LogPath)
	fmt.Printf("  输出:       %s\n", run.Root)
	fmt.Println("  提示: Cloudflare 要求交互时，请在弹出的真实 Chrome 无痕窗口中完成。")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := pipeline.Run(ctx, pipeline.Options{
		Cfg:    cfg,
		Paths:  p,
		Run:    run,
		Target: 1,
		Log:    log,
		Store:  store,
	}); err != nil {
		return fmt.Errorf("browser-mcp 注册失败（产物保留在 %s）: %w", run.Root, err)
	}

	fmt.Printf("\n[✓] browser-mcp 注册流程完成\n")
	fmt.Printf("    CPA: %s\n", filepath.Join(run.Root, "CPA"))
	fmt.Println("    账号无痕窗口已关闭，下一次注册不会继承本账号登录态。")
	return nil
}
