package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/daemon"
	"github.com/grok-free-register/grok-reg/internal/email"
)

func cmdOutlook(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printOutlookHelp()
		return nil
	}
	switch args[0] {
	case "import":
		return cmdOutlookImport(args[1:])
	case "check", "preview":
		if len(args) != 1 {
			return fmt.Errorf("用法: grok outlook check")
		}
		return cmdOutlookCheck()
	case "allocate", "next":
		if len(args) != 1 {
			return fmt.Errorf("用法: grok outlook allocate")
		}
		return cmdOutlookAllocate()
	default:
		return fmt.Errorf("未知 outlook 子命令: %s", args[0])
	}
}

func cmdOutlookImport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法: grok outlook import <账号文件>")
	}
	p, err := paths()
	if err != nil {
		return err
	}
	if pid, readErr := daemon.ReadPID(p.PID); readErr == nil && daemon.PIDAlive(pid) {
		return fmt.Errorf("后台注册机正在运行 (PID %d)，请先执行 grok stop", pid)
	}
	source, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(source); statErr != nil {
		return statErr
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("账号文件不是普通文件: %s", source)
	}
	count, err := email.ImportOutlookAccounts(source, p.OutlookAccounts)
	if err != nil {
		return err
	}
	fmt.Printf("[✓] 已导入 %d 个 Outlook 主邮箱\n", count)
	fmt.Printf("    账号池: %s\n", p.OutlookAccounts)
	fmt.Printf("    状态:   %s\n", p.OutlookState)
	fmt.Println("    请在 config.env 设置 EMAIL_MODE=outlook；默认每个主邮箱使用 5 个地址。")
	return nil
}

func cmdOutlookCheck() error {
	provider, err := configuredOutlookProvider()
	if err != nil {
		return err
	}
	previews, err := provider.OutlookPreviews()
	if err != nil {
		return err
	}
	total := 0
	fmt.Printf("Outlook 随机 plus-tag 预览（不会消耗游标）\n")
	for _, preview := range previews {
		total += preview.Remaining
		if preview.NextEmail == "" {
			fmt.Printf("  %s: 已耗尽\n", preview.MainEmail)
			continue
		}
		fmt.Printf("  %s -> %s", preview.MainEmail, preview.NextEmail)
		if preview.FollowingEmail != "" {
			fmt.Printf("；下一个将是 %s", preview.FollowingEmail)
		}
		fmt.Printf("（剩余 %d）\n", preview.Remaining)
	}
	fmt.Printf("共 %d 个主邮箱，剩余 %d 个可分配地址。\n", len(previews), total)
	return nil
}

func cmdOutlookAllocate() error {
	p, err := paths()
	if err != nil {
		return err
	}
	if pid, readErr := daemon.ReadPID(p.PID); readErr == nil && daemon.PIDAlive(pid) {
		return fmt.Errorf("后台注册机正在运行 (PID %d)，请先执行 grok stop", pid)
	}
	provider, err := configuredOutlookProvider()
	if err != nil {
		return err
	}
	handle, err := provider.Create()
	if err != nil {
		return err
	}
	provider.Release(handle)
	remaining, _ := provider.OutlookRemaining()
	fmt.Printf("[✓] 已分配 %s\n", handle.Email)
	fmt.Printf("    主邮箱: %s\n", handle.MainEmail)
	fmt.Printf("    池内剩余: %d\n", remaining)
	return nil
}

func configuredOutlookProvider() (*email.Provider, error) {
	p, err := paths()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(p.Config)
	if err != nil {
		return nil, err
	}
	accountsPath := strings.TrimSpace(cfg.OutlookAccountsFile)
	if accountsPath == "" {
		accountsPath = p.OutlookAccounts
	}
	statePath := strings.TrimSpace(cfg.OutlookStateFile)
	if statePath == "" {
		statePath = p.OutlookState
	}
	provider := email.New(email.Config{
		Mode:                     config.EmailOutlook,
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         statePath,
		OutlookAliasesPerAccount: cfg.OutlookAliasesPerAccount,
	})
	if err := provider.Validate(); err != nil {
		return nil, err
	}
	return provider, nil
}

func printOutlookHelp() {
	fmt.Print(`grok outlook — Outlook/Hotmail plus-address 别名池

用法:
  grok outlook import <账号文件>
  grok outlook check
  grok outlook allocate

账号文件每行格式（与 grok-register-web 兼容）:
  邮箱----密码----ClientID----RefreshToken

说明:
  - 邮箱密码只保留以兼容导入格式，程序通过 OAuth token 收信。
  - 每次分配 主邮箱+<10位随机字母数字>，例如 user+k7m2q9x4ab@outlook.com。
  - 随机种子保存在 outlook-state.json；check、allocate 和重启后的结果保持一致。
  - Graph、Outlook REST、IMAP XOAUTH2 会自动探测并回落。
  - check 只预览下一个地址，不消耗持久化别名游标。
  - allocate 分配下一个地址并推进持久化游标。
  - 导入后在 ~/.grok/config.env 设置 EMAIL_MODE=outlook。
`)
}
