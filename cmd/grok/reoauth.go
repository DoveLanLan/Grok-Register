package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/cpa"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/reoauth"
)

func cmdReoauth(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(`grok reoauth — 对已有账号重新拿 CPA 凭证

用法:
  grok reoauth <path> [选项]

<path> 支持 inspection JSON、单个 CPA JSON、CPA/run 目录、
accounts.txt 或 auth-sessions.jsonl。

策略:
  1) 有 refresh_token：直接刷新，无需邮箱验证码
  2) 否则有 SSO：重新执行 Device OAuth
  3) 只有 email：从 ~/.grok/outputs 查找历史 CPA/SSO
  4) 配置 CPA_UPLOAD_ENABLED 和管理密钥后，成功文件自动上传

选项:
  --thread N / -j N   并发数（1-8，默认 2）
  --out DIR / -o DIR  CPA 输出目录
  --no-lookup         不扫描历史 outputs
  --no-probe          不做 CPA 探活
  --interval SEC      请求最小间隔（默认 2 秒）
  --upload             强制上传（仍需 CPA_MANAGEMENT_KEY）
  --no-upload          禁止上传
`)
		return nil
	}

	inputPath := ""
	threads := 2
	outDir := ""
	lookup := true
	probe := true
	intervalSec := 2.0
	uploadForce := false
	uploadOff := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--thread" || arg == "-j":
			if i+1 >= len(args) {
				return fmt.Errorf("%s 需要数字", arg)
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 || n > 8 {
				return fmt.Errorf("无效线程: %s", args[i+1])
			}
			threads = n
			i++
		case strings.HasPrefix(arg, "--thread="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--thread="))
			if err != nil || n < 1 || n > 8 {
				return fmt.Errorf("无效线程: %s", arg)
			}
			threads = n
		case arg == "--out" || arg == "-o":
			if i+1 >= len(args) {
				return fmt.Errorf("%s 需要目录", arg)
			}
			outDir = args[i+1]
			i++
		case strings.HasPrefix(arg, "--out="):
			outDir = strings.TrimPrefix(arg, "--out=")
		case arg == "--no-lookup":
			lookup = false
		case arg == "--no-probe":
			probe = false
		case arg == "--upload":
			uploadForce = true
		case arg == "--no-upload":
			uploadOff = true
		case arg == "--interval":
			if i+1 >= len(args) {
				return fmt.Errorf("--interval 需要秒数")
			}
			value, err := strconv.ParseFloat(args[i+1], 64)
			if err != nil || value < 0 {
				return fmt.Errorf("无效 interval: %s", args[i+1])
			}
			intervalSec = value
			i++
		case strings.HasPrefix(arg, "--interval="):
			value, err := strconv.ParseFloat(strings.TrimPrefix(arg, "--interval="), 64)
			if err != nil || value < 0 {
				return fmt.Errorf("无效 interval: %s", arg)
			}
			intervalSec = value
		case arg == "-h" || arg == "--help":
			return cmdReoauth(nil)
		case strings.HasPrefix(arg, "-"):
			return fmt.Errorf("未知参数: %s（见 grok reoauth -h）", arg)
		default:
			if inputPath != "" {
				return fmt.Errorf("多余参数: %s", arg)
			}
			inputPath = arg
		}
	}
	if inputPath == "" {
		return fmt.Errorf("需要 path（见 grok reoauth -h）")
	}
	absPath, err := filepath.Abs(inputPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("路径不存在: %s", absPath)
	}

	pathsValue, err := paths()
	if err != nil {
		return err
	}
	cfg, err := config.Load(pathsValue.Config)
	if err != nil {
		return err
	}
	if value := os.Getenv("CPA_UPLOAD_ENABLED"); value != "" {
		cfg.CPAUploadEnabled = value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
	}
	if value := os.Getenv("CPA_MANAGEMENT_BASE"); value != "" {
		cfg.CPAManagementBase = value
	}
	if value := os.Getenv("CPA_MANAGEMENT_KEY"); value != "" {
		cfg.CPAManagementKey = value
	}

	accounts, err := reoauth.ParsePath(absPath)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return fmt.Errorf("未解析到任何账号: %s", absPath)
	}
	fmt.Printf("[*] 解析到 %d 个账号 from %s\n", len(accounts), absPath)

	if outDir == "" {
		runDirs, err := pathsValue.PrepareRun("reoauth-" + home.NewRunID())
		if err != nil {
			return err
		}
		outDir = runDirs.CPA
		fmt.Printf("[*] 输出目录: %s\n", runDirs.Root)
	} else {
		outDir, _ = filepath.Abs(outDir)
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return err
		}
		fmt.Printf("[*] 输出 CPA: %s\n", outDir)
	}

	var lookupRoots []string
	if lookup {
		lookupRoots = []string{pathsValue.Outputs}
	}
	proxy := strings.TrimSpace(cfg.RegisterProxy)
	if proxy == "" {
		proxy = strings.TrimSpace(cfg.HTTPSProxy)
	}

	uploadEnabled := cfg.CPAUploadEnabled || uploadForce
	if uploadOff {
		uploadEnabled = false
	}
	var uploader *cpa.Uploader
	if uploadEnabled {
		if strings.TrimSpace(cfg.CPAManagementKey) == "" {
			fmt.Println("[!] CPA 上传已启用但未配置 CPA_MANAGEMENT_KEY，跳过")
		} else {
			baseURL := strings.TrimSpace(cfg.CPAManagementBase)
			if baseURL == "" {
				baseURL = "http://127.0.0.1:8317/v0/management"
			}
			uploader = cpa.NewUploader(cpa.UploadConfig{
				Enabled:      true,
				BaseURL:      baseURL,
				Key:          cfg.CPAManagementKey,
				TimeoutSec:   cfg.CPAUploadTimeoutSec,
				Retries:      cfg.CPAUploadRetries,
				NameTemplate: cfg.CPAUploadNameTemplate,
				Verify:       cfg.CPAUploadVerify,
				Mode:         cfg.CPAUploadMode,
			}, func(format string, values ...any) {
				fmt.Printf("[cpa] "+format+"\n", values...)
			})
			fmt.Printf("[*] CPA 自动入库: %s\n", cpa.NormalizeManagementBase(baseURL))
		}
	}

	_, err = reoauth.Run(context.Background(), accounts, reoauth.Options{
		Proxy:       proxy,
		OutCPA:      outDir,
		Workers:     threads,
		MinInterval: time.Duration(intervalSec * float64(time.Second)),
		Probe:       probe,
		ProbeWarmup: 3,
		LookupRoots: lookupRoots,
		Secret:      cpa.DefaultSecret(),
		Uploader:    uploader,
		OutLog: func(format string, values ...any) {
			fmt.Printf(format+"\n", values...)
		},
	})
	return err
}
