package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/cpa"
	"github.com/grok-free-register/grok-reg/internal/daemon"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/logx"
	"github.com/grok-free-register/grok-reg/internal/pipeline"
	"github.com/grok-free-register/grok-reg/internal/state"
)

func main() {
	args := os.Args[1:]
	if daemon.IsWorker() {
		if err := runWorker(args); err != nil {
			fmt.Fprintf(os.Stderr, "worker error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(args) == 0 {
		printHelp()
		os.Exit(0)
	}
	cmd := args[0]
	switch cmd {
	case "start":
		if err := cmdStart(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := cmdStatus(); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "stop":
		if err := cmdStop(); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "logs":
		if err := cmdLogs(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "upload":
		if err := cmdUpload(); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "reoauth", "reauth", "relogin":
		if err := cmdReoauth(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "test-email":
		if err := cmdTestEmail(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "mcp-register", "mcpreg":
		if err := cmdMCPRegister(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printHelp()
	case "version", "-v", "--version":
		fmt.Println("grok-reg 0.1.0")
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Print(`grok — Grok 注册 + OAuth 二合一 CLI

用法:
  grok start [-t N]   后台启动注册机；N=目标账号数(1-10000)，默认 10
  grok status         查看运行状态与进度
  grok stop           立即停止注册机
  grok logs [-f]      查看最近一次运行日志；-f 实时跟踪
  grok upload         选择最近 run 的 CPA JSON 上传到 Management API
  grok reoauth <path> 对 inspection/CPA/accounts 重新签发并可自动上传 CPA
  grok test-email --email user@outlook.com
                      前台用指定邮箱注册一次，手动输入验证码并测试 OAuth/CPA
  grok mcp-register   通过 browser-mcp 真实 Chrome 注册一个账号（需扩展已连接）
  grok help           显示帮助

数据目录: ~/.grok/ (可用 GROK_HOME 覆盖)
输出:     ~/.grok/outputs/<yyyymmdd-HHMMSS>/{SSO,CPA}/
`)
}

func paths() (home.Paths, error) {
	p, err := home.Resolve()
	if err != nil {
		return p, err
	}
	if err := p.EnsureBase(); err != nil {
		return p, err
	}
	return p, nil
}

func cmdStart(args []string) error {
	target := 10
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" || a == "--target":
			if i+1 >= len(args) {
				return fmt.Errorf("-t 需要数字参数")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("无效目标: %s", args[i+1])
			}
			target, err = config.ClampTarget(n)
			if err != nil {
				return err
			}
			i++
		case strings.HasPrefix(a, "-t"):
			// -t10
			n, err := strconv.Atoi(strings.TrimPrefix(a, "-t"))
			if err != nil {
				return fmt.Errorf("无效 -t: %s", a)
			}
			target, err = config.ClampTarget(n)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("未知参数: %s", a)
		}
	}

	p, err := paths()
	if err != nil {
		return err
	}

	// already running?
	if pid, err := daemon.ReadPID(p.PID); err == nil && daemon.PIDAlive(pid) {
		return fmt.Errorf("注册机已经在运行 (PID %d)，先 grok status / grok stop", pid)
	}

	// config
	if _, err := os.Stat(p.Config); os.IsNotExist(err) {
		if _, err := config.InteractiveSetup(p.Config); err != nil {
			return err
		}
	}

	runID := home.NewRunID()
	// prepare log path early (dirs created fully in worker before first write)
	_ = os.MkdirAll(p.LogsDir, 0o700)
	logPath := filepath.Join(p.LogsDir, fmt.Sprintf("run-%s.log", runID))

	// seed state
	st := state.NewStore(p.State)
	_ = st.Set(func(s *state.Snapshot) {
		s.Status = state.StatusRunning
		s.RunID = runID
		s.Target = target
		s.Done = 0
		s.Phase = state.PhaseIdle
		s.PhaseDetail = "启动中"
		s.LogPath = logPath
		s.OutputDir = filepath.Join(p.Outputs, runID)
		s.Error = ""
		s.PID = 0
	})

	pid, err := daemon.StartBackground(target, runID)
	if err != nil {
		return err
	}
	if err := daemon.WritePID(p.PID, pid); err != nil {
		return err
	}
	_ = st.Set(func(s *state.Snapshot) { s.PID = pid })

	fmt.Printf("[✓] 注册机已后台启动\n")
	fmt.Printf("    PID:    %d\n", pid)
	fmt.Printf("    目标:   %d\n", target)
	fmt.Printf("    Run:    %s\n", runID)
	fmt.Printf("    日志:   %s\n", logPath)
	fmt.Printf("    输出:   %s\n", filepath.Join(p.Outputs, runID))
	fmt.Printf("    查看:   grok status  |  grok logs -f\n")
	return nil
}

func runWorker(args []string) error {
	target := 10
	runID := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--worker":
			continue
		case "--target":
			if i+1 < len(args) {
				n, _ := strconv.Atoi(args[i+1])
				if n > 0 {
					target = n
				}
				i++
			}
		case "--run-id":
			if i+1 < len(args) {
				runID = args[i+1]
				i++
			}
		}
	}
	target, err := config.ClampTarget(target)
	if err != nil {
		return err
	}

	p, err := paths()
	if err != nil {
		return err
	}
	// hold lock for process lifetime
	unlock, err := daemon.TryLock(p.Lock)
	if err != nil {
		return err
	}
	defer unlock()

	if err := daemon.WritePID(p.PID, os.Getpid()); err != nil {
		return err
	}
	defer daemon.ClearPID(p.PID)

	cfg, err := config.Load(p.Config)
	if err != nil {
		return err
	}
	cfg.Target = target

	run, err := p.PrepareRun(runID)
	if err != nil {
		return err
	}
	// open log: only file (daemon has no tty)
	log, err := logx.New(run.LogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	// worker: log to file only by reopening — logx multiwriter includes stdout; OK for journal

	st := state.NewStore(p.State)
	_ = st.Set(func(s *state.Snapshot) {
		s.Status = state.StatusRunning
		s.RunID = run.RunID
		s.Target = target
		s.PID = os.Getpid()
		s.LogPath = run.LogPath
		s.OutputDir = run.Root
	})

	ctx := context.Background()
	err = pipeline.Run(ctx, pipeline.Options{
		Cfg:    cfg,
		Paths:  p,
		Run:    run,
		Target: target,
		Log:    log,
		Store:  st,
	})
	if err != nil {
		_ = st.Set(func(s *state.Snapshot) {
			s.Status = state.StatusError
			s.Error = err.Error()
			s.PhaseDetail = "错误退出"
			s.PID = 0
		})
		log.Errf("%v", err)
		return err
	}
	return nil
}

func cmdStatus() error {
	p, err := paths()
	if err != nil {
		return err
	}
	st := state.NewStore(p.State)
	snap, err := st.Load()
	if err != nil && !os.IsNotExist(err) {
		// no state yet
		fmt.Println("状态: 未运行")
		return nil
	}
	if os.IsNotExist(err) {
		fmt.Println("状态: 未运行")
		return nil
	}
	// reconcile pid
	if snap.Status == state.StatusRunning {
		if snap.PID == 0 {
			if pid, e := daemon.ReadPID(p.PID); e == nil {
				snap.PID = pid
			}
		}
		if snap.PID != 0 && !daemon.PIDAlive(snap.PID) {
			snap.Status = state.StatusStopped
			snap.PhaseDetail = "进程已结束"
			snap.PID = 0
		}
	}
	fmt.Print(daemon.FormatStatus(snap))
	return nil
}

func cmdStop() error {
	p, err := paths()
	if err != nil {
		return err
	}
	if err := daemon.Stop(p); err != nil {
		return err
	}
	st := state.NewStore(p.State)
	_ = st.Set(func(s *state.Snapshot) {
		s.Status = state.StatusStopped
		s.Phase = state.PhaseIdle
		s.PhaseDetail = "已手动停止"
		s.PID = 0
	})
	fmt.Println("[✓] 注册机已停止")
	return nil
}

func cmdLogs(args []string) error {
	follow := false
	for _, a := range args {
		if a == "-f" || a == "--follow" {
			follow = true
		}
	}
	p, err := paths()
	if err != nil {
		return err
	}
	st := state.NewStore(p.State)
	snap, _ := st.Load()
	path := snap.LogPath
	if path == "" {
		// pick latest in logs dir
		path = latestLog(p.LogsDir)
	}
	if path == "" {
		return fmt.Errorf("没有日志文件")
	}
	if !follow {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	}
	fmt.Fprintf(os.Stderr, "跟踪 %s (Ctrl-C 退出)\n", path)
	var offset int64
	if fi, err := os.Stat(path); err == nil {
		// show last 4k first
		offset = fi.Size() - 4096
		if offset < 0 {
			offset = 0
		}
	}
	for {
		f, err := os.Open(path)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if _, err := f.Seek(offset, 0); err != nil {
			_ = f.Close()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		buf := make([]byte, 8192)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				_, _ = os.Stdout.Write(buf[:n])
				offset += int64(n)
			}
			if err != nil {
				break
			}
		}
		_ = f.Close()
		time.Sleep(400 * time.Millisecond)
	}
}

func latestLog(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestT time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "run-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(bestT) {
			bestT = info.ModTime()
			best = filepath.Join(dir, e.Name())
		}
	}
	return best
}

func cmdUpload() error {
	p, err := paths()
	if err != nil {
		return err
	}
	cfg, err := config.Load(p.Config)
	if err != nil {
		return err
	}
	// env overrides
	if v := os.Getenv("CPA_UPLOAD_ENABLED"); v != "" {
		cfg.CPAUploadEnabled = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := os.Getenv("CPA_MANAGEMENT_BASE"); v != "" {
		cfg.CPAManagementBase = v
	}
	if v := os.Getenv("CPA_MANAGEMENT_KEY"); v != "" {
		cfg.CPAManagementKey = v
	}
	// interactive upload always allowed if key+base set
	if strings.TrimSpace(cfg.CPAManagementKey) == "" {
		return fmt.Errorf("未配置 CPA_MANAGEMENT_KEY（在 ~/.grok/config.env 或环境变量中设置）")
	}
	if strings.TrimSpace(cfg.CPAManagementBase) == "" {
		cfg.CPAManagementBase = "http://localhost:8317/v0/management"
	}

	runs, err := cpa.ListRunDirs(p.Outputs, 10)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		return fmt.Errorf("outputs 下没有注册结果目录")
	}

	fmt.Println("最近注册 run（最多 10 个）:")
	type item struct {
		dir   string
		name  string
		files []string
	}
	var items []item
	for i, dir := range runs {
		files, _ := cpa.CollectCPAJSON(dir)
		name := filepath.Base(dir)
		items = append(items, item{dir: dir, name: name, files: files})
		fmt.Printf("  [%d] %s  CPA文件=%d\n", i+1, name, len(files))
	}
	fmt.Print("选择要上传的序号（如 1 或 1,2,3；回车取消）: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		fmt.Println("已取消")
		return nil
	}
	var selected []int
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// allow ranges? no — only comma list
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > len(items) {
			return fmt.Errorf("无效序号: %s", part)
		}
		selected = append(selected, n-1)
	}
	if len(selected) == 0 {
		fmt.Println("未选择")
		return nil
	}

	up := cpa.NewUploader(cpa.UploadConfig{
		Enabled:      true,
		BaseURL:      cfg.CPAManagementBase,
		Key:          cfg.CPAManagementKey,
		TimeoutSec:   cfg.CPAUploadTimeoutSec,
		Retries:      cfg.CPAUploadRetries,
		NameTemplate: cfg.CPAUploadNameTemplate,
		Verify:       cfg.CPAUploadVerify,
		Mode:         cfg.CPAUploadMode,
	}, func(f string, a ...any) {
		fmt.Printf(f+"\n", a...)
	})

	var okN, failN, skipN int
	for _, idx := range selected {
		it := items[idx]
		if len(it.files) == 0 {
			fmt.Printf("[!] %s 无 CPA json，跳过\n", it.name)
			skipN++
			continue
		}
		fmt.Printf("[*] 上传 %s (%d 个文件)...\n", it.name, len(it.files))
		for _, f := range it.files {
			res := up.UploadFile(f)
			if res.OK {
				okN++
			} else {
				failN++
			}
		}
	}
	fmt.Printf("[✓] 完成 ok=%d fail=%d skip_runs=%d\n", okN, failN, skipN)
	return nil
}
