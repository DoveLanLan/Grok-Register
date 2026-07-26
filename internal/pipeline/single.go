package pipeline

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/clearance"
	"github.com/grok-free-register/grok-reg/internal/config"
	"github.com/grok-free-register/grok-reg/internal/cpa"
	"github.com/grok-free-register/grok-reg/internal/home"
	"github.com/grok-free-register/grok-reg/internal/logx"
	"github.com/grok-free-register/grok-reg/internal/oauth"
	"github.com/grok-free-register/grok-reg/internal/protocol"
	"github.com/grok-free-register/grok-reg/internal/signup"
	"github.com/grok-free-register/grok-reg/internal/turnstile"
)

// SingleEmailOptions configures the foreground, manually verified one-account
// flow. ReadCode is called only after x.ai accepts the request to send a code.
type SingleEmailOptions struct {
	Cfg      config.Config
	Run      home.RunDirs
	Email    string
	ReadCode func(context.Context) (string, error)
	Log      *logx.Logger
}

// SingleEmailResult identifies the local artifacts produced by a successful
// foreground test. Passwords and tokens are deliberately not returned.
type SingleEmailResult struct {
	Email   string
	CPAPath string
	Probed  bool
}

// RunSingleEmail registers one caller-owned mailbox, exchanges its SSO session
// through OAuth Device Flow, probes the credential, and writes a CPA document.
func RunSingleEmail(ctx context.Context, opt SingleEmailOptions) (SingleEmailResult, error) {
	if strings.TrimSpace(opt.Email) == "" {
		return SingleEmailResult{}, fmt.Errorf("邮箱不能为空")
	}
	if opt.ReadCode == nil {
		return SingleEmailResult{}, fmt.Errorf("未配置验证码输入")
	}
	if opt.Log == nil {
		return SingleEmailResult{}, fmt.Errorf("未配置日志")
	}

	config.ApplyProxyEnv(opt.Cfg)
	log := opt.Log

	var cm *clearance.Manager
	if opt.Cfg.ClearanceEnabled {
		cm = clearance.NewManager(opt.Cfg.FlareSolverrURL, opt.Cfg.ClearanceProxy, opt.Cfg.ClearanceURLs)
		msg, err := cm.Prewarm()
		if err != nil {
			log.Warnf("clearance: %v (%s)", err, msg)
		} else {
			log.Infof("[clearance] %s", msg)
		}
	} else {
		log.Info("[clearance] 未启用")
	}

	xai, err := protocol.NewClient(opt.Cfg.RegisterProxy, cm)
	if err != nil {
		return SingleEmailResult{}, fmt.Errorf("初始化注册客户端: %w", err)
	}
	turn := turnstile.New(turnstile.Options{
		Provider: opt.Cfg.TurnstileProvider,
		LiteURL:  opt.Cfg.LiteSolverURL,
		Proxy:    opt.Cfg.RegisterProxy,
		Clear:    cm,
	})
	if closer, ok := turn.(turnstile.Closer); ok {
		defer closer.Close()
	}

	password, err := singleAccountPassword()
	if err != nil {
		return SingleEmailResult{}, fmt.Errorf("生成账号密码: %w", err)
	}

	regMode := strings.ToLower(strings.TrimSpace(opt.Cfg.RegisterMode))
	if regMode == "" {
		regMode = "browser"
	}

	var sso string
	var sameSessionCred *oauth.Credential
	if isBrowserRegisterMode(regMode) {
		var sb signup.Driver
		if regMode == "browser-mcp" {
			workingDir, _ := os.Getwd()
			log.Infof("Register mode=browser-mcp cli=%s incognito=%v", opt.Cfg.BrowserMCPCommand, opt.Cfg.BrowserMCPIncognito)
			sb = signup.NewMCPBrowser(signup.MCPBrowserOptions{
				Command:       opt.Cfg.BrowserMCPCommand,
				Incognito:     opt.Cfg.BrowserMCPIncognito,
				Timeout:       time.Duration(opt.Cfg.SignupBrowserTimeoutSec * float64(time.Second)),
				CodeTimeout:   120 * time.Second,
				DiagnosticDir: filepath.Join(opt.Run.Root, "signup-browser-mcp"),
				WorkingDir:    workingDir,
				Tracef:        log.Infof,
			})
		} else {
			log.Infof("Register mode=browser script=%s", signup.DetectedScript())
			sb = signup.NewBrowser(signup.BrowserOptions{
				Proxy:         opt.Cfg.RegisterProxy,
				Timeout:       time.Duration(opt.Cfg.SignupBrowserTimeoutSec * float64(time.Second)),
				CodeTimeout:   120 * time.Second,
				DiagnosticDir: filepath.Join(opt.Run.Root, "signup-browser"),
				Tracef:        log.Infof,
			})
		}
		sb.SetProxy(opt.Cfg.RegisterProxy)
		// ReadCode runs only after the browser reaches the verification-code step.
		poll := func(pctx context.Context) (string, error) {
			log.Startf("等待邮箱验证码输入 %s", opt.Email)
			code, err := opt.ReadCode(pctx)
			if err != nil {
				return "", err
			}
			code, err = normalizeVerificationCode(code)
			if err != nil {
				return "", err
			}
			return code, nil
		}

		verificationURL := ""
		var oauthClient *oauth.Client
		type pollResult struct {
			cred oauth.Credential
			err  error
		}
		var pollCh chan pollResult
		var cancelPoll context.CancelFunc
		if regMode == "browser-mcp" {
			oauthClient, err = oauth.NewClient(
				opt.Cfg.RegisterProxy,
				cm,
				time.Duration(opt.Cfg.OAuthRetrySec*float64(time.Second)),
				oauth.Options{ConfirmMode: "http", Tracef: log.Infof},
			)
			if err != nil {
				return SingleEmailResult{}, fmt.Errorf("初始化 OAuth: %w", err)
			}
			flow, flowErr := oauthClient.StartDeviceFlow(ctx)
			if flowErr != nil {
				return SingleEmailResult{}, fmt.Errorf("启动 OAuth Device Flow: %w", flowErr)
			}
			verificationURL = flow.VerificationURL
			var pollCtx context.Context
			pollCtx, cancelPoll = context.WithCancel(ctx)
			defer cancelPoll()
			pollCh = make(chan pollResult, 1)
			go func() {
				cred, pollErr := oauthClient.PollToken(pollCtx, flow)
				pollCh <- pollResult{cred: cred, err: pollErr}
			}()
		}

		log.Startf("浏览器注册 %s", opt.Email)
		result, regErr := sb.RegisterWithOAuth(ctx, opt.Email, password, "", "", verificationURL, poll)
		if regErr != nil || !result.OK {
			if cancelPoll != nil {
				cancelPoll()
			}
			return SingleEmailResult{}, fmt.Errorf("浏览器注册失败: %v", regErr)
		}
		sso = strings.TrimSpace(result.SSO)
		if regMode == "browser-mcp" {
			if !result.OAuthAuthorized {
				cancelPoll()
				return SingleEmailResult{}, fmt.Errorf("真实浏览器注册成功，但同会话 OAuth 未批准")
			}
			select {
			case <-ctx.Done():
				cancelPoll()
				return SingleEmailResult{}, ctx.Err()
			case polled := <-pollCh:
				cancelPoll()
				if polled.err != nil {
					return SingleEmailResult{}, fmt.Errorf("OAuth token 轮询失败: %w", polled.err)
				}
				sameSessionCred = &polled.cred
			case <-time.After(2 * time.Minute):
				cancelPoll()
				return SingleEmailResult{}, fmt.Errorf("OAuth token 轮询超时")
			}
		}
	} else {
		log.Info("获取 x.ai 注册配置...")
		signupCfg, err := xai.FetchConfig()
		if err != nil {
			return SingleEmailResult{}, fmt.Errorf("获取注册配置: %w", err)
		}
		log.Infof("注册配置就绪 SITE_KEY=%s ACTION_ID=%s...", signupCfg.SiteKey, trim(signupCfg.ActionID, 12))

		log.Startf("发送验证码到 %s", opt.Email)
		if err := xai.CreateEmailCode(opt.Email); err != nil {
			return SingleEmailResult{}, fmt.Errorf("发送验证码: %w", err)
		}
		code, err := opt.ReadCode(ctx)
		if err != nil {
			return SingleEmailResult{}, fmt.Errorf("读取验证码: %w", err)
		}
		code, err = normalizeVerificationCode(code)
		if err != nil {
			return SingleEmailResult{}, err
		}

		log.Startf("获取 Turnstile token (%s)", turn.Name())
		token, err := turn.Solve(ctx, signupCfg.SiteKey, protocol.SiteURL+"/sign-up")
		if err != nil {
			return SingleEmailResult{}, fmt.Errorf("Turnstile: %w", err)
		}
		log.Infof("Turnstile token ok (len=%d)", len(token))

		xai.ClearAuthCookies()
		log.Startf("验证邮箱并注册 %s", opt.Email)
		if err := xai.VerifyEmailCode(opt.Email, code); err != nil {
			return SingleEmailResult{}, fmt.Errorf("验证邮箱验证码: %w", err)
		}
		body := protocol.BuildSignupBody(opt.Email, password, code, token)
		text, ssoVal, signupErr := xai.SignupServerAction(body, signupCfg.ActionID, signupCfg.StateTree)
		if ssoVal == "" {
			ssoVal = protocol.ExtractSSOFromText(text)
		}
		if signupErr != nil || ssoVal == "" {
			preview := strings.TrimSpace(text)
			if len(preview) > 180 {
				preview = preview[:180]
			}
			return SingleEmailResult{}, fmt.Errorf("注册失败: err=%v sso=%v body=%q", signupErr, ssoVal != "", preview)
		}
		sso = ssoVal
	}

	if err := cpa.AppendSSO(filepath.Join(opt.Run.SSO, "accounts.txt"), opt.Email, password, sso); err != nil {
		return SingleEmailResult{}, fmt.Errorf("保存 SSO: %w", err)
	}
	if sso != "" {
		if err := cpa.AppendAuthSession(filepath.Join(opt.Run.SSO, "auth-sessions.jsonl"), opt.Email, sso); err != nil {
			return SingleEmailResult{}, fmt.Errorf("保存认证会话: %w", err)
		}
	}
	log.OKf("注册成功 %s，SSO 已保存", opt.Email)
	log.Info("等待 2s 让新 SSO 会话生效...")
	select {
	case <-ctx.Done():
		return SingleEmailResult{}, ctx.Err()
	case <-time.After(2 * time.Second):
	}

	var cred oauth.Credential
	if sameSessionCred != nil {
		cred = *sameSessionCred
		log.OKf("OAuth token 获取成功 %s（browser-mcp 同会话）", opt.Email)
	} else {
		oauthClient, err := oauth.NewClient(
			opt.Cfg.RegisterProxy,
			cm,
			time.Duration(opt.Cfg.OAuthRetrySec*float64(time.Second)),
			oauth.Options{
				ConfirmMode:          opt.Cfg.OAuthConfirmMode,
				BrowserTimeout:       time.Duration(opt.Cfg.OAuthBrowserTimeoutSec * float64(time.Second)),
				BrowserDiagnosticDir: filepath.Join(opt.Run.Root, "oauth-browser"),
				Tracef:               log.Infof,
			},
		)
		if err != nil {
			return SingleEmailResult{}, fmt.Errorf("初始化 OAuth: %w", err)
		}
		log.Startf("OAuth Device Flow %s (confirm=%s)", opt.Email, oauthClient.ConfirmMode())
		cred, err = oauthClient.ExchangeAccount(ctx, sso, opt.Email, password)
		if err != nil {
			_ = cpa.AppendOAuthFailure(filepath.Join(opt.Run.SSO, "oauth-failures.jsonl"), opt.Email, err.Error())
			return SingleEmailResult{}, fmt.Errorf("OAuth 失败（SSO 已保留）: %w", err)
		}
		log.OKf("OAuth token 获取成功 %s", opt.Email)
	}

	doc := cpa.FromCredential(cred, opt.Email)
	if opt.Cfg.ProbeEnabled {
		log.Startf("探活 CPA %s", opt.Email)
		if err := cpa.Probe(doc, opt.Cfg.RegisterProxy); err != nil {
			path, writeErr := cpa.WriteAtomic(opt.Run.Discarded, doc, cpa.DefaultSecret())
			if writeErr != nil {
				return SingleEmailResult{}, fmt.Errorf("CPA 探活失败: %v；保存 discarded 也失败: %w", err, writeErr)
			}
			return SingleEmailResult{}, fmt.Errorf("CPA 探活失败（token 已保存到 %s）: %w", path, err)
		}
	}

	path, err := cpa.WriteAtomic(opt.Run.CPA, doc, cpa.DefaultSecret())
	if err != nil {
		return SingleEmailResult{}, fmt.Errorf("写 CPA: %w", err)
	}
	log.OKf("CPA 就绪 %s -> %s", opt.Email, path)
	return SingleEmailResult{Email: opt.Email, CPAPath: path, Probed: opt.Cfg.ProbeEnabled}, nil
}

func normalizeVerificationCode(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 6 && (len(code) != 7 || code[3] != '-') {
		return "", fmt.Errorf("验证码格式无效：应为 6 位字母/数字（如 ABC-123）")
	}
	compact := strings.ReplaceAll(code, "-", "")
	if len(compact) != 6 {
		return "", fmt.Errorf("验证码格式无效：应为 6 位字母/数字（如 ABC-123）")
	}
	for _, r := range compact {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return "", fmt.Errorf("验证码格式无效：应为 6 位字母/数字（如 ABC-123）")
		}
	}
	return code, nil
}

func singleAccountPassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const length = 18
	buf := make([]byte, length)
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	// Ensure all commonly required character classes are represented.
	buf[0], buf[1], buf[2] = 'G', 'r', '7'
	return string(buf), nil
}
