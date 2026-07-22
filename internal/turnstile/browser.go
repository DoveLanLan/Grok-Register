package turnstile

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/grok-free-register/grok-reg/internal/browser"
	"github.com/grok-free-register/grok-reg/internal/clearance"
)

// Browser mints Turnstile via headless Chromium.
// Aligns with grok_register/register.py inject + click + poll (same api.js, same widget JS).
type Browser struct {
	ExecPath string
	Proxy    string
	Clear    *clearance.Manager

	HardTimeout   time.Duration
	InitialWait   time.Duration
	PollInterval  time.Duration
	PollAttempts  int
	ClickRetries  int
	ClickInterval time.Duration

	mu          sync.Mutex
	allocCtx    context.Context
	allocCancel context.CancelFunc
}

func NewBrowser(proxy string, cm *clearance.Manager) *Browser {
	return &Browser{
		ExecPath:      browser.FindChrome(),
		Proxy:         proxy,
		Clear:         cm,
		HardTimeout:   45 * time.Second, // 与 Playwright mint 对齐（实测成功 15.8~27.5s，45s 足够且留余量）
		InitialWait:   500 * time.Millisecond, // match Python SOLVER_INITIAL_WAIT_MS default
		PollInterval:  500 * time.Millisecond,
		PollAttempts:  100,
		ClickRetries:  3,
		ClickInterval: 600 * time.Millisecond,
	}
}

func (b *Browser) Name() string { return "browser" }

func (b *Browser) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.allocCancel != nil {
		b.allocCancel()
		b.allocCancel = nil
		b.allocCtx = nil
	}
}

func (b *Browser) ensureAllocator() (context.Context, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.allocCtx != nil {
		return b.allocCtx, nil
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Match CloakBrowser/Playwright-ish flags used by original project.
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-infobars", true),
		chromedp.WindowSize(800, 600),
	)
	if b.ExecPath != "" {
		opts = append(opts, chromedp.ExecPath(b.ExecPath))
	}
	if b.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(b.Proxy))
	}
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	if b.Clear != nil {
		if u := b.Clear.UserAgent(); u != "" {
			ua = u
		}
	}
	opts = append(opts, chromedp.UserAgent(ua))
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	b.allocCtx = allocCtx
	b.allocCancel = cancel
	return allocCtx, nil
}

func (b *Browser) Solve(ctx context.Context, siteKey, pageURL string) (string, error) {
	if siteKey == "" {
		return "", fmt.Errorf("empty site key")
	}
	if pageURL == "" {
		pageURL = "https://accounts.x.ai/sign-up"
	}
	if b.ExecPath == "" {
		b.ExecPath = browser.FindChrome()
	}
	if b.ExecPath == "" {
		return "", fmt.Errorf("chrome/chromium not found; set CHROME_PATH or install cloakbrowser")
	}

	hard := b.HardTimeout
	if hard <= 0 {
		hard = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, hard)
	defer cancel()

	allocCtx, err := b.ensureAllocator()
	if err != nil {
		return "", err
	}
	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	tabCtx, cancel2 := context.WithCancel(tabCtx)
	defer cancel2()
	go func() {
		select {
		case <-ctx.Done():
			cancel2()
		case <-tabCtx.Done():
		}
	}()

	// --- navigate (Python: page.goto sign-up, wait 1s) ---
	if err := chromedp.Run(tabCtx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return b.injectClearanceCookies(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(
				`Object.defineProperty(navigator,"webdriver",{get:()=>undefined})`,
			).Do(ctx)
			return err
		}),
		chromedp.Navigate(pageURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("navigate: %w", err)
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(1000 * time.Millisecond):
	}

	// --- inject EXACT Python widget (api.js without ?render=explicit) ---
	if err := chromedp.Run(tabCtx, chromedp.Evaluate(buildInjectJSPython(siteKey), nil)); err != nil {
		return "", fmt.Errorf("inject: %w", err)
	}

	// Python: SOLVER_INITIAL_WAIT_MS then early poll
	iw := b.InitialWait
	if iw <= 0 {
		iw = 500 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(iw):
	}

	// early poll (Python SOLVER_EARLY_POLL: 2 x 800ms)
	for i := 0; i < 2; i++ {
		if tok, _ := readToken(tabCtx); len(tok) > 10 {
			return tok, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(800 * time.Millisecond):
		}
	}

	// click stage (Python SOLVER_MOUSE_CLICK_RETRIES=3, interval 600ms)
	retries := b.ClickRetries
	if retries < 0 {
		retries = 3
	}
	interval := b.ClickInterval
	if interval <= 0 {
		interval = 600 * time.Millisecond
	}
	for i := 0; i < retries; i++ {
		if tok, _ := readToken(tabCtx); len(tok) > 10 {
			return tok, nil
		}
		_ = mouseClickTurnstileCenter(tabCtx)
		if i+1 < retries {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(interval):
			}
		}
	}

	// poll (Python 100 x 500ms)
	attempts := b.PollAttempts
	if attempts <= 0 {
		attempts = 100
	}
	poll := b.PollInterval
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("turnstile timeout (no token) %s", pageDiag(tabCtx))
		case <-time.After(poll):
		}
		tok, err := readToken(tabCtx)
		if err != nil {
			continue
		}
		if len(tok) > 10 {
			return tok, nil
		}
		// Python re-clicks every ~10s while polling
		if i > 0 && i%20 == 0 {
			_ = mouseClickTurnstileCenter(tabCtx)
		}
	}
	return "", fmt.Errorf("turnstile timeout (no token) %s", pageDiag(tabCtx))
}

func (b *Browser) injectClearanceCookies(ctx context.Context) error {
	if b.Clear == nil {
		return nil
	}
	for _, c := range b.Clear.Get().Cookies {
		if c.Name == "" {
			continue
		}
		domain := c.Domain
		if domain == "" {
			domain = ".x.ai"
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		_ = network.SetCookie(c.Name, c.Value).
			WithURL("https://accounts.x.ai/").
			WithDomain(domain).
			WithPath(path).
			Do(ctx)
	}
	return nil
}

// buildInjectJSPython is a line-for-line port of register.py _inject_turnstile_widget.
func buildInjectJSPython(siteKey string) string {
	sk := strings.ReplaceAll(siteKey, `'`, `\'`)
	// Same structure as Python f-string inject (non-timeline path).
	return fmt.Sprintf(
		`var d=document.createElement('div');d.className='cf-turnstile';d.setAttribute('data-sitekey','%s');d.style.cssText='position:fixed;top:10px;left:10px;z-index:99999;background:white;padding:12px;border:2px solid red;border-radius:6px;width:300px;height:70px';document.body.appendChild(d);function __r(){window.turnstile&&window.turnstile.render(d,{sitekey:'%s',callback:function(t){var i=document.querySelector('input[name="cf-turnstile-response"]');if(!i){i=document.createElement('input');i.type='hidden';i.name='cf-turnstile-response';document.body.appendChild(i);}i.value=t;}})}if(window.turnstile){__r()}else{var s=document.createElement('script');s.src='https://challenges.cloudflare.com/turnstile/v0/api.js';s.onload=function(){setTimeout(__r,1000)};document.head.appendChild(s);}`,
		sk, sk,
	)
}

func readToken(ctx context.Context) (string, error) {
	var tok string
	err := chromedp.Run(ctx, chromedp.Evaluate(
		`document.querySelector('input[name="cf-turnstile-response"]')?.value||""`,
		&tok,
	))
	return tok, err
}

// mouseClickTurnstileCenter ports Python _mouse_click_turnstile_center_trace.
func mouseClickTurnstileCenter(ctx context.Context) error {
	var raw any
	err := chromedp.Run(ctx, chromedp.Evaluate(`(function(){
  const e = document.querySelector('.cf-turnstile');
  if (!e) return null;
  const r = e.getBoundingClientRect();
  return {x: r.left + r.width / 2, y: r.top + r.height / 2};
})()`, &raw))
	if err != nil || raw == nil {
		return err
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	x, _ := m["x"].(float64)
	y, _ := m["y"].(float64)
	if x <= 0 || y <= 0 {
		return nil
	}
	// Python: move (x-25,y-8) → move (x,y) steps → down → sleep 50ms → up
	return chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		_ = input.DispatchMouseEvent(input.MouseMoved, max0(x-25), max0(y-8)).Do(ctx)
		time.Sleep(30 * time.Millisecond)
		_ = input.DispatchMouseEvent(input.MouseMoved, x, y).Do(ctx)
		time.Sleep(20 * time.Millisecond)
		if err := input.DispatchMouseEvent(input.MousePressed, x, y).
			WithButton(input.Left).WithClickCount(1).Do(ctx); err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
		return input.DispatchMouseEvent(input.MouseReleased, x, y).
			WithButton(input.Left).WithClickCount(1).Do(ctx)
	}))
}

func max0(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

func pageDiag(ctx context.Context) string {
	var s string
	_ = chromedp.Run(ctx, chromedp.Evaluate(`(function(){
  var ifr=document.querySelectorAll('iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]').length;
  var allIfr=document.querySelectorAll('iframe').length;
  var w=!!document.querySelector('.cf-turnstile');
  var ts=!!window.turnstile;
  var tok=(document.querySelector('input[name="cf-turnstile-response"]')||{}).value||'';
  return 'iframes='+ifr+' all_ifr='+allIfr+' widget='+w+' turnstile='+ts+' toklen='+tok.length;
})()`, &s))
	if s == "" {
		return "(no diag)"
	}
	return s
}
