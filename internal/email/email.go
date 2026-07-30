package email

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
)

var bannedDomains = map[string]struct{}{
	"duckmail.sbs":    {},
	"web-library.net": {},
	"mail.tm":         {},
	"mail.gw":         {},
	"baldur.edu.kg":   {},
}

var codeRe = []*regexp.Regexp{
	regexp.MustCompile(`>([A-Z0-9]{3}-[A-Z0-9]{3})<`),
	regexp.MustCompile(`>([A-Z0-9]{6})<`),
	regexp.MustCompile(`\b([A-Z0-9]{3}-?[A-Z0-9]{3})\b`),
}

type Handle struct {
	Kind      string // lol | mt | custom | cftemp | outlook
	Email     string
	Password  string
	Token     string
	Base      string // mail.tm base or cloudflare_temp_email Worker root
	AddressID int64
	// Microsoft mailbox metadata. The xAI address may be a plus alias while
	// MainEmail remains the OAuth-authorized inbox used to read its code.
	MainEmail    string
	ClientID     string
	RefreshToken string
}

type Provider struct {
	cfg Config
	mu  sync.Mutex
	// lol rate limit
	lolNextOK time.Time
	// cfTempDomains is the rotation pool built from CFTempDomain; benched
	// entries are skipped until the pool would otherwise be empty.
	cfTempDomains   []string
	cfTempBenched   map[string]struct{}
	outlook         *outlookPool
	outlookErr      error
	outlookFallback bool
	useOutlook      bool
	rotationMu      sync.Mutex
	rotation        []mailboxSource
	rotationNext    int
	rotationErr     error
}

type mailboxSource string

const (
	mailboxSourceCFTemp  mailboxSource = "cf_temp_email"
	mailboxSourceOutlook mailboxSource = "outlook"
)

type Config struct {
	Mode                     config.EmailMode
	Domain                   string
	API                      string
	LOLRetries               int
	LOLIntervalMS            int
	CFTempAPI                string
	CFTempAdmin              string
	CFTempDomain             string
	CFTempAuth               string
	CFTempPrefix             bool
	OutlookAccountsFile      string
	OutlookStateFile         string
	OutlookAliasesPerAccount int
	OutlookPollInterval      time.Duration
	ProviderRotation         string
	InvalidGrantFallback     string
	HTTPClient               *http.Client
}

type OutlookAliasPreview struct {
	MainEmail      string
	NextEmail      string
	FollowingEmail string
	NextIndex      int
	Remaining      int
}

func New(cfg Config) *Provider {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.LOLRetries <= 0 {
		cfg.LOLRetries = 8
	}
	if cfg.LOLIntervalMS <= 0 {
		cfg.LOLIntervalMS = 400
	}
	rotation, rotationErr := parseProviderRotation(cfg.ProviderRotation)
	p := &Provider{
		cfg:             cfg,
		cfTempDomains:   SplitDomains(cfg.CFTempDomain),
		cfTempBenched:   map[string]struct{}{},
		outlookFallback: strings.EqualFold(strings.TrimSpace(cfg.InvalidGrantFallback), "outlook"),
		useOutlook:      cfg.Mode == config.EmailOutlook,
		rotation:        rotation,
		rotationErr:     rotationErr,
	}
	if cfg.Mode == config.EmailOutlook || p.outlookFallback || rotationContains(rotation, mailboxSourceOutlook) {
		p.outlook, p.outlookErr = newOutlookPool(cfg)
	}
	return p
}

// Validate reports non-transient provider configuration failures. Temporary
// mailbox API errors remain Create-time errors, while an Outlook pool must be
// readable before a batch starts.
func (p *Provider) Validate() error {
	if p.rotationErr != nil {
		return p.rotationErr
	}
	if len(p.rotation) > 0 {
		if p.outlookFallback {
			return fmt.Errorf("EMAIL_PROVIDER_ROTATION 与 EMAIL_INVALID_GRANT_FALLBACK 不能同时启用")
		}
		if p.cfg.Mode != config.EmailCFTemp {
			return fmt.Errorf("EMAIL_PROVIDER_ROTATION 包含 cf_temp_email 时需要 EMAIL_MODE=cf_temp_email")
		}
		if strings.TrimSpace(p.cfg.CFTempAPI) == "" && strings.TrimSpace(p.cfg.API) == "" {
			return fmt.Errorf("EMAIL_PROVIDER_ROTATION: set CF_TEMP_EMAIL_API")
		}
	}
	if p.cfg.Mode == config.EmailOutlook || p.outlookFallback || rotationContains(p.rotation, mailboxSourceOutlook) {
		return p.outlookErr
	}
	return nil
}

// RequiredOutlookAllocations returns the minimum number of Outlook aliases
// consumed by the next total allocations in an explicit provider sequence.
func (p *Provider) RequiredOutlookAllocations(total int) int {
	if p == nil || total <= 0 || len(p.rotation) == 0 {
		return 0
	}
	required := 0
	for i := 0; i < total; i++ {
		if p.rotation[i%len(p.rotation)] == mailboxSourceOutlook {
			required++
		}
	}
	return required
}

func parseProviderRotation(raw string) ([]mailboxSource, error) {
	fields := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(raw)), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(fields) == 0 {
		return nil, nil
	}
	sources := make([]mailboxSource, 0, len(fields))
	seen := map[mailboxSource]struct{}{}
	for _, field := range fields {
		var source mailboxSource
		switch field {
		case "cf", "cloudflare", "cf_temp", "cf-temp", "cf_temp_email", "cloudflare_temp_email":
			source = mailboxSourceCFTemp
		case "outlook", "hotmail", "microsoft", "ms":
			source = mailboxSourceOutlook
		default:
			return nil, fmt.Errorf("EMAIL_PROVIDER_ROTATION 不支持邮箱源 %q", field)
		}
		if _, duplicate := seen[source]; duplicate {
			return nil, fmt.Errorf("EMAIL_PROVIDER_ROTATION 邮箱源重复: %s", source)
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	if len(sources) < 2 {
		return nil, fmt.Errorf("EMAIL_PROVIDER_ROTATION 至少需要两个邮箱源")
	}
	return sources, nil
}

func rotationContains(rotation []mailboxSource, want mailboxSource) bool {
	for _, source := range rotation {
		if source == want {
			return true
		}
	}
	return false
}

// OutlookRemaining returns the number of not-yet-reserved aliases in the
// persistent pool. The boolean is false for non-Outlook modes.
func (p *Provider) OutlookRemaining() (int, bool) {
	if p.outlook == nil {
		return 0, false
	}
	return p.outlook.remaining(), true
}

// OutlookPreviews shows the next generated address for every imported mailbox
// without reserving it or advancing the persistent cursor.
func (p *Provider) OutlookPreviews() ([]OutlookAliasPreview, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.outlook == nil {
		return nil, fmt.Errorf("当前不是 Outlook 邮箱模式")
	}
	return p.outlook.previews(), nil
}

// OutlookFallbackEnabled reports whether domain-mailbox invalid_grant can
// switch future allocations to the imported Outlook alias pool.
func (p *Provider) OutlookFallbackEnabled() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.outlookFallback && p.outlook != nil && p.outlookErr == nil
}

// UsingOutlook reports the currently active allocation source.
func (p *Provider) UsingOutlook() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.useOutlook
}

// SwitchToOutlook atomically changes future Create calls to Outlook. Already
// staged domain handles are rejected by the pipeline before they are used.
func (p *Provider) SwitchToOutlook() bool {
	if p == nil || !p.OutlookFallbackEnabled() || p.outlook.remaining() <= 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.useOutlook {
		return false
	}
	p.useOutlook = true
	return true
}

// SplitDomains parses a comma/whitespace separated mailbox domain list.
//
// x.ai's trust in a mailbox domain decays with the number of accounts it has
// seen, so a run should spread across every domain the Worker serves instead of
// hammering one. A single value stays a single-entry pool.
func SplitDomains(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		domain := strings.ToLower(strings.TrimSpace(field))
		if domain == "" || domainBanned(domain) {
			continue
		}
		if _, dup := seen[domain]; dup {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

// CFTempDomainPool reports the domains still in rotation (benched ones excluded).
func (p *Provider) CFTempDomainPool() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.liveDomainsLocked()
}

func (p *Provider) liveDomainsLocked() []string {
	var live []string
	for _, candidate := range p.cfTempDomains {
		if _, benched := p.cfTempBenched[candidate]; !benched {
			live = append(live, candidate)
		}
	}
	return live
}

// BenchDomain removes a mailbox domain from the rotation after x.ai starts
// rejecting its accounts. The last live domain is never benched: an empty pool
// would fall back to the Worker's default and silently undo the rotation.
func (p *Provider) BenchDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, already := p.cfTempBenched[domain]; already {
		return false
	}
	if len(p.liveDomainsLocked()) <= 1 {
		return false
	}
	p.cfTempBenched[domain] = struct{}{}
	return true
}

// nextCFTempDomain picks a random live domain from the pool.
func (p *Provider) nextCFTempDomain() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	live := p.liveDomainsLocked()
	if len(live) == 0 {
		return ""
	}
	return live[rand.Intn(len(live))]
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (p *Provider) Create() (Handle, error) {
	password := randStr(15)
	p.mu.Lock()
	useOutlook := p.useOutlook
	p.mu.Unlock()
	if useOutlook {
		return p.createOutlook(password)
	}
	if len(p.rotation) > 0 {
		return p.createRotated(password)
	}
	switch p.cfg.Mode {
	case config.EmailCustom:
		email := fmt.Sprintf("oc%s@%s", randStr(10), p.cfg.Domain)
		return Handle{Kind: "custom", Email: email, Password: password}, nil
	case config.EmailCFTemp:
		h, err := p.cfTempCreate()
		if err != nil {
			return Handle{}, err
		}
		h.Password = password
		return h, nil
	}
	var last error
	for i := 0; i < p.cfg.LOLRetries; i++ {
		h, err := p.lolCreate()
		if err == nil {
			h.Password = password
			return h, nil
		}
		last = err
		time.Sleep(time.Duration(50*(i+1)) * time.Millisecond)
	}
	// mail.tm family fallback
	for _, base := range []string{"https://api.mail.tm", "https://api.mail.gw", "https://api.duckmail.sbs"} {
		h, err := p.mailtmCreate(base, password)
		if err == nil {
			return h, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("所有临时邮箱 provider 均不可用")
	}
	return Handle{}, last
}

// createRotated serializes source selection so successful allocations retain
// the configured order even if callers become concurrent. A failed allocation
// does not advance the cursor: the same source is retried until it succeeds.
func (p *Provider) createRotated(password string) (Handle, error) {
	p.rotationMu.Lock()
	defer p.rotationMu.Unlock()
	if p.rotationErr != nil {
		return Handle{}, p.rotationErr
	}
	if len(p.rotation) == 0 {
		return Handle{}, fmt.Errorf("EMAIL_PROVIDER_ROTATION 为空")
	}
	source := p.rotation[p.rotationNext%len(p.rotation)]
	var (
		h   Handle
		err error
	)
	switch source {
	case mailboxSourceCFTemp:
		h, err = p.cfTempCreate()
		if err == nil {
			h.Password = password
		}
	case mailboxSourceOutlook:
		h, err = p.createOutlook(password)
	default:
		err = fmt.Errorf("未知邮箱轮询源: %s", source)
	}
	if err != nil {
		return Handle{}, err
	}
	p.rotationNext = (p.rotationNext + 1) % len(p.rotation)
	return h, nil
}

func (p *Provider) createOutlook(password string) (Handle, error) {
	if p.outlookErr != nil {
		return Handle{}, p.outlookErr
	}
	if p.outlook == nil {
		return Handle{}, fmt.Errorf("Outlook 邮箱池未初始化")
	}
	return p.outlook.reserve(password)
}

func (p *Provider) lolCreate() (Handle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if now.Before(p.lolNextOK) {
		time.Sleep(time.Until(p.lolNextOK))
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.tempmail.lol/v2/inbox/create", nil)
	if err != nil {
		return Handle{}, err
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return Handle{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var data map[string]any
	_ = json.Unmarshal(body, &data)
	if resp.StatusCode == 429 || strings.Contains(strings.ToLower(string(body)), "rate limit") {
		cool := 5 * time.Second
		p.lolNextOK = time.Now().Add(cool)
		return Handle{}, fmt.Errorf("lol rate limited status=%d", resp.StatusCode)
	}
	addr, _ := data["address"].(string)
	tok, _ := data["token"].(string)
	if addr == "" || tok == "" {
		p.lolNextOK = time.Now().Add(800 * time.Millisecond)
		return Handle{}, fmt.Errorf("lol create failed status=%d body=%s", resp.StatusCode, truncate(string(body), 80))
	}
	if domainBanned(addr) {
		p.lolNextOK = time.Now().Add(time.Duration(p.cfg.LOLIntervalMS) * time.Millisecond)
		return Handle{}, fmt.Errorf("lol domain banned: %s", domainOf(addr))
	}
	p.lolNextOK = time.Now().Add(time.Duration(p.cfg.LOLIntervalMS) * time.Millisecond)
	return Handle{Kind: "lol", Email: addr, Token: tok}, nil
}

func (p *Provider) mailtmCreate(base, password string) (Handle, error) {
	resp, err := p.cfg.HTTPClient.Get(base + "/domains")
	if err != nil {
		return Handle{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return Handle{}, err
	}
	members, _ := doc["hydra:member"].([]any)
	var doms []string
	for _, m := range members {
		mm, _ := m.(map[string]any)
		if mm == nil {
			continue
		}
		d, _ := mm["domain"].(string)
		if d == "" || domainBanned(d) {
			continue
		}
		active, _ := mm["isActive"].(bool)
		priv, _ := mm["isPrivate"].(bool)
		if mm["isActive"] != nil && !active {
			continue
		}
		if priv {
			continue
		}
		doms = append(doms, d)
	}
	if len(doms) == 0 {
		return Handle{}, fmt.Errorf("no domain from %s", base)
	}
	rand.Shuffle(len(doms), func(i, j int) { doms[i], doms[j] = doms[j], doms[i] })
	var last error
	for _, dom := range doms {
		if len(doms) > 6 {
			// try at most 6
		}
		email := fmt.Sprintf("oc%s@%s", randStr(10), dom)
		payload := map[string]string{"address": email, "password": password}
		raw, _ := json.Marshal(payload)
		r, err := p.cfg.HTTPClient.Post(base+"/accounts", "application/json", strings.NewReader(string(raw)))
		if err != nil {
			last = err
			continue
		}
		_ = r.Body.Close()
		r2, err := p.cfg.HTTPClient.Post(base+"/token", "application/json", strings.NewReader(string(raw)))
		if err != nil {
			last = err
			continue
		}
		tb, _ := io.ReadAll(io.LimitReader(r2.Body, 1<<20))
		_ = r2.Body.Close()
		var tokDoc map[string]any
		_ = json.Unmarshal(tb, &tokDoc)
		tok, _ := tokDoc["token"].(string)
		if tok == "" {
			last = fmt.Errorf("no token")
			continue
		}
		return Handle{Kind: "mt", Email: email, Password: password, Token: tok, Base: base}, nil
	}
	if last == nil {
		last = fmt.Errorf("mailtm create failed")
	}
	return Handle{}, last
}

func (p *Provider) PollCode(h Handle, maxWait time.Duration) (string, error) {
	if h.Kind == "outlook" {
		defer p.Release(h)
		if p.outlook == nil {
			return "", fmt.Errorf("Outlook 邮箱池未初始化")
		}
		return p.outlook.pollCode(h, maxWait)
	}
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		text, err := p.fetch(h)
		if err == nil && text != "" {
			if code := extractCode(text); code != "" {
				return code, nil
			}
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("验证码超时")
}

// Release marks a reserved mailbox as available again. It is intentionally
// idempotent: PollCode calls it automatically, while pipeline error paths call
// it when registration fails before code polling starts.
func (p *Provider) Release(h Handle) {
	if h.Kind == "outlook" && p.outlook != nil {
		p.outlook.release(h)
	}
}

func (p *Provider) fetch(h Handle) (string, error) {
	switch h.Kind {
	case "custom":
		u := strings.TrimRight(p.cfg.API, "/") + "/check/" + url.PathEscape(h.Email)
		resp, err := p.cfg.HTTPClient.Get(u)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("status %d", resp.StatusCode)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		if c, _ := doc["code"].(string); c != "" {
			return c, nil
		}
		return "", nil
	case "lol":
		resp, err := p.cfg.HTTPClient.Get("https://api.tempmail.lol/v2/inbox?token=" + url.QueryEscape(h.Token))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		var data map[string]any
		_ = json.Unmarshal(body, &data)
		items, _ := data["emails"].([]any)
		if items == nil {
			items, _ = data["messages"].([]any)
		}
		var b strings.Builder
		for _, it := range items {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			fmt.Fprintf(&b, "%v\n%v\n%v\n", m["subject"], m["body"], m["html"])
		}
		return b.String(), nil
	case "mt":
		req, _ := http.NewRequest(http.MethodGet, h.Base+"/messages", nil)
		req.Header.Set("Authorization", "Bearer "+h.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := p.cfg.HTTPClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		var data map[string]any
		_ = json.Unmarshal(body, &data)
		msgs, _ := data["hydra:member"].([]any)
		if len(msgs) == 0 {
			return "", nil
		}
		m0, _ := msgs[0].(map[string]any)
		id, _ := m0["id"].(string)
		req2, _ := http.NewRequest(http.MethodGet, h.Base+"/messages/"+id, nil)
		req2.Header.Set("Authorization", "Bearer "+h.Token)
		resp2, err := p.cfg.HTTPClient.Do(req2)
		if err != nil {
			return "", err
		}
		defer resp2.Body.Close()
		b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 2<<20))
		return string(b2), nil
	case "cftemp":
		return p.cfTempFetch(h)
	default:
		return "", fmt.Errorf("unknown handle kind")
	}
}

// cfTempCreate creates a mailbox through a self-hosted
// dreamhunter2333/cloudflare_temp_email Worker. Admin creation is preferred
// when configured; otherwise the public endpoint is used.
func (p *Provider) cfTempCreate() (Handle, error) {
	base := strings.TrimRight(strings.TrimSpace(p.cfg.CFTempAPI), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(p.cfg.API), "/")
	}
	if base == "" {
		return Handle{}, fmt.Errorf("cf_temp_email: set CF_TEMP_EMAIL_API")
	}
	domain := p.nextCFTempDomain()
	if domain == "" {
		domain = strings.TrimSpace(p.cfg.Domain)
	}
	payload := map[string]any{
		"name":         "oc" + randStr(10),
		"enablePrefix": p.cfg.CFTempPrefix,
	}
	if domain != "" {
		payload["domain"] = domain
	}

	admin := strings.TrimSpace(p.cfg.CFTempAdmin)
	endpoint := base + "/api/new_address"
	if admin != "" {
		endpoint = base + "/admin/new_address"
	} else {
		// Current Worker frontends use these fields for public creation. An empty
		// cf_token is accepted when Turnstile enforcement is disabled.
		payload["cf_token"] = ""
		payload["enableRandomSubdomain"] = false
		if domain == "" {
			if picked, err := p.cfTempPickDomain(base); err == nil && picked != "" {
				payload["domain"] = picked
			}
		}
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return Handle{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if admin != "" {
		req.Header.Set("x-admin-auth", admin)
	}
	if auth := strings.TrimSpace(p.cfg.CFTempAuth); auth != "" {
		req.Header.Set("x-custom-auth", auth)
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return Handle{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Handle{}, fmt.Errorf("cf_temp_email create http=%d body=%s", resp.StatusCode, truncate(string(body), 120))
	}
	return cfTempParseCreate(body, base)
}

func (p *Provider) cfTempPickDomain(base string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, base+"/open_api/settings", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	if auth := strings.TrimSpace(p.cfg.CFTempAuth); auth != "" {
		req.Header.Set("x-custom-auth", auth)
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("settings http=%d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	for _, key := range []string{"defaultDomains", "domains"} {
		items, _ := data[key].([]any)
		var domains []string
		for _, item := range items {
			if domain, ok := item.(string); ok && strings.TrimSpace(domain) != "" {
				domains = append(domains, strings.TrimSpace(domain))
			}
		}
		if len(domains) > 0 {
			return domains[rand.Intn(len(domains))], nil
		}
	}
	return "", fmt.Errorf("no domains in open_api/settings")
}

func cfTempParseCreate(body []byte, base string) (Handle, error) {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return Handle{}, fmt.Errorf("cf_temp_email create response is not JSON")
	}
	address, _ := data["address"].(string)
	token, _ := data["jwt"].(string)
	if address == "" || token == "" {
		return Handle{}, fmt.Errorf("cf_temp_email create response missing address or jwt")
	}
	var addressID int64
	switch value := data["address_id"].(type) {
	case float64:
		addressID = int64(value)
	case json.Number:
		addressID, _ = value.Int64()
	}
	return Handle{
		Kind:      "cftemp",
		Email:     address,
		Token:     token,
		Base:      base,
		AddressID: addressID,
	}, nil
}

func (p *Provider) cfTempFetch(h Handle) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(h.Base), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(p.cfg.CFTempAPI), "/")
	}
	if base == "" || strings.TrimSpace(h.Token) == "" {
		return "", fmt.Errorf("cf_temp_email not configured")
	}
	parsed, parsedErr := p.cfTempGet(base+"/api/parsed_mails?limit=10&offset=0", h.Token, true)
	if parsedErr == nil && parsed != "" {
		return parsed, nil
	}
	raw, rawErr := p.cfTempGet(base+"/api/mails?limit=10&offset=0", h.Token, false)
	if rawErr != nil {
		if parsedErr != nil {
			return "", fmt.Errorf("cf_temp_email fetch: parsed=%v raw=%v", parsedErr, rawErr)
		}
		return "", rawErr
	}
	return raw, nil
}

func (p *Provider) cfTempGet(endpoint, token string, parsed bool) (string, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if auth := strings.TrimSpace(p.cfg.CFTempAuth); auth != "" {
		req.Header.Set("x-custom-auth", auth)
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("http=%d body=%s", resp.StatusCode, truncate(string(body), 80))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		var items []any
		if json.Unmarshal(body, &items) == nil {
			return cfTempJoinMails(items, parsed), nil
		}
		return "", fmt.Errorf("cf_temp_email mail response is not JSON")
	}
	items, _ := data["results"].([]any)
	if items == nil {
		items, _ = data["mails"].([]any)
	}
	if items == nil {
		return cfTempJoinMails([]any{data}, parsed), nil
	}
	return cfTempJoinMails(items, parsed), nil
}

func cfTempJoinMails(items []any, parsed bool) string {
	var joined strings.Builder
	for _, item := range items {
		mail, _ := item.(map[string]any)
		if mail == nil {
			continue
		}
		if parsed {
			fmt.Fprintf(&joined, "%v\n%v\n%v\n%v\n", mail["subject"], mail["text"], mail["html"], mail["sender"])
		} else {
			fmt.Fprintf(&joined, "%v\n%v\n%v\n%v\n%v\n", mail["subject"], mail["text"], mail["html"], mail["raw"], mail["source"])
		}
	}
	return joined.String()
}

func extractCode(text string) string {
	for _, re := range codeRe {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return strings.ReplaceAll(m[1], "-", "")
		}
	}
	return ""
}

func domainBanned(emailOrDomain string) bool {
	dom := strings.ToLower(strings.TrimSpace(emailOrDomain))
	if i := strings.LastIndexByte(dom, '@'); i >= 0 {
		dom = dom[i+1:]
	}
	if _, ok := bannedDomains[dom]; ok {
		return true
	}
	parts := strings.Split(dom, ".")
	for i := 0; i < len(parts)-1; i++ {
		if _, ok := bannedDomains[strings.Join(parts[i:], ".")]; ok {
			return true
		}
	}
	return false
}

func domainOf(email string) string {
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		return email[i+1:]
	}
	return email
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
