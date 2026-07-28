package email

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const outlookAccountSeparator = "----"

const (
	outlookStateVersion   = 2
	outlookAliasTagLength = 10
	outlookAliasAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

type outlookAccount struct {
	Email        string
	Password     string
	ClientID     string
	RefreshToken string
}

type outlookAccountState struct {
	NextAlias       int    `json:"next_alias"`
	AliasSeed       string `json:"alias_seed,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	SourceTokenHash string `json:"source_token_hash,omitempty"`
}

type outlookStateFile struct {
	Version  int                            `json:"version"`
	Accounts map[string]outlookAccountState `json:"accounts"`
}

type outlookEndpoints struct {
	liveToken       string
	consumersToken  string
	graphMessages   string
	outlookMessages string
}

type outlookPool struct {
	mu           sync.Mutex
	accounts     []outlookAccount
	state        outlookStateFile
	active       map[string]bool
	statePath    string
	maxAliases   int
	pollInterval time.Duration
	http         httpDoer
	endpoints    outlookEndpoints
	seen         map[string]struct{}
	seenMu       sync.Mutex
	imapFetch    func(accessToken, mailbox string) ([]outlookMessage, error)
}

// These small aliases keep the pool independent from a concrete HTTP client
// and make its Microsoft endpoints testable without changing user config.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// ImportOutlookAccounts validates a reference-compatible account dump and
// stores a normalized 0600 copy at dest. Password is retained only for format
// compatibility; OAuth is used for mailbox access.
func ImportOutlookAccounts(source, dest string) (int, error) {
	raw, err := os.ReadFile(source)
	if err != nil {
		return 0, err
	}
	accounts, err := parseOutlookAccounts(string(raw))
	if err != nil {
		return 0, err
	}
	if len(accounts) == 0 {
		return 0, fmt.Errorf("没有可导入的 Outlook 账号")
	}
	var out strings.Builder
	for _, account := range accounts {
		fmt.Fprintf(
			&out,
			"%s%s%s%s%s%s%s\n",
			account.Email,
			outlookAccountSeparator,
			account.Password,
			outlookAccountSeparator,
			account.ClientID,
			outlookAccountSeparator,
			account.RefreshToken,
		)
	}
	if err := writePrivateAtomic(dest, []byte(out.String())); err != nil {
		return 0, err
	}
	return len(accounts), nil
}

func parseOutlookAccounts(raw string) ([]outlookAccount, error) {
	var accounts []outlookAccount
	seen := map[string]struct{}{}
	for lineNo, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, outlookAccountSeparator, 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("Outlook 账号文件第 %d 行格式错误：应为 邮箱----密码----ClientID----RefreshToken", lineNo+1)
		}
		account := outlookAccount{
			Email:        strings.TrimSpace(parts[0]),
			Password:     strings.TrimSpace(parts[1]),
			ClientID:     strings.TrimSpace(parts[2]),
			RefreshToken: strings.TrimSpace(parts[3]),
		}
		parsed, err := mail.ParseAddress(account.Email)
		if err != nil || !strings.EqualFold(parsed.Address, account.Email) || !strings.Contains(account.Email, "@") {
			return nil, fmt.Errorf("Outlook 账号文件第 %d 行邮箱格式无效", lineNo+1)
		}
		if account.ClientID == "" || account.RefreshToken == "" {
			return nil, fmt.Errorf("Outlook 账号文件第 %d 行缺少 ClientID 或 RefreshToken", lineNo+1)
		}
		key := strings.ToLower(account.Email)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("Outlook 账号文件第 %d 行邮箱重复：%s", lineNo+1, account.Email)
		}
		seen[key] = struct{}{}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func newOutlookPool(cfg Config) (*outlookPool, error) {
	accountsPath := strings.TrimSpace(cfg.OutlookAccountsFile)
	if accountsPath == "" {
		return nil, fmt.Errorf("Outlook 邮箱模式需要 OUTLOOK_ACCOUNTS_FILE（可先执行 grok outlook import <文件>）")
	}
	raw, err := os.ReadFile(accountsPath)
	if err != nil {
		return nil, fmt.Errorf("读取 Outlook 账号文件: %w", err)
	}
	accounts, err := parseOutlookAccounts(string(raw))
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("Outlook 账号文件为空")
	}
	maxAliases := cfg.OutlookAliasesPerAccount
	if maxAliases <= 0 {
		maxAliases = 5
	}
	pollInterval := cfg.OutlookPollInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	pool := &outlookPool{
		accounts:     accounts,
		state:        outlookStateFile{Version: outlookStateVersion, Accounts: map[string]outlookAccountState{}},
		active:       map[string]bool{},
		statePath:    strings.TrimSpace(cfg.OutlookStateFile),
		maxAliases:   maxAliases,
		pollInterval: pollInterval,
		http:         cfg.HTTPClient,
		endpoints: outlookEndpoints{
			liveToken:       "https://login.live.com/oauth20_token.srf",
			consumersToken:  "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
			graphMessages:   "https://graph.microsoft.com/v1.0/me/messages",
			outlookMessages: "https://outlook.office.com/api/v2.0/me/messages",
		},
		seen: map[string]struct{}{},
	}
	pool.imapFetch = pool.fetchIMAPMessages
	if pool.statePath != "" {
		if err := pool.loadState(); err != nil {
			return nil, err
		}
	}
	stateChanged := false
	for i := range pool.accounts {
		key := strings.ToLower(pool.accounts[i].Email)
		savedState := pool.state.Accounts[key]
		if savedState.NextAlias < 0 {
			savedState.NextAlias = 0
			stateChanged = true
		}
		if savedState.AliasSeed == "" {
			seed, seedErr := newOutlookAliasSeed()
			if seedErr != nil {
				return nil, fmt.Errorf("生成 Outlook 随机别名种子: %w", seedErr)
			}
			savedState.AliasSeed = seed
			stateChanged = true
		}
		sourceHash := outlookTokenHash(pool.accounts[i].RefreshToken)
		if savedState.SourceTokenHash != "" && savedState.SourceTokenHash != sourceHash {
			// A manual edit or `grok outlook import` supplied a replacement
			// credential. It must override a previously rotated saved token.
			savedState.RefreshToken = pool.accounts[i].RefreshToken
			stateChanged = true
		}
		if savedState.SourceTokenHash == "" {
			savedState.SourceTokenHash = sourceHash
			stateChanged = true
		}
		if saved := savedState.RefreshToken; saved != "" {
			pool.accounts[i].RefreshToken = saved
		}
		pool.state.Accounts[key] = savedState
	}
	if stateChanged {
		if err := pool.saveStateLocked(); err != nil {
			return nil, err
		}
	}
	return pool, nil
}

func (p *outlookPool) loadState() error {
	raw, err := os.ReadFile(p.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取 Outlook 状态: %w", err)
	}
	var state outlookStateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("解析 Outlook 状态: %w", err)
	}
	if state.Accounts == nil {
		state.Accounts = map[string]outlookAccountState{}
	}
	state.Version = outlookStateVersion
	p.state = state
	return nil
}

func (p *outlookPool) reserve(password string) (Handle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	busy := false
	for i := range p.accounts {
		account := &p.accounts[i]
		key := strings.ToLower(account.Email)
		state := p.state.Accounts[key]
		if state.NextAlias >= p.maxAliases {
			continue
		}
		if p.active[key] {
			busy = true
			continue
		}
		index := state.NextAlias
		state.NextAlias++
		if state.RefreshToken == "" {
			state.RefreshToken = account.RefreshToken
		}
		if state.SourceTokenHash == "" {
			state.SourceTokenHash = outlookTokenHash(account.RefreshToken)
		}
		p.state.Accounts[key] = state
		if err := p.saveStateLocked(); err != nil {
			state.NextAlias--
			p.state.Accounts[key] = state
			return Handle{}, err
		}
		p.active[key] = true
		return Handle{
			Kind:         "outlook",
			Email:        outlookAlias(account.Email, index, state.AliasSeed),
			Password:     password,
			MainEmail:    account.Email,
			ClientID:     account.ClientID,
			RefreshToken: account.RefreshToken,
		}, nil
	}
	if busy {
		return Handle{}, fmt.Errorf("Outlook 主邮箱当前均有别名正在收信")
	}
	return Handle{}, fmt.Errorf("Outlook 别名池已耗尽：每个主邮箱最多 %d 个地址", p.maxAliases)
}

func outlookTokenHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return fmt.Sprintf("%x", sum[:])
}

func newOutlookAliasSeed() (string, error) {
	var raw [16]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// outlookAlias returns a stable random-looking plus address for an allocation
// index. A per-mailbox seed is persisted in outlook-state.json, so check,
// allocate, and a restarted process all resolve the same index to the same
// address without storing mailbox credentials in the tag.
func outlookAlias(main string, index int, seed string) string {
	at := strings.LastIndexByte(main, '@')
	if at <= 0 {
		return main
	}
	mac := hmac.New(sha256.New, []byte(seed))
	_, _ = fmt.Fprintf(mac, "%s:%d", strings.ToLower(strings.TrimSpace(main)), index)
	digest := mac.Sum(nil)
	var tag strings.Builder
	tag.Grow(outlookAliasTagLength)
	for i := 0; i < outlookAliasTagLength; i++ {
		tag.WriteByte(outlookAliasAlphabet[int(digest[i])%len(outlookAliasAlphabet)])
	}
	return fmt.Sprintf("%s+%s%s", main[:at], tag.String(), main[at:])
}

func (p *outlookPool) release(h Handle) {
	p.mu.Lock()
	delete(p.active, strings.ToLower(strings.TrimSpace(h.MainEmail)))
	p.mu.Unlock()
}

func (p *outlookPool) remaining() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, account := range p.accounts {
		remaining := p.maxAliases - p.state.Accounts[strings.ToLower(account.Email)].NextAlias
		if remaining > 0 {
			total += remaining
		}
	}
	return total
}

func (p *outlookPool) previews() []OutlookAliasPreview {
	p.mu.Lock()
	defer p.mu.Unlock()
	previews := make([]OutlookAliasPreview, 0, len(p.accounts))
	for _, account := range p.accounts {
		next := p.state.Accounts[strings.ToLower(account.Email)].NextAlias
		remaining := p.maxAliases - next
		preview := OutlookAliasPreview{
			MainEmail: account.Email,
			NextIndex: next,
			Remaining: remaining,
		}
		if remaining > 0 {
			preview.NextEmail = outlookAlias(account.Email, next, p.state.Accounts[strings.ToLower(account.Email)].AliasSeed)
		}
		if remaining > 1 {
			preview.FollowingEmail = outlookAlias(account.Email, next+1, p.state.Accounts[strings.ToLower(account.Email)].AliasSeed)
		}
		previews = append(previews, preview)
	}
	return previews
}

func (p *outlookPool) updateRefreshToken(mainEmail, refreshToken string) error {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(mainEmail))
	for i := range p.accounts {
		if strings.EqualFold(p.accounts[i].Email, mainEmail) {
			p.accounts[i].RefreshToken = refreshToken
			break
		}
	}
	state := p.state.Accounts[key]
	state.RefreshToken = refreshToken
	p.state.Accounts[key] = state
	return p.saveStateLocked()
}

func (p *outlookPool) saveStateLocked() error {
	if p.statePath == "" {
		return nil
	}
	raw, err := json.MarshalIndent(p.state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writePrivateAtomic(p.statePath, raw); err != nil {
		return fmt.Errorf("保存 Outlook 状态: %w", err)
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("目标路径不能为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
