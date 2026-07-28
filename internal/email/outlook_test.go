package email

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
)

func writeOutlookFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertRandomOutlookAlias(t *testing.T, got, main string) {
	t.Helper()
	at := strings.LastIndexByte(main, '@')
	if at <= 0 {
		t.Fatalf("invalid main email in test: %q", main)
	}
	prefix := main[:at] + "+"
	domain := main[at:]
	if !strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, domain) {
		t.Fatalf("alias %q does not preserve main mailbox %q", got, main)
	}
	tag := strings.TrimSuffix(strings.TrimPrefix(got, prefix), domain)
	if len(tag) != outlookAliasTagLength {
		t.Fatalf("alias tag %q length=%d want=%d", tag, len(tag), outlookAliasTagLength)
	}
	for _, char := range tag {
		if !strings.ContainsRune(outlookAliasAlphabet, char) {
			t.Fatalf("alias tag %q contains unsupported character %q", tag, char)
		}
	}
}

func TestImportOutlookAccountsValidatesAndProtectsFile(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	dest := filepath.Join(root, "private", "outlook-accounts.txt")
	writeOutlookFixture(t, source, strings.Join([]string{
		"# reference-compatible dump",
		"first@outlook.com----mail-password----client-one----refresh-one",
		"second@hotmail.com--------client-two----refresh-two",
	}, "\n"))

	count, err := ImportOutlookAccounts(source, dest)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if count != 2 {
		t.Fatalf("count=%d", count)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	accounts, err := parseOutlookAccounts(string(mustReadFile(t, dest)))
	if err != nil || len(accounts) != 2 {
		t.Fatalf("parsed=%d err=%v", len(accounts), err)
	}
	if accounts[1].Password != "" || accounts[1].ClientID != "client-two" {
		t.Fatalf("empty password field was not preserved: %+v", accounts[1])
	}
}

func TestOutlookPoolAllocatesAliasesPersistentlyAndSerializesMailbox(t *testing.T) {
	root := t.TempDir()
	accountsPath := filepath.Join(root, "accounts.txt")
	statePath := filepath.Join(root, "state.json")
	writeOutlookFixture(t, accountsPath, strings.Join([]string{
		"first@outlook.com----mail-pass-one----client-one----refresh-one",
		"second@outlook.com----mail-pass-two----client-two----refresh-two",
	}, "\n"))

	provider := New(Config{
		Mode:                     config.EmailOutlook,
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         statePath,
		OutlookAliasesPerAccount: 3,
	})
	previews, err := provider.OutlookPreviews()
	if err != nil {
		t.Fatal(err)
	}
	if len(previews) != 2 {
		t.Fatalf("previews=%+v", previews)
	}
	assertRandomOutlookAlias(t, previews[0].NextEmail, "first@outlook.com")
	assertRandomOutlookAlias(t, previews[0].FollowingEmail, "first@outlook.com")
	assertRandomOutlookAlias(t, previews[1].NextEmail, "second@outlook.com")
	if previews[0].NextEmail == previews[0].FollowingEmail {
		t.Fatalf("adjacent allocations reused alias: %+v", previews[0])
	}
	first, err := provider.Create()
	if err != nil {
		t.Fatal(err)
	}
	if first.Email != previews[0].NextEmail || first.MainEmail != "first@outlook.com" {
		t.Fatalf("first handle=%+v", first)
	}
	if first.Password == "mail-pass-one" || first.Password == "" {
		t.Fatal("mailbox password must not become the xAI password")
	}

	// The same mailbox cannot have two code polls in flight; the next reserve
	// therefore moves to the second imported account.
	second, err := provider.Create()
	if err != nil {
		t.Fatal(err)
	}
	if second.Email != previews[1].NextEmail || second.MainEmail != "second@outlook.com" {
		t.Fatalf("second=%s", second.Email)
	}
	provider.Release(first)
	third, err := provider.Create()
	if err != nil {
		t.Fatal(err)
	}
	if third.Email != previews[0].FollowingEmail || third.MainEmail != "first@outlook.com" {
		t.Fatalf("third handle=%+v", third)
	}
	if remaining, ok := provider.OutlookRemaining(); !ok || remaining != 3 {
		t.Fatalf("remaining=%d ok=%v", remaining, ok)
	}

	provider.Release(second)
	provider.Release(third)
	reloaded := New(Config{
		Mode:                     config.EmailOutlook,
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         statePath,
		OutlookAliasesPerAccount: 3,
	})
	reloadedPreviews, err := reloaded.OutlookPreviews()
	if err != nil {
		t.Fatal(err)
	}
	expectedNext := reloadedPreviews[0].NextEmail
	assertRandomOutlookAlias(t, expectedNext, "first@outlook.com")
	next, err := reloaded.Create()
	if err != nil {
		t.Fatal(err)
	}
	if next.Email != expectedNext {
		t.Fatalf("persistent next alias=%s", next.Email)
	}
	var saved outlookStateFile
	if err := json.Unmarshal(mustReadFile(t, statePath), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Version != outlookStateVersion || saved.Accounts["first@outlook.com"].AliasSeed == "" {
		t.Fatalf("random alias seed was not persisted: %+v", saved)
	}
}

func TestOutlookProviderValidatesMissingAccountPool(t *testing.T) {
	provider := New(Config{Mode: config.EmailOutlook})
	if err := provider.Validate(); err == nil || !strings.Contains(err.Error(), "OUTLOOK_ACCOUNTS_FILE") {
		t.Fatalf("validation error=%v", err)
	}
}

func TestOutlookGraphRefreshAndExactAliasCode(t *testing.T) {
	now := time.Now().UTC()
	var targetAlias string
	var wrongAlias string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			if r.Form.Get("client_id") != "client-id" || r.Form.Get("refresh_token") != "refresh-old" {
				t.Errorf("unexpected token form: %v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "header.payload.signature",
				"refresh_token": "refresh-rotated",
			})
		case "/graph":
			if r.Header.Get("Authorization") != "Bearer header.payload.signature" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("$top") == "1" {
				_, _ = w.Write([]byte(`{"value":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]any{
					"id":               "wrong-newer",
					"subject":          "Your Grok confirmation code",
					"receivedDateTime": now.Format(time.RFC3339Nano),
					"toRecipients": []any{map[string]any{"emailAddress": map[string]any{
						"address": wrongAlias,
					}}},
					"body": map[string]any{"contentType": "text", "content": "BAD-222"},
				},
				map[string]any{
					"id":               "target",
					"subject":          "Your Grok confirmation code",
					"receivedDateTime": now.Add(-time.Second).Format(time.RFC3339Nano),
					"toRecipients": []any{map[string]any{"emailAddress": map[string]any{
						"address": "user@outlook.com",
					}}},
					"internetMessageHeaders": []any{map[string]any{
						"name": "X-Original-To", "value": targetAlias,
					}},
					"body": map[string]any{"contentType": "html", "content": "<b>OKA-111</b>"},
				},
			}})
		case "/outlook":
			http.Error(w, `{"error":"denied"}`, http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	accountsPath := filepath.Join(root, "accounts.txt")
	statePath := filepath.Join(root, "state.json")
	writeOutlookFixture(t, accountsPath, "user@outlook.com----mail-pass----client-id----refresh-old\n")
	provider := New(Config{
		Mode:                     config.EmailOutlook,
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         statePath,
		OutlookAliasesPerAccount: 3,
		OutlookPollInterval:      time.Millisecond,
		HTTPClient:               server.Client(),
	})
	provider.outlook.endpoints = outlookEndpoints{
		liveToken:       server.URL + "/token",
		consumersToken:  server.URL + "/token",
		graphMessages:   server.URL + "/graph",
		outlookMessages: server.URL + "/outlook",
	}
	main, err := provider.Create()
	if err != nil {
		t.Fatal(err)
	}
	wrongAlias = main.Email
	provider.Release(main)
	handle, err := provider.Create()
	if err != nil {
		t.Fatal(err)
	}
	targetAlias = handle.Email
	assertRandomOutlookAlias(t, targetAlias, "user@outlook.com")
	code, err := provider.PollCode(handle, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != "OKA111" {
		t.Fatalf("code=%q", code)
	}
	var state outlookStateFile
	if err := json.Unmarshal(mustReadFile(t, statePath), &state); err != nil {
		t.Fatal(err)
	}
	if state.Accounts["user@outlook.com"].RefreshToken != "refresh-rotated" {
		t.Fatalf("rotated token was not persisted: %+v", state.Accounts["user@outlook.com"])
	}

	// Re-importing a newly issued credential is an explicit operator update and
	// must override the older token cached in the state file.
	writeOutlookFixture(t, accountsPath, "user@outlook.com----mail-pass----client-id----refresh-manual\n")
	reloaded := New(Config{
		Mode:                     config.EmailOutlook,
		OutlookAccountsFile:      accountsPath,
		OutlookStateFile:         statePath,
		OutlookAliasesPerAccount: 3,
	})
	if got := reloaded.outlook.accounts[0].RefreshToken; got != "refresh-manual" {
		t.Fatalf("manual replacement token was ignored: %q", got)
	}
}

func TestOutlookPlusAliasRejectsRewrittenMainRecipient(t *testing.T) {
	pool := &outlookPool{seen: map[string]struct{}{}}
	message := outlookMessage{
		ID:         "rewritten",
		Subject:    "Your Grok confirmation code",
		Sender:     "noreply@x.ai",
		Recipients: []string{"user@outlook.com"},
		ReceivedAt: time.Now(),
		Body:       "BAD-111",
	}
	if code := pool.verificationCode([]outlookMessage{message}, "user+1@outlook.com", "user@outlook.com", time.Now().Add(-time.Minute)); code != "" {
		t.Fatalf("ambiguous plus-alias code accepted: %s", code)
	}
	message.Recipients = append(message.Recipients, "User Alias <user+1@outlook.com>")
	if code := pool.verificationCode([]outlookMessage{message}, "user+1@outlook.com", "user@outlook.com", time.Now().Add(-time.Minute)); code != "BAD111" {
		t.Fatalf("exact alias header not accepted: %s", code)
	}
}

func TestParseRFC822MessageUsesOriginalRecipientHeader(t *testing.T) {
	raw := []byte(fmt.Sprintf("Date: %s\r\nFrom: xAI <noreply@x.ai>\r\nTo: user@outlook.com\r\nX-Original-To: user+3@outlook.com\r\nSubject: Your Grok code\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Use IMAP-1</p>", time.Now().UTC().Format(time.RFC1123Z)))
	message, err := parseRFC822Message(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(message.Recipients, " "), "user+3@outlook.com") {
		t.Fatalf("recipients=%v", message.Recipients)
	}
	if !strings.Contains(message.Body, "IMAP-1") {
		t.Fatalf("body=%q", message.Body)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
