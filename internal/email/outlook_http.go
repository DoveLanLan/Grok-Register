package email

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const outlookGraphScopes = "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read"

var (
	htmlTagRe      = regexp.MustCompile(`(?s)<[^>]+>`)
	emailAddressRe = regexp.MustCompile(`(?i)[A-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Z0-9.-]+`)
)

type outlookMessage struct {
	ID         string
	Subject    string
	Sender     string
	Recipients []string
	ReceivedAt time.Time
	Body       string
}

type outlookMailError struct {
	API        string
	StatusCode int
	Detail     string
}

func (e *outlookMailError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("Microsoft %s 收信失败: HTTP %d%s", e.API, e.StatusCode, suffixDetail(e.Detail))
	}
	return fmt.Sprintf("Microsoft %s 收信失败%s", e.API, suffixDetail(e.Detail))
}

func suffixDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	return ": " + detail
}

func (p *outlookPool) pollCode(h Handle, maxWait time.Duration) (string, error) {
	if strings.TrimSpace(h.MainEmail) == "" || strings.TrimSpace(h.ClientID) == "" || strings.TrimSpace(h.RefreshToken) == "" {
		return "", fmt.Errorf("Outlook 句柄缺少主邮箱、ClientID 或 RefreshToken")
	}
	if maxWait <= 0 {
		maxWait = 90 * time.Second
	}
	deadline := time.Now().Add(maxWait)
	// Capture the send window before token refresh/probing: imported legacy
	// tokens may need several audience probes, during which the email can arrive.
	receivedAfter := time.Now().Add(-30 * time.Second)
	accessToken, api, rotated, err := p.refreshAccessToken(h)
	if err != nil {
		return "", err
	}
	if rotated != "" && rotated != h.RefreshToken {
		if err := p.updateRefreshToken(h.MainEmail, rotated); err != nil {
			return "", err
		}
	}

	var lastErr error
	for time.Now().Before(deadline) {
		var messages []outlookMessage
		switch api {
		case "graph":
			messages, err = p.fetchGraphMessages(accessToken)
		case "outlook":
			messages, err = p.fetchOutlookMessages(accessToken)
		case "imap":
			messages, err = p.imapFetch(accessToken, h.MainEmail)
		default:
			err = fmt.Errorf("未知 Microsoft 收信通道 %q", api)
		}
		if err == nil {
			if code := p.verificationCode(messages, h.Email, h.MainEmail, receivedAfter); code != "" {
				return code, nil
			}
		} else {
			lastErr = err
			var mailErr *outlookMailError
			if asOutlookMailError(err, &mailErr) && (mailErr.StatusCode == http.StatusUnauthorized || mailErr.StatusCode == http.StatusForbidden) {
				return "", err
			}
		}

		wait := p.pollInterval
		if wait <= 0 {
			wait = 5 * time.Second
		}
		if remaining := time.Until(deadline); wait > remaining {
			wait = remaining
		}
		if wait > 0 {
			time.Sleep(wait)
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("Outlook 验证码超时（最后一次收信错误: %w）", lastErr)
	}
	return "", fmt.Errorf("Outlook 验证码超时")
}

// Kept as a helper instead of importing errors in several Outlook files.
func asOutlookMailError(err error, target **outlookMailError) bool {
	for err != nil {
		if typed, ok := err.(*outlookMailError); ok {
			*target = typed
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

type tokenAttempt struct {
	endpoint string
	scope    string
	tryIMAP  bool
}

func (p *outlookPool) refreshAccessToken(h Handle) (accessToken, api, refreshToken string, err error) {
	attempts := []tokenAttempt{
		{endpoint: p.endpoints.liveToken},
		{endpoint: p.endpoints.consumersToken},
		{endpoint: p.endpoints.liveToken, scope: "https://outlook.office.com/IMAP.AccessAsUser.All offline_access", tryIMAP: true},
		{endpoint: p.endpoints.liveToken, scope: "https://graph.microsoft.com/.default offline_access"},
		{endpoint: p.endpoints.consumersToken, scope: outlookGraphScopes},
		{endpoint: p.endpoints.liveToken, scope: outlookGraphScopes},
	}
	currentRefresh := h.RefreshToken
	var failures []string
	for _, attempt := range attempts {
		form := url.Values{
			"client_id":     {h.ClientID},
			"refresh_token": {currentRefresh},
			"grant_type":    {"refresh_token"},
		}
		if attempt.scope != "" {
			form.Set("scope", attempt.scope)
		}
		req, reqErr := http.NewRequest(http.MethodPost, attempt.endpoint, strings.NewReader(form.Encode()))
		if reqErr != nil {
			failures = append(failures, reqErr.Error())
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		resp, doErr := p.http.Do(req)
		if doErr != nil {
			failures = append(failures, doErr.Error())
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		var data struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &data)
		if data.AccessToken == "" {
			detail := strings.TrimSpace(data.ErrorDescription)
			if detail == "" {
				detail = strings.TrimSpace(data.Error)
			}
			if detail == "" {
				detail = truncate(string(body), 160)
			}
			failures = append(failures, fmt.Sprintf("HTTP %d %s", resp.StatusCode, detail))
			continue
		}
		candidateRefresh := currentRefresh
		if data.RefreshToken != "" {
			candidateRefresh = data.RefreshToken
		}
		mailAPI, probeErr := p.detectMailAPI(data.AccessToken, h.MainEmail, attempt.tryIMAP)
		if mailAPI != "" {
			return data.AccessToken, mailAPI, candidateRefresh, nil
		}
		// A successful refresh may rotate the token even when that access-token
		// audience cannot read mail. Use the rotated value for the next scope.
		currentRefresh = candidateRefresh
		failures = append(failures, probeErr.Error())
	}
	return "", "", "", fmt.Errorf("Microsoft 邮箱 token 刷新或收信权限探测失败: %s", strings.Join(failures, " | "))
}

func (p *outlookPool) detectMailAPI(accessToken, mailbox string, tryIMAP bool) (string, error) {
	type probe struct {
		name string
		url  string
	}
	probes := []probe{
		{name: "graph", url: withQuery(p.endpoints.graphMessages, url.Values{"$top": {"1"}, "$select": {"id"}})},
		{name: "outlook", url: withQuery(p.endpoints.outlookMessages, url.Values{"$top": {"1"}, "$select": {"Id"}})},
	}
	var failures []string
	for _, candidate := range probes {
		req, err := http.NewRequest(http.MethodGet, candidate.url, nil)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")
		resp, err := p.http.Do(req)
		if err != nil {
			failures = append(failures, candidate.name+": "+err.Error())
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return candidate.name, nil
		}
		failures = append(failures, fmt.Sprintf("%s HTTP %d %s", candidate.name, resp.StatusCode, microsoftErrorDetail(body)))
	}
	if tryIMAP || strings.Count(accessToken, ".") == 0 {
		if err := p.probeIMAP(accessToken, mailbox); err == nil {
			return "imap", nil
		} else {
			failures = append(failures, "imap: "+err.Error())
		}
	}
	return "", fmt.Errorf("所有收信通道均不可用: %s", strings.Join(failures, "; "))
}

func (p *outlookPool) fetchGraphMessages(accessToken string) ([]outlookMessage, error) {
	endpoint := withQuery(p.endpoints.graphMessages, url.Values{
		"$top":     {"25"},
		"$select":  {"id,subject,from,toRecipients,internetMessageHeaders,receivedDateTime,bodyPreview,body"},
		"$orderby": {"receivedDateTime desc"},
	})
	var payload struct {
		Value []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
			From    struct {
				EmailAddress struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"from"`
			ToRecipients []struct {
				EmailAddress struct {
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"toRecipients"`
			Headers []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"internetMessageHeaders"`
			ReceivedDateTime string `json:"receivedDateTime"`
			BodyPreview      string `json:"bodyPreview"`
			Body             struct {
				ContentType string `json:"contentType"`
				Content     string `json:"content"`
			} `json:"body"`
		} `json:"value"`
	}
	if err := p.getMicrosoftJSON("Graph", endpoint, accessToken, &payload); err != nil {
		return nil, err
	}
	messages := make([]outlookMessage, 0, len(payload.Value))
	for _, item := range payload.Value {
		recipients := make([]string, 0, len(item.ToRecipients)+len(item.Headers))
		for _, recipient := range item.ToRecipients {
			recipients = append(recipients, recipient.EmailAddress.Address)
		}
		for _, header := range item.Headers {
			if isRecipientHeader(header.Name) {
				recipients = append(recipients, emailAddresses(header.Value)...)
			}
		}
		body := item.Body.Content
		if strings.EqualFold(item.Body.ContentType, "html") {
			body = stripHTML(body)
		}
		messages = append(messages, outlookMessage{
			ID:         "graph:" + item.ID,
			Subject:    item.Subject,
			Sender:     strings.TrimSpace(item.From.EmailAddress.Name + " " + item.From.EmailAddress.Address),
			Recipients: recipients,
			ReceivedAt: parseMicrosoftTime(item.ReceivedDateTime),
			Body:       item.BodyPreview + "\n" + body,
		})
	}
	return messages, nil
}

func (p *outlookPool) fetchOutlookMessages(accessToken string) ([]outlookMessage, error) {
	endpoint := withQuery(p.endpoints.outlookMessages, url.Values{
		"$top":     {"25"},
		"$select":  {"Id,Subject,From,ToRecipients,InternetMessageHeaders,ReceivedDateTime,BodyPreview,Body"},
		"$orderby": {"ReceivedDateTime desc"},
	})
	var payload struct {
		Value []struct {
			ID      string `json:"Id"`
			Subject string `json:"Subject"`
			From    struct {
				EmailAddress struct {
					Name    string `json:"Name"`
					Address string `json:"Address"`
				} `json:"EmailAddress"`
			} `json:"From"`
			ToRecipients []struct {
				EmailAddress struct {
					Address string `json:"Address"`
				} `json:"EmailAddress"`
			} `json:"ToRecipients"`
			Headers []struct {
				Name  string `json:"Name"`
				Value string `json:"Value"`
			} `json:"InternetMessageHeaders"`
			ReceivedDateTime string `json:"ReceivedDateTime"`
			BodyPreview      string `json:"BodyPreview"`
			Body             struct {
				ContentType string `json:"ContentType"`
				Content     string `json:"Content"`
			} `json:"Body"`
		} `json:"value"`
	}
	if err := p.getMicrosoftJSON("Outlook REST", endpoint, accessToken, &payload); err != nil {
		return nil, err
	}
	messages := make([]outlookMessage, 0, len(payload.Value))
	for _, item := range payload.Value {
		recipients := make([]string, 0, len(item.ToRecipients)+len(item.Headers))
		for _, recipient := range item.ToRecipients {
			recipients = append(recipients, recipient.EmailAddress.Address)
		}
		for _, header := range item.Headers {
			if isRecipientHeader(header.Name) {
				recipients = append(recipients, emailAddresses(header.Value)...)
			}
		}
		body := item.Body.Content
		if strings.EqualFold(item.Body.ContentType, "html") {
			body = stripHTML(body)
		}
		messages = append(messages, outlookMessage{
			ID:         "outlook:" + item.ID,
			Subject:    item.Subject,
			Sender:     strings.TrimSpace(item.From.EmailAddress.Name + " " + item.From.EmailAddress.Address),
			Recipients: recipients,
			ReceivedAt: parseMicrosoftTime(item.ReceivedDateTime),
			Body:       item.BodyPreview + "\n" + body,
		})
	}
	return messages, nil
}

func (p *outlookPool) getMicrosoftJSON(api, endpoint, accessToken string, target any) error {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return &outlookMailError{API: api, Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 6<<20))
	if resp.StatusCode != http.StatusOK {
		return &outlookMailError{API: api, StatusCode: resp.StatusCode, Detail: microsoftErrorDetail(body)}
	}
	if err := json.Unmarshal(body, target); err != nil {
		return &outlookMailError{API: api, Detail: "响应不是有效 JSON"}
	}
	return nil
}

func (p *outlookPool) verificationCode(messages []outlookMessage, targetEmail, mainEmail string, receivedAfter time.Time) string {
	sort.SliceStable(messages, func(i, j int) bool {
		return messages[i].ReceivedAt.After(messages[j].ReceivedAt)
	})
	var fallback []struct {
		id   string
		code string
	}
	for _, message := range messages {
		if message.ID != "" && p.wasSeen(message.ID) {
			continue
		}
		if !message.ReceivedAt.IsZero() && message.ReceivedAt.Before(receivedAfter) {
			continue
		}
		combined := strings.ToLower(message.Subject + " " + message.Sender + " " + message.Body)
		if !strings.Contains(combined, "x.ai") && !strings.Contains(combined, "xai") && !strings.Contains(combined, "grok") {
			continue
		}
		code := extractCode(message.Subject + "\n" + message.Body)
		if code == "" {
			continue
		}
		match := recipientMatch(message.Recipients, targetEmail, mainEmail)
		if match > 0 {
			p.markSeen(message.ID)
			return code
		}
		if match == 0 && allowAmbiguousRecipient(targetEmail, mainEmail) {
			fallback = append(fallback, struct {
				id   string
				code string
			}{message.ID, code})
		}
	}
	if len(fallback) == 1 {
		p.markSeen(fallback[0].id)
		return fallback[0].code
	}
	return ""
}

// recipientMatch returns 1 exact, 0 ambiguous, -1 mismatch.
func recipientMatch(recipients []string, targetEmail, mainEmail string) int {
	target := strings.ToLower(strings.TrimSpace(targetEmail))
	main := strings.ToLower(strings.TrimSpace(mainEmail))
	normalized := map[string]struct{}{}
	for _, recipient := range recipients {
		for _, address := range emailAddresses(recipient) {
			normalized[strings.ToLower(address)] = struct{}{}
		}
	}
	if _, ok := normalized[target]; ok {
		return 1
	}
	if len(normalized) == 0 {
		return 0
	}
	local := target
	if at := strings.LastIndexByte(local, '@'); at >= 0 {
		local = local[:at]
	}
	if strings.Contains(local, "+") {
		if _, ok := normalized[main]; ok {
			return 0
		}
	}
	return -1
}

func allowAmbiguousRecipient(targetEmail, mainEmail string) bool {
	target := strings.ToLower(strings.TrimSpace(targetEmail))
	main := strings.ToLower(strings.TrimSpace(mainEmail))
	if target == "" || (main != "" && target == main) {
		return true
	}
	local := target
	if at := strings.LastIndexByte(local, '@'); at >= 0 {
		local = local[:at]
	}
	return !strings.Contains(local, "+")
}

func (p *outlookPool) wasSeen(id string) bool {
	if id == "" {
		return false
	}
	p.seenMu.Lock()
	defer p.seenMu.Unlock()
	_, ok := p.seen[id]
	return ok
}

func (p *outlookPool) markSeen(id string) {
	if id == "" {
		return
	}
	p.seenMu.Lock()
	if len(p.seen) > 2000 {
		p.seen = map[string]struct{}{}
	}
	p.seen[id] = struct{}{}
	p.seenMu.Unlock()
}

func withQuery(endpoint string, values url.Values) string {
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	return endpoint + separator + values.Encode()
}

func microsoftErrorDetail(body []byte) string {
	var payload struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		switch value := payload.Error.(type) {
		case string:
			return value
		case map[string]any:
			code, _ := value["code"].(string)
			message, _ := value["message"].(string)
			return strings.TrimSpace(strings.TrimSpace(code) + " " + strings.TrimSpace(message))
		}
	}
	return truncate(strings.TrimSpace(string(body)), 180)
}

func parseMicrosoftTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	return parsed
}

func stripHTML(value string) string {
	return strings.TrimSpace(html.UnescapeString(htmlTagRe.ReplaceAllString(value, " ")))
}

func isRecipientHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "to", "cc", "delivered-to", "x-original-to", "x-delivered-to", "envelope-to", "x-envelope-to":
		return true
	default:
		return false
	}
}

func emailAddresses(value string) []string {
	return emailAddressRe.FindAllString(value, -1)
}
