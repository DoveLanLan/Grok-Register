package email

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var imapLiteralRe = regexp.MustCompile(`\{([0-9]+)\}\r?\n$`)

type imapSession struct {
	conn   net.Conn
	reader *bufio.Reader
	next   int
}

func (p *outlookPool) probeIMAP(accessToken, mailbox string) error {
	var failures []string
	for _, host := range []string{"outlook.office365.com", "imap-mail.outlook.com"} {
		session, err := dialIMAP(host)
		if err != nil {
			failures = append(failures, host+": "+err.Error())
			continue
		}
		err = session.authenticateXOAUTH2(mailbox, accessToken)
		_ = session.logout()
		_ = session.conn.Close()
		if err == nil {
			return nil
		}
		failures = append(failures, host+": "+err.Error())
	}
	return &outlookMailError{API: "IMAP XOAUTH2", Detail: strings.Join(failures, "; ")}
}

func (p *outlookPool) fetchIMAPMessages(accessToken, mailbox string) ([]outlookMessage, error) {
	var failures []string
	for _, host := range []string{"outlook.office365.com", "imap-mail.outlook.com"} {
		messages, err := fetchIMAPHost(host, accessToken, mailbox)
		if err == nil {
			return messages, nil
		}
		failures = append(failures, host+": "+err.Error())
	}
	return nil, &outlookMailError{API: "IMAP XOAUTH2", Detail: strings.Join(failures, "; ")}
}

func fetchIMAPHost(host, accessToken, mailbox string) ([]outlookMessage, error) {
	session, err := dialIMAP(host)
	if err != nil {
		return nil, err
	}
	defer session.conn.Close()
	defer session.logout()
	if err := session.authenticateXOAUTH2(mailbox, accessToken); err != nil {
		return nil, err
	}
	if _, err := session.command("SELECT INBOX"); err != nil {
		return nil, err
	}
	lines, err := session.command("UID SEARCH ALL")
	if err != nil {
		return nil, err
	}
	var uids []string
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if !strings.HasPrefix(upper, "* SEARCH") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 2 {
			uids = append(uids, fields[2:]...)
		}
	}
	if len(uids) > 40 {
		uids = uids[len(uids)-40:]
	}
	messages := make([]outlookMessage, 0, len(uids))
	for i := len(uids) - 1; i >= 0; i-- {
		raw, err := session.fetchRFC822(uids[i])
		if err != nil || len(raw) == 0 {
			continue
		}
		message, err := parseRFC822Message(raw)
		if err != nil {
			continue
		}
		message.ID = "imap:" + strings.ToLower(mailbox) + ":" + uids[i]
		messages = append(messages, message)
	}
	return messages, nil
}

func dialIMAP(host string) (*imapSession, error) {
	dialer := &net.Dialer{Timeout: 25 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "993"), &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(greeting)), "* OK") {
		_ = conn.Close()
		return nil, fmt.Errorf("IMAP greeting rejected: %s", truncate(strings.TrimSpace(greeting), 160))
	}
	return &imapSession{conn: conn, reader: reader}, nil
}

func (s *imapSession) tag() string {
	s.next++
	return fmt.Sprintf("A%04d", s.next)
}

func (s *imapSession) authenticateXOAUTH2(mailbox, accessToken string) error {
	tag := s.tag()
	auth := base64.StdEncoding.EncodeToString([]byte("user=" + mailbox + "\x01auth=Bearer " + accessToken + "\x01\x01"))
	_ = s.conn.SetDeadline(time.Now().Add(45 * time.Second))
	if _, err := fmt.Fprintf(s.conn, "%s AUTHENTICATE XOAUTH2 %s\r\n", tag, auth); err != nil {
		return err
	}
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return err
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "+") {
			// A continuation after SASL-IR normally carries an OAuth error. An
			// empty response terminates the exchange so the server returns NO.
			if _, err := io.WriteString(s.conn, "\r\n"); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), strings.ToUpper(tag)+" ") {
			if imapTaggedOK(trimmed) {
				return nil
			}
			return fmt.Errorf("IMAP AUTHENTICATE rejected: %s", truncate(trimmed, 200))
		}
	}
}

func (s *imapSession) command(command string) ([]string, error) {
	tag := s.tag()
	_ = s.conn.SetDeadline(time.Now().Add(45 * time.Second))
	if _, err := fmt.Fprintf(s.conn, "%s %s\r\n", tag, command); err != nil {
		return nil, err
	}
	var lines []string
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), strings.ToUpper(tag)+" ") {
			if imapTaggedOK(trimmed) {
				return lines, nil
			}
			return nil, fmt.Errorf("IMAP %s rejected: %s", strings.Fields(command)[0], truncate(trimmed, 200))
		}
		lines = append(lines, trimmed)
	}
}

func (s *imapSession) fetchRFC822(uid string) ([]byte, error) {
	if _, err := strconv.ParseUint(uid, 10, 64); err != nil {
		return nil, fmt.Errorf("invalid IMAP UID")
	}
	tag := s.tag()
	_ = s.conn.SetDeadline(time.Now().Add(45 * time.Second))
	if _, err := fmt.Fprintf(s.conn, "%s UID FETCH %s (BODY.PEEK[])\r\n", tag, uid); err != nil {
		return nil, err
	}
	var raw []byte
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if match := imapLiteralRe.FindStringSubmatch(line); len(match) == 2 {
			size, _ := strconv.Atoi(match[1])
			if size < 0 || size > 12<<20 {
				return nil, fmt.Errorf("IMAP message literal too large: %d", size)
			}
			raw = make([]byte, size)
			if _, err := io.ReadFull(s.reader, raw); err != nil {
				return nil, err
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), strings.ToUpper(tag)+" ") {
			if imapTaggedOK(trimmed) {
				return raw, nil
			}
			return nil, fmt.Errorf("IMAP FETCH rejected: %s", truncate(trimmed, 200))
		}
	}
}

func (s *imapSession) logout() error {
	_, err := s.command("LOGOUT")
	return err
}

func imapTaggedOK(line string) bool {
	fields := strings.Fields(line)
	return len(fields) >= 2 && strings.EqualFold(fields[1], "OK")
}

func parseRFC822Message(raw []byte) (outlookMessage, error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return outlookMessage{}, err
	}
	decodeHeader := func(value string) string {
		decoded, err := new(mime.WordDecoder).DecodeHeader(value)
		if err != nil {
			return value
		}
		return decoded
	}
	recipients := []string{}
	for _, name := range []string{"To", "Cc", "Delivered-To", "X-Original-To", "X-Delivered-To", "Envelope-To", "X-Envelope-To"} {
		for _, value := range message.Header[name] {
			recipients = append(recipients, emailAddresses(decodeHeader(value))...)
		}
	}
	receivedAt, _ := mail.ParseDate(message.Header.Get("Date"))
	body, err := readMIMEBody(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return outlookMessage{}, err
	}
	return outlookMessage{
		Subject:    decodeHeader(message.Header.Get("Subject")),
		Sender:     decodeHeader(message.Header.Get("From")),
		Recipients: recipients,
		ReceivedAt: receivedAt,
		Body:       body,
	}, nil
}

func readMIMEBody(header textproto.MIMEHeader, body io.Reader) (string, error) {
	contentType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if strings.HasPrefix(strings.ToLower(contentType), "multipart/") && params["boundary"] != "" {
		reader := multipart.NewReader(body, params["boundary"])
		var joined strings.Builder
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}
			text, err := readMIMEBody(part.Header, part)
			_ = part.Close()
			if err == nil && text != "" {
				joined.WriteString(text)
				joined.WriteByte('\n')
			}
		}
		return joined.String(), nil
	}

	var decoded io.Reader = body
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		decoded = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		decoded = quotedprintable.NewReader(body)
	}
	raw, err := io.ReadAll(io.LimitReader(decoded, 6<<20))
	if err != nil {
		return "", err
	}
	text := string(raw)
	if strings.EqualFold(contentType, "text/html") {
		text = stripHTML(text)
	}
	if contentType == "" || strings.HasPrefix(strings.ToLower(contentType), "text/") {
		return text, nil
	}
	return "", nil
}
