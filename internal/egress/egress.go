// Package egress resolves and validates the public network identity used by a
// signup browser.  The resulting profile is shared by proxy selection,
// browser fingerprint configuration, and per-stage metrics.
package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTraceURL = "https://www.cloudflare.com/cdn-cgi/trace"
	defaultMetaURL  = "https://ipwho.is/{ip}"
)

// Profile is the non-secret public identity of one proxy exit.
type Profile struct {
	IP          string  `json:"ip,omitempty"`
	ASN         int     `json:"asn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	Locale      string  `json:"locale,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Proxy       bool    `json:"proxy_detected,omitempty"`
	Hosting     bool    `json:"hosting,omitempty"`
	Mobile      bool    `json:"mobile,omitempty"`
	Source      string  `json:"source,omitempty"`
}

// Summary is safe for logs; it never includes proxy credentials.
func (p Profile) Summary() string {
	parts := make([]string, 0, 5)
	if p.IP != "" {
		parts = append(parts, "ip="+p.IP)
	}
	if p.ASN > 0 {
		parts = append(parts, fmt.Sprintf("asn=AS%d", p.ASN))
	}
	if p.ISP != "" {
		parts = append(parts, "isp="+p.ISP)
	}
	if p.CountryCode != "" {
		parts = append(parts, "country="+p.CountryCode)
	}
	if p.Timezone != "" {
		parts = append(parts, "tz="+p.Timezone)
	}
	return strings.Join(parts, " ")
}

// Options controls strict validation. Metadata lookup is best effort; a valid
// Cloudflare-visible public IP is the hard requirement.
type Options struct {
	Timeout       time.Duration
	TraceURL      string
	MetadataURL   string
	BlockedASNs   string
	BlockedISPs   string
	RejectHosting bool
	HTTPClient    *http.Client // optional test/direct client
}

// Inspector resolves exit profiles through the candidate proxy.
type Inspector struct {
	timeout       time.Duration
	traceURL      string
	metadataURL   string
	blockedASNs   map[int]struct{}
	blockedISPs   []string
	rejectHosting bool
	direct        *http.Client
}

func NewInspector(opt Options) *Inspector {
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	traceURL := strings.TrimSpace(opt.TraceURL)
	if traceURL == "" {
		traceURL = defaultTraceURL
	}
	metadataURL := strings.TrimSpace(opt.MetadataURL)
	if metadataURL == "" {
		metadataURL = defaultMetaURL
	}
	direct := opt.HTTPClient
	if direct == nil {
		direct = &http.Client{
			Transport: &http.Transport{
				Proxy:             nil, // metadata lookup must not inherit HTTP_PROXY
				DisableKeepAlives: true,
			},
			Timeout: timeout,
		}
	}
	return &Inspector{
		timeout:       timeout,
		traceURL:      traceURL,
		metadataURL:   metadataURL,
		blockedASNs:   parseASNs(opt.BlockedASNs),
		blockedISPs:   parseTerms(opt.BlockedISPs),
		rejectHosting: opt.RejectHosting,
		direct:        direct,
	}
}

// Inspect requires the candidate exit to reach Cloudflare trace and expose a
// public IP. ASN/ISP/geolocation enrichment is best effort unless a configured
// policy needs it for rejection.
func (i *Inspector) Inspect(ctx context.Context, rawProxy string) (Profile, error) {
	if i == nil {
		return Profile{}, fmt.Errorf("egress inspector is nil")
	}
	client, err := i.clientFor(rawProxy)
	if err != nil {
		return Profile{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, i.traceURL, nil)
	if err != nil {
		return Profile{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; grok-reg-egress-check/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return Profile{}, fmt.Errorf("egress trace: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return Profile{}, fmt.Errorf("egress trace read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Profile{}, fmt.Errorf("egress trace http=%d", resp.StatusCode)
	}
	trace := parseTrace(string(body))
	ip := strings.TrimSpace(trace["ip"])
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !parsedIP.IsGlobalUnicast() || parsedIP.IsPrivate() {
		return Profile{}, fmt.Errorf("egress trace missing public ip")
	}
	profile := Profile{
		IP:          ip,
		CountryCode: strings.ToUpper(strings.TrimSpace(trace["loc"])),
		Source:      "cloudflare-trace",
	}
	profile.Locale = localeForCountry(profile.CountryCode)
	if meta, metaErr := i.lookupMetadata(ctx, ip); metaErr == nil {
		mergeProfile(&profile, meta)
	} else if i.rejectHosting || len(i.blockedASNs) > 0 || len(i.blockedISPs) > 0 {
		return profile, fmt.Errorf("egress metadata required by policy: %w", metaErr)
	}
	if _, blocked := i.blockedASNs[profile.ASN]; blocked && profile.ASN > 0 {
		return profile, fmt.Errorf("egress AS%d is blocked (%s)", profile.ASN, firstNonEmpty(profile.ISP, profile.ASName))
	}
	ispText := strings.ToLower(strings.Join([]string{profile.ISP, profile.ASName}, " "))
	for _, term := range i.blockedISPs {
		if strings.Contains(ispText, term) {
			return profile, fmt.Errorf("egress ISP is blocked (%s)", firstNonEmpty(profile.ISP, profile.ASName))
		}
	}
	if i.rejectHosting && (profile.Hosting || profile.Proxy) {
		return profile, fmt.Errorf("egress is proxy/hosting (%s)", firstNonEmpty(profile.ISP, profile.ASName))
	}
	return profile, nil
}

func (i *Inspector) clientFor(rawProxy string) (*http.Client, error) {
	transport := &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   i.timeout,
		ResponseHeaderTimeout: i.timeout,
		DialContext: (&net.Dialer{
			Timeout:   i.timeout,
			KeepAlive: 0,
		}).DialContext,
	}
	rawProxy = strings.TrimSpace(rawProxy)
	if rawProxy != "" {
		u, err := url.Parse(rawProxy)
		if err != nil {
			return nil, fmt.Errorf("parse proxy: %w", err)
		}
		if u.Scheme == "" {
			u, err = url.Parse("http://" + rawProxy)
			if err != nil {
				return nil, fmt.Errorf("parse proxy: %w", err)
			}
		}
		if u.Host == "" {
			return nil, fmt.Errorf("parse proxy: missing host")
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   i.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (i *Inspector) lookupMetadata(ctx context.Context, ip string) (Profile, error) {
	rawURL := strings.ReplaceAll(i.metadataURL, "{ip}", url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Profile{}, err
	}
	resp, err := i.direct.Do(req)
	if err != nil {
		return Profile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Profile{}, fmt.Errorf("metadata http=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return Profile{}, err
	}
	return parseMetadata(body)
}

func parseTrace(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key != "" {
			out[key] = value
		}
	}
	return out
}

func parseMetadata(body []byte) (Profile, error) {
	var data struct {
		Success     *bool   `json:"success"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Type        string  `json:"type"`
		Timezone    struct {
			ID string `json:"id"`
		} `json:"timezone"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
		Security struct {
			Proxy   bool `json:"proxy"`
			Hosting bool `json:"hosting"`
		} `json:"security"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return Profile{}, err
	}
	if data.Success != nil && !*data.Success {
		return Profile{}, fmt.Errorf("metadata lookup failed")
	}
	profile := Profile{
		ASN:         data.Connection.ASN,
		ASName:      strings.TrimSpace(data.Connection.Org),
		ISP:         strings.TrimSpace(data.Connection.ISP),
		Country:     strings.TrimSpace(data.Country),
		CountryCode: strings.ToUpper(strings.TrimSpace(data.CountryCode)),
		Region:      strings.TrimSpace(data.Region),
		City:        strings.TrimSpace(data.City),
		Timezone:    strings.TrimSpace(data.Timezone.ID),
		Latitude:    data.Latitude,
		Longitude:   data.Longitude,
		Proxy:       data.Security.Proxy,
		Hosting:     data.Security.Hosting,
		Mobile:      strings.EqualFold(strings.TrimSpace(data.Type), "mobile"),
		Source:      "ipwho.is",
	}
	profile.Locale = localeForCountry(profile.CountryCode)
	return profile, nil
}

func mergeProfile(dst *Profile, src Profile) {
	if src.ASN > 0 {
		dst.ASN = src.ASN
	}
	for target, value := range map[*string]string{
		&dst.ASName: src.ASName, &dst.ISP: src.ISP, &dst.Country: src.Country,
		&dst.CountryCode: src.CountryCode, &dst.Region: src.Region, &dst.City: src.City,
		&dst.Timezone: src.Timezone, &dst.Locale: src.Locale,
	} {
		if value != "" {
			*target = value
		}
	}
	if src.Latitude != 0 || src.Longitude != 0 {
		dst.Latitude, dst.Longitude = src.Latitude, src.Longitude
	}
	dst.Proxy, dst.Hosting, dst.Mobile = src.Proxy, src.Hosting, src.Mobile
	if src.Source != "" {
		dst.Source = dst.Source + "+" + src.Source
	}
}

func parseASNs(raw string) map[int]struct{} {
	out := map[int]struct{}{}
	for _, term := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	}) {
		term = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(term)), "AS")
		if n, err := strconv.Atoi(term); err == nil && n > 0 {
			out[n] = struct{}{}
		}
	}
	return out
}

func parseTerms(raw string) []string {
	var out []string
	for _, term := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	}) {
		if term = strings.ToLower(strings.TrimSpace(term)); term != "" {
			out = append(out, term)
		}
	}
	return out
}

func localeForCountry(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "GB":
		return "en-GB"
	case "CA":
		return "en-CA"
	case "AU":
		return "en-AU"
	case "NZ":
		return "en-NZ"
	case "DE":
		return "de-DE"
	case "FR":
		return "fr-FR"
	case "ES":
		return "es-ES"
	case "IT":
		return "it-IT"
	case "JP":
		return "ja-JP"
	case "KR":
		return "ko-KR"
	case "BR":
		return "pt-BR"
	case "SG":
		return "en-SG"
	case "HK":
		return "en-HK"
	case "TW":
		return "zh-TW"
	case "CN":
		return "zh-CN"
	default:
		return "en-US"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}
