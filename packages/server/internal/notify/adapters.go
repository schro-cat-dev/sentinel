package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// --- Webhook Adapter ---

// WebhookNotifier はHTTP Webhookベースの通知アダプタ
type WebhookNotifier struct {
	url        string
	httpClient *http.Client
	secret     []byte
	headers    map[string]string
}

// WebhookConfig はWebhookアダプタの設定
type WebhookConfig struct {
	URL        string
	TimeoutSec int
	Secret     string
	Headers    map[string]string
}

func NewWebhookNotifier(cfg WebhookConfig) *WebhookNotifier {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &WebhookNotifier{
		url:        cfg.URL,
		httpClient: &http.Client{Timeout: timeout},
		secret:     []byte(cfg.Secret),
		headers:    cfg.Headers,
	}
}

func (w *WebhookNotifier) Type() string { return "webhook" }

func (w *WebhookNotifier) Send(ctx context.Context, n Notification) error {
	payload := map[string]interface{}{
		"channel":    n.Channel,
		"subject":    n.Subject,
		"body":       n.Body,
		"severity":   n.Severity,
		"trace_id":   n.TraceID,
		"event_name": n.EventName,
		"fields":     n.Fields,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	if len(w.secret) > 0 {
		mac := hmac.New(sha256.New, w.secret)
		mac.Write(body)
		req.Header.Set("X-Sentinel-Signature", fmt.Sprintf("%x", mac.Sum(nil)))
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// --- Slack Adapter ---

// SlackNotifier はSlack Incoming Webhookベースの通知アダプタ
type SlackNotifier struct {
	webhookURL string
	httpClient *http.Client
	username   string
	iconEmoji  string
}

// SlackConfig はSlackアダプタの設定
type SlackConfig struct {
	WebhookURL string
	TimeoutSec int
	Username   string // bot名 (デフォルト: "Sentinel")
	IconEmoji  string // アイコン (デフォルト: ":shield:")
}

func NewSlackNotifier(cfg SlackConfig) *SlackNotifier {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if cfg.Username == "" {
		cfg.Username = "Sentinel"
	}
	if cfg.IconEmoji == "" {
		cfg.IconEmoji = ":shield:"
	}
	return &SlackNotifier{
		webhookURL: cfg.WebhookURL,
		httpClient: &http.Client{Timeout: timeout},
		username:   cfg.Username,
		iconEmoji:  cfg.IconEmoji,
	}
}

func (s *SlackNotifier) Type() string { return "slack" }

func (s *SlackNotifier) Send(ctx context.Context, n Notification) error {
	color := slackColor(n.Severity)
	var fields []map[string]interface{}
	for k, v := range n.Fields {
		fields = append(fields, map[string]interface{}{
			"title": k,
			"value": v,
			"short": len(v) < 40,
		})
	}

	payload := map[string]interface{}{
		"channel":    n.Channel,
		"username":   s.username,
		"icon_emoji": s.iconEmoji,
		"attachments": []map[string]interface{}{
			{
				"color":    color,
				"title":    n.Subject,
				"text":     n.Body,
				"fields":   fields,
				"footer":   "Sentinel Security Monitor",
				"ts":       time.Now().Unix(),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

func slackColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "#FF0000"
	case "high":
		return "#FF6600"
	case "medium":
		return "#FFCC00"
	case "low":
		return "#36A64F"
	default:
		return "#439FE0"
	}
}

// --- Gmail (SMTP) Adapter ---

// GmailNotifier はSMTPベースのGmail通知アダプタ
type GmailNotifier struct {
	from     string
	password string
	smtpHost string
	smtpPort string
	to       []string // デフォルト宛先
}

// GmailConfig はGmailアダプタの設定
type GmailConfig struct {
	From     string   // 送信元メールアドレス
	Password string   // アプリパスワード
	SMTPHost string   // デフォルト: "smtp.gmail.com"
	SMTPPort string   // デフォルト: "587"
	To       []string // デフォルト宛先
}

func NewGmailNotifier(cfg GmailConfig) *GmailNotifier {
	if cfg.SMTPHost == "" {
		cfg.SMTPHost = "smtp.gmail.com"
	}
	if cfg.SMTPPort == "" {
		cfg.SMTPPort = "587"
	}
	return &GmailNotifier{
		from:     cfg.From,
		password: cfg.Password,
		smtpHost: cfg.SMTPHost,
		smtpPort: cfg.SMTPPort,
		to:       cfg.To,
	}
}

func (g *GmailNotifier) Type() string { return "gmail" }

func (g *GmailNotifier) Send(ctx context.Context, n Notification) error {
	to := g.to
	if n.Channel != "" && strings.Contains(n.Channel, "@") {
		to = []string{n.Channel}
	}
	if len(to) == 0 {
		return fmt.Errorf("no recipients")
	}

	subject := n.Subject
	if subject == "" {
		subject = fmt.Sprintf("[Sentinel %s] %s", strings.ToUpper(n.Severity), n.EventName)
	}

	var bodyBuilder strings.Builder
	bodyBuilder.WriteString(n.Body)
	if len(n.Fields) > 0 {
		bodyBuilder.WriteString("\n\n--- Details ---\n")
		for k, v := range n.Fields {
			bodyBuilder.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	if n.TraceID != "" {
		bodyBuilder.WriteString(fmt.Sprintf("\nTrace ID: %s\n", n.TraceID))
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n%s",
		g.from,
		strings.Join(to, ", "),
		subject,
		bodyBuilder.String(),
	)

	auth := smtp.PlainAuth("", g.from, g.password, g.smtpHost)
	addr := g.smtpHost + ":" + g.smtpPort

	return smtp.SendMail(addr, auth, g.from, to, []byte(msg))
}

// --- Discord Adapter ---

// DiscordNotifier はDiscord Webhookベースの通知アダプタ
type DiscordNotifier struct {
	webhookURL string
	httpClient *http.Client
	username   string
}

// DiscordConfig はDiscordアダプタの設定
type DiscordConfig struct {
	WebhookURL string
	TimeoutSec int
	Username   string
}

func NewDiscordNotifier(cfg DiscordConfig) *DiscordNotifier {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if cfg.Username == "" {
		cfg.Username = "Sentinel"
	}
	return &DiscordNotifier{
		webhookURL: cfg.WebhookURL,
		httpClient: &http.Client{Timeout: timeout},
		username:   cfg.Username,
	}
}

func (d *DiscordNotifier) Type() string { return "discord" }

func (d *DiscordNotifier) Send(ctx context.Context, n Notification) error {
	color := discordColor(n.Severity)
	var fields []map[string]interface{}
	for k, v := range n.Fields {
		fields = append(fields, map[string]interface{}{
			"name":   k,
			"value":  v,
			"inline": len(v) < 40,
		})
	}

	payload := map[string]interface{}{
		"username": d.username,
		"embeds": []map[string]interface{}{
			{
				"title":       n.Subject,
				"description": n.Body,
				"color":       color,
				"fields":      fields,
				"footer":      map[string]string{"text": "Sentinel Security Monitor"},
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send discord: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord returned %d", resp.StatusCode)
	}
	return nil
}

func discordColor(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0xFF0000
	case "high":
		return 0xFF6600
	case "medium":
		return 0xFFCC00
	case "low":
		return 0x36A64F
	default:
		return 0x439FE0
	}
}

// --- Log Adapter (fallback / testing) ---

// LogNotifier はslogに通知内容を書き出すフォールバックアダプタ
type LogNotifier struct{}

func NewLogNotifier() *LogNotifier { return &LogNotifier{} }

func (l *LogNotifier) Type() string { return "log" }

func (l *LogNotifier) Send(ctx context.Context, n Notification) error {
	fmt.Printf("[NOTIFY:%s] %s | %s | severity=%s traceId=%s\n",
		n.EventName, n.Subject, n.Body, n.Severity, n.TraceID)
	return nil
}
