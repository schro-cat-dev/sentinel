package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// --- Webhook Adapter Tests ---

func TestWebhookNotifier_Send(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer server.Close()

	wh := NewWebhookNotifier(WebhookConfig{
		URL: server.URL, TimeoutSec: 5, Secret: "test-secret",
		Headers: map[string]string{"X-Custom": "value"},
	})

	if wh.Type() != "webhook" {
		t.Errorf("expected webhook, got %s", wh.Type())
	}

	err := wh.Send(context.Background(), Notification{
		Channel: "#security", Subject: "Alert", Body: "Intrusion detected",
		Severity: "high", TraceID: "t-001", EventName: "SECURITY_INTRUSION",
		Fields: map[string]string{"ip": "10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Verify body
	var payload map[string]interface{}
	json.Unmarshal(receivedBody, &payload)
	if payload["channel"] != "#security" {
		t.Errorf("expected #security, got %v", payload["channel"])
	}
	if payload["severity"] != "high" {
		t.Errorf("expected high, got %v", payload["severity"])
	}

	// Verify HMAC signature
	sig := receivedHeaders.Get("X-Sentinel-Signature")
	if sig == "" {
		t.Error("expected HMAC signature")
	}
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write(receivedBody)
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if sig != expected {
		t.Error("HMAC signature mismatch")
	}

	// Verify custom header
	if receivedHeaders.Get("X-Custom") != "value" {
		t.Error("custom header missing")
	}
}

func TestWebhookNotifier_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	wh := NewWebhookNotifier(WebhookConfig{URL: server.URL, TimeoutSec: 5})
	err := wh.Send(context.Background(), Notification{Subject: "test"})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestWebhookNotifier_InvalidURL(t *testing.T) {
	wh := NewWebhookNotifier(WebhookConfig{URL: "http://localhost:99999", TimeoutSec: 1})
	err := wh.Send(context.Background(), Notification{Subject: "test"})
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestWebhookNotifier_NoSecret(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer server.Close()

	wh := NewWebhookNotifier(WebhookConfig{URL: server.URL})
	wh.Send(context.Background(), Notification{Subject: "test"})

	if receivedHeaders.Get("X-Sentinel-Signature") != "" {
		t.Error("should not set signature without secret")
	}
}

func TestWebhookNotifier_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	wh := NewWebhookNotifier(WebhookConfig{URL: server.URL, TimeoutSec: 5})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := wh.Send(ctx, Notification{Subject: "test"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestWebhookNotifier_DefaultTimeout(t *testing.T) {
	wh := NewWebhookNotifier(WebhookConfig{URL: "http://example.com"})
	if wh.httpClient.Timeout != 10*1e9 { // 10 seconds in nanoseconds
		t.Errorf("expected 10s default timeout, got %v", wh.httpClient.Timeout)
	}
}

// --- Slack Adapter Tests ---

func TestSlackNotifier_Send(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	slack := NewSlackNotifier(SlackConfig{
		WebhookURL: server.URL, TimeoutSec: 5,
		Username: "TestBot", IconEmoji: ":test:",
	})

	if slack.Type() != "slack" {
		t.Errorf("expected slack, got %s", slack.Type())
	}

	err := slack.Send(context.Background(), Notification{
		Channel: "#security", Subject: "Security Alert",
		Body: "Intrusion from 10.0.0.1", Severity: "critical",
		Fields: map[string]string{"ip": "10.0.0.1", "action": "blocked"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var payload map[string]interface{}
	json.Unmarshal(receivedBody, &payload)
	if payload["channel"] != "#security" {
		t.Errorf("expected #security, got %v", payload["channel"])
	}
	if payload["username"] != "TestBot" {
		t.Errorf("expected TestBot, got %v", payload["username"])
	}
	attachments := payload["attachments"].([]interface{})
	if len(attachments) != 1 {
		t.Fatal("expected 1 attachment")
	}
	att := attachments[0].(map[string]interface{})
	if att["color"] != "#FF0000" { // critical = red
		t.Errorf("expected red color for critical, got %v", att["color"])
	}
	if att["title"] != "Security Alert" {
		t.Errorf("wrong title: %v", att["title"])
	}
}

func TestSlackNotifier_Defaults(t *testing.T) {
	slack := NewSlackNotifier(SlackConfig{WebhookURL: "http://example.com"})
	if slack.username != "Sentinel" {
		t.Errorf("expected Sentinel default, got %s", slack.username)
	}
	if slack.iconEmoji != ":shield:" {
		t.Errorf("expected :shield: default, got %s", slack.iconEmoji)
	}
}

func TestSlackNotifier_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer server.Close()

	slack := NewSlackNotifier(SlackConfig{WebhookURL: server.URL})
	err := slack.Send(context.Background(), Notification{Subject: "test"})
	if err == nil {
		t.Error("expected error for 403")
	}
}

// --- Discord Adapter Tests ---

func TestDiscordNotifier_Send(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(204) // Discord returns 204 on success
	}))
	defer server.Close()

	discord := NewDiscordNotifier(DiscordConfig{
		WebhookURL: server.URL, Username: "SentinelBot",
	})

	if discord.Type() != "discord" {
		t.Errorf("expected discord, got %s", discord.Type())
	}

	err := discord.Send(context.Background(), Notification{
		Subject: "Alert", Body: "Details", Severity: "high",
		Fields: map[string]string{"key": "value"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var payload map[string]interface{}
	json.Unmarshal(receivedBody, &payload)
	if payload["username"] != "SentinelBot" {
		t.Errorf("expected SentinelBot, got %v", payload["username"])
	}
	embeds := payload["embeds"].([]interface{})
	if len(embeds) != 1 {
		t.Fatal("expected 1 embed")
	}
	embed := embeds[0].(map[string]interface{})
	if embed["title"] != "Alert" {
		t.Errorf("wrong title: %v", embed["title"])
	}
	// high = 0xFF6600 = 16737792
	if int(embed["color"].(float64)) != 0xFF6600 {
		t.Errorf("wrong color for high: %v", embed["color"])
	}
}

func TestDiscordNotifier_Defaults(t *testing.T) {
	d := NewDiscordNotifier(DiscordConfig{WebhookURL: "http://example.com"})
	if d.username != "Sentinel" {
		t.Errorf("expected Sentinel, got %s", d.username)
	}
}

func TestDiscordNotifier_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429) // rate limited
	}))
	defer server.Close()

	d := NewDiscordNotifier(DiscordConfig{WebhookURL: server.URL})
	err := d.Send(context.Background(), Notification{Subject: "test"})
	if err == nil {
		t.Error("expected error for 429")
	}
}

// --- Gmail Adapter Tests ---

func TestGmailNotifier_Type(t *testing.T) {
	g := NewGmailNotifier(GmailConfig{From: "test@gmail.com"})
	if g.Type() != "gmail" {
		t.Errorf("expected gmail, got %s", g.Type())
	}
}

func TestGmailNotifier_Defaults(t *testing.T) {
	g := NewGmailNotifier(GmailConfig{})
	if g.smtpHost != "smtp.gmail.com" {
		t.Errorf("expected smtp.gmail.com, got %s", g.smtpHost)
	}
	if g.smtpPort != "587" {
		t.Errorf("expected 587, got %s", g.smtpPort)
	}
}

func TestGmailNotifier_NoRecipients(t *testing.T) {
	g := NewGmailNotifier(GmailConfig{From: "test@gmail.com"})
	err := g.Send(context.Background(), Notification{Subject: "test", Channel: ""})
	if err == nil {
		t.Error("expected error for no recipients")
	}
}

func TestGmailNotifier_ChannelOverride(t *testing.T) {
	// Can't test actual SMTP, but verify the recipient resolution
	g := NewGmailNotifier(GmailConfig{
		From: "sentinel@company.com",
		To:   []string{"default@company.com"},
	})
	// When channel contains @, it should use that as recipient
	// We can't test actual sending without SMTP, so just verify the type
	if g.Type() != "gmail" {
		t.Error("wrong type")
	}
	if len(g.to) != 1 || g.to[0] != "default@company.com" {
		t.Error("default recipients not set")
	}
}

// --- Log Adapter Tests ---

func TestLogNotifier_Send(t *testing.T) {
	l := NewLogNotifier()
	if l.Type() != "log" {
		t.Errorf("expected log, got %s", l.Type())
	}
	err := l.Send(context.Background(), Notification{
		Subject: "Test", Body: "Test body", Severity: "info",
		EventName: "TEST", TraceID: "t-1",
	})
	if err != nil {
		t.Errorf("log notifier should not fail: %v", err)
	}
}

// --- Color Tests ---

func TestSlackColor_AllSeverities(t *testing.T) {
	tests := map[string]string{
		"critical": "#FF0000",
		"high":     "#FF6600",
		"medium":   "#FFCC00",
		"low":      "#36A64F",
		"info":     "#439FE0",
		"":         "#439FE0",
		"CRITICAL": "#FF0000", // case insensitive
	}
	for sev, expected := range tests {
		if got := slackColor(sev); got != expected {
			t.Errorf("slackColor(%q) = %s, want %s", sev, got, expected)
		}
	}
}

func TestDiscordColor_AllSeverities(t *testing.T) {
	tests := map[string]int{
		"critical": 0xFF0000,
		"high":     0xFF6600,
		"medium":   0xFFCC00,
		"low":      0x36A64F,
		"info":     0x439FE0,
		"":         0x439FE0,
	}
	for sev, expected := range tests {
		if got := discordColor(sev); got != expected {
			t.Errorf("discordColor(%q) = %d, want %d", sev, got, expected)
		}
	}
}

// --- Concurrent Safety Tests ---

func TestWebhookNotifier_ConcurrentSend(t *testing.T) {
	var mu sync.Mutex
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()

	wh := NewWebhookNotifier(WebhookConfig{URL: server.URL, TimeoutSec: 5})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wh.Send(context.Background(), Notification{Subject: "concurrent"})
		}()
	}
	wg.Wait()

	mu.Lock()
	if count != 50 {
		t.Errorf("expected 50 requests, got %d", count)
	}
	mu.Unlock()
}

// --- Large Payload Tests ---

func TestWebhookNotifier_LargePayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	wh := NewWebhookNotifier(WebhookConfig{URL: server.URL, TimeoutSec: 5})
	err := wh.Send(context.Background(), Notification{
		Subject: "Large test",
		Body:    strings.Repeat("x", 100000), // 100KB body
	})
	if err != nil {
		t.Errorf("large payload should work: %v", err)
	}
}

// --- Special Characters Tests ---

func TestSlackNotifier_SpecialCharsInBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	slack := NewSlackNotifier(SlackConfig{WebhookURL: server.URL})
	err := slack.Send(context.Background(), Notification{
		Subject: "Alert <script>",
		Body:    "Attack: \"SQL injection\" & 'XSS' from <10.0.0.1>",
		Fields:  map[string]string{"payload": "'; DROP TABLE --"},
	})
	if err != nil {
		t.Errorf("special chars should not fail: %v", err)
	}
}
