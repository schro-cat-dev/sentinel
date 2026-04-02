package notify

import (
	"testing"
)

// --- ValidateWebhookURL Tests (F-05: SSRF prevention) ---

func TestValidateWebhookURL_ValidHTTPS(t *testing.T) {
	tests := []string{
		"https://hooks.slack.com/services/T0/B0/xxx",
		"https://discord.com/api/webhooks/123/abc",
		"https://example.com/webhook",
		"https://my-company.internal:8443/notify",
	}
	for _, url := range tests {
		if err := ValidateWebhookURL(url); err != nil {
			t.Errorf("ValidateWebhookURL(%q) = %v, want nil", url, err)
		}
	}
}

func TestValidateWebhookURL_EmptyURL(t *testing.T) {
	if err := ValidateWebhookURL(""); err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestValidateWebhookURL_RejectsHTTP(t *testing.T) {
	urls := []string{
		"http://hooks.slack.com/services/T0/B0/xxx",
		"http://example.com/webhook",
	}
	for _, url := range urls {
		if err := ValidateWebhookURL(url); err == nil {
			t.Errorf("ValidateWebhookURL(%q) should reject http scheme", url)
		}
	}
}

func TestValidateWebhookURL_RejectsNonHTTPSchemes(t *testing.T) {
	urls := []string{
		"ftp://example.com/file",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"data:text/html,<h1>XSS</h1>",
		"gopher://evil.com",
	}
	for _, url := range urls {
		if err := ValidateWebhookURL(url); err == nil {
			t.Errorf("ValidateWebhookURL(%q) should reject non-https scheme", url)
		}
	}
}

func TestValidateWebhookURL_RejectsLocalhost(t *testing.T) {
	urls := []string{
		"https://localhost/webhook",
		"https://localhost:8080/webhook",
		"https://LOCALHOST/webhook",
	}
	for _, url := range urls {
		if err := ValidateWebhookURL(url); err == nil {
			t.Errorf("ValidateWebhookURL(%q) should reject localhost", url)
		}
	}
}

func TestValidateWebhookURL_RejectsLoopbackIP(t *testing.T) {
	urls := []string{
		"https://127.0.0.1/webhook",
		"https://127.0.0.1:443/webhook",
		"https://[::1]/webhook",
		"https://[::1]:8443/webhook",
	}
	for _, url := range urls {
		if err := ValidateWebhookURL(url); err == nil {
			t.Errorf("ValidateWebhookURL(%q) should reject loopback", url)
		}
	}
}

func TestValidateWebhookURL_RejectsPrivateRanges(t *testing.T) {
	urls := []string{
		"https://10.0.0.1/webhook",
		"https://10.255.255.255/webhook",
		"https://172.16.0.1/webhook",
		"https://172.31.255.255/webhook",
		"https://192.168.0.1/webhook",
		"https://192.168.255.255/webhook",
		"https://169.254.169.254/latest/meta-data/", // AWS metadata SSRF
		"https://[fd00::1]/webhook",                  // IPv6 ULA
	}
	for _, url := range urls {
		if err := ValidateWebhookURL(url); err == nil {
			t.Errorf("ValidateWebhookURL(%q) should reject private IP", url)
		}
	}
}

func TestValidateWebhookURL_RejectsMalformedURL(t *testing.T) {
	urls := []string{
		"not-a-url",
		"://missing-scheme",
		"https://",
		"https:///no-host",
	}
	for _, url := range urls {
		if err := ValidateWebhookURL(url); err == nil {
			t.Errorf("ValidateWebhookURL(%q) should reject malformed URL", url)
		}
	}
}

func TestValidateWebhookURL_RejectsZeroIP(t *testing.T) {
	if err := ValidateWebhookURL("https://0.0.0.0/webhook"); err == nil {
		t.Error("expected error for 0.0.0.0")
	}
}

// --- Constructor error tests ---

func TestNewWebhookNotifierValidated_RejectsHTTP(t *testing.T) {
	_, err := NewWebhookNotifierValidated(WebhookConfig{URL: "http://example.com/hook"})
	if err == nil {
		t.Error("expected error for http URL")
	}
}

func TestNewWebhookNotifierValidated_AcceptsHTTPS(t *testing.T) {
	n, err := NewWebhookNotifierValidated(WebhookConfig{URL: "https://example.com/hook"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Type() != "webhook" {
		t.Errorf("expected webhook, got %s", n.Type())
	}
}

func TestNewSlackNotifierValidated_RejectsPrivateIP(t *testing.T) {
	_, err := NewSlackNotifierValidated(SlackConfig{WebhookURL: "https://192.168.1.1/hook"})
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestNewSlackNotifierValidated_AcceptsSlackURL(t *testing.T) {
	n, err := NewSlackNotifierValidated(SlackConfig{WebhookURL: "https://hooks.slack.com/services/T/B/x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Type() != "slack" {
		t.Errorf("expected slack, got %s", n.Type())
	}
}

func TestNewDiscordNotifierValidated_RejectsLocalhost(t *testing.T) {
	_, err := NewDiscordNotifierValidated(DiscordConfig{WebhookURL: "https://localhost/hook"})
	if err == nil {
		t.Error("expected error for localhost")
	}
}

func TestNewDiscordNotifierValidated_AcceptsDiscordURL(t *testing.T) {
	n, err := NewDiscordNotifierValidated(DiscordConfig{WebhookURL: "https://discord.com/api/webhooks/123/abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Type() != "discord" {
		t.Errorf("expected discord, got %s", n.Type())
	}
}
