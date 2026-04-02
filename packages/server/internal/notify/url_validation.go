package notify

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateWebhookURL validates that a webhook URL is safe for outbound requests.
// Rejects non-HTTPS schemes, localhost, loopback, private/link-local IPs (SSRF prevention).
func ValidateWebhookURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("webhook URL is empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	// Scheme: HTTPS only
	if parsed.Scheme != "https" {
		return fmt.Errorf("webhook URL must use https scheme, got %q", parsed.Scheme)
	}

	// Host must be present
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("webhook URL has no host")
	}

	// Reject localhost
	if strings.EqualFold(hostname, "localhost") {
		return fmt.Errorf("webhook URL must not target localhost")
	}

	// Parse IP if present — reject loopback, private, link-local, unspecified
	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("webhook URL must not target loopback address")
		}
		if ip.IsPrivate() {
			return fmt.Errorf("webhook URL must not target private IP range")
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL must not target link-local address")
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("webhook URL must not target unspecified address (0.0.0.0)")
		}
	}

	return nil
}

// --- Validated constructors (F-05) ---

// NewWebhookNotifierValidated creates a WebhookNotifier with URL validation.
func NewWebhookNotifierValidated(cfg WebhookConfig) (*WebhookNotifier, error) {
	if err := ValidateWebhookURL(cfg.URL); err != nil {
		return nil, fmt.Errorf("webhook notifier: %w", err)
	}
	return NewWebhookNotifier(cfg), nil
}

// NewSlackNotifierValidated creates a SlackNotifier with URL validation.
func NewSlackNotifierValidated(cfg SlackConfig) (*SlackNotifier, error) {
	if err := ValidateWebhookURL(cfg.WebhookURL); err != nil {
		return nil, fmt.Errorf("slack notifier: %w", err)
	}
	return NewSlackNotifier(cfg), nil
}

// NewDiscordNotifierValidated creates a DiscordNotifier with URL validation.
func NewDiscordNotifierValidated(cfg DiscordConfig) (*DiscordNotifier, error) {
	if err := ValidateWebhookURL(cfg.WebhookURL); err != nil {
		return nil, fmt.Errorf("discord notifier: %w", err)
	}
	return NewDiscordNotifier(cfg), nil
}
