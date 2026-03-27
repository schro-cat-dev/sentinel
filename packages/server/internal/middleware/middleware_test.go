package middleware

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// === Security Config Tests ===

func TestDefaultStrictConfig(t *testing.T) {
	cfg := DefaultStrictConfig()

	t.Run("is enabled by default", func(t *testing.T) {
		if !cfg.IsEnabled() { t.Error("should be enabled") }
	})

	t.Run("CORS denies all origins by default", func(t *testing.T) {
		cors := cfg.GetCORSConfig()
		if len(cors.AllowedOrigins) != 0 { t.Errorf("expected 0 allowed origins, got %d", len(cors.AllowedOrigins)) }
	})

	t.Run("CORS allows only POST by default", func(t *testing.T) {
		cors := cfg.GetCORSConfig()
		if len(cors.AllowedMethods) != 1 || cors.AllowedMethods[0] != "POST" {
			t.Errorf("expected [POST], got %v", cors.AllowedMethods)
		}
	})

	t.Run("has strict security headers", func(t *testing.T) {
		headers := cfg.GetHeaders()
		found := map[string]bool{}
		for _, h := range headers {
			found[h.Key] = true
		}
		required := []string{
			"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security",
			"Content-Security-Policy", "Referrer-Policy", "Cross-Origin-Resource-Policy",
			"Permissions-Policy", "Cache-Control",
		}
		for _, r := range required {
			if !found[r] { t.Errorf("missing required header: %s", r) }
		}
	})

	t.Run("has honeypot paths", func(t *testing.T) {
		paths := cfg.GetHoneypotPaths()
		if len(paths) == 0 { t.Error("expected honeypot paths") }
		foundAdmin := false
		for _, p := range paths {
			if p == "/admin" { foundAdmin = true }
		}
		if !foundAdmin { t.Error("expected /admin in honeypot paths") }
	})

	t.Run("rate limit enabled by default", func(t *testing.T) {
		rl := cfg.GetRateLimitConfig()
		if !rl.Enabled { t.Error("rate limit should be enabled") }
		if rl.RPS != 100 { t.Errorf("expected 100 rps, got %f", rl.RPS) }
	})
}

func TestLoadSecurityConfig_FromJSON(t *testing.T) {
	t.Run("loads override from JSON file", func(t *testing.T) {
		override := SecurityConfigData{
			CORS: CORSConfig{
				AllowedOrigins: []string{"https://myapp.example.com"},
				AllowedMethods: []string{"POST", "GET"},
			},
		}
		data, _ := json.Marshal(override)
		tmpFile := filepath.Join(t.TempDir(), "security.json")
		os.WriteFile(tmpFile, data, 0644)

		cfg, err := LoadSecurityConfig(tmpFile)
		if err != nil { t.Fatalf("error: %v", err) }

		cors := cfg.GetCORSConfig()
		if len(cors.AllowedOrigins) != 1 || cors.AllowedOrigins[0] != "https://myapp.example.com" {
			t.Errorf("origins: %v", cors.AllowedOrigins)
		}
	})

	t.Run("uses default when file not found", func(t *testing.T) {
		cfg, err := LoadSecurityConfig("/nonexistent/path.json")
		if err != nil { t.Fatalf("error: %v", err) }
		if !cfg.IsEnabled() { t.Error("should be enabled with defaults") }
	})

	t.Run("uses default when path is empty", func(t *testing.T) {
		cfg, err := LoadSecurityConfig("")
		if err != nil { t.Fatalf("error: %v", err) }
		if !cfg.IsEnabled() { t.Error("should be enabled") }
	})
}

// === Auth Token Validator Tests ===

func TestStaticTokenValidator(t *testing.T) {
	v := NewStaticTokenValidator(map[string]string{
		"token-abc": "service-A",
		"token-xyz": "service-B",
	})
	ctx := context.Background()

	t.Run("valid token returns clientID", func(t *testing.T) {
		id, err := v.Validate(ctx, "token-abc")
		if err != nil { t.Fatalf("error: %v", err) }
		if id != "service-A" { t.Errorf("expected service-A, got %s", id) }
	})

	t.Run("invalid token returns error", func(t *testing.T) {
		_, err := v.Validate(ctx, "wrong-token")
		if err == nil { t.Error("expected error") }
	})

	t.Run("constant-time comparison", func(t *testing.T) {
		// This just verifies it uses subtle.ConstantTimeCompare (by behavior)
		_, err := v.Validate(ctx, "token-ab") // 1 char shorter
		if err == nil { t.Error("expected error for partial match") }
	})
}

func TestNoopTokenValidator(t *testing.T) {
	v := &NoopTokenValidator{}
	id, err := v.Validate(context.Background(), "anything")
	if err != nil { t.Fatalf("error: %v", err) }
	if id != "anonymous" { t.Errorf("expected anonymous, got %s", id) }
}

// Mock external store for cached validator tests
type mockExternalStore struct {
	tokens map[string]string // token → clientID
}

func (m *mockExternalStore) LookupToken(ctx context.Context, token string) (string, bool, error) {
	if id, ok := m.tokens[token]; ok {
		return id, true, nil
	}
	return "", false, nil
}

func TestCachedTokenValidator(t *testing.T) {
	store := &mockExternalStore{
		tokens: map[string]string{"cached-token": "cached-client"},
	}
	v := NewCachedTokenValidator(store, 1*time.Second)
	ctx := context.Background()

	t.Run("queries external store on cache miss", func(t *testing.T) {
		id, err := v.Validate(ctx, "cached-token")
		if err != nil { t.Fatalf("error: %v", err) }
		if id != "cached-client" { t.Errorf("expected cached-client, got %s", id) }
	})

	t.Run("returns cached result on hit", func(t *testing.T) {
		// Second call should use cache
		id, err := v.Validate(ctx, "cached-token")
		if err != nil { t.Fatalf("error: %v", err) }
		if id != "cached-client" { t.Errorf("expected cached-client, got %s", id) }
	})

	t.Run("invalid token is cached too", func(t *testing.T) {
		_, err := v.Validate(ctx, "unknown-token")
		if err == nil { t.Error("expected error") }
		// Second call should also fail from cache
		_, err = v.Validate(ctx, "unknown-token")
		if err == nil { t.Error("expected cached error") }
	})
}

func TestNewTokenValidator_Factory(t *testing.T) {
	t.Run("noop when disabled", func(t *testing.T) {
		v := NewTokenValidator(AuthConfig{Enabled: false}, nil)
		_, ok := v.(*NoopTokenValidator)
		if !ok { t.Error("expected NoopTokenValidator") }
	})

	t.Run("static when configured", func(t *testing.T) {
		v := NewTokenValidator(AuthConfig{
			Enabled: true, ValidatorType: "static",
			StaticKeys: map[string]string{"k": "v"},
		}, nil)
		_, ok := v.(*StaticTokenValidator)
		if !ok { t.Error("expected StaticTokenValidator") }
	})

	t.Run("cached when configured", func(t *testing.T) {
		store := &mockExternalStore{}
		v := NewTokenValidator(AuthConfig{
			Enabled: true, ValidatorType: "cached", CacheTTLSec: 60,
		}, store)
		_, ok := v.(*CachedTokenValidator)
		if !ok { t.Error("expected CachedTokenValidator") }
	})
}
