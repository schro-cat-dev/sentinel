package middleware

import (
	"encoding/json"
	"fmt"
	"os"
)

// SecurityConfig はセキュリティヘッダー・CORS・ハニーポット等の一元設定
// JSON設定ファイルで外部からオーバーライド可能
type SecurityConfig interface {
	GetCORSConfig() CORSConfig
	GetHeaders() []HeaderRule
	GetHoneypotPaths() []string
	GetRateLimitConfig() RateLimitConfig
	IsEnabled() bool
}

// CORSConfig はCORS設定
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAgeSec        int      `json:"max_age_sec"`
}

// HeaderRule はレスポンスヘッダールール
type HeaderRule struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RateLimitConfig はレート制限設定
type RateLimitConfig struct {
	Enabled  bool    `json:"enabled"`
	RPS      float64 `json:"rps"`
	BurstMax int     `json:"burst_max"`
}

// SecurityConfigData は設定の実データ構造
type SecurityConfigData struct {
	Enabled       bool            `json:"enabled"`
	CORS          CORSConfig      `json:"cors"`
	Headers       []HeaderRule    `json:"headers"`
	HoneypotPaths []string        `json:"honeypot_paths"`
	RateLimit     RateLimitConfig `json:"rate_limit"`
}

func (c *SecurityConfigData) GetCORSConfig() CORSConfig       { return c.CORS }
func (c *SecurityConfigData) GetHeaders() []HeaderRule         { return c.Headers }
func (c *SecurityConfigData) GetHoneypotPaths() []string       { return c.HoneypotPaths }
func (c *SecurityConfigData) GetRateLimitConfig() RateLimitConfig { return c.RateLimit }
func (c *SecurityConfigData) IsEnabled() bool                  { return c.Enabled }

// DefaultStrictConfig は超厳格なデフォルトセキュリティ設定を返す
func DefaultStrictConfig() *SecurityConfigData {
	return &SecurityConfigData{
		Enabled: true,
		CORS: CORSConfig{
			AllowedOrigins:   []string{}, // デフォルト: 全オリジン拒否
			AllowedMethods:   []string{"POST"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID"},
			ExposedHeaders:   []string{},
			AllowCredentials: false,
			MaxAgeSec:        0, // preflight キャッシュなし
		},
		Headers: []HeaderRule{
			{Key: "X-Content-Type-Options", Value: "nosniff"},
			{Key: "X-Frame-Options", Value: "DENY"},
			{Key: "X-DNS-Prefetch-Control", Value: "off"},
			{Key: "X-Download-Options", Value: "noopen"},
			{Key: "Strict-Transport-Security", Value: "max-age=63072000; includeSubDomains; preload"},
			{Key: "Referrer-Policy", Value: "no-referrer"},
			{Key: "Cross-Origin-Resource-Policy", Value: "same-origin"},
			{Key: "Cross-Origin-Embedder-Policy", Value: "require-corp"},
			{Key: "Cross-Origin-Opener-Policy", Value: "same-origin"},
			{Key: "Content-Security-Policy", Value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"},
			{Key: "Permissions-Policy", Value: "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), speaker-selection=(), usb=(), xr-spatial-tracking=()"},
			{Key: "Cache-Control", Value: "no-store, no-cache, must-revalidate, max-age=0"},
			{Key: "Pragma", Value: "no-cache"},
		},
		HoneypotPaths: []string{
			"/admin", "/wp-login.php", "/.env", "/config", "/.git/config",
			"/.aws/credentials", "/phpinfo.php", "/wp-admin", "/test.php",
			"/shell", "/backup", "/db", "/api/keys", "/vendor",
			"/.git/HEAD", "/server-status", "/phpmyadmin", "/administrator",
			"/manager", "/debug", "/_profiler", "/composer.json",
			"/package.json", "/.DS_Store", "/.gitignore", "/backup.sql",
		},
		RateLimit: RateLimitConfig{
			Enabled:  true,
			RPS:      100,
			BurstMax: 200,
		},
	}
}

// LoadSecurityConfig はJSON設定ファイルを読み込む。ファイルがなければデフォルトを使用。
func LoadSecurityConfig(path string) (SecurityConfig, error) {
	cfg := DefaultStrictConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // ファイルなし → デフォルト使用
		}
		return nil, fmt.Errorf("read security config: %w", err)
	}

	override := &SecurityConfigData{}
	if err := json.Unmarshal(data, override); err != nil {
		return nil, fmt.Errorf("parse security config: %w", err)
	}

	// オーバーライド（指定されたフィールドのみ）
	merged := mergeConfig(cfg, override)
	return merged, nil
}

func mergeConfig(base, override *SecurityConfigData) *SecurityConfigData {
	if len(override.CORS.AllowedOrigins) > 0 {
		base.CORS.AllowedOrigins = override.CORS.AllowedOrigins
	}
	if len(override.CORS.AllowedMethods) > 0 {
		base.CORS.AllowedMethods = override.CORS.AllowedMethods
	}
	if len(override.CORS.AllowedHeaders) > 0 {
		base.CORS.AllowedHeaders = override.CORS.AllowedHeaders
	}
	if override.CORS.MaxAgeSec > 0 {
		base.CORS.MaxAgeSec = override.CORS.MaxAgeSec
	}
	if len(override.Headers) > 0 {
		base.Headers = override.Headers
	}
	if len(override.HoneypotPaths) > 0 {
		base.HoneypotPaths = override.HoneypotPaths
	}
	if override.RateLimit.RPS > 0 {
		base.RateLimit = override.RateLimit
	}
	return base
}
