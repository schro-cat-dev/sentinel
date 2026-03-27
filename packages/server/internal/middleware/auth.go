package middleware

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// TokenValidator はトークン検証の抽象インターフェース
// 外部キャッシュ（Redis等）やDBなど複数のバックエンドに対応
type TokenValidator interface {
	// Validate はトークンを検証し、有効ならクライアントIDを返す
	Validate(ctx context.Context, token string) (clientID string, err error)
}

// --- Static Token Validator (APIキー直接指定) ---

type StaticTokenValidator struct {
	keys map[string]string // token → clientID
}

func NewStaticTokenValidator(keyMap map[string]string) *StaticTokenValidator {
	return &StaticTokenValidator{keys: keyMap}
}

func (v *StaticTokenValidator) Validate(ctx context.Context, token string) (string, error) {
	for key, clientID := range v.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
			return clientID, nil
		}
	}
	return "", fmt.Errorf("invalid token")
}

// --- Cached Token Validator (外部キャッシュ連携) ---

// ExternalTokenStore は外部トークンストアのインターフェース
type ExternalTokenStore interface {
	LookupToken(ctx context.Context, token string) (clientID string, valid bool, err error)
}

type CachedTokenValidator struct {
	mu       sync.RWMutex
	cache    map[string]cachedEntry
	store    ExternalTokenStore
	ttl      time.Duration
}

type cachedEntry struct {
	clientID  string
	valid     bool
	expiresAt time.Time
}

func NewCachedTokenValidator(store ExternalTokenStore, ttl time.Duration) *CachedTokenValidator {
	return &CachedTokenValidator{
		cache: make(map[string]cachedEntry),
		store: store,
		ttl:   ttl,
	}
}

func (v *CachedTokenValidator) Validate(ctx context.Context, token string) (string, error) {
	// Check cache
	v.mu.RLock()
	entry, found := v.cache[token]
	v.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		if entry.valid {
			return entry.clientID, nil
		}
		return "", fmt.Errorf("cached: invalid token")
	}

	// Cache miss or expired → query external store
	clientID, valid, err := v.store.LookupToken(ctx, token)
	if err != nil {
		slog.Error("token store lookup failed", "error", err)
		return "", fmt.Errorf("token validation failed: %w", err)
	}

	// Update cache
	v.mu.Lock()
	v.cache[token] = cachedEntry{
		clientID:  clientID,
		valid:     valid,
		expiresAt: time.Now().Add(v.ttl),
	}
	v.mu.Unlock()

	if !valid {
		return "", fmt.Errorf("invalid token")
	}
	return clientID, nil
}

// --- Noop Validator (認証無効時) ---

type NoopTokenValidator struct{}

func (v *NoopTokenValidator) Validate(ctx context.Context, token string) (string, error) {
	return "anonymous", nil
}

// --- Auth Config ---

// AuthConfig は認証設定
type AuthConfig struct {
	Enabled       bool              `json:"enabled"`
	ValidatorType string            `json:"validator_type"` // "static", "cached", "noop"
	StaticKeys    map[string]string `json:"static_keys"`    // token → clientID
	CacheTTLSec   int               `json:"cache_ttl_sec"`
}

// NewTokenValidator は設定に応じたTokenValidatorを生成する
func NewTokenValidator(cfg AuthConfig, externalStore ExternalTokenStore) TokenValidator {
	if !cfg.Enabled {
		return &NoopTokenValidator{}
	}

	switch cfg.ValidatorType {
	case "static":
		return NewStaticTokenValidator(cfg.StaticKeys)
	case "cached":
		ttl := time.Duration(cfg.CacheTTLSec) * time.Second
		if ttl == 0 {
			ttl = 5 * time.Minute
		}
		return NewCachedTokenValidator(externalStore, ttl)
	default:
		return &NoopTokenValidator{}
	}
}
