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
	// タイミングオラクル防止: 全キーを常にイテレート（early returnしない）
	var matchedID string
	found := false
	for key, clientID := range v.keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
			matchedID = clientID
			found = true
			// early returnしない: キー数のタイミング漏洩を防ぐ
		}
	}
	if found {
		return matchedID, nil
	}
	return "", fmt.Errorf("invalid token")
}

// --- Cached Token Validator (外部キャッシュ連携) ---

// ExternalTokenStore は外部トークンストアのインターフェース
type ExternalTokenStore interface {
	LookupToken(ctx context.Context, token string) (clientID string, valid bool, err error)
}

type CachedTokenValidator struct {
	mu           sync.RWMutex
	cache        map[string]cachedEntry
	store        ExternalTokenStore
	ttl          time.Duration
	maxCacheSize int // 0 = unlimited (default for backward compat)
}

type cachedEntry struct {
	clientID  string
	valid     bool
	expiresAt time.Time
}

func NewCachedTokenValidator(store ExternalTokenStore, ttl time.Duration) *CachedTokenValidator {
	return &CachedTokenValidator{
		cache:        make(map[string]cachedEntry),
		store:        store,
		ttl:          ttl,
		maxCacheSize: 10000, // デフォルト上限: OOM防止
	}
}

// SetMaxCacheSize はキャッシュの最大エントリ数を設定する（0=無制限）
func (v *CachedTokenValidator) SetMaxCacheSize(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxCacheSize = n
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

	// Update cache (with size limit to prevent OOM from unique-token flooding)
	v.mu.Lock()
	if v.maxCacheSize > 0 && len(v.cache) >= v.maxCacheSize {
		// Evict expired entries first
		now := time.Now()
		for k, e := range v.cache {
			if e.expiresAt.Before(now) {
				delete(v.cache, k)
			}
		}
		// If still over limit, evict oldest 10%
		if len(v.cache) >= v.maxCacheSize {
			evictCount := v.maxCacheSize / 10
			if evictCount < 1 {
				evictCount = 1
			}
			for k := range v.cache {
				delete(v.cache, k)
				evictCount--
				if evictCount <= 0 {
					break
				}
			}
		}
	}
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
