package store

import (
	"fmt"
)

// StoreConfig はストア生成の設定
type StoreConfig struct {
	Driver        string // "sqlite" (default) or "sqlite_encrypted"
	DSN           string // データソース名
	EncryptionKey string // 暗号化キー（sqlite_encrypted時のみ）
}

// NewStore は設定に基づいてStore実装を生成する（ファクトリパターン）
// driver:
//   - "sqlite": 通常のSQLite（平文）
//   - "sqlite_encrypted": SQLCipher（AES-256暗号化）
func NewStore(cfg StoreConfig) (Store, error) {
	switch cfg.Driver {
	case "sqlite", "":
		return NewSQLiteStore(cfg.DSN)
	case "sqlite_encrypted":
		if cfg.EncryptionKey == "" {
			return nil, fmt.Errorf("encryption_key is required for sqlite_encrypted driver")
		}
		return NewEncryptedSQLiteStore(cfg.DSN, cfg.EncryptionKey)
	default:
		return nil, fmt.Errorf("unsupported store driver: %s", cfg.Driver)
	}
}
