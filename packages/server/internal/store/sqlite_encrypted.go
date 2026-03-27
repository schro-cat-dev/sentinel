package store

import (
	"database/sql"
	"fmt"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// NewEncryptedSQLiteStore はSQLCipherで暗号化されたSQLiteStoreを生成する（AES-256-CBC）
func NewEncryptedSQLiteStore(dsn string, encryptionKey string) (*SQLiteStore, error) {
	// SQLCipher DSN format: file:path?_pragma_key=KEY&_pragma_cipher_page_size=4096
	encDSN := dsn
	if encDSN == "" {
		encDSN = "file:sentinel_encrypted.db"
	}
	encDSN += fmt.Sprintf("&_pragma_key=%s&_pragma_cipher_page_size=4096", encryptionKey)

	db, err := sql.Open("sqlite3", encDSN) // go-sqlcipher registers as "sqlite3"
	if err != nil {
		return nil, fmt.Errorf("open encrypted sqlite: %w", err)
	}

	// Verify encryption works by running a query
	if _, err := db.Exec("SELECT 1"); err != nil {
		db.Close()
		return nil, fmt.Errorf("encrypted sqlite verification failed (wrong key?): %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema (encrypted): %w", err)
	}

	return &SQLiteStore{db: db}, nil
}
