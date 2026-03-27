package store

import (
	"testing"
)

func TestNewStore_SQLite(t *testing.T) {
	s, err := NewStore(StoreConfig{Driver: "sqlite", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	defer s.Close()
}

func TestNewStore_DefaultDriver(t *testing.T) {
	s, err := NewStore(StoreConfig{DSN: ":memory:"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	defer s.Close()
}

func TestNewStore_UnsupportedDriver(t *testing.T) {
	_, err := NewStore(StoreConfig{Driver: "postgres"})
	if err == nil {
		t.Error("expected error for unsupported driver")
	}
}

func TestNewStore_EncryptedWithoutKey(t *testing.T) {
	_, err := NewStore(StoreConfig{Driver: "sqlite_encrypted"})
	if err == nil {
		t.Error("expected error for encrypted without key")
	}
}
