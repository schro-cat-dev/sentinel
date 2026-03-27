package security

import (
	"regexp"
	"sync"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

var hexHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var testKey = []byte("test-hmac-key-that-is-32-bytes!!")

func mustSigner(t *testing.T) *IntegritySigner {
	t.Helper()
	s, err := NewIntegritySigner(testKey)
	if err != nil {
		t.Fatalf("NewIntegritySigner: %v", err)
	}
	return s
}

func TestNewIntegritySigner_Validation(t *testing.T) {
	t.Run("rejects empty key", func(t *testing.T) {
		_, err := NewIntegritySigner(nil)
		if err != ErrHMACKeyRequired {
			t.Errorf("expected ErrHMACKeyRequired, got %v", err)
		}
	})

	t.Run("rejects short key", func(t *testing.T) {
		_, err := NewIntegritySigner([]byte("short"))
		if err != ErrHMACKeyTooShort {
			t.Errorf("expected ErrHMACKeyTooShort, got %v", err)
		}
	})

	t.Run("accepts 32-byte key", func(t *testing.T) {
		_, err := NewIntegritySigner(testKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCalculateHash(t *testing.T) {
	t.Run("produces 64-char hex HMAC-SHA256", func(t *testing.T) {
		log := testutil.NewTestLog()
		hash := CalculateHash(log, "", testKey)
		if !hexHash.MatchString(hash) {
			t.Errorf("expected 64-char hex, got %q", hash)
		}
	})

	t.Run("different messages produce different hashes", func(t *testing.T) {
		log1 := testutil.NewTestLog(func(l *domain.Log) { l.Message = "message A" })
		log2 := testutil.NewTestLog(func(l *domain.Log) { l.Message = "message B" })
		if CalculateHash(log1, "", testKey) == CalculateHash(log2, "", testKey) {
			t.Error("expected different hashes")
		}
	})

	t.Run("different keys produce different hashes", func(t *testing.T) {
		log := testutil.NewTestLog()
		key2 := []byte("another-key-that-is-32-bytes!!xx")
		if CalculateHash(log, "", testKey) == CalculateHash(log, "", key2) {
			t.Error("expected different hashes for different keys")
		}
	})

	t.Run("is deterministic", func(t *testing.T) {
		log := testutil.NewTestLog()
		h1 := CalculateHash(log, "prev", testKey)
		h2 := CalculateHash(log, "prev", testKey)
		if h1 != h2 {
			t.Error("expected same hash")
		}
	})

	t.Run("excludes hash and signature fields", func(t *testing.T) {
		log1 := testutil.NewTestLog(func(l *domain.Log) { l.Hash = "ignored"; l.Signature = "ignored" })
		log2 := testutil.NewTestLog()
		if CalculateHash(log1, "", testKey) != CalculateHash(log2, "", testKey) {
			t.Error("hash/signature should not affect computation")
		}
	})
}

func TestVerifyHash(t *testing.T) {
	t.Run("constant-time verify passes for correct hash", func(t *testing.T) {
		log := testutil.NewTestLog()
		log.Hash = CalculateHash(log, "", testKey)
		if !VerifyHash(log, "", testKey) {
			t.Error("expected pass")
		}
	})

	t.Run("fails for tampered log", func(t *testing.T) {
		log := testutil.NewTestLog()
		log.Hash = CalculateHash(log, "", testKey)
		log.Message = "tampered"
		if VerifyHash(log, "", testKey) {
			t.Error("expected fail")
		}
	})

	t.Run("fails for empty hash", func(t *testing.T) {
		if VerifyHash(testutil.NewTestLog(), "", testKey) {
			t.Error("expected fail for empty hash")
		}
	})

	t.Run("fails for wrong key", func(t *testing.T) {
		log := testutil.NewTestLog()
		log.Hash = CalculateHash(log, "", testKey)
		wrongKey := []byte("wrong-key-that-is-also-32-bytes!")
		if VerifyHash(log, "", wrongKey) {
			t.Error("expected fail for wrong key")
		}
	})
}

func TestIntegritySigner_Chain(t *testing.T) {
	s := mustSigner(t)

	t.Run("starts empty", func(t *testing.T) {
		if s.PreviousHash() != "" {
			t.Error("expected empty")
		}
	})

	t.Run("builds chain of 3 logs", func(t *testing.T) {
		s2 := mustSigner(t)
		logs := []domain.Log{
			testutil.NewTestLog(func(l *domain.Log) { l.Message = "first"; l.TraceID = "t1" }),
			testutil.NewTestLog(func(l *domain.Log) { l.Message = "second"; l.TraceID = "t2" }),
			testutil.NewTestLog(func(l *domain.Log) { l.Message = "third"; l.TraceID = "t3" }),
		}
		hashes := make([]string, 3)
		for i := range logs {
			s2.ApplyHashChain(&logs[i])
			hashes[i] = logs[i].Hash
		}

		seen := map[string]bool{}
		for _, h := range hashes {
			if seen[h] {
				t.Error("duplicate hash")
			}
			seen[h] = true
		}

		if !VerifyHash(logs[0], "", testKey) {
			t.Error("log 0 verify failed")
		}
		if !VerifyHash(logs[1], hashes[0], testKey) {
			t.Error("log 1 verify failed")
		}
		if !VerifyHash(logs[2], hashes[1], testKey) {
			t.Error("log 2 verify failed")
		}
	})
}

func TestIntegritySigner_ConcurrentSafety(t *testing.T) {
	s := mustSigner(t)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			log := testutil.NewTestLog(func(l *domain.Log) {
				l.Message = "concurrent " + string(rune('A'+n%26))
			})
			s.ApplyHashChain(&log)
			if log.Hash == "" {
				t.Error("hash should not be empty")
			}
		}(i)
	}
	wg.Wait()
}
