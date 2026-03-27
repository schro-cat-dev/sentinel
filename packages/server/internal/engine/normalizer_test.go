package engine

import (
	"strings"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestNormalizer_Validate(t *testing.T) {
	n := NewLogNormalizer("test-svc")

	t.Run("rejects empty message", func(t *testing.T) {
		_, err := n.Normalize(domain.Log{})
		if err == nil {
			t.Fatal("expected error for empty message")
		}
	})

	t.Run("rejects whitespace-only message", func(t *testing.T) {
		_, err := n.Normalize(domain.Log{Message: "   "})
		if err == nil {
			t.Fatal("expected error for whitespace message")
		}
	})

	t.Run("rejects oversized message", func(t *testing.T) {
		_, err := n.Normalize(domain.Log{Message: strings.Repeat("x", 65537)})
		if err == nil {
			t.Fatal("expected error for oversized message")
		}
	})

	t.Run("accepts max-length message", func(t *testing.T) {
		log, err := n.Normalize(domain.Log{Message: strings.Repeat("x", 65536)})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(log.Message) != 65536 {
			t.Errorf("expected message length 65536, got %d", len(log.Message))
		}
	})
}

func TestNormalizer_Defaults(t *testing.T) {
	n := NewLogNormalizer("test-svc")

	t.Run("generates traceID", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test"})
		if log.TraceID == "" {
			t.Error("expected traceID to be generated")
		}
	})

	t.Run("preserves provided traceID", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test", TraceID: "my-trace"})
		if log.TraceID != "my-trace" {
			t.Errorf("expected traceID my-trace, got %s", log.TraceID)
		}
	})

	t.Run("defaults type to SYSTEM", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test"})
		if log.Type != domain.LogTypeSystem {
			t.Errorf("expected type SYSTEM, got %s", log.Type)
		}
	})

	t.Run("defaults level to 3", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test"})
		if log.Level != domain.LogLevelInfo {
			t.Errorf("expected level 3, got %d", log.Level)
		}
	})

	t.Run("sets serviceID from config", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test"})
		if log.ServiceID != "test-svc" {
			t.Errorf("expected serviceID test-svc, got %s", log.ServiceID)
		}
	})

	t.Run("defaults boundary to unknown", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test"})
		if log.Boundary != "unknown" {
			t.Errorf("expected boundary unknown, got %s", log.Boundary)
		}
	})

	t.Run("preserves valid log types", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test", Type: domain.LogTypeSecurity})
		if log.Type != domain.LogTypeSecurity {
			t.Errorf("expected SECURITY, got %s", log.Type)
		}
	})

	t.Run("falls back to SYSTEM for invalid type", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "test", Type: "INVALID"})
		if log.Type != domain.LogTypeSystem {
			t.Errorf("expected SYSTEM fallback, got %s", log.Type)
		}
	})

	t.Run("trims message whitespace", func(t *testing.T) {
		log, _ := n.Normalize(domain.Log{Message: "  hello world  "})
		if log.Message != "hello world" {
			t.Errorf("expected trimmed message, got %q", log.Message)
		}
	})

	_ = testutil.FixedTime // ensure testutil compiles
}
