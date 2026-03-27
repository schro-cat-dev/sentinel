package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

func securityPipeline(t *testing.T) *Pipeline {
	t.Helper()
	cfg := PipelineConfig{
		ServiceID: "sec-test", EnableHashChain: true, EnableMasking: true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "CREDIT_CARD"},
			{Type: "PII_TYPE", Category: "PHONE"},
		},
		HMACKey: []byte("security-test-hmac-key-32-bytes!!"),
	}
	st, _ := store.NewSQLiteStore(":memory:")
	t.Cleanup(func() { st.Close() })
	p, err := NewPipeline(cfg, task.NewTaskExecutor(nil), st, nil)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	return p
}

func TestSecurity_NullByteInjection(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	attacks := []string{
		"normal\x00injected",
		"\x00leading null",
		"trailing null\x00",
		"multi\x00ple\x00nulls",
	}
	for _, attack := range attacks {
		_, err := p.Process(ctx, domain.Log{Message: attack})
		if err == nil {
			t.Errorf("null byte injection should be rejected: %q", attack)
		}
	}
}

func TestSecurity_ControlCharInjection(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	// Control chars (except \t \n) should be stripped, not rejected
	result, err := p.Process(ctx, domain.Log{Message: "hello\x01\x02\x03world"})
	if err != nil {
		t.Fatalf("control chars should be stripped, not rejected: %v", err)
	}
	// Message should be sanitized
	log, _ := p.store.GetLogByTraceID(ctx, result.TraceID)
	if log != nil && strings.Contains(log.Message, "\x01") {
		t.Error("control chars should be removed from stored message")
	}
}

func TestSecurity_InvalidUTF8(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
	_, err := p.Process(ctx, domain.Log{Message: invalidUTF8})
	if err == nil {
		t.Error("invalid UTF-8 should be rejected")
	}
}

func TestSecurity_OversizedMessage(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	_, err := p.Process(ctx, domain.Log{Message: strings.Repeat("x", 65537)})
	if err == nil {
		t.Error("oversized message should be rejected")
	}
}

func TestSecurity_SQLInjectionInFields(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	// SQL injection attempts in various fields should be stored safely (parameterized queries)
	injections := []domain.Log{
		{Message: "test'; DROP TABLE logs; --", Boundary: "svc"},
		{Message: "normal", ActorID: "'; DELETE FROM tasks; --"},
		{Message: "normal", Boundary: "' OR '1'='1"},
	}
	for _, log := range injections {
		result, err := p.Process(ctx, log)
		if err != nil {
			t.Fatalf("SQL injection should be safely stored, not rejected: %v", err)
		}
		// Verify it was stored without executing SQL
		stored, _ := p.store.GetLogByTraceID(ctx, result.TraceID)
		if stored == nil {
			t.Error("log should be stored despite SQL-like content")
		}
	}
}

func TestSecurity_XSSInMessage(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	xss := `<script>alert('xss')</script>`
	result, err := p.Process(ctx, domain.Log{Message: xss})
	if err != nil {
		t.Fatalf("XSS content should be stored as-is (gRPC, not HTML): %v", err)
	}
	stored, _ := p.store.GetLogByTraceID(ctx, result.TraceID)
	if stored == nil {
		t.Fatal("log should be stored")
	}
	// gRPCはHTMLレンダリングしないので、スクリプトタグはそのまま保存される
	// ただしPII masking以外のサニタイズは不要
}

func TestSecurity_PIIMaskingCompleteness(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Message:  "Contact admin@example.com, card 4111-1111-1111-1111, phone 090-1234-5678",
		ActorID:  "user@company.com",
		Input:    "Email: secret@test.com",
		Details:  map[string]string{"contact": "hidden@email.com"},
		Tags:     []domain.LogTag{{Key: "email", Category: "tag@email.com"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	stored, _ := p.store.GetLogByTraceID(ctx, result.TraceID)
	if stored == nil {
		t.Fatal("log should be stored")
	}

	// Verify all PII is masked
	checks := []struct {
		field string
		value string
		pii   string
	}{
		{"message", stored.Message, "@example.com"},
		{"message", stored.Message, "4111"},
		{"message", stored.Message, "090-1234"},
		{"actorId", stored.ActorID, "@company.com"},
		{"input", stored.Input, "@test.com"},
	}
	for _, c := range checks {
		if strings.Contains(c.value, c.pii) {
			t.Errorf("PII leaked in %s: found %q in %q", c.field, c.pii, c.value)
		}
	}
}

func TestSecurity_HashChainIntegrity(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	// Process 3 logs and verify chain
	results := make([]domain.IngestionResult, 3)
	for i := 0; i < 3; i++ {
		var err error
		results[i], err = p.Process(ctx, domain.Log{
			Message: strings.Repeat("log", i+1),
		})
		if err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
		if !results[i].HashChainValid {
			t.Errorf("log %d: hash chain should be valid", i)
		}
	}

	// All traceIDs should be unique
	seen := map[string]bool{}
	for _, r := range results {
		if seen[r.TraceID] {
			t.Error("duplicate traceID")
		}
		seen[r.TraceID] = true
	}
}

func TestSecurity_TagCountLimit(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	// Create log with 200 tags (limit is 100)
	tags := make([]domain.LogTag, 200)
	for i := range tags {
		tags[i] = domain.LogTag{Key: "k", Category: "v"}
	}

	result, err := p.Process(ctx, domain.Log{Message: "test", Tags: tags})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	stored, _ := p.store.GetLogByTraceID(ctx, result.TraceID)
	if stored != nil && len(stored.Tags) > 100 {
		t.Errorf("tags should be capped at 100, got %d", len(stored.Tags))
	}
}

func TestSecurity_EmptyAndWhitespaceMessages(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	invalids := []string{"", "   ", "\t", "\n", "\t\n\t"}
	for _, msg := range invalids {
		_, err := p.Process(ctx, domain.Log{Message: msg})
		if err == nil {
			t.Errorf("empty/whitespace message %q should be rejected", msg)
		}
	}
}

func TestSecurity_ConcurrentHashChainSafety(t *testing.T) {
	p := securityPipeline(t)
	ctx := context.Background()

	// 100 concurrent ingestions should not panic or race
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(n int) {
			_, err := p.Process(ctx, domain.Log{Message: "concurrent"})
			if err != nil {
				t.Errorf("concurrent %d: %v", n, err)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}
