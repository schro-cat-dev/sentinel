package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func benchPipeline(b *testing.B) *Pipeline {
	b.Helper()
	cfg := PipelineConfig{
		ServiceID: "bench", EnableHashChain: true, EnableMasking: true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "CREDIT_CARD"},
		},
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "bench-rule"
				r.EventName = "SYSTEM_CRITICAL_FAILURE"
				r.Severity = domain.SeverityHigh
			}),
		},
		HMACKey: []byte("benchmark-hmac-key-32-bytes-long!"),
	}
	st, _ := store.NewSQLiteStore(":memory:")
	b.Cleanup(func() { st.Close() })
	p, _ := NewPipeline(cfg, task.NewTaskExecutor(nil), st, nil)
	return p
}

func BenchmarkPipeline_NormalLog(b *testing.B) {
	p := benchPipeline(b)
	ctx := context.Background()
	log := domain.Log{Message: "benchmark normal log", Level: 3}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Message = fmt.Sprintf("bench log %d", i)
		p.Process(ctx, log)
	}
}

func BenchmarkPipeline_CriticalLogWithTask(b *testing.B) {
	p := benchPipeline(b)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{
			Message: fmt.Sprintf("critical %d", i), IsCritical: true, Level: 6,
		})
	}
}

func BenchmarkPipeline_PIIMasking(b *testing.B) {
	p := benchPipeline(b)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{
			Message: "Contact admin@example.com card 4111-1111-1111-1111",
		})
	}
}

func BenchmarkHashChain(b *testing.B) {
	signer, _ := security.NewIntegritySigner([]byte("benchmark-hmac-key-32-bytes-long!"))
	log := testutil.NewTestLog()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.ApplyHashChain(&log)
	}
}

func BenchmarkStore_InsertLog(b *testing.B) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.InsertLog(ctx, domain.Log{
			TraceID: fmt.Sprintf("trace-%d", i), Message: "bench", Level: 3,
			Type: domain.LogTypeSystem, Origin: domain.OriginSystem,
		})
	}
}
