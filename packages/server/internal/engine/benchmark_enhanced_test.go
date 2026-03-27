package engine

import (
	"context"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

func benchmarkEnhancedPipeline(b *testing.B) *Pipeline {
	b.Helper()
	st, _ := store.NewSQLiteStore(":memory:")
	b.Cleanup(func() { st.Close() })

	cfg := PipelineConfig{
		ServiceID: "bench", EnableHashChain: true, EnableMasking: true,
		HMACKey: []byte("benchmark-hmac-key-32-bytes-ok!!"),
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		},
		EnableEnsemble: true, EnsembleThreshold: 0.5,
		EnableAnomalyDetection: true, AnomalyConfig: detection.DefaultAnomalyConfig(),
		EnableMaskingVerification: true,
		TaskRules: []domain.TaskRule{
			{RuleID: "bench-crit", EventName: "SYSTEM_CRITICAL_FAILURE", Severity: domain.SeverityHigh,
				ActionType: domain.ActionSystemNotification, ExecutionLevel: domain.ExecLevelAuto, Priority: 1},
		},
	}
	p, _ := NewPipeline(cfg, task.NewTaskExecutor(nil), st, nil)
	return p
}

func BenchmarkEnsemble_NormalLog(b *testing.B) {
	p := benchmarkEnhancedPipeline(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{Message: "Normal operation"})
	}
}

func BenchmarkEnsemble_SecurityDetection(b *testing.B) {
	p := benchmarkEnhancedPipeline(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
			Message: "Suspicious login", Boundary: "auth",
		})
	}
}

func BenchmarkEnsemble_CriticalWithTask(b *testing.B) {
	p := benchmarkEnhancedPipeline(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{
			Message: "DB pool exhausted", IsCritical: true, Level: 6,
		})
	}
}

func BenchmarkAnomaly_HighTraffic(b *testing.B) {
	p := benchmarkEnhancedPipeline(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelWarn,
			Message: "Auth event", Boundary: "auth-svc",
		})
	}
}

func BenchmarkMaskingVerification(b *testing.B) {
	p := benchmarkEnhancedPipeline(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Process(ctx, domain.Log{
			Message: "Contact admin@example.com phone 090-1234-5678",
		})
	}
}
