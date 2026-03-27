package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/response"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func threatResponsePipeline(t *testing.T, respCfg response.ThreatResponseConfig) (*Pipeline, *response.IPBlockAction, *response.MockAnalysisAgent) {
	t.Helper()
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := PipelineConfig{
		ServiceID:       "threat-e2e",
		EnableHashChain: true,
		EnableMasking:   true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		},
		HMACKey: []byte("threat-e2e-hmac-key-32-bytes-ok!!"),
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-notify"
				r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityHigh
				r.ActionType = domain.ActionSystemNotification
			}),
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "crit-notify"
				r.EventName = "SYSTEM_CRITICAL_FAILURE"
				r.Severity = domain.SeverityHigh
			}),
		},
	}

	executor := task.NewTaskExecutor(nil)
	p, err := NewPipeline(cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	// Setup threat response
	blocker := response.NewBlockDispatcher()
	ipBlock := response.NewIPBlockAction()
	acctLock := response.NewAccountLockAction()
	blocker.Register(ipBlock)
	blocker.Register(acctLock)

	analyzer := response.NewMockAnalysisAgent()

	orch := response.NewThreatResponseOrchestrator(respCfg, blocker, analyzer)
	p.SetThreatOrchestrator(orch)

	return p, ipBlock, analyzer
}

func TestThreatE2E_SecurityIntrusion_BlockAndNotify(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: response.StrategyNotifyOnly,
		Rules: []response.ResponseRuleConfig{
			{
				EventName:   "SECURITY_INTRUSION_DETECTED",
				Strategy:    response.StrategyBlockAndNotify,
				BlockAction: "block_ip",
			},
		},
	}

	p, ipBlock, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message:  "Brute force attack from 10.0.0.99",
		Boundary: "auth-svc",
		Tags:     []domain.LogTag{{Key: "ip", Category: "10.0.0.99"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Should have threat responses
	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected threat responses")
	}

	resp := result.ThreatResponses[0]
	if resp.Strategy != "BLOCK_AND_NOTIFY" {
		t.Errorf("expected BLOCK_AND_NOTIFY, got %s", resp.Strategy)
	}
	if !resp.Blocked {
		t.Error("expected blocked")
	}
	if resp.BlockTarget != "10.0.0.99" {
		t.Errorf("expected block target 10.0.0.99, got %s", resp.BlockTarget)
	}
	if !resp.Analyzed {
		t.Error("expected analyzed")
	}
	if resp.RiskLevel == "" {
		t.Error("expected risk level from analysis")
	}

	// Verify IP is actually blocked
	if !ipBlock.IsBlocked("10.0.0.99") {
		t.Error("IP should be blocked in IPBlockAction")
	}

	// Should also have tasks generated
	if len(result.TasksGenerated) == 0 {
		t.Fatal("expected tasks alongside threat response")
	}
}

func TestThreatE2E_SecurityIntrusion_AnalyzeAndNotify(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled: true,
		Rules: []response.ResponseRuleConfig{
			{
				EventName:      "SECURITY_INTRUSION_DETECTED",
				Strategy:       response.StrategyAnalyzeAndNotify,
				AnalysisPrompt: "Analyze this security intrusion",
			},
		},
	}

	p, ipBlock, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message:  "Suspicious login",
		Boundary: "auth-svc",
		Tags:     []domain.LogTag{{Key: "ip", Category: "10.0.0.50"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected threat responses")
	}

	resp := result.ThreatResponses[0]
	if resp.Blocked {
		t.Error("should not block in ANALYZE_AND_NOTIFY")
	}
	if !resp.Analyzed {
		t.Error("should analyze")
	}

	// IP should NOT be blocked
	if ipBlock.IsBlocked("10.0.0.50") {
		t.Error("IP should not be blocked")
	}
}

func TestThreatE2E_CriticalLog_DefaultNotifyOnly(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: response.StrategyNotifyOnly,
		// No rules for SYSTEM_CRITICAL_FAILURE → uses default
	}

	p, ipBlock, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Message: "DB pool exhausted", IsCritical: true, Level: 6,
		Boundary: "db-svc",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected threat responses")
	}

	resp := result.ThreatResponses[0]
	if resp.Strategy != "NOTIFY_ONLY" {
		t.Errorf("expected NOTIFY_ONLY, got %s", resp.Strategy)
	}
	if resp.Blocked {
		t.Error("should not block")
	}
	if resp.Analyzed {
		t.Error("should not analyze")
	}

	if ipBlock.BlockedCount() != 0 {
		t.Error("no IPs should be blocked")
	}
}

func TestThreatE2E_MonitorStrategy(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled: true,
		Rules: []response.ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: response.StrategyMonitor},
		},
	}

	p, _, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Suspicious activity", Boundary: "svc",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected threat responses")
	}

	resp := result.ThreatResponses[0]
	if resp.Blocked {
		t.Error("monitor should not block")
	}
	if resp.Analyzed {
		t.Error("monitor should not analyze")
	}
	if resp.Notified {
		t.Error("monitor should not notify")
	}
}

func TestThreatE2E_DisabledOrchestrator(t *testing.T) {
	cfg := response.ThreatResponseConfig{Enabled: false}
	p, _, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, _ := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Security event", Boundary: "svc",
	})

	if len(result.ThreatResponses) != 0 {
		t.Error("disabled orchestrator should produce no responses")
	}
	// Tasks should still be generated
	if len(result.TasksGenerated) == 0 {
		t.Error("tasks should still be generated even with disabled orchestrator")
	}
}

func TestThreatE2E_AnalysisFailure_StillBlocks(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled: true,
		Rules: []response.ResponseRuleConfig{
			{
				EventName:   "SECURITY_INTRUSION_DETECTED",
				Strategy:    response.StrategyBlockAndNotify,
				BlockAction: "block_ip",
			},
		},
	}

	p, ipBlock, analyzer := threatResponsePipeline(t, cfg)
	analyzer.SetShouldFail(true) // Analysis will fail

	ctx := context.Background()
	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Attack", Boundary: "svc",
		Tags: []domain.LogTag{{Key: "ip", Category: "172.16.0.1"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected responses")
	}
	resp := result.ThreatResponses[0]

	// Analysis failed → not analyzed
	if resp.Analyzed {
		t.Error("analysis failed, should not be marked analyzed")
	}

	// But block should still succeed
	if !resp.Blocked {
		t.Error("should still block despite analysis failure")
	}
	if !ipBlock.IsBlocked("172.16.0.1") {
		t.Error("IP should be blocked")
	}
}

func TestThreatE2E_NoIPAvailable_BlockFails(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled: true,
		Rules: []response.ResponseRuleConfig{
			{
				EventName:   "SECURITY_INTRUSION_DETECTED",
				Strategy:    response.StrategyBlockOnly,
				BlockAction: "block_ip",
			},
		},
	}

	p, _, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Attack with no IP info", Boundary: "svc",
		// No IP tags
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected responses")
	}
	resp := result.ThreatResponses[0]
	if resp.Blocked {
		t.Error("should fail to block without IP")
	}
}

func TestThreatE2E_NormalLog_NoThreatResponse(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: response.StrategyBlockAndNotify,
	}

	p, _, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{
		Message: "Everything is fine",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) != 0 {
		t.Error("normal log should have no threat responses")
	}
}

func TestThreatE2E_MultipleDetections(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: response.StrategyNotifyOnly,
		Rules: []response.ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: response.StrategyBlockAndNotify, BlockAction: "block_ip"},
		},
	}

	st, _ := store.NewSQLiteStore(":memory:")
	t.Cleanup(func() { st.Close() })

	pipeCfg := PipelineConfig{
		ServiceID:       "multi-det",
		EnableEnsemble:  true,
		EnsembleThreshold: 0.5,
		MaskingRules: []security.MaskingRule{},
		HMACKey:        []byte("multi-det-hmac-key-32-bytes-ok!!x"),
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-notify"
				r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityHigh
			}),
		},
	}

	executor := task.NewTaskExecutor(nil)
	p, _ := NewPipeline(pipeCfg, executor, st, nil)

	blocker := response.NewBlockDispatcher()
	ipBlock := response.NewIPBlockAction()
	blocker.Register(ipBlock)

	orch := response.NewThreatResponseOrchestrator(cfg, blocker, response.NewMockAnalysisAgent())
	p.SetThreatOrchestrator(orch)

	ctx := context.Background()
	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Security intrusion", Boundary: "auth-svc",
		Tags: []domain.LogTag{{Key: "ip", Category: "192.168.1.50"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected threat responses from ensemble detection")
	}
}

func TestThreatE2E_ConcurrentSafety(t *testing.T) {
	cfg := response.ThreatResponseConfig{
		Enabled: true,
		Rules: []response.ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: response.StrategyBlockAndNotify, BlockAction: "block_ip"},
		},
		DefaultStrategy: response.StrategyNotifyOnly,
	}

	p, _, _ := threatResponsePipeline(t, cfg)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			log := domain.Log{
				Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
				Message: "Concurrent attack", Boundary: "svc",
				Tags: []domain.LogTag{{Key: "ip", Category: "10.0.0.1"}},
			}
			_, err := p.Process(ctx, log)
			if err != nil {
				t.Errorf("concurrent error: %v", err)
			}
		}(i)
	}
	wg.Wait()
}
