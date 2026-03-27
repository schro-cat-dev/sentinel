package response

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

// --- Test helpers ---

type testNotifyRecorder struct {
	mu      sync.Mutex
	records []ThreatResponseRecord
}

func (r *testNotifyRecorder) notify(ctx context.Context, rec ThreatResponseRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}

func (r *testNotifyRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func (r *testNotifyRecorder) last() ThreatResponseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.records[len(r.records)-1]
}

type testPersistRecorder struct {
	mu      sync.Mutex
	records []ThreatResponseRecord
}

func (r *testPersistRecorder) persist(ctx context.Context, rec ThreatResponseRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	return nil
}

func (r *testPersistRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func securityDetection() *domain.DetectionResult {
	return &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Priority:  domain.PriorityHigh,
		Payload:   domain.SecurityIntrusionPayload{IP: "192.168.1.100", Severity: 5},
		Score:     0.95,
		RuleID:    "sec-001",
	}
}

func anomalyDetection() *domain.DetectionResult {
	return &domain.DetectionResult{
		EventName: domain.EventAnomaly,
		Priority:  domain.PriorityMedium,
		Payload: domain.AnomalyPayload{
			MetricKey: "SECURITY|auth-svc", Baseline: 5, Observed: 25, DeviationPct: 500,
		},
		Score:  0.8,
		RuleID: "anomaly-001",
	}
}

// --- Orchestrator Tests ---

func TestOrchestrator_Disabled(t *testing.T) {
	orch := NewThreatResponseOrchestrator(
		ThreatResponseConfig{Enabled: false},
		nil, nil,
	)
	record, err := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if record != nil {
		t.Error("disabled orchestrator should return nil")
	}
}

func TestOrchestrator_BlockAndNotify(t *testing.T) {
	blocker := NewBlockDispatcher()
	ipBlock := NewIPBlockAction()
	blocker.Register(ipBlock)

	analyzer := NewMockAnalysisAgent()
	notifier := &testNotifyRecorder{}
	persister := &testPersistRecorder{}

	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
		Rules: []ResponseRuleConfig{
			{
				EventName:      "SECURITY_INTRUSION_DETECTED",
				Strategy:       StrategyBlockAndNotify,
				BlockAction:    "block_ip",
				AnalysisPrompt: "Analyze intrusion from {{ip}}",
				NotifyTargets:  []string{"#security"},
			},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, blocker, analyzer,
		WithNotifyFunc(notifier.notify),
		WithPersistFunc(persister.persist),
	)

	log := testutil.NewSecurityLog(func(l *domain.Log) {
		l.Tags = []domain.LogTag{{Key: "ip", Category: "192.168.1.100"}}
	})

	record, err := orch.Handle(context.Background(), securityDetection(), log)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Verify strategy
	if record.Strategy != StrategyBlockAndNotify {
		t.Errorf("expected BLOCK_AND_NOTIFY, got %s", record.Strategy)
	}

	// Verify analysis was performed
	if record.Analysis == nil {
		t.Fatal("expected analysis result")
	}
	if record.Analysis.RiskLevel == "" {
		t.Error("expected risk level in analysis")
	}
	if record.Analysis.Error != "" {
		t.Errorf("unexpected analysis error: %s", record.Analysis.Error)
	}

	// Verify block was executed
	if record.Block == nil {
		t.Fatal("expected block result")
	}
	if !record.Block.Success {
		t.Error("expected successful block")
	}
	if record.Block.Target != "192.168.1.100" {
		t.Errorf("expected blocked IP 192.168.1.100, got %s", record.Block.Target)
	}
	if !ipBlock.IsBlocked("192.168.1.100") {
		t.Error("IP should be blocked in IPBlockAction")
	}

	// Verify notification
	if !record.Notified {
		t.Error("expected notification")
	}
	if notifier.count() != 1 {
		t.Errorf("expected 1 notification, got %d", notifier.count())
	}

	// Verify persistence
	if persister.count() != 1 {
		t.Errorf("expected 1 persist, got %d", persister.count())
	}

	// Verify notify target
	if record.NotifyTarget != "#security" {
		t.Errorf("expected #security, got %s", record.NotifyTarget)
	}
}

func TestOrchestrator_AnalyzeAndNotify(t *testing.T) {
	analyzer := NewMockAnalysisAgent()
	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{
				EventName:      "ANOMALY_DETECTED",
				Strategy:       StrategyAnalyzeAndNotify,
				AnalysisPrompt: "Analyze anomaly",
			},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, analyzer,
		WithNotifyFunc(notifier.notify),
	)

	record, err := orch.Handle(context.Background(), anomalyDetection(), testutil.NewTestLog())
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if record.Analysis == nil {
		t.Fatal("expected analysis")
	}
	if record.Block != nil {
		t.Error("should not block in ANALYZE_AND_NOTIFY")
	}
	if !record.Notified {
		t.Error("should notify")
	}
}

func TestOrchestrator_NotifyOnly(t *testing.T) {
	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithNotifyFunc(notifier.notify),
	)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())

	if record.Analysis != nil {
		t.Error("should not analyze in NOTIFY_ONLY")
	}
	if record.Block != nil {
		t.Error("should not block in NOTIFY_ONLY")
	}
	if !record.Notified {
		t.Error("should notify")
	}
}

func TestOrchestrator_BlockOnly(t *testing.T) {
	blocker := NewBlockDispatcher()
	blocker.Register(NewIPBlockAction())
	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{
				EventName:   "SECURITY_INTRUSION_DETECTED",
				Strategy:    StrategyBlockOnly,
				BlockAction: "block_ip",
			},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, blocker, nil,
		WithNotifyFunc(notifier.notify),
	)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())

	if record.Block == nil || !record.Block.Success {
		t.Error("should block")
	}
	if record.Notified {
		t.Error("should not notify in BLOCK_ONLY")
	}
	if notifier.count() != 0 {
		t.Error("notifier should not be called")
	}
}

func TestOrchestrator_Monitor(t *testing.T) {
	notifier := &testNotifyRecorder{}
	persister := &testPersistRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "ANOMALY_DETECTED", Strategy: StrategyMonitor},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithNotifyFunc(notifier.notify),
		WithPersistFunc(persister.persist),
	)

	record, _ := orch.Handle(context.Background(), anomalyDetection(), testutil.NewTestLog())

	if record.Analysis != nil {
		t.Error("monitor should not analyze")
	}
	if record.Block != nil {
		t.Error("monitor should not block")
	}
	if record.Notified {
		t.Error("monitor should not notify")
	}
	// But should persist
	if persister.count() != 1 {
		t.Errorf("monitor should persist, got %d", persister.count())
	}
}

func TestOrchestrator_DefaultStrategy(t *testing.T) {
	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
		// No rules — should use default
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithNotifyFunc(notifier.notify),
	)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())
	if record.Strategy != StrategyNotifyOnly {
		t.Errorf("expected default strategy NOTIFY_ONLY, got %s", record.Strategy)
	}
}

func TestOrchestrator_BlockFailure_StillNotifies(t *testing.T) {
	blocker := NewBlockDispatcher()
	mock := NewMockBlockAction("block_ip")
	mock.SetShouldFail(true)
	blocker.Register(mock)

	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{
				EventName:   "SECURITY_INTRUSION_DETECTED",
				Strategy:    StrategyBlockAndNotify,
				BlockAction: "block_ip",
			},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, blocker, nil,
		WithNotifyFunc(notifier.notify),
	)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())

	// Block failed
	if record.Block == nil {
		t.Fatal("expected block result even on failure")
	}
	if record.Block.Success {
		t.Error("block should have failed")
	}

	// But notification still happened
	if !record.Notified {
		t.Error("should still notify even when block fails")
	}
}

func TestOrchestrator_AnalysisFailure_StillBlocksAndNotifies(t *testing.T) {
	blocker := NewBlockDispatcher()
	blocker.Register(NewIPBlockAction())

	analyzer := NewMockAnalysisAgent()
	analyzer.SetShouldFail(true)

	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{
				EventName:   "SECURITY_INTRUSION_DETECTED",
				Strategy:    StrategyBlockAndNotify,
				BlockAction: "block_ip",
			},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, blocker, analyzer,
		WithNotifyFunc(notifier.notify),
	)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())

	// Analysis failed but recorded
	if record.Analysis == nil {
		t.Fatal("expected analysis result even on failure")
	}
	if record.Analysis.Error == "" {
		t.Error("expected error in analysis")
	}

	// Block still executed
	if record.Block == nil || !record.Block.Success {
		t.Error("block should succeed despite analysis failure")
	}

	// Notification still happened
	if !record.Notified {
		t.Error("should notify despite analysis failure")
	}
}

func TestOrchestrator_NoNotifyFunc(t *testing.T) {
	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())
	if record.Notified {
		t.Error("should not be notified without notify func")
	}
}

func TestOrchestrator_RecordFields(t *testing.T) {
	persister := &testPersistRecorder{}

	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithPersistFunc(persister.persist),
	)

	log := testutil.NewSecurityLog(func(l *domain.Log) {
		l.TraceID = "trace-test-123"
	})

	record, _ := orch.Handle(context.Background(), securityDetection(), log)

	if record.ResponseID == "" {
		t.Error("expected ResponseID")
	}
	if record.TraceID != "trace-test-123" {
		t.Errorf("expected trace-test-123, got %s", record.TraceID)
	}
	if record.EventName != domain.EventSecurityIntrusion {
		t.Error("wrong event name")
	}
	if record.CreatedAt.IsZero() {
		t.Error("expected CreatedAt")
	}
}

func TestOrchestrator_ConcurrentSafety(t *testing.T) {
	blocker := NewBlockDispatcher()
	blocker.Register(NewIPBlockAction())
	analyzer := NewMockAnalysisAgent()
	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: StrategyBlockAndNotify, BlockAction: "block_ip"},
		},
		DefaultStrategy: StrategyNotifyOnly,
	}

	orch := NewThreatResponseOrchestrator(cfg, blocker, analyzer,
		WithNotifyFunc(notifier.notify),
	)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())
		}()
	}
	wg.Wait()

	if notifier.count() != 50 {
		t.Errorf("expected 50 notifications, got %d", notifier.count())
	}
}

func TestOrchestrator_IsEnabled(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		orch := NewThreatResponseOrchestrator(ThreatResponseConfig{Enabled: true}, nil, nil)
		if !orch.IsEnabled() {
			t.Error("should be enabled")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		orch := NewThreatResponseOrchestrator(ThreatResponseConfig{Enabled: false}, nil, nil)
		if orch.IsEnabled() {
			t.Error("should be disabled")
		}
	})
}

func TestOrchestrator_NotifyFuncError(t *testing.T) {
	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
	}

	failNotify := func(ctx context.Context, rec ThreatResponseRecord) error {
		return fmt.Errorf("notification service unavailable")
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithNotifyFunc(failNotify),
	)

	record, _ := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())
	if record.Notified {
		t.Error("should not be marked notified when notifyFn fails")
	}
}

func TestOrchestrator_PersistFuncError(t *testing.T) {
	persister := &testPersistRecorder{}
	failPersist := func(ctx context.Context, rec ThreatResponseRecord) error {
		return fmt.Errorf("database write failed")
	}

	cfg := ThreatResponseConfig{
		Enabled:         true,
		DefaultStrategy: StrategyNotifyOnly,
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithPersistFunc(failPersist),
	)

	// Should not panic or return error — persist failure is logged but non-fatal
	record, err := orch.Handle(context.Background(), securityDetection(), testutil.NewSecurityLog())
	if err != nil {
		t.Errorf("persist failure should not cause Handle error: %v", err)
	}
	if record == nil {
		t.Error("record should still be returned")
	}
	_ = persister
}

func TestOrchestrator_ComplianceViolation_NotifyOnly(t *testing.T) {
	notifier := &testNotifyRecorder{}

	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "COMPLIANCE_VIOLATION", Strategy: StrategyNotifyOnly, NotifyTargets: []string{"#compliance"}},
		},
	}

	orch := NewThreatResponseOrchestrator(cfg, nil, nil,
		WithNotifyFunc(notifier.notify),
	)

	det := &domain.DetectionResult{
		EventName: domain.EventComplianceViolation,
		Priority:  domain.PriorityHigh,
		Payload: domain.ComplianceViolationPayload{
			UserID: "user-1", DocumentID: "doc-1", RuleID: "comp-001",
		},
	}

	record, _ := orch.Handle(context.Background(), det, testutil.NewComplianceLog())

	if record.Target.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", record.Target.UserID)
	}
	if record.NotifyTarget != "#compliance" {
		t.Errorf("expected #compliance, got %s", record.NotifyTarget)
	}
	if !record.Notified {
		t.Error("should notify")
	}
}
