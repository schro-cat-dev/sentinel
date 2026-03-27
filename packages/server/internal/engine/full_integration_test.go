package engine

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/agent"
	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/middleware"
	"github.com/schro-cat-dev/sentinel-server/internal/response"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

// fullStackPipeline creates a pipeline with ALL modules enabled simultaneously
func fullStackPipeline(t *testing.T) (*Pipeline, *store.SQLiteStore, *response.IPBlockAction) {
	t.Helper()
	st, _ := store.NewSQLiteStore(":memory:")
	t.Cleanup(func() { st.Close() })

	cfg := PipelineConfig{
		ServiceID:       "full-stack",
		EnableHashChain: true,
		EnableMasking:   true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "PHONE"},
		},
		PreserveFields: []string{"traceId"},
		HMACKey:        []byte("full-stack-hmac-key-32-bytes-ok!!"),

		// Ensemble
		EnableEnsemble:     true,
		EnsembleThreshold:  0.5,
		EnsembleAggregator: detection.AggregateMax,
		DynamicDetectionRules: []detection.DynamicRuleConfig{
			{
				RuleID: "dyn-bruteforce", EventName: "SECURITY_INTRUSION_DETECTED",
				Priority: "HIGH", Score: 0.95,
				Conditions: detection.DynamicRuleConditions{
					LogTypes: []string{"SECURITY"}, MinLevel: 4,
					MessagePattern: `(?i)brute\s*force`,
				},
				PayloadBuilder: "security_intrusion",
			},
		},
		DedupWindowSec: 2,

		// Anomaly
		EnableAnomalyDetection: true,
		AnomalyConfig:          detection.DefaultAnomalyConfig(),

		// Masking policy
		EnableMaskingPolicy: true,
		MaskingPolicies: []security.MaskingPolicyRule{
			{
				PolicyID:  "sec-strict",
				Condition: security.MaskingPolicyCondition{LogTypes: []domain.LogType{domain.LogTypeSecurity}},
				MaskingRules: []security.MaskingRule{
					{Type: "PII_TYPE", Category: "EMAIL"},
					{Type: "PII_TYPE", Category: "PHONE"},
					{Type: "PII_TYPE", Category: "CREDIT_CARD"},
				},
			},
		},

		// Verification
		EnableMaskingVerification: true,

		// Authorization
		EnableAuthorization: true,
		AuthzConfig: middleware.AuthzConfig{
			Enabled:     true,
			DefaultRole: "writer",
			Roles: map[string]middleware.Role{
				"admin":  {Name: "admin", Permissions: middleware.Permission{CanWrite: true, CanRead: true, CanApprove: true, CanAdmin: true}},
				"writer": {Name: "writer", Permissions: middleware.Permission{AllowedLogTypes: []string{"SYSTEM", "SECURITY", "COMPLIANCE", "INFRA", "SLA"}, MaxLogLevel: 6, CanWrite: true, CanRead: true}},
			},
			ClientRoles: map[string]string{"admin-client": "admin"},
		},

		// Task rules
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-ai"; r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityHigh; r.ActionType = domain.ActionAIAnalyze
			}),
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "crit-notify"; r.EventName = "SYSTEM_CRITICAL_FAILURE"
				r.Severity = domain.SeverityHigh; r.ActionType = domain.ActionSystemNotification
			}),
		},
	}

	executor := task.NewTaskExecutor(nil)
	p, err := NewPipeline(cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	// Agent bridge
	provider := agent.NewMockProvider("full-stack-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{MaxLoopDepth: 5, TimeoutSec: 10}, nil)
	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled: true, AllowedActions: []domain.TaskActionType{domain.ActionAIAnalyze},
	})
	p.SetAgentBridge(bridge)

	// Threat response orchestrator
	blocker := response.NewBlockDispatcher()
	ipBlock := response.NewIPBlockAction()
	blocker.Register(ipBlock)
	orch := response.NewThreatResponseOrchestrator(
		response.ThreatResponseConfig{
			Enabled:         true,
			DefaultStrategy: response.StrategyNotifyOnly,
			Rules: []response.ResponseRuleConfig{
				{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: response.StrategyBlockAndNotify, BlockAction: "block_ip"},
			},
		},
		blocker, response.NewMockAnalysisAgent(),
	)
	p.SetThreatOrchestrator(orch)

	return p, st, ipBlock
}

func TestFullStack_SecurityIntrusion_EndToEnd(t *testing.T) {
	p, _, ipBlock := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message:  "Brute force attack from admin@evil.com, IP 10.0.0.99",
		Boundary: "auth-svc",
		Tags:     []domain.LogTag{{Key: "ip", Category: "10.0.0.99"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// 1. Masking: PII should be masked
	if !result.Masked {
		t.Error("expected masked")
	}

	// 2. Hash chain
	if !result.HashChainValid {
		t.Error("expected hash chain valid")
	}

	// 3. Tasks generated (AI analyze via ensemble detection)
	if len(result.TasksGenerated) == 0 {
		t.Fatal("expected tasks")
	}

	// 4. Threat response (block + analyze + notify)
	if len(result.ThreatResponses) == 0 {
		t.Fatal("expected threat responses")
	}
	tr := result.ThreatResponses[0]
	if !tr.Blocked {
		t.Error("expected IP blocked")
	}
	if !tr.Analyzed {
		t.Error("expected analysis")
	}

	// 5. Verify IP is actually blocked
	if !ipBlock.IsBlocked("10.0.0.99") {
		t.Error("IP should be blocked")
	}
}

func TestFullStack_CriticalLog_EndToEnd(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	result, err := p.Process(ctx, domain.Log{
		Message: "Database connection pool exhausted", IsCritical: true, Level: 6,
		Boundary: "db-svc",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(result.TasksGenerated) == 0 {
		t.Fatal("critical log should generate tasks")
	}
}

func TestFullStack_ComplianceViolation_EndToEnd(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeCompliance, Level: domain.LogLevelWarn,
		Message:     "Data retention policy violation detected",
		Boundary:    "audit-svc",
		ActorID:     "user@company.com",
		ResourceIDs: []string{"doc-123"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	_ = result // compliance detection generates tasks via ensemble
}

func TestFullStack_NormalLog_NoDetection(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	result, err := p.Process(ctx, domain.Log{Message: "All systems operational"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(result.TasksGenerated) != 0 {
		t.Error("normal log should not generate tasks")
	}
	if len(result.ThreatResponses) != 0 {
		t.Error("normal log should not trigger threat response")
	}
}

func TestFullStack_AuthorizationDenied(t *testing.T) {
	p, _, _ := fullStackPipeline(t)

	// writer role has AllowedLogTypes but no DEBUG
	ctx := middleware.ContextWithClientID(context.Background(), "some-writer")

	_, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeDebug, Level: domain.LogLevelInfo,
		Message: "Debug log attempt",
	})
	if err == nil {
		t.Error("expected authorization denial for DEBUG type")
	}
	if !strings.Contains(err.Error(), "authorization") {
		t.Errorf("expected authorization error, got: %v", err)
	}
}

func TestFullStack_Deduplication(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	secLog := domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Attack detected", Boundary: "auth-svc", ServiceID: "test",
	}

	r1, _ := p.Process(ctx, secLog)
	r2, _ := p.Process(ctx, secLog)

	if len(r1.TasksGenerated) == 0 {
		t.Fatal("first should detect")
	}
	if len(r2.TasksGenerated) != 0 {
		t.Error("second within dedup window should be suppressed")
	}
}

func TestFullStack_ConcurrentMixed(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	var wg sync.WaitGroup
	errCh := make(chan error, 200)

	logs := []domain.Log{
		{Type: domain.LogTypeSecurity, Level: domain.LogLevelError, Message: "Security event", Boundary: "svc"},
		{Message: "Normal log"},
		{Type: domain.LogTypeCompliance, Level: domain.LogLevelWarn, Message: "Compliance violation detected", Boundary: "audit"},
		{Message: "Critical!", IsCritical: true, Level: 6, Boundary: "db"},
	}

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			log := logs[n%len(logs)]
			_, err := p.Process(ctx, log)
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}
}

// --- Penetration-style Input Tests ---

func TestFullStack_Pentest_SQLInjection(t *testing.T) {
	p, st, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	attacks := []domain.Log{
		{Message: "'; DROP TABLE logs; --", Boundary: "svc"},
		{Message: "1' OR '1'='1", Boundary: "svc"},
		{Message: "UNION SELECT * FROM users--", Boundary: "svc"},
		{Message: `{"$gt": ""}`, Boundary: "svc"},
		{Message: "admin'--", ActorID: "'; DELETE FROM tasks; --"},
	}
	for _, log := range attacks {
		result, err := p.Process(ctx, log)
		if err != nil {
			t.Fatalf("SQL injection should be safely handled: %v", err)
		}
		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored == nil {
			t.Error("SQL injection attempt should be stored safely")
		}
	}
}

func TestFullStack_Pentest_XSSPayloads(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	attacks := []string{
		`<script>alert('xss')</script>`,
		`<img src=x onerror=alert(1)>`,
		`javascript:alert(document.cookie)`,
		`<svg/onload=alert('XSS')>`,
		`"><script>alert(String.fromCharCode(88,83,83))</script>`,
	}
	for _, payload := range attacks {
		_, err := p.Process(ctx, domain.Log{Message: payload, Boundary: "svc"})
		if err != nil {
			t.Errorf("XSS payload should be safely stored: %v", err)
		}
	}
}

func TestFullStack_Pentest_NullByteInjection(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	_, err := p.Process(ctx, domain.Log{Message: "hello\x00world"})
	if err == nil {
		t.Error("null byte injection should be rejected")
	}
}

func TestFullStack_Pentest_OversizedPayload(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	_, err := p.Process(ctx, domain.Log{Message: strings.Repeat("A", 70000)})
	if err == nil {
		t.Error("oversized payload should be rejected")
	}
}

func TestFullStack_Pentest_InvalidUTF8(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	_, err := p.Process(ctx, domain.Log{Message: string([]byte{0xff, 0xfe, 0xfd})})
	if err == nil {
		t.Error("invalid UTF-8 should be rejected")
	}
}

func TestFullStack_Pentest_ControlCharInjection(t *testing.T) {
	p, st, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	result, err := p.Process(ctx, domain.Log{Message: "hello\x01\x02world"})
	if err != nil {
		t.Fatalf("control chars should be stripped: %v", err)
	}
	stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
	if stored != nil && strings.Contains(stored.Message, "\x01") {
		t.Error("control chars should be removed")
	}
}

func TestFullStack_Pentest_PIILeakDetection(t *testing.T) {
	p, st, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "admin@secret.com, 090-1234-5678, 4111-1111-1111-1111",
		ActorID: "user@leaked.com", Boundary: "auth",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
	if stored != nil {
		if strings.Contains(stored.Message, "admin@secret.com") {
			t.Error("email PII leaked")
		}
		if strings.Contains(stored.Message, "090-1234") {
			t.Error("phone PII leaked")
		}
		if strings.Contains(stored.Message, "4111") {
			t.Error("credit card PII leaked")
		}
	}
}

func TestFullStack_Pentest_ExcessiveTags(t *testing.T) {
	p, st, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	tags := make([]domain.LogTag, 500) // way over limit
	for i := range tags {
		tags[i] = domain.LogTag{Key: "k", Category: "v"}
	}

	result, err := p.Process(ctx, domain.Log{Message: "test", Tags: tags})
	if err != nil {
		t.Fatalf("excessive tags should be truncated, not rejected: %v", err)
	}
	stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
	if stored != nil && len(stored.Tags) > 100 {
		t.Errorf("tags should be capped at 100, got %d", len(stored.Tags))
	}
}

func TestFullStack_Pentest_ReDoSRegex(t *testing.T) {
	// Ensure the system doesn't hang on ReDoS patterns
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	// This is a normal message that shouldn't cause issues
	_, err := p.Process(ctx, domain.Log{
		Message: strings.Repeat("a", 1000) + "@" + strings.Repeat("b", 1000) + ".com",
	})
	if err != nil {
		t.Fatalf("large email-like string should process: %v", err)
	}
}

func TestFullStack_Pentest_EmptyFields(t *testing.T) {
	p, _, _ := fullStackPipeline(t)
	ctx := middleware.ContextWithClientID(context.Background(), "admin-client")

	// Empty message should be rejected
	_, err := p.Process(ctx, domain.Log{Message: ""})
	if err == nil {
		t.Error("empty message should be rejected")
	}

	// Whitespace only should be rejected
	_, err = p.Process(ctx, domain.Log{Message: "   \t\n  "})
	if err == nil {
		t.Error("whitespace-only should be rejected")
	}
}
