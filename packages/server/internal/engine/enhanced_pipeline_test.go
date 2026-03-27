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
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

// --- Test helpers ---

func enhancedPipeline(t *testing.T, opts ...func(*PipelineConfig)) (*Pipeline, *store.SQLiteStore) {
	t.Helper()
	cfg := PipelineConfig{
		ServiceID:       "enhanced-test",
		EnableHashChain: true,
		EnableMasking:   true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "PHONE"},
		},
		PreserveFields: []string{"traceId"},
		HMACKey:        []byte("enhanced-test-hmac-key-32-bytes!!"),
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "crit-notify"
				r.EventName = "SYSTEM_CRITICAL_FAILURE"
				r.Severity = domain.SeverityHigh
				r.ActionType = domain.ActionSystemNotification
			}),
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-analyze"
				r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityHigh
				r.ActionType = domain.ActionAIAnalyze
				r.ExecutionLevel = domain.ExecLevelAuto
			}),
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "comp-escalate"
				r.EventName = "COMPLIANCE_VIOLATION"
				r.Severity = domain.SeverityMedium
				r.ActionType = domain.ActionEscalate
				r.ExecutionLevel = domain.ExecLevelManual
			}),
		},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	executor := task.NewTaskExecutor(nil)
	p, err := NewPipeline(cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return p, st
}

func withEnsemble(cfg *PipelineConfig) {
	cfg.EnableEnsemble = true
	cfg.EnsembleThreshold = 0.5
	cfg.EnsembleAggregator = detection.AggregateMax
}

func withAnomalyDetection(cfg *PipelineConfig) {
	cfg.EnableAnomalyDetection = true
	cfg.AnomalyConfig = detection.DefaultAnomalyConfig()
}

func withMaskingPolicy(cfg *PipelineConfig) {
	cfg.EnableMaskingPolicy = true
	cfg.MaskingPolicies = []security.MaskingPolicyRule{
		{
			PolicyID: "security-strict",
			Condition: security.MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeSecurity},
			},
			MaskingRules: []security.MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
				{Type: "PII_TYPE", Category: "PHONE"},
				{Type: "PII_TYPE", Category: "CREDIT_CARD"},
			},
		},
		{
			PolicyID: "compliance-preserve-actor",
			Condition: security.MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeCompliance},
			},
			MaskingRules: []security.MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
			},
			PreserveExtra: []string{"actorId"},
		},
	}
}

func withVerification(cfg *PipelineConfig) {
	cfg.EnableMaskingVerification = true
}

func withAuthz(cfg *PipelineConfig) {
	cfg.EnableAuthorization = true
	cfg.AuthzConfig = middleware.AuthzConfig{
		Enabled:     true,
		DefaultRole: "viewer",
		Roles: map[string]middleware.Role{
			"admin": {
				Name: "admin",
				Permissions: middleware.Permission{
					CanWrite: true, CanRead: true, CanApprove: true, CanAdmin: true,
				},
			},
			"writer": {
				Name: "writer",
				Permissions: middleware.Permission{
					AllowedLogTypes: []string{"SYSTEM", "INFRA", "DEBUG"},
					MaxLogLevel:     5,
					CanWrite:        true,
					CanRead:         true,
				},
			},
			"viewer": {
				Name: "viewer",
				Permissions: middleware.Permission{
					CanRead: true,
				},
			},
		},
		ClientRoles: map[string]string{
			"client-admin":  "admin",
			"client-writer": "writer",
		},
	}
}

func withDynamicRules(cfg *PipelineConfig) {
	cfg.EnableEnsemble = true
	cfg.EnsembleThreshold = 0.5
	cfg.DynamicDetectionRules = []detection.DynamicRuleConfig{
		{
			RuleID:    "dyn-brute-force",
			EventName: "SECURITY_INTRUSION_DETECTED",
			Priority:  "HIGH",
			Score:     0.95,
			Conditions: detection.DynamicRuleConditions{
				LogTypes:       []string{"SECURITY"},
				MinLevel:       4,
				MessagePattern: `(?i)brute\s*force`,
			},
			PayloadBuilder: "security_intrusion",
		},
		{
			RuleID:    "dyn-data-exfil",
			EventName: "SECURITY_INTRUSION_DETECTED",
			Priority:  "HIGH",
			Score:     0.9,
			Conditions: detection.DynamicRuleConditions{
				LogTypes:       []string{"SECURITY"},
				MinLevel:       5,
				MessagePattern: `(?i)exfiltration|data\s*leak`,
			},
			PayloadBuilder: "security_intrusion",
		},
	}
}

func withDedup(cfg *PipelineConfig) {
	cfg.EnableEnsemble = true
	cfg.EnsembleThreshold = 0.5
	cfg.DedupWindowSec = 5
}

// --- Ensemble Detection Tests ---

func TestEnhancedPipeline_EnsembleDetection(t *testing.T) {
	p, _ := enhancedPipeline(t, withEnsemble)
	ctx := context.Background()

	t.Run("ensemble detects critical log and generates tasks", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Message: "DB pool exhausted", IsCritical: true, Level: 6, Boundary: "db-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks from ensemble detection")
		}
		if result.TasksGenerated[0].RuleID != "crit-notify" {
			t.Errorf("expected crit-notify, got %s", result.TasksGenerated[0].RuleID)
		}
	})

	t.Run("ensemble detects security intrusion", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
			Message: "Suspicious login from 10.0.0.1", Boundary: "auth-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks for security intrusion")
		}
	})

	t.Run("normal log produces no tasks", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{Message: "All systems normal"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) != 0 {
			t.Error("normal log should not generate tasks")
		}
	})
}

// --- Dynamic Rule Tests ---

func TestEnhancedPipeline_DynamicRules(t *testing.T) {
	p, _ := enhancedPipeline(t, withDynamicRules)
	ctx := context.Background()

	t.Run("dynamic rule detects brute force pattern", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelWarn,
			Message: "Brute force attack detected from 192.168.1.50",
			Boundary: "auth-svc",
			Tags: []domain.LogTag{{Key: "ip", Category: "192.168.1.50"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks from dynamic brute force rule")
		}
	})

	t.Run("dynamic rule detects data exfiltration", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
			Message: "Potential data exfiltration detected",
			Boundary: "data-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks from data exfil rule")
		}
	})

	t.Run("unmatched pattern produces no detection", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelWarn,
			Message: "Normal security audit completed",
			Boundary: "audit-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) != 0 {
			t.Error("unmatched pattern should not generate tasks")
		}
	})
}

// --- Deduplication Tests ---

func TestEnhancedPipeline_Deduplication(t *testing.T) {
	p, _ := enhancedPipeline(t, withDedup)
	ctx := context.Background()

	log := domain.Log{
		Message: "Critical failure", IsCritical: true, Level: 6,
		Boundary: "db-svc", ServiceID: "test",
	}

	// First should generate tasks
	r1, _ := p.Process(ctx, log)
	if len(r1.TasksGenerated) == 0 {
		t.Fatal("first log should generate tasks")
	}

	// Second within window should be deduplicated
	r2, _ := p.Process(ctx, log)
	if len(r2.TasksGenerated) != 0 {
		t.Error("second log within dedup window should not generate tasks")
	}
}

// --- Authorization Tests ---

func TestEnhancedPipeline_Authorization(t *testing.T) {
	p, _ := enhancedPipeline(t, withAuthz)

	t.Run("admin can write any log type", func(t *testing.T) {
		ctx := middleware.ContextWithClientID(context.Background(), "client-admin")
		_, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelCritical,
			Message: "Critical security event",
		})
		if err != nil {
			t.Errorf("admin should write any type: %v", err)
		}
	})

	t.Run("writer denied SECURITY type", func(t *testing.T) {
		ctx := middleware.ContextWithClientID(context.Background(), "client-writer")
		_, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelInfo,
			Message: "Should be denied",
		})
		if err == nil {
			t.Error("writer should be denied SECURITY type")
		}
		if !strings.Contains(err.Error(), "authorization") {
			t.Errorf("expected authorization error, got: %v", err)
		}
	})

	t.Run("writer can write SYSTEM type", func(t *testing.T) {
		ctx := middleware.ContextWithClientID(context.Background(), "client-writer")
		_, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSystem, Level: domain.LogLevelInfo,
			Message: "Normal system log",
		})
		if err != nil {
			t.Errorf("writer should write SYSTEM: %v", err)
		}
	})

	t.Run("writer denied level exceeding max", func(t *testing.T) {
		ctx := middleware.ContextWithClientID(context.Background(), "client-writer")
		_, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSystem, Level: domain.LogLevelCritical,
			Message: "High level log",
		})
		if err == nil {
			t.Error("writer should be denied level 6 (max 5)")
		}
	})

	t.Run("viewer denied write access", func(t *testing.T) {
		ctx := middleware.ContextWithClientID(context.Background(), "unknown-client")
		_, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSystem, Level: domain.LogLevelInfo,
			Message: "Viewer attempt",
		})
		if err == nil {
			t.Error("viewer should be denied write access")
		}
	})

	t.Run("anonymous client denied", func(t *testing.T) {
		ctx := context.Background() // no clientID
		_, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSystem, Level: domain.LogLevelInfo,
			Message: "Anonymous attempt",
		})
		if err == nil {
			t.Error("anonymous should be denied")
		}
	})
}

// --- Masking Policy Tests ---

func TestEnhancedPipeline_MaskingPolicy(t *testing.T) {
	p, st := enhancedPipeline(t, withMaskingPolicy)
	ctx := context.Background()

	t.Run("security log gets strict masking (email+phone+card)", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
			Message: "Contact admin@evil.com card 4111-1111-1111-1111 phone 090-1234-5678",
			Boundary: "auth-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored != nil {
			if strings.Contains(stored.Message, "admin@evil.com") {
				t.Error("email should be masked for security logs")
			}
			if strings.Contains(stored.Message, "4111") {
				t.Error("credit card should be masked for security logs")
			}
			if strings.Contains(stored.Message, "090-1234") {
				t.Error("phone should be masked for security logs")
			}
		}
	})

	t.Run("compliance log preserves actorId", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeCompliance, Level: domain.LogLevelWarn,
			Message:  "Violation by admin@company.com",
			ActorID:  "admin@company.com",
			Boundary: "audit-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored != nil {
			if stored.ActorID != "admin@company.com" {
				t.Errorf("compliance actorId should be preserved, got %q", stored.ActorID)
			}
			if strings.Contains(stored.Message, "admin@company.com") {
				t.Error("email in message should still be masked")
			}
		}
	})

	t.Run("system log uses default masking", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Message: "User user@test.com logged in",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored != nil && strings.Contains(stored.Message, "user@test.com") {
			t.Error("default masking should mask email")
		}
	})
}

// --- Masking Verification Tests ---

func TestEnhancedPipeline_MaskingVerification(t *testing.T) {
	p, st := enhancedPipeline(t, withVerification)
	ctx := context.Background()

	t.Run("verifier catches leaks and re-masks", func(t *testing.T) {
		// Even with standard masking, verification adds a safety net
		result, err := p.Process(ctx, domain.Log{
			Message: "Contact admin@example.com for help",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored != nil && strings.Contains(stored.Message, "admin@example.com") {
			t.Error("PII should be masked (possibly by verification fallback)")
		}
	})
}

// --- Agent Bridge E2E Tests ---

func TestEnhancedPipeline_AgentBridgeE2E(t *testing.T) {
	var reIngestedLogs []domain.Log
	var mu sync.Mutex

	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 10,
	}, func(ctx context.Context, log domain.Log) error {
		mu.Lock()
		defer mu.Unlock()
		reIngestedLogs = append(reIngestedLogs, log)
		return nil
	})

	cfg := PipelineConfig{
		ServiceID:       "agent-e2e",
		EnableHashChain: true,
		EnableMasking:   true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		},
		HMACKey: []byte("agent-e2e-hmac-key-32-bytes-ok!!"),
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-ai-analyze"
				r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityHigh
				r.ActionType = domain.ActionAIAnalyze
				r.ExecutionLevel = domain.ExecLevelAuto
			}),
		},
	}

	executor := task.NewTaskExecutor(nil)
	p, err := NewPipeline(cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled:      true,
		MaxLoopDepth: 5,
		TimeoutSec:   10,
		AllowedActions: []domain.TaskActionType{domain.ActionAIAnalyze},
		MinSeverity:  domain.SeverityLow,
	})
	p.SetAgentBridge(bridge)

	ctx := context.Background()

	t.Run("security intrusion triggers AI agent", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
			Message: "Brute force from 192.168.1.100", Boundary: "auth-svc",
			Tags: []domain.LogTag{{Key: "ip", Category: "192.168.1.100"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks for security intrusion")
		}
		// Task should be dispatched (not blocked) because ActionAIAnalyze + AUTO
		for _, tr := range result.TasksGenerated {
			if tr.RuleID == "sec-ai-analyze" {
				if tr.Status != domain.StatusDispatched {
					t.Errorf("expected dispatched, got %s", tr.Status)
				}
			}
		}

		// AI agent should have re-ingested a log
		mu.Lock()
		logCount := len(reIngestedLogs)
		mu.Unlock()
		if logCount == 0 {
			t.Fatal("expected re-ingested agent log")
		}

		mu.Lock()
		agentLog := reIngestedLogs[len(reIngestedLogs)-1]
		mu.Unlock()

		if agentLog.Origin != domain.OriginAIAgent {
			t.Errorf("expected AI_AGENT origin, got %s", agentLog.Origin)
		}
		if agentLog.AIContext == nil {
			t.Fatal("expected AIContext")
		}
		if agentLog.AIContext.LoopDepth != 1 {
			t.Errorf("expected loop depth 1, got %d", agentLog.AIContext.LoopDepth)
		}
		if len(agentLog.AgentBackLog) == 0 {
			t.Fatal("expected agent backlog")
		}
		if agentLog.AgentBackLog[0].Status != "success" {
			t.Errorf("expected success, got %s", agentLog.AgentBackLog[0].Status)
		}
	})

	t.Run("normal log does not trigger AI agent", func(t *testing.T) {
		mu.Lock()
		beforeCount := len(reIngestedLogs)
		mu.Unlock()

		_, err := p.Process(ctx, domain.Log{Message: "Normal operation"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		mu.Lock()
		afterCount := len(reIngestedLogs)
		mu.Unlock()

		if afterCount != beforeCount {
			t.Error("normal log should not trigger AI agent")
		}
	})
}

func TestEnhancedPipeline_AgentBridgeDisabled(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	t.Cleanup(func() { st.Close() })

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 10,
	}, nil)

	cfg := PipelineConfig{
		ServiceID: "disabled-agent",
		MaskingRules: []security.MaskingRule{},
		HMACKey:   []byte("disabled-agent-hmac-32-bytes-ok!!"),
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-analyze"
				r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityHigh
				r.ActionType = domain.ActionAIAnalyze
			}),
		},
	}

	executor := task.NewTaskExecutor(nil)
	p, _ := NewPipeline(cfg, executor, st, nil)

	// Bridge is disabled
	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled: false,
	})
	p.SetAgentBridge(bridge)

	ctx := context.Background()
	result, err := p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Security event", Boundary: "svc",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Tasks should still be generated, but agent handler returns nil (disabled)
	if len(result.TasksGenerated) == 0 {
		t.Fatal("tasks should still be generated")
	}
}

func TestEnhancedPipeline_AgentBridgeSeverityFilter(t *testing.T) {
	var agentCalled bool
	var mu sync.Mutex

	st, _ := store.NewSQLiteStore(":memory:")
	t.Cleanup(func() { st.Close() })

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 10,
	}, func(ctx context.Context, log domain.Log) error {
		mu.Lock()
		agentCalled = true
		mu.Unlock()
		return nil
	})

	cfg := PipelineConfig{
		ServiceID: "severity-filter",
		MaskingRules: []security.MaskingRule{},
		HMACKey:   []byte("severity-filter-hmac-32-bytes!!xx"),
		TaskRules: []domain.TaskRule{
			testutil.NewTestTaskRule(func(r *domain.TaskRule) {
				r.RuleID = "sec-analyze"
				r.EventName = "SECURITY_INTRUSION_DETECTED"
				r.Severity = domain.SeverityLow // Low severity threshold so it matches
				r.ActionType = domain.ActionAIAnalyze
			}),
		},
	}

	executor := task.NewTaskExecutor(nil)
	p, _ := NewPipeline(cfg, executor, st, nil)

	// Bridge with HIGH min severity — should skip low severity tasks
	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled:      true,
		AllowedActions: []domain.TaskActionType{domain.ActionAIAnalyze},
		MinSeverity:  domain.SeverityCritical, // Only execute for CRITICAL
	})
	p.SetAgentBridge(bridge)

	ctx := context.Background()
	_, _ = p.Process(ctx, domain.Log{
		Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
		Message: "Security event", Boundary: "svc",
	})

	mu.Lock()
	called := agentCalled
	mu.Unlock()
	if called {
		t.Error("agent should not be called when severity is below threshold")
	}
}

// --- Combined Module Tests ---

func TestEnhancedPipeline_AllModulesEnabled(t *testing.T) {
	p, st := enhancedPipeline(t,
		withEnsemble,
		withMaskingPolicy,
		withVerification,
	)
	ctx := context.Background()

	t.Run("full pipeline processes security log", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
			Message:  "Attack from admin@evil.com, card 4111-1111-1111-1111",
			Boundary: "auth-svc",
			Tags:     []domain.LogTag{{Key: "ip", Category: "192.168.1.100"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if !result.Masked {
			t.Error("expected masked")
		}
		if !result.HashChainValid {
			t.Error("expected hash chain valid")
		}

		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored != nil {
			if strings.Contains(stored.Message, "admin@evil.com") {
				t.Error("PII should be masked")
			}
		}

		// Should have generated tasks via ensemble detection
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks")
		}
	})

	t.Run("full pipeline processes compliance log", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{
			Type: domain.LogTypeCompliance, Level: domain.LogLevelWarn,
			Message:     "Data retention violation detected by user@test.com",
			ActorID:     "user@audit.com",
			Boundary:    "audit-svc",
			ResourceIDs: []string{"doc-123"},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		stored, _ := st.GetLogByTraceID(ctx, result.TraceID)
		if stored != nil {
			// ActorID should be preserved for compliance (policy)
			if stored.ActorID != "user@audit.com" {
				t.Errorf("compliance actorId should be preserved, got %q", stored.ActorID)
			}
		}
	})
}

// --- Backward Compatibility Tests ---

func TestEnhancedPipeline_BackwardCompatibility(t *testing.T) {
	// Default pipeline with no enhanced modules should work exactly as before
	p, _ := enhancedPipeline(t)
	ctx := context.Background()

	t.Run("simple log processing", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{Message: "Hello"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if result.TraceID == "" {
			t.Error("expected traceID")
		}
		if !result.Masked || !result.HashChainValid {
			t.Error("expected masked and hash chain valid")
		}
	})

	t.Run("critical log generates tasks (legacy detector)", func(t *testing.T) {
		result, _ := p.Process(ctx, domain.Log{
			Message: "Critical", IsCritical: true, Level: 6,
		})
		if len(result.TasksGenerated) == 0 {
			t.Fatal("legacy detector should generate tasks")
		}
	})
}

// --- Concurrent Safety with Enhanced Modules ---

func TestEnhancedPipeline_ConcurrentSafety(t *testing.T) {
	p, _ := enhancedPipeline(t, withEnsemble, withMaskingPolicy, withVerification)
	ctx := context.Background()

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var log domain.Log
			if n%3 == 0 {
				log = domain.Log{
					Type: domain.LogTypeSecurity, Level: domain.LogLevelError,
					Message: "Concurrent security event", Boundary: "svc",
				}
			} else if n%3 == 1 {
				log = domain.Log{
					Message: "Concurrent normal", IsCritical: n%7 == 0, Level: 3 + domain.LogLevel(n%4),
				}
			} else {
				log = domain.Log{
					Type: domain.LogTypeCompliance, Level: domain.LogLevelWarn,
					Message: "Concurrent compliance violation detected", Boundary: "audit",
				}
			}
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

// --- Edge Cases ---

func TestEnhancedPipeline_EdgeCases(t *testing.T) {
	t.Run("ensemble with no dynamic rules", func(t *testing.T) {
		p, _ := enhancedPipeline(t, func(cfg *PipelineConfig) {
			cfg.EnableEnsemble = true
			cfg.EnsembleThreshold = 0.5
		})
		result, err := p.Process(context.Background(), domain.Log{
			Message: "Critical", IsCritical: true, Level: 6,
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(result.TasksGenerated) == 0 {
			t.Fatal("builtin rules should still work")
		}
	})

	t.Run("masking policy with empty policies list", func(t *testing.T) {
		p, _ := enhancedPipeline(t, func(cfg *PipelineConfig) {
			cfg.EnableMaskingPolicy = true
			cfg.MaskingPolicies = nil // empty
		})
		// Should fall back to default masking service
		result, err := p.Process(context.Background(), domain.Log{
			Message: "Contact admin@test.com",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		_ = result
	})

	t.Run("anomaly detection alone (no ensemble)", func(t *testing.T) {
		p, _ := enhancedPipeline(t, withAnomalyDetection)
		ctx := context.Background()

		// Just make sure it doesn't panic
		for i := 0; i < 10; i++ {
			_, err := p.Process(ctx, domain.Log{
				Type: domain.LogTypeSecurity, Level: domain.LogLevelWarn,
				Message: "Normal event", Boundary: "svc",
			})
			if err != nil {
				t.Fatalf("error: %v", err)
			}
		}
	})

	t.Run("verification with empty masking rules", func(t *testing.T) {
		p, _ := enhancedPipeline(t, func(cfg *PipelineConfig) {
			cfg.EnableMaskingVerification = true
			cfg.MaskingRules = nil
		})
		result, err := p.Process(context.Background(), domain.Log{
			Message: "Contact admin@test.com",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		_ = result
	})
}

// --- Agent Bridge Unit Tests ---

func TestAgentBridge_AllowedActions(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, nil)

	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled: true,
		AllowedActions: []domain.TaskActionType{
			domain.ActionAIAnalyze,
			domain.ActionAutomatedRemediate,
		},
	})

	executor := task.NewTaskExecutor(nil)
	bridge.RegisterHandlers(executor)

	// AI_ANALYZE should be handled
	result := executor.Dispatch(domain.GeneratedTask{
		TaskID: "t1", ActionType: domain.ActionAIAnalyze,
		ExecutionLevel: domain.ExecLevelAuto,
		Guardrails:     domain.Guardrails{},
	})
	if result.Status != domain.StatusDispatched {
		t.Errorf("AI_ANALYZE should be dispatched, got %s", result.Status)
	}
}

func TestAgentBridge_DefaultAllowedAction(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, nil)

	// No explicit AllowedActions → defaults to AI_ANALYZE
	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled: true,
	})

	if !bridge.allowedActions[domain.ActionAIAnalyze] {
		t.Error("AI_ANALYZE should be default allowed action")
	}
}

func TestAgentBridge_SourceLogCache(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, nil)

	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{Enabled: true})

	log := testutil.NewSecurityLog()
	bridge.SetSourceLog("task-1", log)

	retrieved, ok := bridge.getSourceLog("task-1")
	if !ok {
		t.Fatal("expected source log")
	}
	if retrieved.TraceID != log.TraceID {
		t.Error("traceID mismatch")
	}

	bridge.ClearSourceLog("task-1")
	_, ok = bridge.getSourceLog("task-1")
	if ok {
		t.Error("should be cleared")
	}
}
