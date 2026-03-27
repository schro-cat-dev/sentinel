package store

import (
	"context"
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteStore_Logs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	log := domain.Log{
		TraceID: "trace-001", Type: domain.LogTypeSystem, Level: 3,
		Timestamp: time.Now().UTC(), Boundary: "test-service", ServiceID: "svc-1",
		Origin: domain.OriginSystem, Message: "test log message",
		Tags: []domain.LogTag{{Key: "env", Category: "prod"}},
		Details: map[string]string{"key": "value"},
	}

	t.Run("insert and retrieve log", func(t *testing.T) {
		id, err := s.InsertLog(ctx, log)
		if err != nil { t.Fatalf("InsertLog: %v", err) }
		if id == 0 { t.Error("expected non-zero ID") }

		got, _ := s.GetLogByTraceID(ctx, "trace-001")
		if got == nil { t.Fatal("expected log") }
		if got.Message != "test log message" { t.Errorf("message: %s", got.Message) }
		if got.Details["key"] != "value" { t.Errorf("details: %v", got.Details) }
	})

	t.Run("duplicate traceID fails", func(t *testing.T) {
		_, err := s.InsertLog(ctx, log)
		if err == nil { t.Error("expected error") }
	})

	t.Run("not found returns nil", func(t *testing.T) {
		got, _ := s.GetLogByTraceID(ctx, "nonexistent")
		if got != nil { t.Error("expected nil") }
	})
}

func TestSQLiteStore_Tasks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	task := domain.GeneratedTask{
		TaskID: "task-001", RuleID: "rule-001", EventName: "SYSTEM_CRITICAL_FAILURE",
		Severity: domain.SeverityCritical, ActionType: domain.ActionSystemNotification,
		ExecutionLevel: domain.ExecLevelAuto, Priority: 1, Description: "Test task",
		SourceLog: domain.SourceLogInfo{TraceID: "trace-001", Message: "test", Level: 6, Timestamp: time.Now()},
		CreatedAt: time.Now(),
	}

	t.Run("insert and retrieve task", func(t *testing.T) {
		s.InsertTask(ctx, task, domain.StatusDispatched)
		got, _ := s.GetTask(ctx, "task-001")
		if got == nil { t.Fatal("expected task") }
		if got.Status != domain.StatusDispatched { t.Errorf("status: %s", got.Status) }
	})

	t.Run("update task status", func(t *testing.T) {
		s.UpdateTaskStatus(ctx, "task-001", domain.StatusCompleted, "")
		got, _ := s.GetTask(ctx, "task-001")
		if got.Status != domain.StatusCompleted { t.Errorf("status: %s", got.Status) }
	})

	t.Run("list tasks with filter", func(t *testing.T) {
		tasks, total, _ := s.ListTasks(ctx, TaskFilter{EventName: "SYSTEM_CRITICAL_FAILURE"})
		if total != 1 || len(tasks) != 1 { t.Errorf("got %d/%d", total, len(tasks)) }
	})

	t.Run("not found returns nil", func(t *testing.T) {
		got, _ := s.GetTask(ctx, "nonexistent")
		if got != nil { t.Error("expected nil") }
	})
}

func TestSQLiteStore_Approvals_MultiStep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	task := domain.GeneratedTask{
		TaskID: "task-ms-001", RuleID: "rule-001", EventName: "TEST",
		Severity: domain.SeverityHigh, ActionType: domain.ActionEscalate,
		ExecutionLevel: domain.ExecLevelManual, Priority: 1,
		SourceLog: domain.SourceLogInfo{TraceID: "t1", Timestamp: time.Now()},
		CreatedAt: time.Now(),
	}
	s.InsertTask(ctx, task, domain.StatusBlockedApproval)

	contentHash := domain.ComputeTaskContentHash(task)

	approval := domain.ApprovalRequest{
		ApprovalID:  "appr-ms-001",
		TaskID:      "task-ms-001",
		RequestedAt: time.Now().UTC(),
		Status:      "pending",
		ContentHash: contentHash,
		CurrentStep: 1,
		TotalSteps:  3,
	}

	t.Run("insert multi-step approval", func(t *testing.T) {
		err := s.InsertApproval(ctx, approval)
		if err != nil { t.Fatalf("InsertApproval: %v", err) }

		got, _ := s.GetApprovalByTaskID(ctx, "task-ms-001")
		if got == nil { t.Fatal("expected approval") }
		if got.TotalSteps != 3 { t.Errorf("totalSteps: %d", got.TotalSteps) }
		if got.CurrentStep != 1 { t.Errorf("currentStep: %d", got.CurrentStep) }
		if got.ContentHash != contentHash { t.Errorf("contentHash mismatch") }
	})

	t.Run("advance approval step", func(t *testing.T) {
		s.UpdateApprovalStep(ctx, "appr-ms-001", 2, "in_review")
		got, _ := s.GetApprovalByTaskID(ctx, "task-ms-001")
		if got.CurrentStep != 2 { t.Errorf("step: %d", got.CurrentStep) }
		if got.Status != "in_review" { t.Errorf("status: %s", got.Status) }
	})

	t.Run("resolve approval", func(t *testing.T) {
		err := s.ResolveApproval(ctx, "appr-ms-001", "approved", "admin", "ok")
		if err != nil { t.Fatalf("error: %v", err) }
		got, _ := s.GetApprovalByTaskID(ctx, "task-ms-001")
		if got.Status != "approved" { t.Errorf("status: %s", got.Status) }
		if got.ResolvedAt == nil { t.Error("expected resolved_at") }
	})

	t.Run("cannot re-resolve", func(t *testing.T) {
		err := s.ResolveApproval(ctx, "appr-ms-001", "rejected", "other", "no")
		if err == nil { t.Error("expected error for re-resolve") }
	})
}

func TestSQLiteStore_ApprovalStepRecords(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	record1 := domain.ApprovalStepRecord{
		RecordID: "rec-001", ApprovalID: "appr-001", StepOrder: 1,
		Action: "approved", ActorID: "lead-001", ActorRole: "team_lead",
		Reason: "Verified", ContentHash: "hash-at-step1", CreatedAt: time.Now(),
	}
	record2 := domain.ApprovalStepRecord{
		RecordID: "rec-002", ApprovalID: "appr-001", StepOrder: 2,
		Action: "approved", ActorID: "mgr-001", ActorRole: "manager",
		Reason: "Confirmed", ContentHash: "hash-at-step2", CreatedAt: time.Now(),
	}

	t.Run("insert and retrieve step records", func(t *testing.T) {
		s.InsertApprovalStepRecord(ctx, record1)
		s.InsertApprovalStepRecord(ctx, record2)

		records, _ := s.GetApprovalStepRecords(ctx, "appr-001")
		if len(records) != 2 { t.Fatalf("expected 2, got %d", len(records)) }
		if records[0].ActorRole != "team_lead" { t.Errorf("role: %s", records[0].ActorRole) }
		if records[1].ActorRole != "manager" { t.Errorf("role: %s", records[1].ActorRole) }
		if records[0].ContentHash != "hash-at-step1" { t.Error("hash mismatch step 1") }
	})
}

func TestSQLiteStore_TaskModifications(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	mod := domain.TaskModification{
		ModificationID: "mod-001", TaskID: "task-001",
		ModifiedBy: "admin-001", Field: "description",
		OldValue: "old desc", NewValue: "new desc",
		ContentHash: "hash-after-mod", CreatedAt: time.Now(),
	}

	t.Run("insert and retrieve modification", func(t *testing.T) {
		s.InsertTaskModification(ctx, mod)
		mods, _ := s.GetTaskModifications(ctx, "task-001")
		if len(mods) != 1 { t.Fatalf("expected 1, got %d", len(mods)) }
		if mods[0].Field != "description" { t.Errorf("field: %s", mods[0].Field) }
		if mods[0].OldValue != "old desc" { t.Errorf("old: %s", mods[0].OldValue) }
		if mods[0].NewValue != "new desc" { t.Errorf("new: %s", mods[0].NewValue) }
		if mods[0].ContentHash != "hash-after-mod" { t.Error("hash mismatch") }
	})

	t.Run("multiple modifications are append-only", func(t *testing.T) {
		mod2 := mod
		mod2.ModificationID = "mod-002"
		mod2.OldValue = "new desc"
		mod2.NewValue = "final desc"
		s.InsertTaskModification(ctx, mod2)

		mods, _ := s.GetTaskModifications(ctx, "task-001")
		if len(mods) != 2 { t.Fatalf("expected 2, got %d", len(mods)) }
	})
}

func TestSQLiteStore_TaskResults(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	result := domain.TaskResult{
		TaskID: "task-001", RuleID: "rule-001",
		Status: domain.StatusDispatched, DispatchedAt: time.Now(),
	}

	t.Run("insert task result", func(t *testing.T) {
		if err := s.InsertTaskResult(ctx, result); err != nil { t.Fatalf("error: %v", err) }
	})

	t.Run("multiple results append-only", func(t *testing.T) {
		result2 := result
		result2.Status = domain.StatusCompleted
		if err := s.InsertTaskResult(ctx, result2); err != nil { t.Fatalf("error: %v", err) }
	})
}

func TestSQLiteStore_ContentHashIntegrity(t *testing.T) {
	task := domain.GeneratedTask{
		TaskID: "task-hash-001", RuleID: "rule-001", EventName: "TEST",
		Severity: domain.SeverityHigh, ActionType: domain.ActionEscalate,
		ExecutionLevel: domain.ExecLevelManual, Description: "Test integrity",
		SourceLog: domain.SourceLogInfo{TraceID: "t1", Message: "original"},
	}

	t.Run("same task produces same hash", func(t *testing.T) {
		h1 := domain.ComputeTaskContentHash(task)
		h2 := domain.ComputeTaskContentHash(task)
		if h1 != h2 { t.Error("same task should produce same hash") }
	})

	t.Run("modified task produces different hash", func(t *testing.T) {
		h1 := domain.ComputeTaskContentHash(task)
		modified := task
		modified.Description = "Tampered description"
		h2 := domain.ComputeTaskContentHash(modified)
		if h1 == h2 { t.Error("modified task should produce different hash") }
	})
}

// === Threat Response Tests ===

func TestStore_InsertThreatResponse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	record := domain.ThreatResponseStoreRecord{
		ResponseID: "resp-001",
		TraceID:    "trace-001",
		EventName:  "SECURITY_INTRUSION_DETECTED",
		Strategy:   "BLOCK_AND_NOTIFY",
		TargetIP:   "192.168.1.100",
		TargetUserID: "user-1",
		Boundary:   "auth-svc",
		BlockAction: "block_ip",
		BlockSuccess: true,
		BlockTarget: "192.168.1.100",
		Analyzed:   true,
		RiskLevel:  "high",
		Confidence: 0.92,
		AnalysisSummary: "Brute force attack detected",
		Notified:   true,
		NotifyTarget: "#security",
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	err := s.InsertThreatResponse(ctx, record)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Retrieve
	records, err := s.GetThreatResponsesByTraceID(ctx, "trace-001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.ResponseID != "resp-001" {
		t.Errorf("responseID: %s", r.ResponseID)
	}
	if r.EventName != "SECURITY_INTRUSION_DETECTED" {
		t.Error("wrong event name")
	}
	if r.Strategy != "BLOCK_AND_NOTIFY" {
		t.Error("wrong strategy")
	}
	if r.TargetIP != "192.168.1.100" {
		t.Error("wrong target IP")
	}
	if !r.BlockSuccess {
		t.Error("block should be successful")
	}
	if !r.Analyzed {
		t.Error("should be analyzed")
	}
	if r.RiskLevel != "high" {
		t.Error("wrong risk level")
	}
	if r.Confidence != 0.92 {
		t.Errorf("wrong confidence: %f", r.Confidence)
	}
}

func TestStore_GetThreatResponsesByTraceID_Empty(t *testing.T) {
	s := newTestStore(t)
	records, err := s.GetThreatResponsesByTraceID(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(records) != 0 {
		t.Error("expected empty")
	}
}

func TestStore_MultipleThreatResponses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		s.InsertThreatResponse(ctx, domain.ThreatResponseStoreRecord{
			ResponseID: "resp-" + string(rune('A'+i)),
			TraceID:    "trace-multi",
			EventName:  "TEST",
			Strategy:   "NOTIFY_ONLY",
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		})
	}

	records, _ := s.GetThreatResponsesByTraceID(ctx, "trace-multi")
	if len(records) != 3 {
		t.Errorf("expected 3, got %d", len(records))
	}
}
