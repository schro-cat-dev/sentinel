package grpc

import (
	"context"
	"strings"
	"testing"

	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
)

// E2E: サーバ起動→全RPC→永続化→整合性の包括テスト
func TestE2E_FullServerLifecycle(t *testing.T) {
	client, st, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	// 1. HealthCheck
	t.Run("1_HealthCheck", func(t *testing.T) {
		resp, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{})
		if err != nil { t.Fatalf("error: %v", err) }
		if resp.Status != "SERVING" { t.Errorf("status: %s", resp.Status) }
	})

	// 2. Ingest normal log (no task)
	var normalTraceID string
	t.Run("2_IngestNormalLog", func(t *testing.T) {
		resp, err := client.Ingest(ctx, &pb.IngestRequest{
			Message: "User login successful", Type: "SYSTEM", Level: 3,
			ActorId: "user-001", Boundary: "auth-service",
		})
		if err != nil { t.Fatalf("error: %v", err) }
		normalTraceID = resp.TraceId
		if normalTraceID == "" { t.Error("missing traceId") }
		if !resp.HashChainValid { t.Error("hash chain should be valid") }
		if !resp.Masked { t.Error("should be masked") }
		if len(resp.TasksGenerated) != 0 { t.Error("no tasks expected") }
	})

	// 3. Verify normal log persisted
	t.Run("3_NormalLogPersisted", func(t *testing.T) {
		log, _ := st.GetLogByTraceID(ctx, normalTraceID)
		if log == nil { t.Fatal("log should be persisted") }
		if log.Boundary != "auth-service" { t.Errorf("boundary: %s", log.Boundary) }
	})

	// 4. Ingest critical log (generates AUTO task)
	var critTaskID string
	t.Run("4_IngestCriticalLog", func(t *testing.T) {
		resp, err := client.Ingest(ctx, &pb.IngestRequest{
			Message: "Database pool exhausted", Level: 6, IsCritical: true,
			Boundary: "db-service:pool",
		})
		if err != nil { t.Fatalf("error: %v", err) }
		if len(resp.TasksGenerated) == 0 { t.Fatal("expected tasks") }
		critTaskID = resp.TasksGenerated[0].TaskId
		if resp.TasksGenerated[0].Status != "dispatched" {
			t.Errorf("expected dispatched, got %s", resp.TasksGenerated[0].Status)
		}
	})

	// 5. GetTaskStatus for critical task
	t.Run("5_GetCriticalTaskStatus", func(t *testing.T) {
		resp, err := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: critTaskID})
		if err != nil { t.Fatalf("error: %v", err) }
		if resp.Status != "dispatched" { t.Errorf("status: %s", resp.Status) }
		if resp.RuleId != "crit-notify" { t.Errorf("ruleId: %s", resp.RuleId) }
	})

	// 6. Ingest compliance violation (generates MANUAL task → blocked)
	var compTaskID string
	t.Run("6_IngestComplianceViolation", func(t *testing.T) {
		resp, err := client.Ingest(ctx, &pb.IngestRequest{
			Message: "Data retention policy violation detected",
			Type: "COMPLIANCE", Level: 4,
		})
		if err != nil { t.Fatalf("error: %v", err) }
		if len(resp.TasksGenerated) == 0 { t.Fatal("expected tasks") }
		compTaskID = resp.TasksGenerated[0].TaskId
		if resp.TasksGenerated[0].Status != "blocked_approval" {
			t.Errorf("expected blocked, got %s", resp.TasksGenerated[0].Status)
		}
	})

	// 7. GetTaskStatus → blocked_approval
	t.Run("7_ComplianceTaskBlocked", func(t *testing.T) {
		resp, _ := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: compTaskID})
		if resp.Status != "blocked_approval" { t.Errorf("status: %s", resp.Status) }
	})

	// 8. ApproveTask → dispatched
	t.Run("8_ApproveComplianceTask", func(t *testing.T) {
		resp, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
			TaskId: compTaskID, ApproverId: "legal-officer-001",
			Reason: "Verified by legal team",
		})
		if err != nil { t.Fatalf("error: %v", err) }
		if resp.Status != "dispatched" { t.Errorf("expected dispatched, got %s", resp.Status) }
	})

	// 9. GetTaskStatus after approval → dispatched
	t.Run("9_ComplianceTaskDispatched", func(t *testing.T) {
		resp, _ := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: compTaskID})
		if resp.Status != "dispatched" { t.Errorf("status: %s", resp.Status) }
	})

	// 10. ListTasks
	t.Run("10_ListAllTasks", func(t *testing.T) {
		resp, _ := client.ListTasks(ctx, &pb.ListTasksRequest{Limit: 100})
		if resp.TotalCount < 2 { t.Errorf("expected at least 2 tasks, got %d", resp.TotalCount) }
	})

	// 11. Ingest security intrusion
	t.Run("11_SecurityIntrusion", func(t *testing.T) {
		resp, _ := client.Ingest(ctx, &pb.IngestRequest{
			Message: "Brute force attack detected", Type: "SECURITY", Level: 5,
			Boundary: "auth-service", Tags: []*pb.LogTag{{Key: "ip", Category: "10.0.0.1"}},
		})
		if resp.TraceId == "" { t.Error("missing traceId") }
	})

	// 12. AI_AGENT loop prevention
	t.Run("12_AIAgentNoRedetect", func(t *testing.T) {
		resp, _ := client.Ingest(ctx, &pb.IngestRequest{
			Message: "AI analysis complete", Type: "SECURITY", Level: 5, Origin: "AI_AGENT",
		})
		if len(resp.TasksGenerated) != 0 { t.Error("AI_AGENT should not trigger tasks") }
	})

	// 13. PII masking end-to-end
	t.Run("13_PIIMasking", func(t *testing.T) {
		resp, _ := client.Ingest(ctx, &pb.IngestRequest{
			Message: "Contact admin@example.com for help",
		})
		log, _ := st.GetLogByTraceID(ctx, resp.TraceId)
		if log != nil && strings.Contains(log.Message, "admin@example.com") {
			t.Error("PII should be masked in stored log")
		}
	})

	// 14. Hash chain across multiple requests
	t.Run("14_HashChainContinuity", func(t *testing.T) {
		r1, _ := client.Ingest(ctx, &pb.IngestRequest{Message: "chain-1"})
		r2, _ := client.Ingest(ctx, &pb.IngestRequest{Message: "chain-2"})
		r3, _ := client.Ingest(ctx, &pb.IngestRequest{Message: "chain-3"})
		ids := map[string]bool{r1.TraceId: true, r2.TraceId: true, r3.TraceId: true}
		if len(ids) != 3 { t.Error("all traceIds should be unique") }
		if !r1.HashChainValid || !r2.HashChainValid || !r3.HashChainValid {
			t.Error("all should have valid hash chain")
		}
	})

	// 15. Reject flow
	t.Run("15_RejectFlow", func(t *testing.T) {
		ingestResp, _ := client.Ingest(ctx, &pb.IngestRequest{
			Message: "Another compliance violation detected", Type: "COMPLIANCE", Level: 4,
		})
		if len(ingestResp.TasksGenerated) == 0 { t.Fatal("expected task") }
		taskID := ingestResp.TasksGenerated[0].TaskId

		rejectResp, err := client.RejectTask(ctx, &pb.RejectTaskRequest{
			TaskId: taskID, RejectorId: "auditor-001", Reason: "False positive",
		})
		if err != nil { t.Fatalf("error: %v", err) }
		if rejectResp.Status != "rejected" { t.Errorf("expected rejected, got %s", rejectResp.Status) }

		// Cannot approve after rejection
		_, err = client.ApproveTask(ctx, &pb.ApproveTaskRequest{
			TaskId: taskID, ApproverId: "admin", Reason: "override",
		})
		if err == nil { t.Error("should not approve rejected task") }
	})

	// 16. Invalid inputs
	t.Run("16_InvalidInputs", func(t *testing.T) {
		_, err := client.Ingest(ctx, &pb.IngestRequest{Message: ""})
		if err == nil { t.Error("empty message should fail") }

		_, err = client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: ""})
		if err == nil { t.Error("empty taskId should fail") }

		_, err = client.ApproveTask(ctx, &pb.ApproveTaskRequest{})
		if err == nil { t.Error("empty approve request should fail") }

		_, err = client.RejectTask(ctx, &pb.RejectTaskRequest{})
		if err == nil { t.Error("empty reject request should fail") }

		_, err = client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: "nonexistent"})
		if err == nil { t.Error("nonexistent task should fail") }
	})
}
