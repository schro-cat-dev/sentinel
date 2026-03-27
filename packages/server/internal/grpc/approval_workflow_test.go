package grpc

import (
	"context"
	"testing"

	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
)

// E2E: 完全な承認フロー (Ingest → blocked_approval → GetTaskStatus → ApproveTask → dispatched)
func TestE2E_ApprovalWorkflow_Approve(t *testing.T) {
	client, st, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()
	_ = st

	// 1. Ingest compliance violation → blocked_approval
	ingestResp, err := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Data retention policy violation detected",
		Type:    "COMPLIANCE", Level: 4,
	})
	if err != nil {
		t.Fatalf("Ingest error: %v", err)
	}
	if len(ingestResp.TasksGenerated) == 0 {
		t.Fatal("expected blocked tasks")
	}
	taskID := ingestResp.TasksGenerated[0].TaskId
	if ingestResp.TasksGenerated[0].Status != "blocked_approval" {
		t.Fatalf("expected blocked_approval, got %s", ingestResp.TasksGenerated[0].Status)
	}

	// 2. GetTaskStatus → should be blocked_approval
	statusResp, err := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("GetTaskStatus error: %v", err)
	}
	if statusResp.Status != "blocked_approval" {
		t.Errorf("expected blocked_approval, got %s", statusResp.Status)
	}
	if statusResp.RuleId != "manual-task" {
		t.Errorf("expected manual-task rule, got %s", statusResp.RuleId)
	}

	// 3. ApproveTask → should dispatch
	approveResp, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId:     taskID,
		ApproverId: "admin-user-001",
		Reason:     "Verified by security team",
	})
	if err != nil {
		t.Fatalf("ApproveTask error: %v", err)
	}
	if approveResp.Status != "dispatched" {
		t.Errorf("expected dispatched after approval, got %s", approveResp.Status)
	}

	// 4. GetTaskStatus → should be dispatched
	statusResp2, err := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("GetTaskStatus error: %v", err)
	}
	if statusResp2.Status != "dispatched" {
		t.Errorf("expected dispatched, got %s", statusResp2.Status)
	}
}

// E2E: 却下フロー (Ingest → blocked → RejectTask → rejected)
func TestE2E_ApprovalWorkflow_Reject(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	// 1. Ingest
	ingestResp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Data retention policy violation detected",
		Type:    "COMPLIANCE", Level: 4,
	})
	taskID := ingestResp.TasksGenerated[0].TaskId

	// 2. RejectTask
	rejectResp, err := client.RejectTask(ctx, &pb.RejectTaskRequest{
		TaskId:     taskID,
		RejectorId: "compliance-officer",
		Reason:     "False positive",
	})
	if err != nil {
		t.Fatalf("RejectTask error: %v", err)
	}
	if rejectResp.Status != "rejected" {
		t.Errorf("expected rejected, got %s", rejectResp.Status)
	}

	// 3. Verify final status
	statusResp, _ := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: taskID})
	if statusResp.Status != "rejected" {
		t.Errorf("expected rejected, got %s", statusResp.Status)
	}
}

// E2E: 二重承認の拒否
func TestE2E_ApprovalWorkflow_DoubleApprove(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	ingestResp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Data retention policy violation detected",
		Type:    "COMPLIANCE", Level: 4,
	})
	taskID := ingestResp.TasksGenerated[0].TaskId

	// First approve
	_, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "admin-1", Reason: "ok",
	})
	if err != nil {
		t.Fatalf("first approve error: %v", err)
	}

	// Second approve should fail (task no longer blocked_approval)
	_, err = client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "admin-2", Reason: "also ok",
	})
	if err == nil {
		t.Error("expected error for double approve")
	}
}

// E2E: ListTasks
func TestE2E_ListTasks(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	// Ingest multiple logs
	client.Ingest(ctx, &pb.IngestRequest{Message: "Critical 1", Level: 6, IsCritical: true})
	client.Ingest(ctx, &pb.IngestRequest{Message: "Critical 2", Level: 6, IsCritical: true})
	client.Ingest(ctx, &pb.IngestRequest{
		Message: "Compliance violation detected", Type: "COMPLIANCE", Level: 4,
	})

	// List all
	listResp, err := client.ListTasks(ctx, &pb.ListTasksRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListTasks error: %v", err)
	}
	if listResp.TotalCount < 3 {
		t.Errorf("expected at least 3 tasks, got %d", listResp.TotalCount)
	}

	// List by event
	listResp2, _ := client.ListTasks(ctx, &pb.ListTasksRequest{
		EventName: "COMPLIANCE_VIOLATION", Limit: 10,
	})
	if listResp2.TotalCount != 1 {
		t.Errorf("expected 1 compliance task, got %d", listResp2.TotalCount)
	}

	// List by status
	listResp3, _ := client.ListTasks(ctx, &pb.ListTasksRequest{
		Status: "blocked_approval", Limit: 10,
	})
	if listResp3.TotalCount < 1 {
		t.Errorf("expected at least 1 blocked task, got %d", listResp3.TotalCount)
	}
}

// E2E: GetTaskStatus not found
func TestE2E_GetTaskStatus_NotFound(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.GetTaskStatus(context.Background(), &pb.GetTaskStatusRequest{TaskId: "nonexistent"})
	if err == nil {
		t.Error("expected not found error")
	}
}

// E2E: ApproveTask validation
func TestE2E_ApproveTask_Validation(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.ApproveTask(context.Background(), &pb.ApproveTaskRequest{})
	if err == nil {
		t.Error("expected validation error for empty request")
	}
}
