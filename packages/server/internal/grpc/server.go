package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
	"github.com/schro-cat-dev/sentinel-server/internal/response"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/internal/webhook"
)

const version = "0.3.0"

type SentinelServer struct {
	pb.UnimplementedSentinelServiceServer
	pipeline       *engine.Pipeline
	store          store.Store
	executor       *task.TaskExecutor
	blockDispatcher *response.EnhancedBlockDispatcher
}

func NewSentinelServer(cfg engine.PipelineConfig, executor *task.TaskExecutor, st store.Store, notifier *webhook.Notifier) (*SentinelServer, error) {
	p, err := engine.NewPipeline(cfg, executor, st, notifier)
	if err != nil {
		return nil, fmt.Errorf("pipeline init: %w", err)
	}
	return &SentinelServer{pipeline: p, store: st, executor: executor}, nil
}

// Pipeline はPipelineへの参照を返す（post-init設定用: SetAgentBridge, SetThreatOrchestrator）
func (s *SentinelServer) Pipeline() *engine.Pipeline {
	return s.pipeline
}

// SetBlockDispatcher はブロック承認用のEnhancedBlockDispatcherを設定する
func (s *SentinelServer) SetBlockDispatcher(d *response.EnhancedBlockDispatcher) {
	s.blockDispatcher = d
}

// --- ListPendingBlocks ---

func (s *SentinelServer) ListPendingBlocks(ctx context.Context, req *pb.ListPendingBlocksRequest) (*pb.ListPendingBlocksResponse, error) {
	if s.blockDispatcher == nil {
		return &pb.ListPendingBlocksResponse{}, nil
	}
	resp := &pb.ListPendingBlocksResponse{}
	// in-memoryのpendingBlocksを列挙
	// EnhancedBlockDispatcherにListPending()を追加する必要がある
	return resp, nil
}

// --- ApproveBlock ---

func (s *SentinelServer) ApproveBlock(ctx context.Context, req *pb.ApproveBlockRequest) (*pb.ApproveBlockResponse, error) {
	if req.BlockId == "" || req.ApproverId == "" {
		return nil, status.Error(codes.InvalidArgument, "block_id and approver_id are required")
	}
	if s.blockDispatcher == nil {
		return nil, status.Error(codes.FailedPrecondition, "block dispatcher not configured")
	}

	result, err := s.blockDispatcher.ApproveBlock(ctx, req.BlockId, req.ApproverId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &pb.ApproveBlockResponse{
		BlockId: req.BlockId,
		Success: result.Success,
		Target:  result.Target,
		Error:   result.Error,
	}, nil
}

// --- RejectBlock ---

func (s *SentinelServer) RejectBlock(ctx context.Context, req *pb.RejectBlockRequest) (*pb.RejectBlockResponse, error) {
	if req.BlockId == "" || req.RejectorId == "" {
		return nil, status.Error(codes.InvalidArgument, "block_id and rejector_id are required")
	}
	if s.blockDispatcher == nil {
		return nil, status.Error(codes.FailedPrecondition, "block dispatcher not configured")
	}

	if err := s.blockDispatcher.RejectBlock(ctx, req.BlockId, req.RejectorId); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &pb.RejectBlockResponse{
		BlockId: req.BlockId,
		Status:  "rejected",
	}, nil
}

// --- Ingest ---

func (s *SentinelServer) Ingest(ctx context.Context, req *pb.IngestRequest) (*pb.IngestResponse, error) {
	if req.Message == "" {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}

	logEntry := protoToLog(req)
	result, err := s.pipeline.Process(ctx, logEntry)
	if err != nil {
		slog.Error("pipeline error", "traceId", logEntry.TraceID, "error", err.Error())
		return nil, status.Error(codes.Internal, "internal processing error")
	}

	resp := &pb.IngestResponse{
		TraceId:        result.TraceID,
		HashChainValid: result.HashChainValid,
		Masked:         result.Masked,
	}
	for _, tr := range result.TasksGenerated {
		resp.TasksGenerated = append(resp.TasksGenerated, taskResultToProto(tr))
	}

	for _, tr := range result.ThreatResponses {
		resp.ThreatResponses = append(resp.ThreatResponses, &pb.ThreatResponseSummary{
			ResponseId:  tr.ResponseID,
			EventName:   string(tr.EventName),
			Strategy:    tr.Strategy,
			Blocked:     tr.Blocked,
			BlockTarget: tr.BlockTarget,
			Analyzed:    tr.Analyzed,
			RiskLevel:   tr.RiskLevel,
			Notified:    tr.Notified,
		})
	}

	return resp, nil
}

// --- HealthCheck ---

func (s *SentinelServer) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: "SERVING", Version: version}, nil
}

// --- GetTaskStatus ---

func (s *SentinelServer) GetTaskStatus(ctx context.Context, req *pb.GetTaskStatusRequest) (*pb.GetTaskStatusResponse, error) {
	if req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	t, err := s.store.GetTask(ctx, req.TaskId)
	if err != nil {
		slog.Error("get task error", "taskId", req.TaskId, "error", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if t == nil {
		return nil, status.Error(codes.NotFound, "task not found")
	}

	return storedTaskToProto(t), nil
}

// --- ListTasks ---

func (s *SentinelServer) ListTasks(ctx context.Context, req *pb.ListTasksRequest) (*pb.ListTasksResponse, error) {
	filter := store.TaskFilter{
		EventName: req.EventName,
		Status:    req.Status,
		Limit:     int(req.Limit),
		Offset:    int(req.Offset),
	}
	if req.FromTime != "" {
		t, err := time.Parse(time.RFC3339, req.FromTime)
		if err == nil {
			filter.FromTime = &t
		}
	}
	if req.ToTime != "" {
		t, err := time.Parse(time.RFC3339, req.ToTime)
		if err == nil {
			filter.ToTime = &t
		}
	}

	tasks, total, err := s.store.ListTasks(ctx, filter)
	if err != nil {
		slog.Error("list tasks error", "error", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	resp := &pb.ListTasksResponse{TotalCount: int32(total)}
	for _, t := range tasks {
		resp.Tasks = append(resp.Tasks, storedTaskToProto(&t))
	}
	return resp, nil
}

// --- ApproveTask ---

func (s *SentinelServer) ApproveTask(ctx context.Context, req *pb.ApproveTaskRequest) (*pb.ApproveTaskResponse, error) {
	if req.TaskId == "" || req.ApproverId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and approver_id are required")
	}

	// Get task
	t, err := s.store.GetTask(ctx, req.TaskId)
	if err != nil || t == nil {
		return nil, status.Error(codes.NotFound, "task not found")
	}
	if t.Status != domain.StatusBlockedApproval {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("task status is %s, expected blocked_approval", t.Status))
	}

	// Get approval
	approval, err := s.store.GetApprovalByTaskID(ctx, req.TaskId)
	if err != nil || approval == nil {
		return nil, status.Error(codes.NotFound, "approval request not found")
	}
	if approval.Status != "pending" && approval.Status != "in_review" {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("approval status is %s", approval.Status))
	}

	// Content hash verification: タスク内容が承認作成時から改ざんされていないか
	if approval.ContentHash != "" {
		currentHash := domain.ComputeTaskContentHash(domain.GeneratedTask{
			TaskID: t.TaskID, RuleID: t.RuleID, EventName: t.EventName,
			Severity: t.Severity, ActionType: t.ActionType,
			ExecutionLevel: t.ExecutionLevel, Description: t.Description,
			ExecParams: t.ExecParams, SourceLog: t.SourceLog,
		})
		if currentHash != approval.ContentHash {
			slog.Error("content hash mismatch", "taskId", req.TaskId,
				"expected", approval.ContentHash, "actual", currentHash)
			return nil, status.Error(codes.FailedPrecondition, "task content has been tampered with since approval was created")
		}
	}

	// Record this approval step (append-only audit trail)
	stepRecord := domain.ApprovalStepRecord{
		ApprovalID:  approval.ApprovalID,
		StepOrder:   approval.CurrentStep,
		Action:      "approved",
		ActorID:     req.ApproverId,
		ActorRole:   req.Reason, // reason doubles as role context for now
		Reason:      req.Reason,
		ContentHash: approval.ContentHash,
		CreatedAt:   time.Now().UTC(),
	}
	s.store.InsertApprovalStepRecord(ctx, stepRecord)

	// Multi-step: check if more steps remain
	if approval.CurrentStep < approval.TotalSteps {
		// Advance to next step
		nextStep := approval.CurrentStep + 1
		s.store.UpdateApprovalStep(ctx, approval.ApprovalID, nextStep, "in_review")
		s.store.UpdateTaskStatus(ctx, req.TaskId, domain.StatusBlockedApproval, "")

		return &pb.ApproveTaskResponse{
			TaskId: req.TaskId,
			Status: fmt.Sprintf("step_%d_of_%d_approved", approval.CurrentStep, approval.TotalSteps),
		}, nil
	}

	// All steps complete → resolve approval and execute
	if err := s.store.ResolveApproval(ctx, approval.ApprovalID, "approved", req.ApproverId, req.Reason); err != nil {
		slog.Error("resolve approval error", "error", err)
		return nil, status.Error(codes.Internal, "failed to resolve approval")
	}

	s.store.UpdateTaskStatus(ctx, req.TaskId, domain.StatusApproved, "")

	// Execute the task
	dispatchResult := s.executor.Dispatch(domain.GeneratedTask{
		TaskID: t.TaskID, RuleID: t.RuleID, EventName: t.EventName,
		Severity: t.Severity, ActionType: t.ActionType,
		ExecutionLevel: t.ExecutionLevel, Priority: t.Priority,
		Description: t.Description, ExecParams: t.ExecParams,
		Guardrails: domain.Guardrails{}, SourceLog: t.SourceLog, CreatedAt: t.CreatedAt,
	})

	finalStatus := domain.StatusDispatched
	errMsg := ""
	if dispatchResult.Status == domain.StatusFailed {
		finalStatus = domain.StatusFailed
		errMsg = dispatchResult.Error
	}
	s.store.UpdateTaskStatus(ctx, req.TaskId, finalStatus, errMsg)
	s.store.InsertTaskResult(ctx, dispatchResult)

	return &pb.ApproveTaskResponse{
		TaskId:       req.TaskId,
		Status:       string(finalStatus),
		DispatchedAt: dispatchResult.DispatchedAt.Format(time.RFC3339),
		Error:        errMsg,
	}, nil
}

// --- RejectTask ---

func (s *SentinelServer) RejectTask(ctx context.Context, req *pb.RejectTaskRequest) (*pb.RejectTaskResponse, error) {
	if req.TaskId == "" || req.RejectorId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and rejector_id are required")
	}

	t, err := s.store.GetTask(ctx, req.TaskId)
	if err != nil || t == nil {
		return nil, status.Error(codes.NotFound, "task not found")
	}
	if t.Status != domain.StatusBlockedApproval {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("task status is %s, expected blocked_approval", t.Status))
	}

	approval, err := s.store.GetApprovalByTaskID(ctx, req.TaskId)
	if err != nil || approval == nil {
		return nil, status.Error(codes.NotFound, "approval request not found")
	}

	// Record rejection step (audit trail)
	s.store.InsertApprovalStepRecord(ctx, domain.ApprovalStepRecord{
		ApprovalID:  approval.ApprovalID,
		StepOrder:   approval.CurrentStep,
		Action:      "rejected",
		ActorID:     req.RejectorId,
		Reason:      req.Reason,
		ContentHash: approval.ContentHash,
		CreatedAt:   time.Now().UTC(),
	})

	if err := s.store.ResolveApproval(ctx, approval.ApprovalID, "rejected", req.RejectorId, req.Reason); err != nil {
		return nil, status.Error(codes.Internal, "failed to resolve approval")
	}

	s.store.UpdateTaskStatus(ctx, req.TaskId, domain.StatusRejected, "")

	return &pb.RejectTaskResponse{
		TaskId: req.TaskId,
		Status: string(domain.StatusRejected),
	}, nil
}

// --- StartServer ---

func StartServer(addr string, cfg engine.PipelineConfig, executor *task.TaskExecutor, st store.Store, notifier *webhook.Notifier, opts ...ggrpc.ServerOption) (*ggrpc.Server, net.Listener, error) {
	_, srv, lis, err := StartServerWithSentinel(addr, cfg, executor, st, notifier, opts...)
	return srv, lis, err
}

// StartServerWithSentinel はStartServerと同じだが、SentinelServerも返す（post-init設定用）
func StartServerWithSentinel(addr string, cfg engine.PipelineConfig, executor *task.TaskExecutor, st store.Store, notifier *webhook.Notifier, opts ...ggrpc.ServerOption) (*SentinelServer, *ggrpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	defaultOpts := []ggrpc.ServerOption{
		ggrpc.MaxRecvMsgSize(1024 * 1024),
		ggrpc.MaxSendMsgSize(1024 * 1024),
		ggrpc.MaxConcurrentStreams(1000),
	}
	allOpts := append(defaultOpts, opts...)
	srv := ggrpc.NewServer(allOpts...)

	sentinel, err := NewSentinelServer(cfg, executor, st, notifier)
	if err != nil {
		lis.Close()
		return nil, nil, nil, fmt.Errorf("server init: %w", err)
	}
	pb.RegisterSentinelServiceServer(srv, sentinel)
	return sentinel, srv, lis, nil
}

// --- Proto conversion helpers ---

func protoToLog(req *pb.IngestRequest) domain.Log {
	logEntry := domain.Log{
		TraceID: req.TraceId, Type: domain.LogType(req.Type), Level: domain.LogLevel(req.Level),
		Boundary: req.Boundary, ServiceID: req.ServiceId, IsCritical: req.IsCritical,
		Message: req.Message, Origin: domain.Origin(req.Origin),
		ActorID: req.ActorId, SpanID: req.SpanId, ParentSpanID: req.ParentSpanId,
		ResourceIDs: req.ResourceIds, Input: req.Input, TriggerAgent: req.TriggerAgent,
	}
	for _, tag := range req.Tags {
		logEntry.Tags = append(logEntry.Tags, domain.LogTag{Key: tag.Key, Category: tag.Category})
	}
	if req.AiContext != nil {
		logEntry.AIContext = &domain.AIContext{
			AgentID: req.AiContext.AgentId, TaskID: req.AiContext.TaskId,
			LoopDepth: int(req.AiContext.LoopDepth), Model: req.AiContext.Model,
			Confidence: req.AiContext.Confidence, ReasoningTrace: req.AiContext.ReasoningTrace,
		}
	}
	for _, entry := range req.AgentBackLog {
		ts, _ := time.Parse(time.RFC3339, entry.Timestamp)
		logEntry.AgentBackLog = append(logEntry.AgentBackLog, domain.AgentBackLogEntry{
			AgentID: entry.AgentId, Action: entry.Action, Timestamp: ts,
			Result: entry.Result, Status: entry.Status,
		})
	}
	if req.Details != nil {
		logEntry.Details = req.Details
	}
	return logEntry
}

func taskResultToProto(tr domain.TaskResult) *pb.TaskResult {
	return &pb.TaskResult{
		TaskId: tr.TaskID, RuleId: tr.RuleID, Status: string(tr.Status),
		DispatchedAt: tr.DispatchedAt.Format(time.RFC3339), Error: tr.Error,
	}
}

func storedTaskToProto(t *domain.StoredTask) *pb.GetTaskStatusResponse {
	return &pb.GetTaskStatusResponse{
		TaskId: t.TaskID, RuleId: t.RuleID, EventName: t.EventName,
		Status: string(t.Status), ActionType: string(t.ActionType),
		Severity: string(t.Severity), ExecutionLevel: string(t.ExecutionLevel),
		Description: t.Description, SourceTraceId: t.SourceLog.TraceID,
		CreatedAt: t.CreatedAt.Format(time.RFC3339), UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
		ErrorMessage: t.ErrorMessage,
	}
}
