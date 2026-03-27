package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

const schema = `
CREATE TABLE IF NOT EXISTS logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_id TEXT UNIQUE NOT NULL,
	type TEXT NOT NULL,
	level INTEGER NOT NULL,
	timestamp TEXT NOT NULL,
	boundary TEXT,
	service_id TEXT,
	origin TEXT,
	is_critical BOOLEAN,
	message TEXT NOT NULL,
	actor_id TEXT,
	span_id TEXT,
	parent_span_id TEXT,
	tags_json TEXT,
	resource_ids_json TEXT,
	previous_hash TEXT,
	hash TEXT,
	ai_context_json TEXT,
	input TEXT,
	trigger_agent BOOLEAN,
	details_json TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tasks (
	task_id TEXT PRIMARY KEY,
	rule_id TEXT NOT NULL,
	event_name TEXT NOT NULL,
	severity TEXT NOT NULL,
	action_type TEXT NOT NULL,
	execution_level TEXT NOT NULL,
	priority INTEGER,
	description TEXT,
	exec_params_json TEXT,
	guardrails_json TEXT,
	source_trace_id TEXT NOT NULL,
	source_message TEXT,
	source_boundary TEXT,
	source_level INTEGER,
	source_timestamp TEXT,
	status TEXT NOT NULL DEFAULT 'pending',
	error_message TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
	approval_id TEXT PRIMARY KEY,
	task_id TEXT NOT NULL UNIQUE,
	requested_at TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	content_hash TEXT NOT NULL,
	current_step INTEGER NOT NULL DEFAULT 1,
	total_steps INTEGER NOT NULL DEFAULT 1,
	resolved_at TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS approval_step_records (
	record_id TEXT PRIMARY KEY,
	approval_id TEXT NOT NULL,
	step_order INTEGER NOT NULL,
	action TEXT NOT NULL,
	actor_id TEXT NOT NULL,
	actor_role TEXT,
	reason TEXT,
	content_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_modifications (
	modification_id TEXT PRIMARY KEY,
	task_id TEXT NOT NULL,
	modified_by TEXT NOT NULL,
	field TEXT NOT NULL,
	old_value TEXT,
	new_value TEXT,
	content_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id TEXT NOT NULL,
	status TEXT NOT NULL,
	dispatched_at TEXT NOT NULL,
	error TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS threat_responses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	response_id TEXT UNIQUE NOT NULL,
	trace_id TEXT NOT NULL,
	event_name TEXT NOT NULL,
	strategy TEXT NOT NULL,
	target_ip TEXT,
	target_user_id TEXT,
	boundary TEXT,
	block_action TEXT,
	block_success BOOLEAN,
	block_target TEXT,
	analyzed BOOLEAN,
	risk_level TEXT,
	confidence REAL,
	analysis_summary TEXT,
	notified BOOLEAN,
	notify_target TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_tasks_event ON tasks(event_name);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at);
CREATE INDEX IF NOT EXISTS idx_logs_trace ON logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_step_records_approval ON approval_step_records(approval_id);
CREATE INDEX IF NOT EXISTS idx_modifications_task ON task_modifications(task_id);
CREATE TABLE IF NOT EXISTS pending_blocks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	block_id TEXT UNIQUE NOT NULL,
	action_type TEXT NOT NULL,
	target_ip TEXT,
	target_user_id TEXT,
	boundary TEXT,
	reason TEXT,
	status TEXT NOT NULL DEFAULT 'pending',
	resolved_by TEXT,
	resolved_at TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threat_responses_trace ON threat_responses(trace_id);
CREATE INDEX IF NOT EXISTS idx_pending_blocks_status ON pending_blocks(status);
`

type SQLiteStore struct {
	db *sql.DB
}

// WithTx はトランザクション内で複数操作を原子的に実行する
func (s *SQLiteStore) WithTx(ctx context.Context, fn func(tx interface{}) error) error {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(sqlTx); err != nil {
		if rbErr := sqlTx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed (%v) after: %w", rbErr, err)
		}
		return err
	}
	return sqlTx.Commit()
}

func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// === Logs ===

func (s *SQLiteStore) InsertLog(ctx context.Context, log domain.Log) (int64, error) {
	tagsJSON, _ := json.Marshal(log.Tags)
	ridsJSON, _ := json.Marshal(log.ResourceIDs)
	aiJSON, _ := json.Marshal(log.AIContext)
	detailsJSON, _ := json.Marshal(log.Details)

	result, err := s.db.ExecContext(ctx,
		`INSERT INTO logs (trace_id, type, level, timestamp, boundary, service_id, origin, is_critical, message, actor_id, span_id, parent_span_id, tags_json, resource_ids_json, previous_hash, hash, ai_context_json, input, trigger_agent, details_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.TraceID, string(log.Type), int(log.Level), log.Timestamp.Format(time.RFC3339Nano),
		log.Boundary, log.ServiceID, string(log.Origin), log.IsCritical, log.Message,
		log.ActorID, log.SpanID, log.ParentSpanID,
		string(tagsJSON), string(ridsJSON), log.PreviousHash, log.Hash,
		string(aiJSON), log.Input, log.TriggerAgent, string(detailsJSON),
	)
	if err != nil {
		return 0, fmt.Errorf("insert log: %w", err)
	}
	return result.LastInsertId()
}

func (s *SQLiteStore) GetLogByTraceID(ctx context.Context, traceID string) (*domain.Log, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT trace_id, type, level, timestamp, boundary, service_id, origin, is_critical, message, actor_id, span_id, parent_span_id, tags_json, resource_ids_json, previous_hash, hash, ai_context_json, input, trigger_agent, details_json
		 FROM logs WHERE trace_id = ?`, traceID)

	var log domain.Log
	var typ, ts, origin string
	var level int
	var tagsJSON, ridsJSON, aiJSON, detailsJSON sql.NullString

	err := row.Scan(
		&log.TraceID, &typ, &level, &ts, &log.Boundary, &log.ServiceID,
		&origin, &log.IsCritical, &log.Message, &log.ActorID, &log.SpanID, &log.ParentSpanID,
		&tagsJSON, &ridsJSON, &log.PreviousHash, &log.Hash,
		&aiJSON, &log.Input, &log.TriggerAgent, &detailsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get log: %w", err)
	}

	log.Type = domain.LogType(typ)
	log.Level = domain.LogLevel(level)
	log.Origin = domain.Origin(origin)
	log.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	if tagsJSON.Valid { json.Unmarshal([]byte(tagsJSON.String), &log.Tags) }
	if ridsJSON.Valid { json.Unmarshal([]byte(ridsJSON.String), &log.ResourceIDs) }
	if aiJSON.Valid { json.Unmarshal([]byte(aiJSON.String), &log.AIContext) }
	if detailsJSON.Valid { json.Unmarshal([]byte(detailsJSON.String), &log.Details) }

	return &log, nil
}

// === Tasks ===

func (s *SQLiteStore) InsertTask(ctx context.Context, task domain.GeneratedTask, status domain.TaskDispatchStatus) error {
	epJSON, _ := json.Marshal(task.ExecParams)
	grJSON, _ := json.Marshal(task.Guardrails)
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tasks (task_id, rule_id, event_name, severity, action_type, execution_level, priority, description, exec_params_json, guardrails_json, source_trace_id, source_message, source_boundary, source_level, source_timestamp, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		task.TaskID, task.RuleID, task.EventName, string(task.Severity),
		string(task.ActionType), string(task.ExecutionLevel), int(task.Priority),
		task.Description, string(epJSON), string(grJSON),
		task.SourceLog.TraceID, task.SourceLog.Message, task.SourceLog.Boundary,
		int(task.SourceLog.Level), task.SourceLog.Timestamp.Format(time.RFC3339),
		string(status), now, now,
	)
	return err
}

func (s *SQLiteStore) GetTask(ctx context.Context, taskID string) (*domain.StoredTask, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT task_id, rule_id, event_name, severity, action_type, execution_level, priority, description, source_trace_id, source_message, source_boundary, source_level, source_timestamp, status, error_message, created_at, updated_at
		 FROM tasks WHERE task_id = ?`, taskID)

	var st domain.StoredTask
	var sev, act, el, srcTS, createdAt, updatedAt, status string
	var pri, srcLevel int
	var errMsg sql.NullString

	err := row.Scan(
		&st.TaskID, &st.RuleID, &st.EventName, &sev, &act, &el, &pri,
		&st.Description, &st.SourceLog.TraceID, &st.SourceLog.Message,
		&st.SourceLog.Boundary, &srcLevel, &srcTS, &status, &errMsg, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows { return nil, nil }
	if err != nil { return nil, fmt.Errorf("get task: %w", err) }

	st.Severity = domain.TaskSeverity(sev)
	st.ActionType = domain.TaskActionType(act)
	st.ExecutionLevel = domain.TaskExecutionLevel(el)
	st.Priority = domain.TaskPriority(pri)
	st.SourceLog.Level = domain.LogLevel(srcLevel)
	st.SourceLog.Timestamp, _ = time.Parse(time.RFC3339, srcTS)
	st.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	st.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	st.Status = domain.TaskDispatchStatus(status)
	if errMsg.Valid { st.ErrorMessage = errMsg.String }

	return &st, nil
}

func (s *SQLiteStore) ListTasks(ctx context.Context, filter TaskFilter) ([]domain.StoredTask, int, error) {
	where := "1=1"
	args := []any{}
	if filter.EventName != "" { where += " AND event_name = ?"; args = append(args, filter.EventName) }
	if filter.Status != "" { where += " AND status = ?"; args = append(args, filter.Status) }
	if filter.FromTime != nil { where += " AND created_at >= ?"; args = append(args, filter.FromTime.Format(time.RFC3339)) }
	if filter.ToTime != nil { where += " AND created_at <= ?"; args = append(args, filter.ToTime.Format(time.RFC3339)) }

	var total int
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE "+where, args...).Scan(&total)

	limit := filter.Limit
	if limit <= 0 { limit = 50 }
	query := fmt.Sprintf("SELECT task_id, rule_id, event_name, severity, action_type, execution_level, priority, description, source_trace_id, status, error_message, created_at, updated_at FROM tasks WHERE %s ORDER BY created_at DESC LIMIT ? OFFSET ?", where)
	args = append(args, limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil { return nil, 0, fmt.Errorf("list tasks: %w", err) }
	defer rows.Close()

	var tasks []domain.StoredTask
	for rows.Next() {
		var st domain.StoredTask
		var sev, act, el, status, createdAt, updatedAt string
		var pri int
		var errMsg sql.NullString
		if err := rows.Scan(&st.TaskID, &st.RuleID, &st.EventName, &sev, &act, &el, &pri, &st.Description, &st.SourceLog.TraceID, &status, &errMsg, &createdAt, &updatedAt); err != nil {
			return nil, 0, err
		}
		st.Severity = domain.TaskSeverity(sev)
		st.ActionType = domain.TaskActionType(act)
		st.ExecutionLevel = domain.TaskExecutionLevel(el)
		st.Priority = domain.TaskPriority(pri)
		st.Status = domain.TaskDispatchStatus(status)
		st.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		st.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		if errMsg.Valid { st.ErrorMessage = errMsg.String }
		tasks = append(tasks, st)
	}
	return tasks, total, nil
}

func (s *SQLiteStore) UpdateTaskStatus(ctx context.Context, taskID string, status domain.TaskDispatchStatus, errMsg string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `UPDATE tasks SET status = ?, error_message = ?, updated_at = ? WHERE task_id = ?`,
		string(status), errMsg, now, taskID)
	return err
}

// === Approvals (multi-step) ===

func (s *SQLiteStore) InsertApproval(ctx context.Context, approval domain.ApprovalRequest) error {
	if approval.ApprovalID == "" { approval.ApprovalID = uuid.New().String() }
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approval_requests (approval_id, task_id, requested_at, status, content_hash, current_step, total_steps)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		approval.ApprovalID, approval.TaskID, approval.RequestedAt.Format(time.RFC3339),
		approval.Status, approval.ContentHash, approval.CurrentStep, approval.TotalSteps,
	)
	return err
}

func (s *SQLiteStore) GetApprovalByTaskID(ctx context.Context, taskID string) (*domain.ApprovalRequest, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT approval_id, task_id, requested_at, status, content_hash, current_step, total_steps, resolved_at
		 FROM approval_requests WHERE task_id = ?`, taskID)

	var ar domain.ApprovalRequest
	var requestedAt string
	var resolvedAt sql.NullString

	err := row.Scan(&ar.ApprovalID, &ar.TaskID, &requestedAt, &ar.Status,
		&ar.ContentHash, &ar.CurrentStep, &ar.TotalSteps, &resolvedAt)
	if err == sql.ErrNoRows { return nil, nil }
	if err != nil { return nil, fmt.Errorf("get approval: %w", err) }

	ar.RequestedAt, _ = time.Parse(time.RFC3339, requestedAt)
	if resolvedAt.Valid {
		t, _ := time.Parse(time.RFC3339, resolvedAt.String)
		ar.ResolvedAt = &t
	}
	return &ar, nil
}

func (s *SQLiteStore) UpdateApprovalStep(ctx context.Context, approvalID string, currentStep int, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE approval_requests SET current_step = ?, status = ? WHERE approval_id = ?`,
		currentStep, status, approvalID)
	return err
}

func (s *SQLiteStore) ResolveApproval(ctx context.Context, approvalID string, status string, resolverID string, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx,
		`UPDATE approval_requests SET status = ?, resolved_at = ? WHERE approval_id = ? AND (status = 'pending' OR status = 'in_review')`,
		status, now, approvalID)
	if err != nil { return fmt.Errorf("resolve approval: %w", err) }
	rows, _ := result.RowsAffected()
	if rows == 0 { return fmt.Errorf("approval %s is not pending/in_review or does not exist", approvalID) }
	return nil
}

// === Approval Step Records (audit trail) ===

func (s *SQLiteStore) InsertApprovalStepRecord(ctx context.Context, record domain.ApprovalStepRecord) error {
	if record.RecordID == "" { record.RecordID = uuid.New().String() }
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approval_step_records (record_id, approval_id, step_order, action, actor_id, actor_role, reason, content_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.RecordID, record.ApprovalID, record.StepOrder, record.Action,
		record.ActorID, record.ActorRole, record.Reason, record.ContentHash,
		record.CreatedAt.Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) GetApprovalStepRecords(ctx context.Context, approvalID string) ([]domain.ApprovalStepRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT record_id, approval_id, step_order, action, actor_id, actor_role, reason, content_hash, created_at
		 FROM approval_step_records WHERE approval_id = ? ORDER BY step_order, created_at`, approvalID)
	if err != nil { return nil, err }
	defer rows.Close()

	var records []domain.ApprovalStepRecord
	for rows.Next() {
		var r domain.ApprovalStepRecord
		var createdAt string
		if err := rows.Scan(&r.RecordID, &r.ApprovalID, &r.StepOrder, &r.Action,
			&r.ActorID, &r.ActorRole, &r.Reason, &r.ContentHash, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		records = append(records, r)
	}
	return records, nil
}

// === Task Modifications (audit trail) ===

func (s *SQLiteStore) InsertTaskModification(ctx context.Context, mod domain.TaskModification) error {
	if mod.ModificationID == "" { mod.ModificationID = uuid.New().String() }
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO task_modifications (modification_id, task_id, modified_by, field, old_value, new_value, content_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		mod.ModificationID, mod.TaskID, mod.ModifiedBy, mod.Field,
		mod.OldValue, mod.NewValue, mod.ContentHash, mod.CreatedAt.Format(time.RFC3339),
	)
	return err
}

func (s *SQLiteStore) GetTaskModifications(ctx context.Context, taskID string) ([]domain.TaskModification, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT modification_id, task_id, modified_by, field, old_value, new_value, content_hash, created_at
		 FROM task_modifications WHERE task_id = ? ORDER BY created_at`, taskID)
	if err != nil { return nil, err }
	defer rows.Close()

	var mods []domain.TaskModification
	for rows.Next() {
		var m domain.TaskModification
		var createdAt string
		if err := rows.Scan(&m.ModificationID, &m.TaskID, &m.ModifiedBy, &m.Field,
			&m.OldValue, &m.NewValue, &m.ContentHash, &createdAt); err != nil {
			return nil, err
		}
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		mods = append(mods, m)
	}
	return mods, nil
}

// === Task Results ===

func (s *SQLiteStore) InsertTaskResult(ctx context.Context, result domain.TaskResult) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO task_results (task_id, status, dispatched_at, error) VALUES (?, ?, ?, ?)`,
		result.TaskID, string(result.Status), result.DispatchedAt.Format(time.RFC3339), result.Error)
	return err
}

// === Threat Responses ===

func (s *SQLiteStore) InsertThreatResponse(ctx context.Context, record domain.ThreatResponseStoreRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO threat_responses (response_id, trace_id, event_name, strategy,
		 target_ip, target_user_id, boundary, block_action, block_success, block_target,
		 analyzed, risk_level, confidence, analysis_summary, notified, notify_target, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ResponseID, record.TraceID, record.EventName, record.Strategy,
		record.TargetIP, record.TargetUserID, record.Boundary,
		record.BlockAction, record.BlockSuccess, record.BlockTarget,
		record.Analyzed, record.RiskLevel, record.Confidence, record.AnalysisSummary,
		record.Notified, record.NotifyTarget, record.CreatedAt,
	)
	return err
}

// === Pending Blocks ===

func (s *SQLiteStore) SavePendingBlock(ctx context.Context, block domain.PendingBlockRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pending_blocks (block_id, action_type, target_ip, target_user_id, boundary, reason, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		block.BlockID, block.ActionType, block.TargetIP, block.TargetUserID,
		block.Boundary, block.Reason, block.Status, block.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) GetPendingBlock(ctx context.Context, blockID string) (*domain.PendingBlockRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT block_id, action_type, target_ip, target_user_id, boundary, reason, status, COALESCE(resolved_by,''), COALESCE(resolved_at,''), created_at
		 FROM pending_blocks WHERE block_id = ?`, blockID)
	var r domain.PendingBlockRecord
	if err := row.Scan(&r.BlockID, &r.ActionType, &r.TargetIP, &r.TargetUserID,
		&r.Boundary, &r.Reason, &r.Status, &r.ResolvedBy, &r.ResolvedAt, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *SQLiteStore) UpdatePendingBlock(ctx context.Context, blockID, status, resolvedBy string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE pending_blocks SET status = ?, resolved_by = ?, resolved_at = datetime('now') WHERE block_id = ?`,
		status, resolvedBy, blockID)
	return err
}

func (s *SQLiteStore) ListPendingBlocks(ctx context.Context) ([]domain.PendingBlockRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT block_id, action_type, target_ip, target_user_id, boundary, reason, status, COALESCE(resolved_by,''), COALESCE(resolved_at,''), created_at
		 FROM pending_blocks WHERE status = 'pending' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []domain.PendingBlockRecord
	for rows.Next() {
		var r domain.PendingBlockRecord
		if err := rows.Scan(&r.BlockID, &r.ActionType, &r.TargetIP, &r.TargetUserID,
			&r.Boundary, &r.Reason, &r.Status, &r.ResolvedBy, &r.ResolvedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

func (s *SQLiteStore) GetThreatResponsesByTraceID(ctx context.Context, traceID string) ([]domain.ThreatResponseStoreRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT response_id, trace_id, event_name, strategy,
		 target_ip, target_user_id, boundary, block_action, block_success, block_target,
		 analyzed, risk_level, confidence, analysis_summary, notified, notify_target, created_at
		 FROM threat_responses WHERE trace_id = ? ORDER BY created_at`,
		traceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []domain.ThreatResponseStoreRecord
	for rows.Next() {
		var r domain.ThreatResponseStoreRecord
		if err := rows.Scan(
			&r.ResponseID, &r.TraceID, &r.EventName, &r.Strategy,
			&r.TargetIP, &r.TargetUserID, &r.Boundary,
			&r.BlockAction, &r.BlockSuccess, &r.BlockTarget,
			&r.Analyzed, &r.RiskLevel, &r.Confidence, &r.AnalysisSummary,
			&r.Notified, &r.NotifyTarget, &r.CreatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}
