package task

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/notify"
)

// maxWebhookResponseBytes はwebhookレスポンスの読み取り上限（DoS防止）
const maxWebhookResponseBytes = 1024 * 1024 // 1MB

// PipelineKiller はKILL_SWITCHハンドラが使うインターフェース
type PipelineKiller interface {
	Kill()
	Unkill()
}

// NewEscalateHandler はESCALATEアクションのハンドラを生成する。
// タスクの通知チャネルに高優先度で通知を送信する。
func NewEscalateHandler(mn *notify.MultiNotifier) TaskHandler {
	return func(t domain.GeneratedTask) error {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("ESCALATE handler panic", "taskId", t.TaskID, "panic", r)
			}
		}()

		severity := elevatedSeverity(string(t.Severity))
		n := notify.Notification{
			Channel:   t.ExecParams.NotificationChannel,
			Subject:   fmt.Sprintf("[ESCALATION-%s] %s", t.Severity, t.EventName),
			Body:      t.Description,
			Severity:  severity,
			TraceID:   t.SourceLog.TraceID,
			EventName: t.EventName,
			Fields: map[string]string{
				"task_id": t.TaskID,
				"rule_id": t.RuleID,
				"action":  "ESCALATE",
			},
		}

		if err := mn.Send(context.Background(), n); err != nil {
			slog.Error("ESCALATE notification failed", "taskId", t.TaskID, "error", err)
			return fmt.Errorf("escalate notification: %w", err)
		}

		slog.Info("ESCALATE dispatched", "taskId", t.TaskID, "channel", n.Channel, "severity", severity)
		return nil
	}
}

// NewSystemNotificationHandler はSYSTEM_NOTIFICATIONアクションのハンドラを生成する。
func NewSystemNotificationHandler(mn *notify.MultiNotifier) TaskHandler {
	return func(t domain.GeneratedTask) error {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("SYSTEM_NOTIFICATION handler panic", "taskId", t.TaskID, "panic", r)
			}
		}()

		n := notify.Notification{
			Channel:   t.ExecParams.NotificationChannel,
			Subject:   fmt.Sprintf("[%s] %s", t.Severity, t.EventName),
			Body:      t.Description,
			Severity:  string(t.Severity),
			TraceID:   t.SourceLog.TraceID,
			EventName: t.EventName,
			Fields: map[string]string{
				"task_id": t.TaskID,
				"rule_id": t.RuleID,
				"action":  "SYSTEM_NOTIFICATION",
			},
		}

		if err := mn.Send(context.Background(), n); err != nil {
			slog.Error("SYSTEM_NOTIFICATION failed", "taskId", t.TaskID, "error", err)
			return fmt.Errorf("system notification: %w", err)
		}

		slog.Info("SYSTEM_NOTIFICATION dispatched", "taskId", t.TaskID, "channel", n.Channel)
		return nil
	}
}

// WebhookPayload はEXTERNAL_WEBHOOKが送信するJSON構造
type WebhookPayload struct {
	TaskID    string            `json:"task_id"`
	RuleID    string            `json:"rule_id"`
	EventName string            `json:"event_name"`
	Severity  string            `json:"severity"`
	ActionType string           `json:"action_type"`
	Description string          `json:"description"`
	TraceID   string            `json:"trace_id"`
	Boundary  string            `json:"boundary"`
	Timestamp string            `json:"timestamp"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// NewExternalWebhookHandler はEXTERNAL_WEBHOOKアクションのハンドラを生成する。
// タスクの targetEndpoint に JSON ペイロードを POST する。
func NewExternalWebhookHandler(client *http.Client) TaskHandler {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			// Prevent SSRF via redirect: validate each redirect target
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if err := notify.ValidateWebhookURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect blocked (SSRF prevention): %w", err)
				}
				return nil
			},
		}
	}

	return func(t domain.GeneratedTask) error {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("EXTERNAL_WEBHOOK handler panic", "taskId", t.TaskID, "panic", r)
			}
		}()

		targetURL := t.ExecParams.TargetEndpoint
		if targetURL == "" {
			return fmt.Errorf("EXTERNAL_WEBHOOK: target_endpoint is empty (task=%s)", t.TaskID)
		}

		// URL validation (SSRF prevention)
		if err := notify.ValidateWebhookURL(targetURL); err != nil {
			return fmt.Errorf("EXTERNAL_WEBHOOK: invalid URL: %w", err)
		}

		payload := WebhookPayload{
			TaskID:      t.TaskID,
			RuleID:      t.RuleID,
			EventName:   t.EventName,
			Severity:    string(t.Severity),
			ActionType:  string(t.ActionType),
			Description: t.Description,
			TraceID:     t.SourceLog.TraceID,
			Boundary:    t.SourceLog.Boundary,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("EXTERNAL_WEBHOOK: marshal payload: %w", err)
		}

		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("EXTERNAL_WEBHOOK: create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Sentinel-Server/0.3.0")

		resp, err := client.Do(req)
		if err != nil {
			slog.Error("EXTERNAL_WEBHOOK request failed", "taskId", t.TaskID, "url", targetURL, "error", err)
			return fmt.Errorf("EXTERNAL_WEBHOOK: request failed: %w", err)
		}
		defer resp.Body.Close()
		// Drain response body with size limit to prevent DoS and allow connection reuse
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookResponseBytes))

		if resp.StatusCode >= 400 {
			slog.Error("EXTERNAL_WEBHOOK bad response", "taskId", t.TaskID, "status", resp.StatusCode)
			return fmt.Errorf("EXTERNAL_WEBHOOK: server returned %d", resp.StatusCode)
		}

		slog.Info("EXTERNAL_WEBHOOK dispatched", "taskId", t.TaskID, "url", targetURL, "status", resp.StatusCode)
		return nil
	}
}

// NewKillSwitchHandler はKILL_SWITCHアクションのハンドラを生成する。
// パイプラインを停止し、autoRecoverySec 後に自動回復する（0=手動回復のみ）。
func NewKillSwitchHandler(pipeline PipelineKiller, autoRecoverySec int) TaskHandler {
	return func(t domain.GeneratedTask) error {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("KILL_SWITCH handler panic", "taskId", t.TaskID, "panic", r)
			}
		}()

		slog.Warn("KILL_SWITCH activated",
			"taskId", t.TaskID,
			"ruleId", t.RuleID,
			"traceId", t.SourceLog.TraceID,
			"autoRecoverySec", autoRecoverySec,
		)

		pipeline.Kill()

		if autoRecoverySec > 0 {
			time.AfterFunc(time.Duration(autoRecoverySec)*time.Second, func() {
				pipeline.Unkill()
				slog.Info("KILL_SWITCH auto-recovered", "taskId", t.TaskID, "afterSec", autoRecoverySec)
			})
		}

		return nil
	}
}

// elevatedSeverity は優先度を1段階引き上げる
func elevatedSeverity(severity string) string {
	switch severity {
	case "LOW", "low":
		return "medium"
	case "MEDIUM", "medium":
		return "high"
	case "HIGH", "high":
		return "critical"
	case "CRITICAL", "critical":
		return "critical" // already max
	default:
		return "high"
	}
}
