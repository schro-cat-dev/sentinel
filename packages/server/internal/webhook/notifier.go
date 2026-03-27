package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ApprovalPayload は承認リクエスト通知のペイロード
type ApprovalPayload struct {
	TaskID      string `json:"task_id"`
	RuleID      string `json:"rule_id"`
	EventName   string `json:"event_name"`
	Severity    string `json:"severity"`
	ActionType  string `json:"action_type"`
	Description string `json:"description"`
	RequestedAt string `json:"requested_at"`
	SourceLog   struct {
		TraceID  string `json:"trace_id"`
		Message  string `json:"message"`
		Boundary string `json:"boundary"`
	} `json:"source_log"`
}

// Notifier はWebhook通知クライアント
type Notifier struct {
	url        string
	httpClient *http.Client
	secret     []byte
}

// NewNotifier はNotifierを生成する
func NewNotifier(url string, timeoutSec int, secret string) *Notifier {
	return &Notifier{
		url: url,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
		secret: []byte(secret),
	}
}

// NotifyApprovalRequired は承認リクエストをWebhookで通知する（非ブロッキング）
func (n *Notifier) NotifyApprovalRequired(ctx context.Context, payload ApprovalPayload) {
	go func() {
		if err := n.send(payload); err != nil {
			slog.Error("webhook notification failed",
				"taskId", payload.TaskID,
				"error", err.Error(),
			)
		} else {
			slog.Info("webhook notification sent",
				"taskId", payload.TaskID,
				"url", n.url,
			)
		}
	}()
}

func (n *Notifier) send(payload ApprovalPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// HMAC署名
	if len(n.secret) > 0 {
		mac := hmac.New(sha256.New, n.secret)
		mac.Write(body)
		sig := fmt.Sprintf("%x", mac.Sum(nil))
		req.Header.Set("X-Sentinel-Signature", sig)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
