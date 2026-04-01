# Go Server 追加脆弱性診断 (v2) — 発見・チェック項目・対策

**診断日**: 2026-04-02
**前提**: docs/security-audit/server/ の初回診断を踏まえた深堀り

---

## HIGH 優先度

### V-7: RejectBlock/RejectTask 認可チェック欠如

**影響**: 認証済みの低権限クライアントが承認リクエストを拒否でき、セキュリティ運用を妨害可能

**修正**:
```go
// RejectBlock に追加
if s.authorizer != nil {
    clientID := ClientIDFromContext(ctx)
    if !s.authorizer.CanApprove(clientID) {
        return nil, status.Error(codes.PermissionDenied, "insufficient permission: CanApprove required")
    }
}

// RejectTask に追加（同様）
```

### V-8: ListTasks 認可チェック欠如

**影響**: 全タスク情報への不正アクセス

**修正**: `CanRead` 権限チェック + `AllowedLogTypes` によるフィルタリング

### V-10: GetThreatResponses 認可チェック欠如

**影響**: 脅威レスポンスの機密情報漏洩

**修正**: `CanRead` 権限チェック追加

---

## MEDIUM 優先度

### V-9: GetTaskStatus 認可チェック欠如

**修正**: `CanRead` 権限チェック追加

### V-11: LoopDepth クライアント偽装

**修正**: サーバ側で origin != AI_AGENT のログは LoopDepth を 0 にリセット

### V-17: Approve/Reject レース条件

**修正**: GetApprovalByTaskID をトランザクション内に移動

### V-19: RejectBlock の content_hash 検証欠如

**修正**: ApproveBlock と同等の content_hash 検証を追加

### V-15: Slack マークダウンインジェクション

**修正**: `<`, `>`, `@`, `#` をエスケープ

---

## LOW 優先度

### V-18: ListTasks フィルタ文字列長制限

**修正**: EventName, Status に maxLength 検証追加

### V-21: 時刻パースエラーのサイレント無視

**修正**: `InvalidArgument` エラーを返却

### V-22: Status フィールド enum バリデーション

**修正**: ホワイトリスト検証追加
