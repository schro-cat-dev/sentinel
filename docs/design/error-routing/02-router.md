# ErrorRouter（ルーティング決定）設計

```yaml
status: design
layer: TS SDK → Go Server (共通インターフェース)
```

## 責務

分類済みエラー（ErrorPayloadProtocol + severity）から、送信先と対応アクションを決定する。

## 入力

```typescript
interface RoutingInput {
    payload: ErrorPayloadProtocol;
    severity: "CRITICAL" | "WARNING" | "INFO";
}
```

## 出力

```typescript
interface RoutingDecision {
    destination: RoutingDestination;
    action: RoutingAction;
    priority: number;         // 1=即座, 5=バッチ
    metadata: Record<string, string>;  // 送信先固有メタデータ
}

type RoutingDestination =
    | "task"           // タスク生成→ディスパッチ
    | "ai_agent"       // AIエージェントに回復委任
    | "notification"   // Slack/Gmail/Discord/Webhook
    | "audit_sink"     // Datadog/Sentry/CloudWatch
    | "dead_letter"    // SQS DLQ（再処理用）
    | "log"            // 構造化ログ出力のみ

type RoutingAction =
    | "escalate"       // 上位への通報
    | "auto_remediate" // 自動回復試行
    | "block"          // IPブロック等の防御アクション
    | "record"         // 記録のみ
    | "retry"          // リトライキューに投入
```

## ルーティングルール

### デフォルトルール（configでオーバーライド可能）

```typescript
const DEFAULT_ROUTING_RULES: RoutingRule[] = [
    // CRITICAL → 即座にタスク生成 + 通知 + 監査ログ
    {
        match: { severity: "CRITICAL" },
        decisions: [
            { destination: "task", action: "escalate", priority: 1 },
            { destination: "notification", action: "escalate", priority: 1 },
            { destination: "audit_sink", action: "record", priority: 1 },
        ],
    },
    // WARNING → 監査ログ + 条件付きリトライ
    {
        match: { severity: "WARNING", kind: /Transport.*/ },
        decisions: [
            { destination: "dead_letter", action: "retry", priority: 3 },
            { destination: "audit_sink", action: "record", priority: 3 },
        ],
    },
    // WARNING (handler系) → タスク生成してAI委任
    {
        match: { severity: "WARNING", kind: /Handler.*/ },
        decisions: [
            { destination: "ai_agent", action: "auto_remediate", priority: 2 },
            { destination: "audit_sink", action: "record", priority: 3 },
        ],
    },
    // INFO → ログのみ
    {
        match: { severity: "INFO" },
        decisions: [
            { destination: "log", action: "record", priority: 5 },
        ],
    },
];
```

### YAML設定（Go server）

```yaml
error_routing:
  rules:
    - match:
        severity: CRITICAL
        kind_pattern: ".*"
      decisions:
        - destination: task
          action: escalate
          priority: 1
        - destination: notification
          action: escalate
          priority: 1
          metadata:
            channel: "#incidents-critical"
        - destination: audit_sink
          action: record
          priority: 1

    - match:
        severity: WARNING
        kind_pattern: "Transport.*"
      decisions:
        - destination: dead_letter
          action: retry
          priority: 3
          metadata:
            queue: sentinel-error-retry
            max_retries: "3"
```

## ルール評価順序

1. ルールは定義順で評価
2. **最初にマッチしたルールの全decisionを実行**（first-match-wins）
3. マッチなし → デフォルト（`log` + `record`）

## セキュリティ考慮

- ルーティングルールの`kind_pattern`はRegExpだが、SDK側でReDoS検証を行う（既存のmessagePattern検証と同じパターン）
- `metadata`の値はstring限定。オブジェクト注入を防ぐ
- ルーティング先の認証情報はルールに含めない。アダプタ側のconfigで管理
