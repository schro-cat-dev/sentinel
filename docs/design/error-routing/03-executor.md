# ErrorExecutor（実行層）設計

```yaml
status: implemented
layer: TS SDK (インターフェース) + Go Server (実装)
```

## 責務

RoutingDecisionを受け取り、各送信先アダプタに委任して実行する。

## アダプタインターフェース

```typescript
// TS SDK側: ユーザーが実装を注入するインターフェース
interface AuditSink {
    send(payload: ErrorPayloadProtocol): Promise<void>;
}

interface DeadLetterQueue {
    enqueue(payload: ErrorPayloadProtocol, metadata: Record<string, string>): Promise<void>;
}
```

```go
// Go Server側: 実装アダプタ
type AuditSink interface {
    Send(ctx context.Context, payload ErrorPayload) error
}

type DeadLetterQueue interface {
    Enqueue(ctx context.Context, payload ErrorPayload, metadata map[string]string) error
}
```

## アダプタ実装（Go Server）

### 外部サービスアダプタ

| アダプタ | 送信先 | 設定 | フォールバック |
|---------|--------|------|--------------|
| DatadogSink | Datadog Events API | API key + site | ログ出力 |
| SentrySink | Sentry SDK | DSN | ログ出力 |
| CloudWatchSink | CloudWatch Logs | AWS credentials + log group | ログ出力 |
| SQSDeadLetter | SQS Queue | Queue URL + credentials | ローカルファイル |
| LocalFileSink | ローカルJSONLファイル | ファイルパス | stderr |

### アダプタ選択（config）

```yaml
error_routing:
  sinks:
    audit:
      type: datadog           # datadog / sentry / cloudwatch / local_file
      config:
        api_key: ${SENTINEL_DATADOG_API_KEY}
        site: datadoghq.com
    dead_letter:
      type: sqs               # sqs / local_file
      config:
        queue_url: ${SENTINEL_DLQ_URL}
        region: ap-northeast-1
```

## 実行フロー

```
RoutingDecision[]
  │
  ├─→ destination="task"
  │     └─→ TaskGenerator.generate() に ErrorPayloadProtocol をイベントとして渡す
  │         └─→ eventName: "ERROR_ESCALATION"（新規SystemEventName候補）
  │
  ├─→ destination="ai_agent"
  │     └─→ Go server agent.Execute() にエラーコンテキストを渡す
  │         └─→ AIがエラー分析→回復アクション提案→承認フロー
  │
  ├─→ destination="notification"
  │     └─→ 既存 MultiNotifier.Send() を再利用
  │         └─→ metadata.channel でルーティング
  │
  ├─→ destination="audit_sink"
  │     └─→ AuditSink.send() → Datadog/Sentry/CloudWatch
  │
  ├─→ destination="dead_letter"
  │     └─→ DeadLetterQueue.enqueue() → SQS/ローカルファイル
  │
  └─→ destination="log"
        └─→ serializeForAudit() → logger.error()
```

## エラーハンドリング（Executor自身のエラー）

```
Executor.execute(decision)
  ├─→ try: adapter.send(payload)
  ├─→ catch:
  │     ├─→ フォールバックアダプタがあれば試行
  │     ├─→ フォールバックも失敗 → console.error（最終手段）
  │     └─→ **再帰しない**: Executor自身のエラーはErrorRouterに戻さない
  └─→ return: ExecutionResult { success, fallbackUsed, error? }
```

**無限ループ防止の保証:**
- ErrorRouter → Executor → アダプタ → エラー → **console.error で停止**
- Executor のエラーを ErrorRouter に再投入しない（明示的な設計制約）
- `maxRoutingDepth = 1` をハードコード（設定不可）
