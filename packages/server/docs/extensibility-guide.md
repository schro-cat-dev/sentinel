# Sentinel Server — 拡張ガイド

どこをどう拡張すればいいかの仕様書。

---

## 拡張ポイント一覧

| やりたいこと | 拡張箇所 | 方法 |
|---|---|---|
| 新しい検知ルールを追加 | `config.yaml` の `ensemble.dynamic_rules` | YAML追加のみ（コード不要） |
| 新しいPIIパターンを追加 | `security/masking.go` の `RegisterPIIPattern()` | `init()` で呼ぶ |
| 新しいブロック手段を追加 | `response/block_agent.go` の `BlockAction` I/F | 新struct実装 → `BlockDispatcher.Register()` |
| クラウド連携(AWS/GCP/Azure) | `response/block_provider.go` | `execFn` に実API呼び出しを注入 |
| 新しい通知チャネルを追加 | `notify/notifier.go` の `Notifier` I/F | 新struct実装 → `MultiNotifier.Register()` |
| AIプロバイダを変更 | `agent/provider.go` の `Provider` I/F | 新struct実装 → main.go で注入 |
| 新しいログ種別を追加 | `domain/log.go` の `ValidLogTypes` | mapに追加 + `security/sanitizer.go` の `allowedLogTypes` |
| 認可ロールを追加 | `config.yaml` の `authorization.roles` | YAML追加のみ |
| 承認チェーンをカスタマイズ | `config.yaml` の pipeline RoutingRules | コード上は `PipelineConfig.RoutingRules` で設定 |
| ストレージを変更 | `store/store.go` の `Store` I/F | PostgreSQL等の新実装 |

---

## 検知ルール追加（コード不要）

```yaml
ensemble:
  dynamic_rules:
    - rule_id: "my-custom-rule"
      event_name: "SECURITY_INTRUSION_DETECTED"   # 既存イベント名 or 新規
      priority: "HIGH"
      score: 0.9
      payload_builder: "security_intrusion"
      conditions:
        log_types: ["SECURITY"]
        min_level: 4
        message_pattern: "(?i)my-pattern"
        tag_keys: ["ip", "user_agent"]
        origins: ["SYSTEM"]
```

`conditions` の各フィールドは全てAND。空のフィールドは無条件。

---

## ブロック手段の追加

```go
// 1. BlockAction インターフェースを実装
type MyCustomBlock struct{}

func (b *MyCustomBlock) ActionType() string { return "my_block" }

func (b *MyCustomBlock) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
    // ここに実際のブロック処理
    return &BlockResult{ActionType: "my_block", Target: target.IP, Success: true}, nil
}

// 2. main.go の BlockDispatcher に登録
enhancedBlocker.Register(&MyCustomBlock{})

// 3. config.yaml でルールに指定
// response.rules[].block_action: "my_block"
```

---

## 通知チャネルの追加

```go
// 1. Notifier インターフェースを実装
type PagerDutyNotifier struct{ apiKey string }

func (p *PagerDutyNotifier) Type() string { return "pagerduty" }

func (p *PagerDutyNotifier) Send(ctx context.Context, n Notification) error {
    // PagerDuty API呼び出し
    return nil
}

// 2. main.go で MultiNotifier に登録
multiNotifier.Register(&PagerDutyNotifier{apiKey: os.Getenv("PAGERDUTY_KEY")})
multiNotifier.SetRouting("pd:", []string{"pagerduty"})

// 3. config.yaml で通知先に指定
// response.rules[].notify_targets: ["pd:my-service"]
```

---

## AIプロバイダの変更

```go
// 1. Provider インターフェースを実装
type AnthropicProvider struct{ apiKey string }

func (p *AnthropicProvider) Name() string { return "anthropic" }

func (p *AnthropicProvider) Execute(ctx context.Context, task GeneratedTask, log Log) (*InferenceResult, error) {
    // Anthropic API呼び出し
    return &InferenceResult{
        Thought: "...", Action: "block_ip", Confidence: 0.95, Model: "claude-sonnet-4-20250514",
    }, nil
}

// 2. main.go で agent.NewAgentExecutor に渡す
provider := &AnthropicProvider{apiKey: os.Getenv("ANTHROPIC_API_KEY")}
agentExec := agent.NewAgentExecutor(provider, st, agentCfg, reIngestFn)
```

---

## ストレージの変更

`store.Store` インターフェースを実装すれば PostgreSQL, MySQL, DynamoDB 等に差し替え可能:

```go
type PostgresStore struct{ db *sql.DB }

func (s *PostgresStore) InsertLog(ctx context.Context, log domain.Log) (int64, error) { ... }
func (s *PostgresStore) GetLogByTraceID(ctx context.Context, traceID string) (*domain.Log, error) { ... }
// ... 全メソッド実装

// main.go で差し替え
st, err := NewPostgresStore(cfg.Store.DSN)
```
