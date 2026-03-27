# インスタンス管理・並行処理設計

> **ステータス**: 設計ドラフト。v1ではシングルトン（TS SDK）+ goroutine-per-request（Go Server）で実装済み。
> 以下は将来のスケールアウト時に検討すべき設計方針。

---

## 1. インスタンス管理

**現在の実装**: シングルトンパターン

- **TS SDK**: `Sentinel.initialize()` → `Sentinel.getInstance()` でプロセス内で1インスタンス
- **Go Server**: Pipeline構造体がサーバ起動時に1つ生成され、全gRPCリクエストで共有

**将来拡張: 名前付きレジストリ**

1つのプロセス内で異なるセキュリティレベルのログを分離する場合：

```typescript
const sentinel = Sentinel.getInstance();              // デフォルト
const auditSentinel = Sentinel.getInstance("audit");   // 監査専用（より厳格）
```

---

## 2. 並行処理モデル

### Go Server（現在の実装）

```
gRPC goroutine-per-request
  → Pipeline.Process() は各リクエストで独立実行
  → IntegritySigner: sync.Mutex で排他制御（ハッシュチェーンの一貫性保証）
  → TaskExecutor: sync.RWMutex（ハンドラ登録=Write / ディスパッチ=Read）
  → SQLite: database/sql のコネクションプール
```

### TS SDK（現在の実装）

```
async/await ベース（シングルスレッド）
  → ingest() は同期的にパイプライン全体を実行
  → ハッシュチェーンはインメモリ（単一プロセス前提）
```

---

## 3. バックプレッシャー制御

| 機能 | 内容 |
|------|------|
| **gRPC MaxConcurrentStreams** | 1000（デフォルト）。超過時はクライアント側でブロック |
| **MaxRecvMsgSize** | 1MB。超過時はgRPCエラー |
| **Rate Limiting** | per-client token bucket（設定可能、デフォルト100 RPS） |
| **Graceful Shutdown** | SIGTERM → 30秒タイムアウト → 強制停止 |

---

## 4. 処理フロー

| フェーズ | 役割 | 実装状況 |
|---------|------|---------|
| **Ingest** | ログ受信、バリデーション | 実装済み (Normalizer) |
| **Sanitize** | PIIマスキング、ハッシュチェーン | 実装済み (MaskingService + IntegritySigner) |
| **Analyze** | イベント検知、AIループ防止 | 実装済み (EventDetector, origin=AI_AGENT スキップ) |
| **Dispatch** | タスク生成、承認フロー、ハンドラ実行 | 実装済み (TaskGenerator + TaskExecutor + ApprovalWorkflow) |
| **Persist** | ログ/タスク/承認の永続化 | 実装済み (SQLite Store) |

---

## 5. AIエージェント無限ループ防止

**実装済み**:
- `origin: AI_AGENT` のログはEventDetectorでスキップ（`isCritical`の場合を除く）
- AgentExecutor に `maxLoopDepth` 制限（デフォルト5）
- 各実行で `loopDepth` をインクリメントし、AIContextに記録
- AI実行結果は `origin: AI_AGENT` + `triggerAgent: false` で再投入

---

## 6. ロガー自体の健康診断

**現在の実装**:
- `HealthCheck` gRPC RPC（`SERVING` / `NOT_SERVING`）
- 構造化ログ（`log/slog` JSON出力）でサーバ内部状態を記録

**将来拡張**:
- Prometheus メトリクスエンドポイント
- パイプラインキュー深度の公開
- ハッシュチェーン長の監視
