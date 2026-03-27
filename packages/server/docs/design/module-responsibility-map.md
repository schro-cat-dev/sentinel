# モジュール責務マップ

## パッケージ構成と責務

### internal/detection/ — 脅威検知層
| モジュール | 責務 |
|---|---|
| `detector.go` | レガシー first-match 検知器 |
| `ensemble.go` | アンサンブル検知器（全ルール評価+スコア集約+優先度解決） |
| `rules.go` | 組み込み検知ルール（Critical/Security/Compliance/SLA） |
| `dynamic_rule.go` | 設定ベース動的ルール（YAML/JSONから条件定義） |
| `anomaly.go` | 統計的異常検知（スライディングウィンドウ頻度分析） |
| `dedup.go` | 時間ウィンドウ重複抑制 |

### internal/response/ — 脅威レスポンス層
| モジュール | 責務 |
|---|---|
| `orchestrator.go` | 検知→分析→ブロック→通知の統合制御（戦略パターン） |
| `strategy.go` | レスポンス戦略定義、ThreatTarget抽出、ルールマッチング |
| `block_agent.go` | ブロック実行（IPBlockAction/AccountLockAction/MockBlockAction） |
| `block_provider.go` | 承認待ちパターン（EnhancedBlockDispatcher）、AWS/GCP/Azureアダプタ |
| `analysis_agent.go` | AI分析エージェント（AnalysisAgent I/F + Mock実装） |

### internal/notify/ — 通知アダプタ層
| モジュール | 責務 |
|---|---|
| `notifier.go` | Notifier I/F、MultiNotifier（ルーティング付き複数チャネル配信） |
| `adapters.go` | WebhookNotifier/SlackNotifier/GmailNotifier/DiscordNotifier/LogNotifier |
| `mock.go` | テスト用MockNotifier |

### internal/security/ — データ保護層
| モジュール | 責務 |
|---|---|
| `sanitizer.go` | 入力検証・ReDoS防止・ホワイトリスト検証 |
| `masking.go` | PIIマスキングサービス（REGEX/PII_TYPE/KEY_MATCH） |
| `masking_jp.go` | 日本固有PIIパターン（口座番号/郵便番号/免許証番号） |
| `masking_policy.go` | コンテキスト依存マスクポリシー（ログ種別/オリジン/レベル別） |
| `masking_verify.go` | マスク後PII残留検証（フォールバック再マスク付き） |
| `signer.go` | HMAC-SHA256ハッシュチェーン（定数時間比較、原子操作） |

### internal/middleware/ — 境界防御層
| モジュール | 責務 |
|---|---|
| `auth.go` | 認証（Static/Cached/Noop TokenValidator） |
| `authorizer.go` | RBAC認可（ロール→権限、ログ種別/レベル制限、承認/管理権限） |
| `security_config.go` | セキュリティヘッダ/CORS/ハニーポット/レート制限 |

### internal/engine/ — パイプライン統合層
| モジュール | 責務 |
|---|---|
| `pipeline.go` | ログ処理パイプライン本体（全モジュールopt-in統合） |
| `normalizer.go` | ログ正規化（検証+デフォルト値+サニタイズ） |
| `agent_bridge.go` | TaskExecutor ↔ AgentExecutor 接続（severity/actionフィルタ） |
| `routing.go` | 承認ルーティング（イベント名+レベルでチェーン選択） |

### internal/agent/ — AIエージェント実行層
| モジュール | 責務 |
|---|---|
| `provider.go` | AIプロバイダI/F（InferenceResult、ExecutionRecord） |
| `executor.go` | エージェント実行管理（ループ防止/タイムアウト/結果再投入/監査） |
| `mock_provider.go` | テスト用MockProvider |

### internal/task/ — タスク管理層
| モジュール | 責務 |
|---|---|
| `generator.go` | ルールベースタスク生成（severity分類+優先度ソート） |
| `executor.go` | タスクディスパッチ（ハンドラ呼び出し+ステータス解決） |

### internal/store/ — 永続化層
| モジュール | 責務 |
|---|---|
| `store.go` | Store I/F（Logs/Tasks/Approvals/ThreatResponses） |
| `sqlite.go` | SQLite実装（WALモード、パラメータ化クエリ） |

### internal/grpc/ — gRPCサーバ層
| モジュール | 責務 |
|---|---|
| `server.go` | SentinelService実装（Ingest/HealthCheck/Task管理/承認） |
| `interceptors.go` | 認証インターセプタ/レート制限インターセプタ |

### config/ — 設定管理
| モジュール | 責務 |
|---|---|
| `config.go` | YAML読み込み + 環境変数オーバーライド + バリデーション + デフォルト値 |

---

## データフロー

```
[Client] → gRPC
    ↓
[Interceptors] Auth(x-api-key) → RateLimit(per-client)
    ↓
[Pipeline.Process]
    ↓
[0] Authorization ── RBAC: client→role→permission→allowed?
    ↓
[1] Normalize ────── validate, defaults, sanitize, limits
    ↓
[2] Mask PII ─────── PolicyEngine(log type別ルール選択) or default masking
    ↓
[2b] Verify ──────── PII残留検査 → preserve-aware fallback re-mask
    ↓
[3] Hash-chain ───── HMAC-SHA256(log + previousHash) atomic
    ↓
[4] Persist ──────── store.InsertLog (SQLite WAL)
    ↓
[5] Detect ───────── EnsembleDetector(全ルール+動的ルール+スコア集約+閾値判定)
                      or レガシーDetector(first-match)
    ↓
[5b] Anomaly ─────── FrequencyTracker → baseline比較 → 乖離率判定
    ↓
[5c] ThreatResponse ─ Orchestrator: strategy based
                       ├── Analyze(AI) → AnalysisResult
                       ├── Block(IP/Account/AWS/GCP/Azure) → BlockResult
                       ├── Persist(ThreatResponseRecord)
                       └── Notify(Slack/Gmail/Discord/Webhook)
    ↓
[6] TaskGenerate ──── ルールマッチ → severity分類 → 優先度ソート
    ↓
[7] TaskDispatch ──── status解決(AUTO/MANUAL/MONITOR)
                       ├── AgentBridge → AI_ANALYZE委任
                       ├── ApprovalRequest(多段階承認)
                       └── Webhook通知
    ↓
[Response] IngestionResult
    ├── TraceID, HashChainValid, Masked
    ├── TasksGenerated[]
    └── ThreatResponses[]
```
