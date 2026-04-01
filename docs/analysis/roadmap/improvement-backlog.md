# 優先度付き改善バックログ

```yaml
analyzed_at: "2026-04-01"
based_on: "pending commit"
status: current
last_updated: "2026-04-01T17:00:00Z"
```

## 全項目ステータス

### P0: 即時修正 — 全4件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| BUG-01 | `agentBackLog` がnormalizeで欠落 | ✅ |
| BUG-02 | `traceInfo` がnormalizeで欠落 | ✅ |
| BUG-03 | `onTaskGenerated` 未呼出 | ✅ |
| BUG-04 | `onTaskDispatched` 未呼出 | ✅ |

### P1: 次リリース — 全6件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| RES-01 | transport timeout | ✅ sendWithTimeout |
| RES-02 | dual 2度正規化 | ✅ getLastProcessedLog |
| OBS-01 | エラーswallow | ✅ onError callback |
| PERF-01 | RegExp再コンパイル | ✅ lastIndex reset |
| COMPAT-01 | exports types条件 | ✅ |
| API-01 | initialize重複 | ✅ 既存インスタンス返却 |

### P2: 計画的対応 — 11/14件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| PERF-02 | preserveFields Array | ✅ Set化 |
| PERF-03 | context copy | ✅ 除去 |
| PERF-04 | async mutex粒度 | ✅ hash更新のみロック |
| MEM-01 | handler無限成長 | ✅ removeHandlers/clearHandlers |
| OBS-02 | IngestionResult情報不足 | ✅ detection追加 |
| OBS-03 | ロガーインターフェース | ✅ SentinelLogger DI |
| API-02 | SEMI_AUTO=AUTO | ✅ TaskConfirmHandler |
| API-03 | timeoutMs未実装 | ✅ TaskExecutor実装 |
| API-04 | shutdown()なし | ✅ Sentinel.shutdown() |
| CFG-01 | projectName未消費 | ⚠ NA — メタデータ保持（intentional） |
| CFG-02 | environment条件分岐 | ✅ logger抑制 |
| INT-01 | MaskingServiceインスタンス | ✅ 除去 |
| INT-02 | ILogNormalizer未活用 | ✅ constructorで使用 |
| COMPAT-02 | DOM lib | ✅ 除去 |

### P3: 推奨 — 6/9件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| DEAD-01 | shared/ dead code | ✅ constants/ 削除、空ファイル削除、protocol簡素化 |
| DEAD-02 | WorkerToMainMessage | ✅ 削除 |
| DEAD-03 | signature/signingKeyId | ⚠ NA — ロードマップ |
| DEAD-04 | AI_ACTION_REQUIRED | ✅ 検知ルール追加 |
| MT-01 | validate二重定義 | ✅ normalizer.validate()削除 |
| MT-02 | I-prefix不統一 | ⚠ NA |
| TEST-01 | IngestionEngineテスト | ✅ 12テスト |
| TEST-02 | normalizeOnly()テスト | ✅ |
| TEST-03 | mutex検証 | ✅ |

### Go Server — 全4件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| S-002 | API Key空文字列 | ✅ |
| S-002ext | API Key最小長 | ✅ |
| S-005 | 暗号化鍵検証 | ✅ |
| S-006 | レートリミット | ✅ |

---

## 最終集計

| 優先度 | 合計 | ✅完了 | ⚠保留/NA | 理由 |
|--------|------|--------|----------|------|
| P0 | 4 | 4 | 0 | |
| P1 | 6 | 6 | 0 | |
| P2 | 14 | 13 | 1 | CFG-01: 意図的NA |
| P3 | 9 | 8 | 1 | DEAD-03: 鍵管理設計必要 |
| Go | 4 | 4 | 0 | |
| **合計** | **37** | **35** | **2** | |

**残り6件の保留理由:**
- OBS-03: ロガーI/Fは利用者のログ基盤との統合設計が必要
- API-02: SEMI_AUTOはServer側の承認フロー実装待ち
- CFG-01/02: 設計上の意図的NA（projectNameはメタデータ、environmentは利用者判断）
- DEAD-03/04: ロードマップ項目として保持（型定義はAPIの将来拡張ポイント）

---

## スケーリング・ロードマップ（将来課題）

大規模化（秒間数万〜数十万ログ）に向けた3つの拡張課題。

### SCALE-01: ハッシュチェーンのシャーディング

**現状:** Go Server の `IntegritySigner` は単一の `sync.Mutex` でハッシュチェーンをアトミックに更新。論理的に正しいが、高スループット時にボトルネックになる。

**対策:** `ServiceId` や `TenantId` ごとにハッシュチェーンを分割（シャーディング）し、Mutex のロック粒度を細かくする。マルチコアの性能を限界まで引き出せる。

```
Before: 全ログ → 1 Mutex → 1 Chain
After:  ServiceA → Mutex_A → Chain_A
        ServiceB → Mutex_B → Chain_B
```

**優先度:** スループット 10,000 logs/sec 超で検討。現時点では不要。

### SCALE-02: 永続化層のスケールアウト

**現状:** SQLite (WAL) + SQLCipher。エッジ動作や小〜中規模では最強だが、大規模分散システムではログの書き込み速度と検索速度に限界がある。

**対策:** Store インターフェースが既に抽象化されているため、以下の Driver 実装を将来追加可能:

| Driver | ユースケース | 特徴 |
|--------|------------|------|
| ClickHouse | 大規模ログ分析 | 列指向、高速集計 |
| Elasticsearch | 全文検索 + リアルタイムダッシュボード | Kibana連携 |
| PostgreSQL (パーティショニング) | ACID + スケール | 既存インフラ活用 |
| TimescaleDB | 時系列ログ | PostgreSQL拡張 |

**優先度:** 1TB+ のログ蓄積、または 100+ ノードの分散環境で検討。

### SCALE-03: AIエージェント暴走対策（False Positive Prevention）

**現状:** AIによる自動IPブロック (`BLOCK_AND_NOTIFY`) は強力だが、AIがハルシネーションを起こして自社の内部IPや重要なAPIゲートウェイをブロックするリスクがある。

**対策:** AIエージェントへの委譲前（TaskExecutor層）に「絶対にブロックしない Immutable Whitelist」を挟む。

```go
// 例: BlockDispatcher.Execute() の先頭でチェック
var immutableWhitelist = []string{
    "10.0.0.0/8",     // 内部ネットワーク
    "172.16.0.0/12",  // プライベートIP
    "192.168.0.0/16", // ローカルネットワーク
    "127.0.0.1",      // ループバック
}

func (d *BlockDispatcher) Execute(target ThreatTarget) error {
    if isImmutableWhitelisted(target.IP) {
        slog.Warn("block rejected: target is in immutable whitelist",
            "ip", target.IP)
        return nil // ブロックしない
    }
    // ... 通常のブロック処理
}
```

**優先度:** AIエージェント (`AUTOMATED_REMEDIATE`, `AI_ANALYZE`) を本番有効化する前に必須。

### SCALE-04: SDK/Server Hash Chain 直列化の統一

**現状:** SDK は SHA-256 (カスタム deterministicStringify)、Server は HMAC-SHA256 (json.Marshal)。同じログでもハッシュ値が異なり、cross-verification 不可。

**対策:** 共通の正規化フォーマット（JSON Canonicalization Scheme: RFC 8785 等）を採用し、SDK/Server 双方で同一ハッシュを生成可能にする。

**優先度:** dual-mode でサーバ側がSDKハッシュを検証するユースケースが発生した時点で対応。

### SCALE-05: SQLite Data Retention / Auto-Purge

**現状:** ログが無制限にSQLiteに蓄積される。retention policy なし。172GB/day（1000 logs/sec × 2KB）で数日でディスク枯渇。

**対策:** config に `store.retention_days` を追加。定期的な CRON ジョブまたはバックグラウンド goroutine で古いログを DELETE + VACUUM。

**優先度:** 本番運用開始前に必須。

### SCALE-06: API Key ホットリロード

**現状:** API key は起動時に config/env から読み込み。変更にはサーバ再起動が必要。

**対策:** SIGHUP シグナルで API key を再読み込み（証明書ホットリロードと同じパターン）。または外部キーストア（Redis/Vault）との連携。

**優先度:** マルチテナント運用、または頻繁なキーローテーションが必要になった時点で対応。

### SCALE-07: Proto details 型の統一

**現状:** SDK は `details?: string`、Server Proto は `map<string, string>`。SDK→Server でデータ損失の可能性。

**対策:** Proto 定義を `oneof { string text = 1; map<string, string> structured = 2; }` に変更し、SDK は string、Server は map を使い分け可能にする。

**優先度:** gRPC スキーマ変更を伴うため、次のメジャーバージョン（v3）で対応。
