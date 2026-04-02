# SDK ↔ Server 統合完全化 — 要件・作業計画

```yaml
created_at: "2026-04-02T17:00:00Z"
status: complete (Phase 1-3 all done)
scope: SDK-Server integration gaps
related_issues:
  - ハッシュチェーン鍵管理 (DEAD-03)
  - gRPC認証管理設計・構築
  - SDK ↔ Server 連携完全化
```

---

## 1. 現状の連携状況

### 接続済み（E2Eテスト確認済み）

| # | 連携ポイント | SDK 側 | Server 側 | Proto |
|---|-------------|--------|-----------|-------|
| 1 | ログ投入 | `Sentinel.ingest()` → `RemoteTransport.send()` | `SentinelService.Ingest()` | IngestRequest |
| 2 | レスポンス受信 | `IngestionResult` | IngestResponse | hashChainValid, masked, tasksGenerated |
| 3 | ハッシュチェーン検証 | SHA-256 計算 → ログに付与 | HMAC-SHA256 で検証 → 結果返却 | hash_chain_valid |
| 4 | PII マスキング | SDK側でマスク後に送信 | Server側でも独立マスク | masked |
| 5 | ヘルスチェック | `RemoteTransport.healthCheck()` | `SentinelService.HealthCheck()` | HealthCheckRequest/Response |

### 未接続（本計画の対象）

| # | 連携ポイント | 現状 | 影響 |
|---|-------------|------|------|
| A | 検知ルール同期 | SDK と Server が別々のルールで独立動作 | 同一ログに対して異なる検知結果が出る |
| B | タスク承認フロー | Server に RPC あるが SDK から呼べない | SEMI_AUTO/MANUAL タスクの承認が Server 経由でできない |
| C | 脅威レスポンス | Proto に `threat_responses` あるが SDK が無視 | Server の脅威分析結果が SDK 利用者に届かない |
| D | タスク状態管理 | Server の GetTaskStatus/ListTasks に SDK アクセス不可 | SDK からタスクの進捗追跡ができない |
| E | ハッシュ方式統一 | SDK=SHA-256, Server=HMAC-SHA256 | cross-verification 不可。改竄検知の信頼性に差 |
| F | 設定整合性検証 | SDK config と Server config の一致チェックなし | ルール定義の乖離に気づけない |

---

## 2. 設計原則

### 2.1 設定駆動（Config-Driven）

全ての連携機能は **sentinel.yaml のパラメータ値** で有効/無効が決まる。コード変更なしで挙動を切り替え可能にする。

```yaml
# 例: 全機能有効化
integration:
  sync_detection_rules: true    # A: SDK検知ルールをServerに同期
  task_approval_enabled: true   # B: タスク承認フローをSDK経由で利用
  threat_response_enabled: true # C: 脅威レスポンスをSDK IngestionResultに含める
  task_status_polling: true     # D: タスク状態をSDK経由でクエリ
  hmac_key: "${SENTINEL_HMAC_KEY}"  # E: SDK/Server 共通HMAC鍵
  config_validation: true       # F: 起動時にSDK/Server設定の整合性チェック
```

### 2.2 ゼロ依存維持

SDK 側は引き続きランタイム依存ゼロ。gRPC 実装はユーザー注入（`RemoteTransport` / `ServerManagementTransport` 等）。

### 2.3 後方互換

既存の `local` モードは一切影響を受けない。連携機能は `remote` / `dual` モード時のみ有効。

---

## 3. 要件リスト

### A. 検知ルール同期

| ID | 要件 | 優先度 | 実装先 |
|----|------|--------|--------|
| A-1 | Server起動時にYAML `detection_rules` を読み込み、Server側EventDetectorに反映 | HIGH | Go Server |
| A-2 | SDK `detectionRules` と Server `detection_rules` の形式を統一（条件: log_types, min_level, message_pattern） | HIGH | Proto + 両側 |
| A-3 | dual モード時、SDK検知結果とServer検知結果の重複排除（同一eventNameの dedup） | MEDIUM | SDK |
| A-4 | 設定不一致時に起動ログで警告 | LOW | Go Server |

### B. タスク承認フロー（SDK → Server）

| ID | 要件 | 優先度 | 実装先 |
|----|------|--------|--------|
| B-1 | SDK に `ServerManagementTransport` インターフェース追加（ApproveTask, RejectTask, ListPendingBlocks, ApproveBlock, RejectBlock） | HIGH | SDK |
| B-2 | `Sentinel.approveTask(taskId, approverId, reason)` 公開メソッド | HIGH | SDK |
| B-3 | `Sentinel.rejectTask(taskId, rejectorId, reason)` 公開メソッド | HIGH | SDK |
| B-4 | `Sentinel.listPendingBlocks()` 公開メソッド | MEDIUM | SDK |
| B-5 | `Sentinel.approveBlock(blockId, approverId)` / `rejectBlock()` | MEDIUM | SDK |
| B-6 | `task_approval_enabled: true` 時のみ上記メソッドが利用可能。false 時は `Error("Task approval is disabled")` | HIGH | SDK |

### C. 脅威レスポンス受信

| ID | 要件 | 優先度 | 実装先 |
|----|------|--------|--------|
| C-1 | `IngestionResult` に `threatResponses` フィールド追加 | HIGH | SDK |
| C-2 | IngestResponse の `threat_responses` を `IngestionResult.threatResponses` にマッピング | HIGH | SDK (examples/grpc-transport) |
| C-3 | `threat_response_enabled: false` 時はフィールドを空配列で返す | MEDIUM | SDK |
| C-4 | `onThreatResponse` コールバックを `SentinelConfig` に追加（オプショナル） | MEDIUM | SDK |

### D. タスク状態管理（SDK → Server クエリ）

| ID | 要件 | 優先度 | 実装先 |
|----|------|--------|--------|
| D-1 | `Sentinel.getTaskStatus(taskId)` 公開メソッド | HIGH | SDK |
| D-2 | `Sentinel.listTasks(filter)` 公開メソッド | HIGH | SDK |
| D-3 | `ServerManagementTransport.getTaskStatus()` / `listTasks()` | HIGH | SDK |
| D-4 | `task_status_polling: false` 時は `Error("Task status query is disabled")` | MEDIUM | SDK |

### E. ハッシュ方式統一

| ID | 要件 | 優先度 | 実装先 |
|----|------|--------|--------|
| E-1 | SDK の IntegritySigner を HMAC-SHA256 に変更（`security.hmac_key` 設定時） | HIGH | SDK |
| E-2 | HMAC鍵は SDK config `security.hmacKey` から取得。未設定時は既存SHA-256フォールバック | HIGH | SDK |
| E-3 | Server と SDK で同一ログに対して同一ハッシュ値を生成する cross-verification テスト | HIGH | E2E テスト |
| E-4 | 鍵ローテーション: SDK にも `previousKey` サポート追加 | MEDIUM | SDK |
| E-5 | `signingKeyId` を HMAC 鍵選択用の識別子として正式に定義 | MEDIUM | SDK + Server |

### F. 設定整合性検証

| ID | 要件 | 優先度 | 実装先 |
|----|------|--------|--------|
| F-1 | Server 起動時に HealthCheck レスポンスに設定サマリー（masking rules 数、detection rules 数、task rules 数）を含める | MEDIUM | Go Server |
| F-2 | SDK `remote`/`dual` 初期化時に HealthCheck を呼び、設定サマリーを取得 | MEDIUM | SDK |
| F-3 | SDK 側 config と Server 側サマリーの不一致を `logger.warn` で警告 | MEDIUM | SDK |
| F-4 | `config_validation: false` で警告を抑制 | LOW | SDK |

---

## 4. 定性チェックリスト

### セキュリティ

- [ ] HMAC 鍵が平文で config に書かれないこと（環境変数 or Vault 参照）
- [ ] タスク承認 RPC に認証が必須であること（`auth.enabled: true` 前提）
- [ ] 脅威レスポンスに PII が含まれないこと（Server 側でマスク済み）
- [ ] cross-verification テストで改竄検知が双方向で機能すること
- [ ] 設定整合性チェックがサーバ内部構造を漏洩しないこと

### 後方互換性

- [ ] `local` モードの既存テストが全パスすること
- [ ] `integration` セクション未設定時はデフォルト全 false で現状と同じ挙動
- [ ] `RemoteTransport` インターフェースに破壊的変更がないこと
- [ ] 既存の `onTaskAction` / `onTaskConfirm` コールバックが引き続き動作すること

### パフォーマンス

- [ ] 設定整合性チェックは初期化時1回のみ（ingest パスに影響なし）
- [ ] タスク状態ポーリングは SDK 利用者の明示的呼び出しのみ（自動ポーリングなし）
- [ ] 脅威レスポンスのマッピングは O(n)（n = レスポンス数、通常 0〜3 件）

### テスト

- [ ] 各連携ポイント (A〜F) に対して RED → GREEN の TDD サイクル
- [ ] E2E テスト: SDK → Go Server の全 RPC 通信確認
- [ ] 設定パターン網羅: 全 false / 全 true / 部分有効の組み合わせ
- [ ] Go Server 側の新規テスト追加
- [ ] 全体リグレッション: TS 2,900+ テスト + Go 全パッケージ

### ドキュメント

- [ ] `docs/usage-guide.md` に連携設定セクション追加
- [ ] `docs/architecture.md` に SDK ↔ Server データフロー図更新
- [ ] `docs/analysis/roadmap/improvement-backlog.md` に連携項目追加
- [ ] 脅威カタログに連携関連の脅威追加（SSRF on management RPC 等）

---

## 5. 作業順序（推奨）

```
Phase 1: 基盤（E → F）
  E. ハッシュ方式統一 ← 全連携の信頼性基盤
  F. 設定整合性検証   ← 以降の作業の品質保証

Phase 2: データフロー（C → A）
  C. 脅威レスポンス受信 ← IngestResponse の完全消費
  A. 検知ルール同期     ← dual モードの整合性

Phase 3: 操作フロー（B → D）
  B. タスク承認フロー   ← Server RPC の SDK 公開
  D. タスク状態管理     ← 同上、B と同一インターフェースで提供
```

---

## 6. 設定パラメータ一覧（sentinel.yaml 追加分）

```yaml
integration:
  # A: SDK検知ルールをServerに同期（起動時にHealthCheck経由で照合）
  sync_detection_rules: false

  # B: タスク承認フローをSDK経由で利用可能にする
  task_approval_enabled: false

  # C: IngestResponse の threat_responses を IngestionResult に含める
  threat_response_enabled: false

  # D: タスク状態クエリ (getTaskStatus/listTasks) を有効化
  task_status_enabled: false

  # F: 起動時にSDK/Server設定の整合性チェック
  config_validation: true
```

```yaml
security:
  # E: HMAC鍵（SDK/Server共通）。環境変数 SENTINEL_HMAC_KEY を推奨。
  hmac_key: ""
  # E: 鍵バージョン（ローテーション用）
  hmac_key_version: 1
```

---

## 7. 変更対象ファイル（予定）

### SDK (TypeScript)

| ファイル | 変更内容 |
|---------|---------|
| `src/transport/transport.ts` | `ServerManagementTransport` インターフェース追加 |
| `src/security/integrity-signer.ts` | HMAC-SHA256 モード追加 |
| `src/core/engine/types.ts` | `IngestionResult.threatResponses` 追加 |
| `src/configs/sentinel-config.ts` | integration セクション + hmacKey + onThreatResponse |
| `src/index.ts` | approveTask/rejectTask/getTaskStatus/listTasks 公開メソッド |
| `examples/grpc-transport.ts` | threatResponses マッピング追加 |
| `examples/grpc-management-transport.ts` | 新規: 管理RPC実装例 |

### Go Server

| ファイル | 変更内容 |
|---------|---------|
| `config/config.go` | integration セクション追加 |
| `config/sentinel.yaml` | integration デフォルト値 |
| `internal/grpc/server.go` | HealthCheck に設定サマリー追加 |
| `proto/sentinel.proto` | HealthCheckResponse に config_summary 追加 |

### テスト

| ファイル | 変更内容 |
|---------|---------|
| `tests/e2e/sdk-server.test.ts` | 全連携ポイントの E2E テスト |
| `tests/unit/security/integrity-signer.test.ts` | HMAC モードテスト |
| `tests/unit/transport/management-transport.test.ts` | 新規 |
| `packages/server/config/config_test.go` | integration 設定テスト |

---

## 8. リスク

| リスク | 影響 | 緩和策 |
|--------|------|--------|
| HMAC 鍵の安全な配布 | 鍵漏洩で改竄検知が無効化 | 環境変数 + Vault 参照。config に平文禁止を明記 |
| Proto 変更の後方互換 | 既存クライアントが壊れる | フィールド追加のみ（削除・番号変更なし） |
| 設定チェックの false negative | 不一致に気づかない | ルール数/名前の両方を照合 |
| management RPC の認可漏れ | 未認証ユーザーがタスク承認可能 | auth.enabled + RBAC can_approve 必須 |
