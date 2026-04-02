# 修正レポート: TaskTransport アダプタパターン実装

- **日付**: 2026-04-02
- **スコープ**: タスクトランスポート（外部システムへのタスク配信アダプタ）の新規実装 + 品質監査対応 + バグ修正

---

## 1. 背景

Sentinel のタスクディスパッチは `onTaskAction` コールバック方式のみだった。
外部システム（Slack, Jira, SIEM等）へのタスク配信をアダプタパターンで抽象化し、
利用者が `TaskTransport` インターフェースを実装して注入できるようにする要件があった。

加えて、`docs/audit/00-current-analysis.md` の品質監査で報告された
Issue 2.2（PII短文字列バイパスの根拠欠落）への対応も実施した。

---

## 2. 実施内容一覧

### 2.1 品質監査対応 (Issue 2.2)

| 変更 | ファイル | 内容 |
|------|----------|------|
| テスト追加 | `tests/unit/shared/error-utils.test.ts` | `isPiiSafe()` の length < 3 閾値に対する境界値テスト3件追加（1文字、2文字PII隣接文字、3文字境界） |
| JSDoc追加 | `src/security/pii-context-masker.ts` | `isPiiSafe()` に閾値の設計根拠・不変条件・テスト参照を記載 |
| 不変条件注記 | `src/security/pii-patterns.ts` | モジュールJSDocにパターン追加時の制約（最短マッチ長 >= 3）を追記 |
| 監査ドキュメント更新 | `docs/audit/00-current-analysis.md` | Issue 2.2 を RESOLVED に更新 |

### 2.2 TaskTransport 新規実装

#### 新規ファイル

| ファイル | 内容 |
|----------|------|
| `src/transport/task-transport.ts` | `TaskTransport` インターフェース、`TaskTransportResult` 型定義 |
| `tests/unit/transport/task-transport.test.ts` | インターフェース契約テスト (7件) |
| `tests/unit/core/task-executor-transport.test.ts` | TaskExecutor トランスポート統合テスト (27件) |
| `tests/config/config-loader-transport.test.ts` | YAML task_transports パーステスト (12件) |
| `docs/design/task-transport.md` | 設計ドキュメント |
| `docs/reports/2026-04-02-task-transport-implementation.md` | 本レポート |

#### 変更ファイル

| ファイル | 変更内容 |
|----------|----------|
| `src/core/task/task-executor.ts` | `transports` フィールド追加、`invokeTransports()` 実装、`closeTransports()` 実装、`invokeAll()` でハンドラ+トランスポートのエラー集約 |
| `src/configs/sentinel-config.ts` | `TaskTransportConfig` 型追加、`SentinelConfig.taskTransportConfigs` フィールド追加 |
| `src/configs/config-loader.ts` | `RawTaskTransport` 型追加、YAML `task_transports` パース・バリデーション・変換追加 |
| `src/index.ts` | `SentinelOptions.taskTransports` 追加、TaskExecutor初期化時にトランスポート注入、`shutdown()` で `closeTransports()` 呼出し、`reset()` で best-effort `closeTransports()` 呼出し、`TaskTransport`/`TaskTransportResult`/`TaskTransportConfig` エクスポート追加 |
| `docs/task-gen.md` | 実装状況テーブルにタスクトランスポート追加、利用例とポリシー記載 |
| `tests/unit/core/sentinel.test.ts` | taskTransports統合テスト7件追加（initialize, shutdown, reset, E2E, 後方互換） |

### 2.3 実装バグ修正 (監査で発見)

| バグ | ファイル | 修正内容 |
|------|----------|----------|
| `invokeTransports()` が `TaskTransportResult.success=false` を無視 | `src/core/task/task-executor.ts` | `dispatch()` の戻り値 `.success` をチェックし、`false` の場合はエラーとして集約するよう修正 |
| `Sentinel.reset()` で `closeTransports()` が呼ばれない | `src/index.ts` | `reset()` に best-effort の `closeTransports()` 呼出しを追加（`shutdown()` との対称性確保） |

---

## 3. テスト詳細

### 3.1 task-transport.test.ts (7件) — インターフェース契約

| テスト名 | 検証内容 |
|----------|----------|
| requires name property | `name` プロパティが文字列であること |
| dispatch returns TaskTransportResult with success=true | 正常配信時の戻り値構造 |
| dispatch returns TaskTransportResult with success=false on failure | 失敗配信時の戻り値構造（error含む） |
| dispatch can throw on unrecoverable errors | 致命的エラー時のthrow |
| close is optional and returns Promise<void> | close省略可、close呼出し可能 |
| dispatch receives the full GeneratedTask object | taskオブジェクトの完全性 |
| multiple transports can coexist independently | 複数トランスポートの独立性 |

### 3.2 task-executor-transport.test.ts (27件) — 統合テスト

#### 基本動作 (5件)

| テスト名 | 検証内容 |
|----------|----------|
| dispatches task to registered transports | 単一トランスポートへの配信 |
| dispatches to multiple transports | 複数トランスポートへの配信 |
| executes both handlers and transports | ハンドラとトランスポートの共存 |
| does not dispatch to transports when status is not dispatched | MANUAL → blocked_approval でトランスポート未実行 |
| does not dispatch to transports when MONITOR | MONITOR → skipped でトランスポート未実行 |

#### エラー集約 (4件)

| テスト名 | 検証内容 |
|----------|----------|
| continues dispatching when one transport throws | 1つの失敗が他をブロックしない |
| aggregates errors from handlers and transports | ハンドラ+トランスポート両方のエラーを集約 |
| handler failure does not prevent transport dispatch | ハンドラ失敗→トランスポート実行 |
| transport failure does not prevent other transport dispatch | トランスポート間の独立性 |

#### タイムアウト (1件)

| テスト名 | 検証内容 |
|----------|----------|
| transport is subject to task-level timeout | guardrails.timeoutMs がトランスポートにも適用 |

#### 後方互換 (2件)

| テスト名 | 検証内容 |
|----------|----------|
| works without transports (existing behavior unchanged) | トランスポートなしで既存動作維持 |
| works with empty transport array | 空配列で既存動作維持 |

#### close (2件)

| テスト名 | 検証内容 |
|----------|----------|
| closeTransports calls close on all transports | 全トランスポートのclose呼出し |
| closeTransports tolerates close errors | close失敗に耐える |

#### SEMI_AUTO + トランスポート (3件)

| テスト名 | 検証内容 |
|----------|----------|
| dispatches to transports when confirmHandler approves | 承認→トランスポート実行 |
| does not dispatch to transports when confirmHandler rejects | 拒否→トランスポート未実行 |
| dispatches to transports when SEMI_AUTO and no confirmHandler | handler未設定→AUTO fallback |

#### requireHumanApproval + トランスポート (2件)

| テスト名 | 検証内容 |
|----------|----------|
| blocks transports when requireHumanApproval is true (AUTO) | AUTO+approval→blocked、トランスポート未実行 |
| blocks transports when requireHumanApproval is true (SEMI_AUTO) | SEMI_AUTO+approval→blocked、トランスポート未実行 |

#### defaultHandler + トランスポート (2件)

| テスト名 | 検証内容 |
|----------|----------|
| executes defaultHandler AND transports when no actionType handler | defaultHandlerとトランスポートの同時実行 |
| executes actionType handler (not default) AND transports | actionTypeハンドラ優先、defaultHandler未実行 |

#### success=false ハンドリング (4件)

| テスト名 | 検証内容 |
|----------|----------|
| treats success=false as error | error付きfalse→failed |
| treats success=false without error message as error | error無しfalse→failed（デフォルトメッセージ） |
| success=true transport does not cause error | true→dispatched |
| mixed success/failure across transports aggregates errors | 成功+失敗混在時のエラー集約 |

#### エッジケース (2件)

| テスト名 | 検証内容 |
|----------|----------|
| no handlers and no transports — dispatched but nothing happens | 空状態でdispatched |
| transport receives exact same task object (deep equality) | タスクオブジェクトの同一参照+フィールド検証 |

### 3.3 config-loader-transport.test.ts (12件) — YAML設定

#### 正常系 (6件)

| テスト名 | 検証内容 |
|----------|----------|
| parses multiple task_transports with all fields | 複数トランスポート+endpoint+headers+拡張フィールド |
| parses minimal transport config (name only) | name のみの最小構成 |
| defaults to undefined when task_transports is absent | 未指定時undefined |
| preserves headers field through conversion | headers フィールドの保持 |
| allows duplicate transport names | 同名トランスポート許容 |
| preserves arbitrary extension fields | 任意拡張フィールド（custom_field, nested, numeric）の保持 |

#### 異常系 (4件)

| テスト名 | 検証内容 |
|----------|----------|
| throws when name is missing | name欠落→ConfigLoadError |
| throws when name is empty string | 空文字name→ConfigLoadError |
| throws when name is not a string | 非文字列name→ConfigLoadError |
| throws with correct index in error message for invalid entry | エラーメッセージにインデックス番号含む |

#### エッジケース (2件)

| テスト名 | 検証内容 |
|----------|----------|
| handles empty task_transports array | 空配列→空配列返却 |
| env var expansion applies to transport endpoint values | 展開後の値の保持 |

### 3.4 sentinel.test.ts 追加分 (7件) — Sentinel統合

| テスト名 | 検証内容 |
|----------|----------|
| passes taskTransports to TaskExecutor via options | initialize時にトランスポートが注入される |
| shutdown calls closeTransports | shutdown時にclose呼出し |
| shutdown tolerates transport close errors | close失敗に耐える |
| works without taskTransports option (backward compat) | option無し後方互換 |
| works with empty taskTransports array | 空配列後方互換 |
| reset cleans up taskTransports (best-effort close) | reset時のbest-effort close |
| E2E: ingest → event detection → task generation → transport dispatch | 全パイプラインE2E |

---

## 4. 設計判断

### 4.1 やったこと（と理由）

| 判断 | 理由 |
|------|------|
| `TaskTransport` インターフェースを `RemoteTransport` と同じ設計思想で定義 | 一貫性、学習コスト削減 |
| ハンドラ→トランスポートの順序で実行 | ハンドラ（インプロセス）を先に実行し、失敗してもトランスポート（外部）は実行 |
| トランスポートのリトライをSDK側で行わない | 二重配信防止。リトライはトランスポート実装の責務 |
| `success=false` をエラーとして集約 | 部分失敗を握りつぶさない。呼出元が失敗を検知可能 |
| YAML設定はメタデータのみ、実装はTS側で注入 | zero-dep方針維持。YAML→HTTP clientの暗黙的生成を避ける |
| `closeTransports()` を `reset()` でも呼ぶ | `shutdown()` との対称性。テスト環境でもリソースリーク防止 |

### 4.2 やらなかったこと（と理由）

| 判断 | 理由 |
|------|------|
| 組み込みHTTP/Slack/Jiraアダプタ | zero-dep方針。利用者が実装して注入する |
| タスクキュー/バッチング | 現時点ではスコープ外。トランスポート実装側でバッファリング可能 |
| actionType → transport のルーティング | 全トランスポートが全タスクを受け取る。フィルタリングはトランスポート実装側の責務 |
| タスクライフサイクル追跡 | Goサーバ側の責務。SDKは dispatch + result のみ |

### 4.3 拡張ポリシー

| 差し替え可能 | 差し替え不可（意図的） |
|--------------|----------------------|
| `TaskTransport` 実装（HTTP, gRPC, キュー, SIEM等） | ディスパッチステータスの解決ロジック（AUTO/SEMI_AUTO/MANUAL/MONITOR） |
| トランスポートごとの設定（endpoint, credentials等） | guardrails の適用（タイムアウト、承認要求） |
| YAML メタデータの拡張フィールド | ハンドラ→トランスポートの実行順序 |

---

## 5. テスト結果

| 項目 | 結果 |
|------|------|
| テストファイル数 | 73 (全パス) |
| テスト総数 | 2598 passed + 23 expected fail |
| 失敗 | 0 |
| 型チェック (tsc --noEmit) | エラー 0 |
| 新規テスト追加数 | 53件 (7 + 27 + 12 + 7) |

---

## 6. 影響範囲

### 破壊的変更: なし

- 既存の `onTaskAction` コールバック方式はそのまま動作
- `SentinelOptions.taskTransports` は省略可能（後方互換）
- `SentinelConfig.taskTransportConfigs` は省略可能
- YAML 設定に `task_transports` が無くても動作

### 新規公開API

| エクスポート | 種別 | 用途 |
|-------------|------|------|
| `TaskTransport` | type | トランスポートインターフェース |
| `TaskTransportResult` | type | トランスポート配信結果 |
| `TaskTransportConfig` | type | YAML由来の設定メタデータ |
| `SentinelOptions.taskTransports` | field | 初期化時のトランスポート注入 |

---

## 7. 関連ドキュメント

| ドキュメント | 状態 |
|-------------|------|
| `docs/design/task-transport.md` | 新規作成 |
| `docs/task-gen.md` | 更新済み |
| `docs/audit/00-current-analysis.md` | Issue 2.2 RESOLVED |
| `docs/architecture.md` | 更新対象 |
| `docs/usage-guide.md` | 更新対象 |
| `docs/instance-manage.md` | 更新対象 |
| `docs/coop-siem-like-tools-agent.md` | 更新対象 |
| `docs/architecture-diagrams.md` | 更新対象 |
