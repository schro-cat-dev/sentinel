# リスク分析と対策

```yaml
status: implemented
```

## デメリット分析と全回避策

### デメリット1: パイプライン内のエラーハンドリングが複雑化

**リスク:** ErrorRouterの統合でemitSafe()の分岐が増え、パイプラインのコードが読みにくくなる。

**回避策:**
- ErrorRouterは**1箇所でのみ**パイプラインに接続する: `emitSafe()` 内の catch ブロック
- emitSafe()は今と同じ3行の構造を維持。ErrorRouterへの委任は `errorRouter.route(error, context)` の1行追加のみ
- ErrorRouterの内部複雑性はパイプラインから完全に隠蔽（Classifier/Router/Executorの3層はErrorRouter内部で閉じる）

**テストでの検証:**
- emitSafe()のテストは既存テストをそのまま維持
- ErrorRouter有無でのパイプライン動作の同一性をテスト

### デメリット2: error-utils.tsの関数がパイプラインに依存を持つ

**リスク:** error-utils.ts（shared層）がパイプライン層に依存すると、依存の方向が逆転（クリーンアーキテクチャ違反）。

**回避策:**
- error-utils.tsは**純粋なユーティリティのまま維持**。パイプラインをimportしない
- ErrorClassifierがerror-utils.tsの`classifyError()`を呼ぶ（依存方向: パイプライン層 → shared層）
- ErrorRouterがerror-utils.tsの`serializeForAudit()`を呼ぶ（同上）
- 依存方向: `IngestionEngine → ErrorRouter → ErrorClassifier → error-utils.ts`（一方向）

```
依存方向（正しい）:
  IngestionEngine
    └→ ErrorRouter
         ├→ ErrorClassifier → error-utils (classifyError, isPiiSafe)
         ├→ RuleEngine       (ルーティングロジックのみ、外部依存なし)
         └→ ExecutorPool     → AuditSink interface (DI)
                             → DeadLetterQueue interface (DI)
```

**テストでの検証:**
- tscの`--noEmit`でcircular import検出
- ErrorRouterのテストはerror-utils.tsをモックなしで使用（実依存が正方向であることの証明）

### デメリット3: エラー処理自体がエラーした場合の無限ループリスク

**リスク:** ErrorRouter内のアダプタ送信が失敗 → そのエラーがまたErrorRouterに流れ → 無限再帰。

**回避策（3重防壁）:**

```
防壁1: maxRoutingDepth = 1（ハードコード、設定不可）
  → ErrorRouter.route() は depth引数を持ち、depth > 0 なら即座にconsole.errorで終了

防壁2: Executor自身のエラーはErrorRouterに戻さない（設計制約）
  → Executor.execute() の catch は console.error のみ。ErrorRouter.route()を呼ばない

防壁3: 最終フォールバック
  → ErrorRouter.route() 全体を try/catch で囲み、catchは console.error のみ
```

**テストでの検証:**
- テスト: AuditSinkが例外をスロー → ErrorRouterが無限ループしないことを検証
- テスト: 全アダプタが同時に例外 → console.errorで記録、パイプライン継続

### デメリット4: インターフェース定義の設計コスト

**リスク:** AuditSink/DeadLetterQueueのインターフェース設計が過剰で、利用者の実装負荷が高い。

**回避策:**
- インターフェースは**最小限**（各1メソッド: `send()` / `enqueue()`）
- デフォルト実装を提供:
  - `ConsoleAuditSink`: console.errorに構造化ログ出力（ゼロ設定で動く）
  - `NoopDeadLetterQueue`: 何もしない（DLQ不要な環境用）
- 利用者は必要なアダプタだけ実装すればいい

**テストでの検証:**
- ConsoleAuditSinkが実際に動作するテスト
- カスタムアダプタをDIで差し込めるテスト

## オーバーヘッド分析

| 項目 | enabled=false | enabled=true (正常時) | enabled=true (エラー時) |
|------|-------------|---------------------|----------------------|
| CPU | 0 (分岐1つ) | 0 (エラーなし=何もしない) | 分類+ルール評価+非同期送信 |
| メモリ | ErrorRouter インスタンスのみ | 同左 | +ErrorPayloadProtocol +RoutingDecision[] (即時GC) |
| レイテンシ | 0 | 0 | 0 (非同期、パイプライン非ブロック) |
| ネットワーク | 0 | 0 | アダプタ送信（非同期） |

**結論: パイプラインのhappy pathにオーバーヘッドなし。**

## テスト設計（TDD用）

### 正常系
- ErrorRouter有効 + エラー発生 → 分類 → ルーティング → アダプタ送信
- ErrorRouter無効 → 既存emitSafe動作（onError → console.error）
- CRITICAL → タスク生成 + 通知 + 監査ログ（3 destinations）
- WARNING + Transport → DLQ + 監査ログ
- INFO → ログのみ

### 異常系
- アダプタ送信失敗 → フォールバック → console.error
- 全アダプタ同時失敗 → console.error（パイプライン継続）
- 分類自体が失敗 → "ClassificationError" で最低限ルーティング
- ルール設定なし → デフォルトルール適用

### エッジケース
- ErrorRouter shutdown中にエラー発生 → 安全に無視
- 同時に100エラー発生 → 全て非同期処理、順序保証なし（acceptable）
- AuditSink.send()が永遠に完了しない → タイムアウト設定

### ペネトレーション
- ErrorPayloadProtocol.meta.context にPII注入 → maskPiiContextで除去されるか
- RoutingRule.kind_patternにReDoS → 検証で拒否
- __proto__ in RoutingDecision.metadata → Object.entriesで安全
