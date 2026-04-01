# ランタイム検証 ギャップ分析

```yaml
created_at: "2026-04-02"
status: remediation
```

## 発見された粗 4件

### 粗1: deepFreezeがclassインスタンスを壊す

**問題:** `Sentinel.deepFreeze(config)` が再帰的にObject.freezeする。configの中にclassインスタンス（ConsoleAuditSink等）がある場合、そのメソッドやプロパティもfreezeされ、内部状態を持つclassが動作しなくなる可能性。

**影響:** `errorRouting.sinks.audit = new ConsoleAuditSink()` が初期化後にfreezeされる。ConsoleAuditSink.send()は状態を持たないため実害は薄いが、将来のstatefulなSink実装（DB接続プール等）で壊れる。

**修正方針:** deepFreezeで関数とclassインスタンスをスキップ。`typeof value === 'function'` および `value.constructor !== Object && value.constructor !== Array` をフリーズ対象外にする。

### 粗2: ErrorRouter.onTaskRequest が sync only

**問題:** `onTaskRequest` の型が `(request: TaskRequest) => void` で、async未対応。将来TaskExecutor.dispatch()と連携する場合にasyncが必要。

**修正方針:** 型を `(request: TaskRequest) => void | Promise<void>` に変更。execute()内でPromise.resolve()でラップして統一的にawait。

### 粗3: Go Server側のerror-routing実装がconfig schemaのみ

**修正方針:** sentinel.yamlのschemaに合わせて、config.goにErrorRoutingConfig構造体とvalidation追加。パイプライン統合は将来タスクとしてドキュメントに明記。

### 粗4: テスト数の散在（構造的問題）

**修正方針:**
- dir_structure.txtのテスト数ヘッダーを「`npm test` で確認」に変更（具体的数値を除去）
- checklist-results.mdのtotal_testsを削除し「`npm test` で確認」に変更
- 数値を持つのはREADMEのProject Status表の1箇所のみ（これもCI連携時に自動更新可能な設計）

## 追加: サンプル実行による動作検証

samples/advanced_usage.ts を実際に実行し、全パイプライン出力を検証する。
- PII masking が出力に反映されているか
- メトリクスカウンタが正しくインクリメントされるか
- トレーシングspanが記録されるか
- ErrorRouterがCRITICALエラーで発火するか
- dispose後にハンドラが呼ばれないか
