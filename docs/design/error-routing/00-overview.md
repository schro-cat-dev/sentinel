# エラールーティング層 設計概要

```yaml
created_at: "2026-04-02"
status: implemented
scope: TS SDK + Go Server
```

## 背景

現状のSentinelは「エラーを捕捉はするが、ルーティングしない」。

- ~~`classifyError()` が定義されているがパイプライン未接続~~ → ✅ ErrorRouter 経由で接続済み
- ~~`ErrorPayloadProtocol` が型定義されているが未使用~~ → ✅ error-utils.ts + ConsoleAuditSink で使用済み
- ~~エラーは `emitSafe → onError → console.error` で消費されるだけ~~ → ✅ ErrorRouter → AuditSink で構造化出力
- Go側の通知ルーティングはチャネルプレフィックス（#, @, https://）ベースのみ
- エラー種別に応じた送信先選択、タスク生成、AIエージェント委任が一切ない

## 解決する課題

```
現状:  エラー → ログ出力 → 消滅
目標:  エラー → 分類 → ルーティング → 対応（タスク/通知/分析/ブロック/キュー）
```

## 新規モジュール: ErrorRouter

```
                     ┌──────────────┐
                     │  ErrorRouter │  ← 一段上の制御層
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │Classifier│ │ Router   │ │ Executor │
        └──────────┘ └──────────┘ └──────────┘
              │             │             │
              │ severity    │ destination │ action
              │ + context   │ + priority  │ + result
              ▼             ▼             ▼
        CRITICAL/      Task生成 /    Datadog /
        WARNING/       AI委任 /     Sentry /
        INFO           通知 /       CloudWatch /
                       キュー /     SQS DLQ /
                       ブロック      ログ出力
```

## 責務分離

| モジュール | 責務 | 入力 | 出力 |
|-----------|------|------|------|
| ErrorClassifier | エラー種別→重大度分類 | Error + context | ErrorPayloadProtocol |
| ErrorRouter | 分類結果→送信先決定 | ErrorPayloadProtocol | RoutingDecision[] |
| ErrorExecutor | 決定→実行 | RoutingDecision | ExecutionResult |
| ErrorRouter(制御層) | 上記3つのオーケストレーション | Error | void (副作用) |

## 設計原則

1. **パイプラインに影響しない**: エラールーティングは非同期・non-blocking。パイプラインの処理時間に加算しない
2. **フォールト・トレラント**: エラールーティング自体のエラーは最終手段（console.error）で記録。無限ループしない
3. **設定駆動**: ルーティングルールはconfig/YAMLで定義。コード変更なしで送信先を変更可能
4. **アダプタパターン**: 外部サービス（Datadog/Sentry/CloudWatch/SQS）はインターフェースで抽象化。実装差替え可能
5. **ゼロオーバーヘッド**: ErrorRouter未設定時はemitSafe→onErrorの現行動作を維持
