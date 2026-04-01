# ErrorClassifier 設計

```yaml
status: implemented
layer: TS SDK (shared) → Go Server (移植)
```

## 責務

生のError + 発生コンテキストから、構造化された `ErrorPayloadProtocol` を生成する。

## 入力

```typescript
interface ClassificationInput {
    error: Error;                  // 生のエラー
    context: string;               // "callback", "transport.dual", "task.dispatch" 等
    traceId?: string;              // パイプラインのトレースID
    layer?: string;                // "engine", "transport", "task", "detection"
    operation?: string;            // "ingest", "dispatch", "mask", "sign"
}
```

## 出力

既存の `ErrorPayloadProtocol`:

```typescript
interface ErrorPayloadProtocol {
    kind: string;              // "TransportTimeout", "HandlerCrash", "MaskingFailure"
    detailKind: string;        // 詳細サブタイプ
    code: string;              // "TRANSPORT_TIMEOUT", "HANDLER_EXCEPTION"
    message: string;           // 人間可読メッセージ
    meta: ErrorMeta;           // traceId, layer, context, operation 等
}
```

## 分類ロジック

```typescript
classify(input: ClassificationInput): ErrorPayloadProtocol {
    const kind = deriveKind(input.error, input.context);
    const severity = classifyError(payload, severityConfig);
    return { kind, detailKind, code, message, meta, severity };
}
```

### kind 導出テーブル

| error.message パターン | context | kind | 推奨 severity |
|----------------------|---------|------|--------------|
| `timeout` | transport.* | TransportTimeout | WARNING |
| `timeout` | task.dispatch | HandlerTimeout | WARNING |
| `connection refused` | transport.* | TransportConnectionRefused | CRITICAL |
| `ECONNRESET` | transport.* | TransportConnectionReset | WARNING |
| `validation(*)` | * | ValidationFailure | INFO |
| `shutdown` | * | ShutdownViolation | WARNING |
| (その他) | callback | CallbackException | WARNING |
| (その他) | task.dispatch | HandlerException | WARNING |
| (その他) | engine.* | EngineInternalError | CRITICAL |

### severity 設定（configurable）

既存の `ErrorSeverityConfig` をそのまま使用:

```typescript
const DEFAULT_ERROR_SEVERITY: ErrorSeverityConfig = {
    CRITICAL: ["TransportConnectionRefused", "EngineInternalError", "DbConnection"],
    WARNING: ["TransportTimeout", "HandlerTimeout", "HandlerException", "CallbackException"],
};
// → 上記以外は INFO
```

## 定性的検証

**筋が良い理由:**
- 既存の `classifyError()` と `ErrorPayloadProtocol` をそのまま活用（新規型の導入なし）
- error.message + context の組み合わせで分類するため、既存のemitSafeの引数をそのまま渡せる
- severity設定がconfigurableなので、利用者が自社のSeverityポリシーに合わせられる

**懸念と対策:**
- error.messageのパターンマッチは脆い → kind導出はRegExp配列で設定可能にし、フォールバックは"Unknown"
- 分類自体がエラーした場合 → try/catchで"ClassificationError" kindを生成。無限再帰しない
