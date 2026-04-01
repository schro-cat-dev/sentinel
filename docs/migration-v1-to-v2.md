# v1 → v2 移行ガイド

## 破壊的変更

**v2にはv1からの破壊的変更はありません。** v1のコードはv2でそのまま動作します。

ただし以下の挙動変更があります:

### 1. `onTaskAction()` の戻り値

```typescript
// v1: void
sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);

// v2: () => void (dispose関数を返す)
const dispose = sentinel.onTaskAction("SYSTEM_NOTIFICATION", handler);
dispose(); // ハンドラ解除
```

v1のように戻り値を無視しても問題ありません。

### 2. configがdeepFreezeされる

v2では `Sentinel.initialize(config)` 後にconfigオブジェクトが凍結されます。初期化後の変更は `TypeError` をスローします。

```typescript
// v1: 可能だった（ただし非推奨）
config.security.enableHashChain = false;

// v2: TypeError
// 代わりにupdateCallbacks()を使用
sentinel.updateCallbacks({ onLogProcessed: newHandler });
```

### 3. shutdown後の操作がブロックされる

```typescript
// v1: shutdown後もingest()が動作した
await sentinel.shutdown();
await sentinel.ingest(...); // v1: 動作, v2: エラー
```

## 新機能の段階的導入

### Step 1: そのまま動かす（変更なし）

v1のコードをv2パッケージに差し替えるだけ。全機能はオプショナルです。

### Step 2: ホワイトリスト検証を追加

```typescript
const sentinel = Sentinel.initialize(createDefaultConfig({
    ...existingConfig,
    whitelist: { level: "permissive" }, // まず警告のみ
}));
```

問題なければ `"standard"` → `"strict"` へ段階的に上げる。

### Step 3: カスタム検知ルール追加

```typescript
detectionRules: [{
    ruleId: "my-rule",
    eventName: "SECURITY_INTRUSION_DETECTED",
    priority: "HIGH",
    conditions: { messagePattern: /brute.*force/i },
}],
```

### Step 4: メトリクス・トレーシング追加

```typescript
metrics: { onIngest: () => { /* Datadog/Prometheus */ } },
tracer: { onPipelineEnd: (ctx) => { /* OpenTelemetry */ } },
```

### Step 5: エラールーティング追加

```typescript
import { ConsoleAuditSink } from "@sentinel/client";
errorRouting: { enabled: true, sinks: { audit: new ConsoleAuditSink() } },
```
