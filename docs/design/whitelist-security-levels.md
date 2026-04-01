# ホワイトリスト セキュリティレベル運用ガイド

```yaml
created_at: "2026-04-01"
status: implemented
```

## 概要

`SentinelConfig.whitelist.level` で、ホワイトリスト検証の厳密さを制御する。これは**堅牢性 vs 柔軟性のトレードオフ**を明示的に設定する仕組みであり、パフォーマンスの最適化ではなく、セキュリティポスチャの選択である。

## レベル一覧

### `strict` — 本番環境・セキュリティ最優先

```typescript
whitelist: { level: "strict" }
```

- 全ドメイン検証（security, task, privacy）
- `extensions` は**無視**される — 組込み値のみ許可
- 不正値は `ValidationError` でブロック
- **用途**: 金融、医療、コンプライアンス要件が厳しい環境
- **トレードオフ**: カスタム拡張不可。全ての値が事前定義されている必要がある

### `standard` — 通常運用（デフォルト）

```typescript
whitelist: { level: "standard" }
// または省略（デフォルト）
```

- 全ドメイン検証
- `extensions` で追加値を許可
- 不正値は `ValidationError` でブロック
- **用途**: 一般的な本番環境。カスタムアクションやイベントを使う場合
- **トレードオフ**: extensions経由で任意の値を許可できるため、設定ミスのリスクは残る

### `permissive` — 段階的導入・移行期

```typescript
whitelist: { level: "permissive" }
```

- 全ドメイン検証
- 不正値は**警告のみ**（`logger.warn`）、ブロックしない
- `warnings` 配列で検出された問題を確認可能
- **用途**: 既存システムへのホワイトリスト導入時。まず警告で影響範囲を把握してからstandardに移行
- **トレードオフ**: 不正値が通過するため、セキュリティ機能が無効化される可能性あり

### `off` — 開発・デバッグ用

```typescript
whitelist: { level: "off" }
```

- 検証なし。全ての値が通過
- **用途**: ローカル開発、プロトタイピング
- **トレードオフ**: 設定ミスが検出されない。**本番環境では使用禁止**

## 環境ごとの推奨設定

| 環境 | 推奨レベル | 理由 |
|------|-----------|------|
| production | `strict` または `standard` | セキュリティ機能の無効化を防ぐ |
| staging | `standard` | 本番と同等の検証で問題を事前検出 |
| development | `standard` または `permissive` | 開発中の柔軟性を確保しつつ問題を警告 |
| local | `standard` または `off` | 高速な開発サイクル |
| test | `standard` | テスト時も本番と同じ検証を適用 |

## ドメイン単位の制御

`enabledDomains` でドメインを個別に有効/無効にできる:

```typescript
whitelist: {
    level: "standard",
    enabledDomains: ["security", "task"],  // privacy検証を無効化
}
```

| ドメイン | 検証対象 | 無効化のリスク |
|---------|---------|--------------|
| `security` | eventName, detectionPriority | 検知ルールのタイポが無言で通過 |
| `task` | actionType, severity, executionLevel | タスク生成・ディスパッチの設定ミスが無言で通過 |
| `privacy` | piiCategory | PIIマスキングルールのタイポでPIIが素通り |

## 拡張値の管理

`extensions` でカスタム値を追加:

```typescript
whitelist: {
    level: "standard",
    extensions: {
        eventName: ["CUSTOM_BUSINESS_EVENT"],
        actionType: ["CUSTOM_TICKET", "CUSTOM_ALERT"],
    },
}
```

- `strict` レベルでは extensions は無視される
- extensions は**追加**であり、組込み値を上書きしない
- 追加した値は全ての検証ポイント（初期化時 + onTaskAction実行時）で有効

## 検証ポイントの到達確認

ホワイトリストは以下のパイプラインステージで検証が効く:

```
Sentinel.initialize()
  └→ validateConfigWhitelists()
       ├→ EventDetector設定: eventName, detectionPriority
       ├→ TaskGenerator設定: eventName, severity
       ├→ TaskExecutor設定: actionType, executionLevel
       └→ MaskingService設定: piiCategory

Sentinel.onTaskAction()
  └→ whitelistRegistry.validate("actionType", ...)
```

各検証ポイントへの到達はE2Eテスト（`whitelist-routing-e2e.test.ts`）で保証されている。
