# SDK エラー情報漏洩分析

## 概要

エラーメッセージやスタックトレースを通じた内部情報の漏洩リスクを評価する。

---

## チェック箇所一覧

### 1. ValidationError のメッセージ内容

**ファイル**: `src/validation/log-validator.ts`

| エラーメッセージ | 漏洩リスク | 評価 |
|-----------------|-----------|------|
| `validation(message): is required` | フィールド名の露出 | **低リスク** |
| `validation(type): invalid log type: ${input.type}` | ユーザ入力値の反復 | **低リスク** |
| `validation(level): must be integer 1-6` | 許可範囲の露出 | **低リスク** |
| `validation(origin): invalid origin: ${input.origin}` | ユーザ入力値の反復 | **低リスク** |
| `validation(tags[${i}].key): invalid or too long` | 配列インデックスの露出 | **低リスク** |
| `validation(_total): log exceeds max total size ~${L.maxTotalLogSize} bytes (estimated ${totalSize})` | サイズ制限値の露出 | **低リスク** |

**総合評価**: バリデーションエラーは SDK の公開API境界で発生し、呼び出し元（ユーザコード）に対して出力される。外部攻撃者に直接露出するシナリオは限定的。ただし、バリデーションエラーをそのまま HTTP レスポンスとして返却するアプリケーションの場合、内部スキーマが推測される。

**推奨対策**: ユーザ向けドキュメントに「ValidationError のメッセージをそのまま外部レスポンスに含めないこと」を記載。

### 2. ConfigLoadError のメッセージ内容

**ファイル**: `src/configs/config-loader.ts`

| エラーメッセージ | 漏洩リスク | 評価 |
|-----------------|-----------|------|
| `Config error [project_name]: is required and must be a string` | 設定スキーマの露出 | **低リスク** |
| `Config error [masking.rules[${i}].category]: invalid category "${rule.category}"` | ユーザ入力値の反復 | **低リスク** |
| `Config error [masking.rules[${i}].pattern]: is required for REGEX type` | 設定構造の露出 | **低リスク** |

**総合評価**: 設定ロードは初期化時に1回のみ発生。ランタイムで外部攻撃者に露出しない。

### 3. EventDetector のエラーメッセージ

**ファイル**: `src/core/detection/event-detector.ts`

| エラーメッセージ | 漏洩リスク | 評価 |
|-----------------|-----------|------|
| `detectionRules[${rule.ruleId}].conditions.messagePattern must be a RegExp instance, got ${typeof mp}` | ルールID、型情報の露出 | **低リスク** |
| `detectionRules[${rule.ruleId}].conditions.messagePattern must not have global (g) or sticky (y) flag` | フラグ制限の露出 | **低リスク** |

**総合評価**: 初期化時のバリデーションエラー。ランタイムでは発生しない。

### 4. ErrorRouter のエラー伝播

**ファイル**: `src/error-routing/error-router.ts`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| route() のエラーキャッチ | **OK** | `error-router.ts:40-43` — 最終防壁で `console.error` に出力 |
| execute() のエラーキャッチ | **OK** | `error-router.ts:89-92` — executor のエラーも `console.error` に出力 |
| 再帰防止 | **OK** | route() 内のエラーは route() に再投入されない |
| **console.error 出力内容** | **要注意** | `error-router.ts:42` — `err.message` を出力。エラーメッセージの内容次第でPII漏洩 |

**console.error リスク分析**:
```typescript
console.error(`[Sentinel:ErrorRouter] routing failed: ${err instanceof Error ? err.message : String(err)}`);
```
- `err.message` にPII を含むログメッセージが含まれる可能性がある
- **対策**: `MaskingService` によりログは事前にマスキング済み。エラーメッセージ内の生データはマスキング前の情報ではない
- **残留リスク**: マスキング前のエラー（normalizer段階のエラー等）はPIIを含む可能性がある

**推奨パッチ**:
```typescript
// error-router.ts の console.error 出力をPII安全にする
catch (err) {
    const safeMsg = err instanceof Error
        ? err.message.substring(0, 200)  // メッセージを切り詰め
        : "[non-Error thrown]";
    console.error(`[Sentinel:ErrorRouter] routing failed: ${safeMsg}`);
}
```

### 5. IngestionEngine のコールバックエラー

**ファイル**: `src/core/engine/ingestion-engine.ts`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| emitSafe() の例外隔離 | **OK** | コールバック例外がパイプラインに影響しない |
| コールバックエラーの出力 | **要注意** | `onError` コールバック自体が失敗した場合、`console.error` に内部エラーが出力される |

### 6. Sentinel クラスのエラーメッセージ

| エラーメッセージ | 漏洩リスク | 評価 |
|-----------------|-----------|------|
| `Sentinel must be initialized first. Call Sentinel.initialize(config).` | APIの使い方露出 | **低リスク** |
| `Sentinel is shutdown. Cannot ingest after shutdown.` | 状態の露出 | **低リスク** |
| `Transport timeout after ${timeoutMs}ms` | タイムアウト値の露出 | **低リスク** |

---

## error-utils の PII コンテキストマスキング

**ファイル**: `src/shared/utils/error-utils.ts`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| maskPiiContext() 実装 | **OK** | エラーコンテキストからPIIを除去 |
| キー長制限 | **OK** | 50文字に制限 |
| 配列長の切り詰め | **OK** | 長い配列は要素数のみ表示 |
| オブジェクトキーの列挙 | **OK** | 値ではなくキー名のみ表示 |

---

## Go サーバとの比較

| 項目 | SDK | Go Server |
|------|-----|-----------|
| gRPCエラーコード | N/A | `codes.Internal` + 汎用メッセージ |
| 内部詳細のログ出力 | `console.error` | `slog.Error` (サーバサイド) |
| クライアントへの詳細 | ValidationError のメッセージがそのまま | `"internal processing error"` (汎用) |

**ギャップ**: Go サーバは外部レスポンスで汎用エラーメッセージ (`"internal processing error"`) を返却するのに対し、SDK の ValidationError は詳細なフィールド名・制限値を含む。これはSDKがクライアントライブラリとして開発者に直接エラーを返す設計上、妥当。

---

## 総合判定

**評価: B+（良好）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| ValidationError の詳細度 | LOW | **設計上の選択** | ドキュメントで外部露出回避を案内 |
| console.error のPII残留 | LOW | **要改善** | メッセージ切り詰め推奨 |
| ErrorRouter の再帰防止 | — | **OK** | |
| error-utils のPIIマスキング | — | **OK** | |
| コールバック例外隔離 | — | **OK** | |
