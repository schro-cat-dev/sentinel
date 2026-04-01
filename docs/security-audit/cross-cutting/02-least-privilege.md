# 最小権限の原則 (Principle of Least Privilege) 遵守状況

## 概要

Sentinel の各コンポーネントにおける最小権限の原則の遵守状況を評価する。

---

## 1. SDK クライアント側

### 1.1 API 表面積の最小化

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| Public API の最小化 | **OK** | `Sentinel` クラスの公開メソッドは6つのみ: `initialize`, `getInstance`, `reset`, `shutdown`, `ingest`, `onTaskAction`, `onTaskConfirm`, `updateCallbacks`, `getConfig` |
| 内部モジュールの非公開 | **OK** | `IngestionEngine`, `LogNormalizer` 等は export されていない |
| 型のみの export | **OK** | 多くの型は `export type` で型情報のみ公開 |

### 1.2 設定の最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| マスキングデフォルト無効 | **要注意** | `masking.enabled: false` がデフォルト — PII保護が明示的な有効化を要する |
| ハッシュチェーンデフォルト有効 | **OK** | `security.enableHashChain: true` |
| 環境デフォルト | **OK** | `development` — 本番設定は明示的に変更が必要 |

**マスキングデフォルト無効のリスク分析**:
- ユーザがマスキングを有効化し忘れた場合、PIIが平文でログに含まれる
- **緩和**: 設定バリデーションで本番環境時にマスキング無効の警告を出すことを推奨

**推奨パッチ**:
```typescript
// sentinel-config.ts の createDefaultConfig 内
if (config.environment === "production" && !config.masking.enabled) {
    config.logger?.warn(
        "Masking is disabled in production environment. PII may appear in logs.",
        { source: "sentinel" }
    );
}
```

### 1.3 トランスポートの最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| デフォルトモード | **OK** | `local` — ネットワーク通信なし |
| リモート接続は明示的 | **OK** | `remote` / `dual` は明示的な設定が必要 |
| トランスポート注入 | **OK** | ユーザが明示的に gRPC クライアントを注入 |

### 1.4 コールバックの権限分離

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| SafeLogSubset の使用 | **OK** | タスクハンドラには `input`, `details`, `actorId` を含まないサブセットが渡される |
| PII除去済みデータ | **OK** | マスキング後のデータがハンドラに渡る |

---

## 2. Go Server 側

### 2.1 RBAC の権限分離

| 権限 | 説明 | 最小権限原則 | 判定 |
|------|------|------------|------|
| `CanWrite` | ログの投入 | ログ投入クライアントのみに付与 | **OK** |
| `CanRead` | タスク/ログの参照 | 参照のみのクライアントに付与 | **OK** |
| `CanApprove` | タスクの承認/拒否 | 管理者のみに付与 | **OK** |
| `CanAdmin` | 設定変更 | スーパー管理者のみ | **OK** |

### 2.2 LogType/Level によるアクセス制御

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| AllowedLogTypes | **OK** | クライアントが投入可能なログタイプを制限 |
| DeniedLogTypes | **OK** | 明示的に禁止されたログタイプ |
| MaxLogLevel | **OK** | クライアントが投入可能な最大レベル |

**使用例**:
```yaml
authorization:
  roles:
    monitoring:
      allowed_log_types: ["INFRA", "SYSTEM"]
      max_log_level: 4
      can_write: true
      can_read: true
      can_approve: false
      can_admin: false
    security_admin:
      allowed_log_types: ["SECURITY", "COMPLIANCE"]
      max_log_level: 6
      can_write: true
      can_read: true
      can_approve: true
      can_admin: false
```

### 2.3 HealthCheck の公開

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 認証不要 | **OK** | ヘルスチェックは認証不要（ロードバランサ用） |
| 情報最小化 | **OK** | `SERVING` ステータスのみ返却 |
| **バージョン非公開** | **OK** | バージョン情報はHealthCheckに含まれない |

### 2.4 データベースアクセスの最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 単一プロセスアクセス | **OK** | SQLite は単一プロセスでの使用を前提 |
| ファイルシステム権限 | **要確認** | データベースファイルのパーミッション |
| **アプリケーション権限** | **OK** | Go プロセスは必要最小限のファイルアクセス |

### 2.5 外部通知の最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 通知先の明示的設定 | **OK** | 各プロバイダは設定で明示的に有効化 |
| 通知内容の最小化 | **要注意** | 通知ペイロードにログメッセージが含まれる可能性。マスキング済みデータを使用すべき |
| ルーティングルール | **OK** | プレフィックスベースのルーティングで通知先を制御 |

### 2.6 Agent Bridge の最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| AllowedActions | **OK** | `cfg.Agent.AllowedActions` で許可アクションを制限 |
| MinSeverity | **OK** | 最低重大度以上のタスクのみAI処理 |
| LoopDepth制限 | **OK** | 最大再帰深度で無限ループ防止 |
| デフォルトアクション | **OK** | 未設定時は `AI_ANALYZE` のみ許可 |

---

## 3. 設定セキュリティレベル

### SDK のホワイトリストレベル

| レベル | 説明 | 最小権限度 |
|--------|------|-----------|
| `strict` | 全ドメインで厳格検証 | **最高** |
| `standard` | 標準検証 | **高** |
| `permissive` | 緩和検証 | **中** |
| `off` | 検証無効 | **最低** |

**推奨**: 本番環境では `strict` または `standard` を使用。

---

## 4. ネットワークレベルの最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| gRPC ポートの単一公開 | **OK** | 単一ポートのみリッスン |
| HTTP エンドポイントなし | **OK** | gRPC のみ（HTTPゲートウェイなし） |
| TLS オプション | **OK** | TLSを有効化可能 |
| **バインドアドレスの制限** | **要確認** | `0.0.0.0:port` でバインドする場合、全インターフェースで受け付ける |

---

## 5. プロセスレベルの最小権限

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| root 実行の回避 | **推奨事項** | Docker で非rootユーザでの実行を推奨 |
| ファイルシステム制限 | **推奨事項** | 設定ファイルとDBファイルのみアクセス |
| ネットワーク制限 | **推奨事項** | outbound は Webhook URL と AI Provider URL のみ |
| seccomp プロファイル | **推奨事項** | コンテナ環境で制限的なseccompプロファイルを適用 |

---

## 総合判定

**評価: A-（良好）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| API 表面積 | — | **OK** | 最小限の公開API |
| RBAC 粒度 | — | **OK** | 4レベル + LogType/Level制限 |
| SafeLogSubset | — | **OK** | PIIをハンドラから隔離 |
| マスキングデフォルト無効 | LOW | **要改善** | 本番環境での警告追加 |
| Agent AllowedActions | — | **OK** | デフォルト最小 |
| 通知内容の最小化 | LOW | **要確認** | マスキング済みデータの使用確認 |
| プロセスレベル制限 | — | **推奨事項** | ドキュメントに記載 |
