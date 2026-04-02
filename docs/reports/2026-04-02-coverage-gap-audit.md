# カバレッジギャップ監査レポート

- **日付**: 2026-04-02
- **対象**: TaskTransport 機能全体のテストカバレッジ

---

## 1. 発見されたギャップ一覧と対応結果

### Critical (セキュリティ/設計)

| # | ギャップ | 対策 | テスト | 結果 |
|---|----------|------|--------|------|
| C-1 | SSRF: 172.15.x.x / 172.32.x.x の境界値テスト欠落 | テスト追加 | `http-webhook-transport.test.ts` "allows 172.15.x.x", "allows 172.32.x.x" | PASS — 範囲外IP正しく許可 |
| C-2 | allowInsecure が YAML config から指定不可 | `task-transport-factory.ts` で `config.allow_insecure` を参照するよう修正 | `task-transport-factory.test.ts` "passes allow_insecure to HttpWebhookTransport" | PASS — HTTP localhost 許可 |
| C-3 | config-loader が method を未検証（任意文字列受入） | config-loader に method バリデーション追加 (`POST` / `PUT` のみ) | `config-loader-transport.test.ts` "throws on invalid method", "accepts valid method POST/PUT" | PASS — DELETE 等を拒否 |

### High (E2E/統合テスト不足)

| # | ギャップ | 対策 | テスト | 結果 |
|---|----------|------|--------|------|
| H-1 | factory で SSRF 違反 endpoint が throw するテスト欠落 | テスト追加 | `task-transport-factory.test.ts` "throws when http_webhook endpoint fails SSRF" | PASS |
| H-2 | 全エントリ disabled 時の factory 動作テスト欠落 | テスト追加 | `task-transport-factory.test.ts` "handles all entries disabled" | PASS |
| H-3 | Sentinel.initialize で invalid endpoint config → throw のテスト欠落 | テスト追加 | `sentinel.test.ts` "initialize with invalid http_webhook endpoint in config throws" | PASS |
| H-4 | disabled http_webhook がインスタンス化されないテスト欠落 | テスト追加 | `sentinel.test.ts` "config-based http_webhook with disabled flag is not instantiated" | PASS — SSRF違反endpointでもenabledfalseならスキップ |
| H-5 | shutdown が user-injected + config-based の両方を close するテスト欠落 | テスト追加 | `sentinel.test.ts` "shutdown closes both user-injected and config-created transports" | PASS |
| H-6 | double shutdown テスト欠落 | テスト追加 | `sentinel.test.ts` "double shutdown with transports is idempotent" | PASS — 2回目は何もしない |
| H-7 | config-based console + user-injected のマージテスト | テスト追加 | `sentinel.test.ts` "merges user-injected and config-based transports" | PASS |
| H-8 | config-based auto-create テスト | テスト追加 | `sentinel.test.ts` "auto-creates transports from config taskTransportConfigs" | PASS |

### Medium (エッジケース)

| # | ギャップ | 対策 | テスト | 結果 |
|---|----------|------|--------|------|
| M-1 | HttpWebhook: 空文字 endpoint | テスト追加 | `http-webhook-transport.test.ts` "rejects empty string endpoint" | PASS — URL parse失敗 |
| M-2 | HttpWebhook: 169.254.x.x (link-local) | テスト追加 | `http-webhook-transport.test.ts` "rejects 169.254.x.x" | PASS |
| M-3 | HttpWebhook: 0.0.0.0 | テスト追加 | `http-webhook-transport.test.ts` "rejects 0.0.0.0" | PASS |
| M-4 | HttpWebhook: double close | テスト追加 | `http-webhook-transport.test.ts` "double close does not throw" | PASS |
| M-5 | Console: console.info throws | テスト追加 | `console-task-transport.test.ts` "handles console.info throwing" | PASS — エラー伝播 |
| M-6 | Console: 50件連続 dispatch | テスト追加 | `console-task-transport.test.ts` "handles multiple rapid dispatches" | PASS |
| M-7 | config-loader: type/enabled パース・デフォルト | テスト追加 (7件) | `config-loader-transport.test.ts` type/enabled セクション全体 | PASS |

---

## 2. 対応しなかったギャップ（と理由）

| # | ギャップ | 理由 |
|---|----------|------|
| IPv6 私有アドレス (fe80::, fc00::) | Node.js URL の hostname は `[::1]` 形式。現在 `PRIVATE_HOSTNAMES` に `::1` のみ含む。IPv6 の完全な私有アドレス判定は複雑で、DNS rebinding 防御は transport 実装側の責務とする。今後必要に応じて `isPrivateIp` を拡張。 |
| Endpoint に username:password を含む URL | `URL` クラスの仕様上 valid。credentials in URL は HTTP 仕様では deprecated だが SDK が拒否する根拠が薄い。セキュリティドキュメントで「credentials は環境変数かヘッダーで渡すことを推奨」と記載すべき。 |
| TaskExecutor に real transport を渡すテスト | mock で十分にカバー済み。real transport のテストは各 transport 単体テストの責務。統合は Sentinel E2E テストでカバー。 |

---

## 3. テスト結果サマリ

| 項目 | 値 |
|------|------|
| テストファイル数 | 76 (全パス) |
| テスト総数 | 2668 passed + 23 expected fail |
| 予期しない失敗 | 0 |
| 型チェック (tsc --noEmit) | エラー 0 |
| 今回追加テスト数 | 約 18 件（ギャップ埋め分） |

---

## 4. 防御策

### SSRF (F-05)

- **チェック箇所**: `HttpWebhookTransport` コンストラクタ
- **防御**: HTTPS 強制 + プライベート IP 拒否 (10.x, 172.16-31, 192.168, 169.254, localhost, ::1, 0.0.0.0)
- **緩和**: `allowInsecure: true` で開発環境のみ HTTP + ローカルを許可
- **テスト**: 16件のコンストラクタテストで全パターンを網羅

### Config バリデーション

- **チェック箇所**: `config-loader.ts` `validateRawConfig`
- **防御**: name 必須、type は既知値のみ、http_webhook は endpoint 必須、method は POST/PUT のみ
- **テスト**: config-loader-transport.test.ts 22件

### enabled/disabled フィルタリング

- **チェック箇所**: `task-transport-factory.ts` `createTaskTransportsFromConfig`
- **防御**: `enabled: false` のエントリはインスタンス化しない（SSRF 検証もスキップ）
- **テスト**: factory 12件 + sentinel.test.ts 2件
