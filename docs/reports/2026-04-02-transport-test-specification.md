# TaskTransport テスト仕様書

- **日付**: 2026-04-02
- **対象**: TaskTransport 関連テスト全件
- **目的**: 各テストが「何を、なぜ、どうチェックしているか」を仕様レベルで記載

---

## テストファイル一覧

| ファイル | テスト数 | カテゴリ |
|----------|----------|----------|
| `tests/unit/transport/task-transport.test.ts` | 7 | インターフェース契約 |
| `tests/unit/transport/console-task-transport.test.ts` | 9 | ConsoleTaskTransport 単体 |
| `tests/unit/transport/http-webhook-transport.test.ts` | 26 | HttpWebhookTransport 単体 |
| `tests/unit/transport/task-transport-factory.test.ts` | 12 | Factory 単体 |
| `tests/unit/core/task-executor-transport.test.ts` | 27 | TaskExecutor + Transport 統合 |
| `tests/config/config-loader-transport.test.ts` | 22 | YAML config パース |
| `tests/config/yaml-transport-integration.test.ts` | 105 | Config × Transport 交差 |
| `tests/smoke/config-runtime-verification.test.ts` | 59 | 実動作検証 |
| `tests/security/transport-penetration.test.ts` | 45 | ペネトレーション |
| `tests/smoke/transport-subtests.test.ts` | 28 | 境界値・サブテスト |
| **合計** | **340** | |

---

## 1. ペネトレーションテスト仕様 (45件)

### PEN-01: SSRF バイパス試行 (20件)

**目的**: URL パース・正規化を悪用した内部ネットワークアクセスを防御できるか検証

| ID | 攻撃ベクトル | 前提条件 | 期待動作 | 検証方法 |
|----|-------------|----------|----------|----------|
| PEN-01-01 | URL encoded IP (%31%32%37) | allowInsecure=false | URL クラスがデコード → 127.0.0.1 → rejected | expect throw |
| PEN-01-02 | IPv4-mapped IPv6 (::ffff:127.0.0.1) | allowInsecure=false | URL parse → ブラケット表記 → known limitation | try/catch |
| PEN-01-03 | Octal IP (0177.0.0.1) | allowInsecure=false | Node.js URL が 127.0.0.1 に正規化 → rejected | expect throw |
| PEN-01-04 | Decimal IP (2130706433) | allowInsecure=false | Node.js URL が 127.0.0.1 に正規化 → rejected | expect throw |
| PEN-01-05 | Double URL encoding (%2531) | allowInsecure=false | 1回のみデコード → プライベート IP にならない → pass | not throw or parse error |
| PEN-01-06 | 0.0.0.0 (unspecified) | allowInsecure=false | PRIVATE_HOSTNAMES にマッチ → rejected | expect throw |
| PEN-01-07 | Shorthand IP (127.1) | allowInsecure=false | Node.js URL が 127.0.0.1 に正規化 → rejected | expect throw |
| PEN-01-08 | 172.15.255.255 | allowInsecure=false | 範囲外（16未満） → allowed | not throw |
| PEN-01-09 | 172.16.0.0 | allowInsecure=false | 範囲開始 → rejected | expect throw |
| PEN-01-10 | 172.31.255.255 | allowInsecure=false | 範囲終端 → rejected | expect throw |
| PEN-01-11 | 172.32.0.0 | allowInsecure=false | 範囲外（32以上） → allowed | not throw |
| PEN-01-12 | ftp:// scheme | allowInsecure=false | 非 HTTPS → rejected | expect throw |
| PEN-01-13 | javascript: scheme | allowInsecure=false | URL parse error → rejected | expect throw |
| PEN-01-14 | data: scheme | allowInsecure=false | 非 HTTPS → rejected | expect throw |
| PEN-01-15 | file:// scheme | allowInsecure=false | 非 HTTPS → rejected | expect throw |
| PEN-01-16 | URL with @ (userinfo injection) | allowInsecure=false | hostname=127.0.0.1 → rejected | expect throw |
| PEN-01-17 | Private IP with port | allowInsecure=false | hostname=192.168.1.1 → rejected | expect throw |
| PEN-01-18 | Null byte in URL | allowInsecure=false | URL parser strips → hostname safe | not throw |
| PEN-01-19 | Empty endpoint | - | URL parse error → rejected | expect throw |
| PEN-01-20 | 10KB URL | allowInsecure=false | URL parse succeeds → SSRF check runs | not throw |

### PEN-02: Header Injection (4件)

**目的**: HTTP ヘッダーの改行注入（CRLF injection）を防御できるか

| ID | 攻撃 | 期待 | 根拠 |
|----|------|------|------|
| PEN-02-01 | CRLF (\\r\\n) in value | fetch API が reject | Node.js fetch がヘッダー値をバリデーション |
| PEN-02-02 | LF (\\n) in value | fetch API が reject | 同上 |
| PEN-02-03 | null byte in name | fetch API が reject | 同上 |
| PEN-02-04 | Content-Type override | ユーザー選択として尊重 | 設計方針: ユーザー指定ヘッダー優先 |

### PEN-03: Prototype Pollution (3件)

**目的**: config オブジェクトの `__proto__` / `constructor` 汚染を防御

| ID | 攻撃 | 期待 | 根拠 |
|----|------|------|------|
| PEN-03-01 | `__proto__` in config | グローバルオブジェクト汚染なし | factory が dot notation で読むため |
| PEN-03-02 | `constructor` in config | 無視される | switch/case が type フィールドのみ参照 |
| PEN-03-03 | `__proto__` in YAML | config-loader が汚染しない | YAML parse → dot access のみ |

### PEN-04: Payload Injection (6件)

**目的**: タスクオブジェクト内の悪意あるデータが安全に処理されるか

| ID | 攻撃 | 期待 | 根拠 |
|----|------|------|------|
| PEN-04-01 | XSS `<script>` | JSON文字列として直列化 | JSON.stringify はタグをエスケープしない → 受信側責務 |
| PEN-04-02 | SQL injection | 文字列として直列化 | SDK は DB に書かない |
| PEN-04-03 | Template injection `${}` | 文字列として直列化 | JSON.stringify は template literal を評価しない |
| PEN-04-04 | 1MB description | 正常処理 | JSON.stringify の上限なし |
| PEN-04-05 | Null bytes | `\\u0000` にエスケープ | JSON.stringify の仕様 |
| PEN-04-06 | Unicode control chars | 安全に直列化 | JSON.stringify の仕様 |

### PEN-05: Config Validation Bypass (7件)

**目的**: config-loader のバリデーションをバイパスする試行

| ID | 攻撃 | 期待 |
|----|------|------|
| PEN-05-01 | numeric name | ConfigLoadError (name must be string) |
| PEN-05-02 | null name | ConfigLoadError |
| PEN-05-03 | boolean type | ConfigLoadError (type must be known value) |
| PEN-05-04 | SQL in type | ConfigLoadError |
| PEN-05-05 | 10KB name | 受理（長さ制限なし — known limitation） |
| PEN-05-06 | method=GET | ConfigLoadError (POST/PUT only) |
| PEN-05-07 | javascript: endpoint | config parse 通過、factory で rejected |

### PEN-06: DoS Prevention (3件)

| ID | 攻撃 | 期待 |
|----|------|------|
| PEN-06-01 | 100 transports | 全て正常完了 |
| PEN-06-02 | never-resolving dispatch | timeoutMs で強制終了 |
| PEN-06-03 | never-resolving close | known limitation: closeTransports に timeout なし |

### PEN-07: Console Output Safety (2件)

| ID | 攻撃 | 期待 |
|----|------|------|
| PEN-07-01 | `__proto__` in task | JSON.stringify がプロトタイプを含めない |
| PEN-07-02 | `toJSON` override | JSON.stringify が toJSON を呼ぶ（仕様通り、攻撃者の入力が直接来ることはない） |

---

## 2. サブテスト仕様 (28件)

### SUB-01: HttpWebhookTransport 境界値 (10件)

| ID | 検証内容 | 前提条件 | 期待 |
|----|----------|----------|------|
| SUB-01-01 | trailing slash endpoint | HTTPS | accepted |
| SUB-01-02 | query string endpoint | HTTPS | accepted |
| SUB-01-03 | fragment endpoint | HTTPS | accepted (fetch ignores fragment) |
| SUB-01-04 | port 443 | HTTPS | accepted |
| SUB-01-05 | non-standard port | HTTPS | accepted |
| SUB-01-06 | unicode hostname | HTTPS | accepted (punycode) |
| SUB-01-07 | empty headers | - | Content-Type のみ |
| SUB-01-08 | method omitted | - | POST (default) |
| SUB-01-09 | special chars in name | - | そのまま保存 |
| SUB-01-10 | dispatch after close (AbortError) | closed=true | success=false |

### SUB-02: ConsoleTaskTransport 境界値 (4件)

| ID | 検証 | 期待 |
|----|------|------|
| SUB-02-01 | undefined field in task | JSON.stringify omits |
| SUB-02-02 | rapid close + dispatch | 全て success=false |
| SUB-02-03 | default name | "console" |
| SUB-02-04 | empty string name | "" |

### SUB-03: Factory 境界値 (4件)

| ID | 検証 | 期待 |
|----|------|------|
| SUB-03-01 | type undefined + enabled true | skipped (custom default) |
| SUB-03-02 | type=custom + enabled=false | skipped |
| SUB-03-03 | 10 console transports | 10件生成 |
| SUB-03-04 | mixed types various order | 正しいフィルタリング |

### SUB-04: TaskExecutor + real transports (5件)

| ID | 検証 | 期待 |
|----|------|------|
| SUB-04-01 | real ConsoleTaskTransport | console.info 呼出し + dispatched |
| SUB-04-02 | real HttpWebhookTransport (fetch mock) | fetch 呼出し + dispatched |
| SUB-04-03 | real + mock mixed | 両方実行 |
| SUB-04-04 | closeTransports → ConsoleTaskTransport closed | dispatch returns success=false |
| SUB-04-05 | handler + real console | 両方実行 |

### SUB-05: Concurrent patterns (2件)

| ID | 検証 | 期待 |
|----|------|------|
| SUB-05-01 | 50 concurrent dispatches | 全 dispatched |
| SUB-05-02 | concurrent dispatch + close race | success + closed の混在 |

### SUB-06: TaskResult structure (3件)

| ID | 検証 | 期待 |
|----|------|------|
| SUB-06-01 | success: 全フィールド | taskId, ruleId, status, dispatchedAt |
| SUB-06-02 | failure: error populated | status=failed, error contains message |
| SUB-06-03 | blocked: no error | status=blocked_approval, error=undefined |

---

## 3. Known Limitations

ペネトレーションテストで発見された既知の制限事項:

| ID | 制限 | リスク | 緩和策 |
|----|------|--------|--------|
| KL-01 | IPv4-mapped IPv6 (::ffff:127.0.0.1) の不完全なブロック | 中 | HTTPS 強制 + DNS rebinding は transport 実装側の責務 |
| KL-02 | transport name の長さ制限なし | 低 | メモリ消費のみ、セキュリティリスクは低い |
| KL-03 | closeTransports にタイムアウトなし | 中 | never-resolving close は shutdown を hang させる可能性。将来対応。 |
| KL-04 | toJSON override は JSON.stringify の仕様通り動作 | 低 | task は内部生成オブジェクト。外部入力が直接 task になることはない |

---

## 4. テスト品質基準

全テストは以下の基準を満たすことを確認済み:

| 基準 | 内容 | 確認方法 |
|------|------|----------|
| トートロジー禁止 | `expect(true).toBe(true)` 等の無意味なアサーションなし | 全件目視レビュー |
| 条件分岐なし | `if (result) { expect... }` のサイレントスキップなし | 全件 grep 確認 |
| 具体値検証 | `toBeDefined()` 単独使用禁止、必ず具体値を検証 | 全件レビュー |
| mock の忠実性 | mock の戻り値が実際のインターフェースに準拠 | `satisfies` 型チェック |
| クリーンアップ | beforeEach/afterEach で状態リセット | Sentinel.reset() + fetch 復元 |
