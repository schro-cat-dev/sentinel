# セキュリティテスト一覧・攻撃ベクトル網羅性

**テスト数:** 1,203
**対象:** `tests/security/`

## 攻撃ベクトル × テストカバレッジ

| 攻撃ベクトル | CWE | テストファイル | テスト数 | 検証内容 |
|-------------|-----|--------------|---------|---------|
| ReDoS | CWE-1333 | redos.test.ts | 5 | CREDIT_CARD/EMAIL/カスタムRegexの計算量爆発耐性。50ms閾値 |
| Prototype Pollution | CWE-1321 | prototype-pollution.test.ts | 5 | __proto__/constructor注入でObject.prototypeが汚染されない |
| Input Validation Bypass | CWE-20/626 | input-validation-bypass.test.ts | 19 | null byte/型強制/境界値/空白/tag/resourceId制限 |
| PII Masking Bypass | CWE-200 | masking-bypass.test.ts | 18 | 全PIIカテゴリの正常マスク+回避試行。国際電話、KEY_MATCH大小文字 |
| Hash Chain Tamper | CWE-354 | integrity-chain.test.ts | 16 | メッセージ/レベル/タイムスタンプ改竄検知。チェーン順序。SHA-256特性 |
| Information Leakage | CWE-209 | information-leakage.test.ts | 5 | エラーメッセージにファイルパス/スタックトレースが含まれない |
| Timing Side-Channel | CWE-208 | new-findings-v2.test.ts | 3 | timingSafeEqual使用。異なる長さのハッシュ拒否 |
| Race Condition | CWE-362 | new-findings-v2.test.ts | 1 | 5並行ingestでhash chainが整合 |
| Stateful Regex | CWE-185 | new-findings-v2.test.ts | 2 | isPiiSafe連続呼出で検出率が交互にならない |
| Transport PII Leak | CWE-319 | new-findings-v2.test.ts | 2 | normalizeOnlyがマスク適用。remote/dualで未マスク送信しない |
| Config Override | CWE-1188 | new-findings-v2.test.ts | 2 | deep-mergeでsecurity設定が丸ごと消えない |
| Type Mismatch | CWE-704 | new-findings-v2.test.ts | 2 | agentBackLogのオブジェクト/配列型検証 |
| Retry DoS | CWE-770 | new-findings-v2.test.ts | 1 | safe()リトライ上限10 |
| KEY_MATCH Case | — | new-findings-v2.test.ts | 1 | PASSWORD大文字がsensitiveKeys=["password"]でマスク |
| rawLog PII Leak | CWE-200 | new-findings-v2.test.ts | 1 | 検知ペイロードにactorId/input/detailsが含まれない |
| Ghost Entry | CWE-460 | new-findings-v2.test.ts | 1 | コールバック例外後のhash chainゴースト防止 |
| Message Required | CWE-20 | new-findings-v2.test.ts | 2 | undefined/nullメッセージの拒否 |
| Fuzzing Inputs | CWE-20 | fuzzing-inputs.test.ts | 102 | ランダム/構造化ファズ入力による未知のクラッシュ検出 |
| Encoding Bypass | CWE-838 | encoding-bypass.test.ts | 111 | Unicode/Base64/URL/HTML/混合エンコードによるバリデーション回避 |
| PII Masking Advanced | CWE-200 | pii-masking-advanced.test.ts | 158 | 国際形式/部分マスク/コンテキスト依存/多言語PIIパターン |
| Injection Attacks | CWE-74 | injection-attacks.test.ts | 382 | SQL/NoSQL/LDAP/XPath/コマンド/テンプレート/ヘッダ注入 |
| Crypto Attacks | CWE-310 | crypto-attacks.test.ts | 100 | HMAC偽造/鍵推測/ハッシュ衝突/ダウングレード攻撃 |
| State Manipulation | CWE-362 | state-manipulation.test.ts | 80 | 並行状態変更/TOCTOU/チェーン分岐/不整合復旧 |
| Type Confusion | CWE-843 | type-confusion.test.ts | 94 | 型強制/プロトタイプチェーン/Symbol/Proxy/toString悪用 |
| DoS Resource Exhaustion | CWE-400 | dos-resource-exhaustion.test.ts | 50 | メモリ枯渇/CPU枯渇/深いネスト/巨大ペイロード |
| Config Injection | CWE-15 | config-injection.test.ts | 71 | 設定値注入/環境変数汚染/デフォルト上書き/型変換 |
| Transport Security | CWE-319 | transport-security.test.ts | 55 | TLS検証/証明書ピニング/ダウングレード/中間者攻撃 |

## テスト設計根拠

### なぜこの攻撃ベクトルを選んだか

1. **ReDoS**: ログメッセージはユーザー入力由来。正規表現処理が必須のためReDoSは最大の内部リスク
2. **Prototype Pollution**: `config`と`rule`がJSONデシリアライズ由来の可能性。スプレッド演算子で伝播
3. **Input Validation Bypass**: SDK公開APIの信頼境界。ここを突破されると内部全モジュールに影響
4. **PII Masking Bypass**: Sentinelの中核価値の一つ。エンコード回避・パターン漏れは直接的なPII漏洩
5. **Hash Chain Tamper**: 改竄検知はセキュリティ保証の根幹。1ビット変更でも検出必須
6. **Timing Side-Channel**: hash検証がネットワーク越しに呼ばれる可能性。Brumley-Boneh 2003
7. **Race Condition**: Node.jsのasync/awaitは並行性を持つ。共有状態(previousHash)の保護が必須

### なぜこのテスト数か

- **高リスク（ReDoS, Prototype, Validation, Masking, Hash）**: 5-19テスト — 境界値・複数パターン
- **中リスク（Timing, Race, Config）**: 1-3テスト — 原理的に1パターンで検証可能
- **修正リグレッション**: 各修正に1テスト — 再発防止が目的
- **高度攻撃（Injection, Fuzzing, Encoding, Crypto, DoS）**: 50-382テスト — 実攻撃パターンの網羅的再現
