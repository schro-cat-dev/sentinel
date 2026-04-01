# Sentinel セキュリティ監査レポート v2（統合最終版）

**監査日:** 2026-03-30
**対象:** v0.1.0-alpha.2 / commit 19791fc
**手法:** 手動コードレビュー + 自動スキャン（Trivy, Gitleaks, npm audit, カスタムルール）
**スコープ:** `src/` 全14ファイル、モジュール間依存・データフロー全体

---

## スキャン結果サマリ

| ツール | 結果 |
|--------|------|
| Trivy (Docker分離) | Clean — 0 findings |
| Gitleaks (Docker分離) | Clean — シークレットなし |
| npm audit | 25件（全devDeps、ランタイム影響なし） |
| カスタムルール | 3件（既知: 動的RegExp×2, insecure gRPC×1） |
| **手動レビュー** | **15件の新規所見（第2回監査で発見）** |

---

## 第2回監査で新たに発見された脆弱性

### NEW-01: タイミングサイドチャネル — ハッシュ比較 (HIGH)

**ファイル:** `src/security/integrity-signer.ts:55`
**CWE:** CWE-208 (Observable Timing Discrepancy)

```typescript
return computed === log.hash;  // ← 非定数時間比較
```

**問題:** JavaScriptの `===` は最初の不一致バイトで短絡する。Goサーバが検証APIを公開した場合、攻撃者はレスポンス時間の微差からバイト単位でハッシュを推定できる。

**影響:** ハッシュチェーン偽造の可能性（ネットワーク越しの計測が前提）

**対策:**
```typescript
import { timingSafeEqual } from "node:crypto";
return timingSafeEqual(Buffer.from(computed), Buffer.from(log.hash));
```

**防御モジュール割当:** `IntegritySigner.verifyHash()` — **未パッチ**

---

### NEW-02: レースコンディション — ハッシュチェーン並行破壊 (HIGH)

**ファイル:** `src/core/engine/ingestion-engine.ts:66-69`
**CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)

```typescript
const previousHash = this.signer.getPreviousHash();  // L66: read
log.previousHash = previousHash;                       // L67
log.hash = IntegritySigner.calculateHash(log, previousHash); // L68: compute
this.signer.updateChain(log.hash);                     // L69: write
```

**問題:** `handle()` は `async` で、L81の `await this.taskExecutor.dispatch(task)` でイベントループに制御を戻す。2つの `ingest()` が並行実行されると:

1. Call A: L66で `previousHash=""` を読む
2. Call A: L81で `await dispatch()` — ここでyield
3. Call B: L66で同じ `previousHash=""` を読む（Aの更新前）
4. Call B: L68-69でハッシュ計算・チェーン更新
5. Call A: 再開し、**staleな `previousHash`** でL68-69を実行

結果: 2つのログが同じ `previousHash` を持つフォークチェーンが発生。完全性検証が不可能になる。

**影響:** ハッシュチェーンの改竄検知能力の完全な喪失

**対策:** async mutexパターン:
```typescript
private chainLock = Promise.resolve();
async handle(raw: Partial<Log>): Promise<IngestionResult> {
    const release = this.chainLock;
    let resolve: () => void;
    this.chainLock = new Promise(r => resolve = r);
    await release;
    try { return await this.handleInternal(raw); }
    finally { resolve!(); }
}
```

**防御モジュール割当:** `IngestionEngine.handle()` — **未パッチ**

---

### NEW-03: マスキングが `message` のみ — `input`/`details`/`tags` は素通し (HIGH)

**ファイル:** `src/core/engine/ingestion-engine.ts:53-61`
**CWE:** CWE-200 (Exposure of Sensitive Information)

```typescript
if (this.config.masking.enabled) {
    const maskedMessage = MaskingService.mask(
        log.message,  // ← messageだけ
        ...
    ) as string;
    log.message = maskedMessage;
}
```

**問題:** パイプラインは `log.message` のみをマスクする。`MaskingService.mask()` 自体はオブジェクト全体を再帰マスクする能力を持つ（L47-135）が、`IngestionEngine` がそれを呼ばない。

**素通しするフィールド:**
- `log.input` — `JSONValue` 型で任意のネストされた文字列を含む
- `log.details` — 文字列フィールド
- `log.tags[].key / .category` — 文字列配列
- `log.actorId` — ユーザーID
- `log.aiContext` — AIエージェント情報

開発者が `log.input` にクレジットカード番号を含めた場合、マスクされずにGoサーバ・コールバック・タスクハンドラに流出する。

**対策:**
```typescript
const maskedLog = MaskingService.mask(log, rules, preserveFields) as Log;
// maskedLogをパイプラインの以降に渡す
```

**防御モジュール割当:** `IngestionEngine` (マスキング処理) — **未パッチ**

---

### NEW-04: `isPiiSafe()` のステートフルRegExp — 交互に検出漏れ (HIGH)

**ファイル:** `src/shared/utils/error-utils.ts:6-26`
**CWE:** CWE-185 (Incorrect Regular Expression)

```typescript
const PII_PATTERNS: readonly RegExp[] = [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,  // /g フラグ付き
    // ... 全て /g フラグ
];

export const isPiiSafe = (value: string): boolean => {
    return !PII_PATTERNS.some((pattern) => pattern.test(value));
};
```

**問題:** `/g` フラグ付きRegExpは `lastIndex` を保持するステートフルオブジェクト。`test()` は呼び出しごとに `lastIndex` を進め、末尾に達すると0にリセットする。

モジュールスコープの定数であるため、連続呼び出しで:
```
isPiiSafe("test@example.com") → false (正: PII検出)
isPiiSafe("test@example.com") → true  (誤: 検出漏れ!)
isPiiSafe("test@example.com") → false (正: PII検出)
```

**影響:** PII検出の50%が偽陰性。攻撃者は偶数回目の呼び出しでPIIを通過させられる。

**対策:** `/g` フラグを除去（`test()` には不要）:
```typescript
/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/i,  // gを削除
```

**防御モジュール割当:** `error-utils.isPiiSafe()` — **未パッチ**

---

### NEW-05: remote/dualモードで未マスクPIIを送信 (HIGH)

**ファイル:** `src/index.ts:104-107, 118-125`
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

```typescript
// remote mode
const normalized = this.engine.normalizeOnly(log);  // ← マスクなし
return await this.transportConfig.transport.send(normalized);

// dual mode
const normalized = this.engine.normalizeOnly(log);  // ← 同じ。生ログを送信
await this.transportConfig.transport.send(normalized);
```

**問題:** `normalizeOnly()` はマスキングを行わない。`handle()` で行われるマスキング済みログではなく、元の `raw` 入力（`log` パラメータ）を正規化して送信している。

**データフロー:**
```
ingest(rawLog)
├── remote mode: normalizeOnly(rawLog) → transport.send(UNMASKED)
├── dual mode:
│   ├── handle(rawLog) → local (masked ✓)
│   └── normalizeOnly(rawLog) → transport.send(UNMASKED ✗)
└── local mode: handle(rawLog) → local (masked ✓)
```

**影響:** remote/dualモードでPIIがTLS有無にかかわらず外部サーバに平文で送信される。

**対策:** transport送信前にマスキングを適用:
```typescript
// dual mode
const maskedResult = await this.engine.handle(log);
// handle()結果のログを送信するか、normalizeOnly後にmaskを適用
```

**防御モジュール割当:** `Sentinel.ingest()` (transport送信経路) — **未パッチ**

---

### NEW-06: `rawLog` 参照がイベント→タスク→ハンドラに伝播 (MEDIUM)

**ファイル:** `src/core/detection/event-detector.ts:38`
**CWE:** CWE-200

```typescript
payload: {
    ip: EventDetector.extractIp(log),
    severity: log.level,
    rawLog: log,   // ← 参照渡し。log全体がタスクハンドラに到達
},
```

**問題:** `log` はオブジェクト参照で、マスク済みの `message` は含むが、`input`, `details`, `actorId` 等はNEW-03の通り未マスク。このペイロードが `TaskGenerator.generate()` → `TaskExecutor.dispatch()` → ユーザー定義ハンドラまで伝播し、`EXTERNAL_WEBHOOK` や `SYSTEM_NOTIFICATION` アクションタイプで外部送信される。

**防御モジュール割当:** `EventDetector.detect()` — **未パッチ**

---

### NEW-07: `NaN`/`Infinity`/`-0` によるハッシュ衝突 (MEDIUM)

**ファイル:** `src/security/integrity-signer.ts:67, 90-93`
**CWE:** CWE-354

```typescript
// deterministicStringify:
if (val === null || typeof val !== "object") {
    return JSON.stringify(val);  // JSON.stringify(NaN) → "null"
}

// isJsonValue:
if (type === "number") return true;  // NaN, Infinity を通す
```

**問題:** `typeof NaN === "number"` は `true`。`JSON.stringify(NaN) === "null"`、`JSON.stringify(Infinity) === "null"`。
つまり `level: NaN` と `level: null` が同じハッシュになる。入力バリデーション（`Number.isInteger(level)`）で通常は防御されるが、`input` フィールド（`JSONValue` 型）経由なら `NaN` を注入可能。

**防御モジュール割当:** `IntegritySigner.isJsonValue()` — **未パッチ**

---

### NEW-08: `onLogProcessed` 例外でハッシュチェーンがゴースト化 (MEDIUM)

**ファイル:** `src/core/engine/ingestion-engine.ts:69, 87`
**CWE:** CWE-460 (Improper Cleanup on Thrown Exception)

```typescript
this.signer.updateChain(log.hash);        // L69: チェーン更新（不可逆）
// ... L74-84: タスク処理
this.config.onLogProcessed?.(log);         // L87: ← ここで例外が発生すると
// → ingest()のPromiseがrejectされる
// → 呼び出し元は「処理失敗」と認識してリトライ
// → リトライでは新しいhashが生成される
// → L69で更新済みの「ゴーストエントリ」がチェーンに残る
```

**影響:** チェーン上に対応するログがないハッシュエントリが残り、検証時にギャップとして検出される。

**防御モジュール割当:** `IngestionEngine.handle()` — **未パッチ**

---

### NEW-09: `createDefaultConfig` のスプレッドでセキュリティ設定上書き (MEDIUM)

**ファイル:** `src/configs/sentinel-config.ts:45-51`
**CWE:** CWE-1188 (Initialization with Hard-Coded Network Resource Configuration Reference)

```typescript
export const createDefaultConfig = (overrides) => ({
    environment: "development",
    masking: { enabled: false, rules: [], preserveFields: [...] },
    security: { enableHashChain: true },
    taskRules: [],
    ...overrides,  // ← overridesがsecurity全体を上書き
});
```

**問題:** `...overrides` は浅いマージ。`overrides.security = { enableHashChain: false }` で
ハッシュチェーンが無効化される。config JSONを外部ソース（ファイル、API）から読む場合、攻撃者が設定注入でセキュリティ機能を全無効化できる。

**防御モジュール割当:** `createDefaultConfig()` — **未パッチ**

---

### NEW-10: `agentBackLog` バリデーション型不一致 (MEDIUM)

**ファイル:** `src/validation/log-validator.ts:108-109` vs `src/types/log.ts`
**CWE:** CWE-704 (Incorrect Type Conversion)

```typescript
// validator: 配列を期待
if (!Array.isArray(input.agentBackLog)) {
    throw new ValidationError("agentBackLog", "must be array");
}

// types/log.ts: 単一オブジェクトを定義
agentBackLog?: AIAgentEventBacklog;  // ← 配列ではない
```

**問題:** バリデーターとTypeScript型定義が矛盾。正しいTS型のオブジェクトを渡すとバリデーションで拒否される。配列を渡すとバリデーションは通過するがTS型と不一致。

**防御モジュール割当:** `validateLogInput()` — **未パッチ**

---

### NEW-11: `validateLogInput` が `message` 未定義を許容 (MEDIUM)

**ファイル:** `src/validation/log-validator.ts:34`

```typescript
if (input.message !== undefined && input.message !== null) {
    // message が undefined の場合、この行ごとスキップ
    // → normalizer L26: raw.message!.trim() で TypeError
}
```

**問題:** `message` が `undefined` でもバリデーションを通過する。`LogNormalizer.validate()` (L43-44) が二重防御として存在するが、SDK公開APIの境界バリデーションがこれを見逃すのは設計上の穴。

**防御モジュール割当:** `validateLogInput()` — **未パッチ（二重防御あり）**

---

### NEW-12: ソースマップがnpmパッケージに含まれる (LOW)

**ファイル:** `tsconfig.json:18`, `package.json:23-27`

```json
"sourceMap": true,
"declarationMap": true,
```
```json
"files": ["dist", "README.md", "LICENSE"]  // dist/全体を含む
```

`.npmignore` は `*.map` を除外していない。内部パス構造がnpmパッケージに含まれる。

**防御モジュール割当:** ビルド設定 — **未パッチ**

---

### NEW-13: `safe()` のリトライ上限なし (LOW)

**ファイル:** `src/shared/functional/result.ts:83-103`

```typescript
const { retries = 0, notify } = config;
for (let i = 0; i <= retries; i++) {
    // ... retries に上限なし
    await new Promise((r) => setTimeout(r, i * 100));
}
```

`retries: 1000000` で事実上の無限ループ。

**防御モジュール割当:** `safe()` — **未パッチ**

---

### NEW-14: `Sentinel.reset()` がコンポーネント状態を清掃しない (LOW)

**ファイル:** `src/index.ts:86-88`

```typescript
public static reset(): void {
    Sentinel.instance = null;
    // IntegritySigner, TaskExecutor, handlers は清掃されない
}
```

**防御モジュール割当:** `Sentinel.reset()` — **未パッチ**

---

### NEW-15: KEY_MATCH が大文字小文字を区別する (LOW)

**ファイル:** `src/security/masking-service.ts:105-108`

```typescript
rule.sensitiveKeys?.includes(key)  // 厳密一致のみ
```

`sensitiveKeys: ["password"]` は `PASSWORD` や `Password` にマッチしない。

**防御モジュール割当:** `MaskingService.maskInternal()` — **未パッチ（テストで追跡済み）**

---

## 防御モジュール・パッチ割当マトリクス

### パイプラインのデータフロー順に検証

```
[ingest()] ─→ [validateLogInput] ─→ [LogNormalizer] ─→ [MaskingService]
                                                            ↓
[onLogProcessed] ←── [TaskExecutor] ←── [TaskGenerator] ←── [EventDetector]
                                                            ↓
                        [IntegritySigner] (hash chain)
                                                            ↓
                        [Transport] ─→ remote server
```

| レイヤー | モジュール | 責務 | 防御パッチ状態 | 脆弱性 |
|---------|-----------|------|--------------|--------|
| **入口 (B1)** | `validateLogInput` | 入力検証 | ⚠ 部分的 | NEW-11: message undefined許容, NEW-10: 型不一致 |
| **正規化** | `LogNormalizer` | 正規化+二重検証 | ✅ 機能中 | L26の `!` assertionは要注意だがL43-44で防御 |
| **マスキング** | `MaskingService` | PII除去 | ⚠ messageのみ | NEW-03: input/details素通し, NEW-15: KEY_MATCH大小文字 |
| **マスキング呼出** | `IngestionEngine:53-61` | mask統合 | ❌ 不完全 | NEW-03の根本原因。ログ全体をマスクすべき |
| **ハッシュチェーン** | `IntegritySigner` | 完全性保証 | ⚠ 部分的 | NEW-01: 定数時間比較なし, NEW-07: NaN衝突 |
| **ハッシュチェーン呼出** | `IngestionEngine:66-69` | chain統合 | ❌ 不完全 | NEW-02: 並行破壊, NEW-08: ゴーストエントリ |
| **イベント検知** | `EventDetector` | ログ→イベント | ⚠ 部分的 | NEW-06: rawLog参照漏洩 |
| **タスク生成** | `TaskGenerator` | イベント→タスク | ✅ 機能中 | 第1回監査のPrototype Pollutionのみ |
| **タスク実行** | `TaskExecutor` | タスク→ハンドラ | ✅ 機能中 | ハンドラ順序依存（LOW）のみ |
| **SDK出口 (B2)** | `Sentinel.ingest()` transport | リモート送信 | ❌ 不完全 | NEW-05: 未マスクPII送信 |
| **設定** | `createDefaultConfig` | 初期化 | ⚠ 注意 | NEW-09: セキュリティ設定上書き |
| **エラー系** | `error-utils.isPiiSafe` | PII検出 | ❌ 欠陥 | NEW-04: ステートフルRegExp |
| **ユーティリティ** | `result.safe()` | リトライ | ⚠ 部分的 | NEW-13: 上限なし |

### パッチ集計

| 状態 | 数 | 意味 |
|------|---|------|
| ✅ 機能中 | 3 | 防御が正しく動作 |
| ⚠ 部分的 | 5 | 防御はあるが不完全 |
| ❌ 不完全 | 4 | 防御が欠落または欠陥 |

---

## 優先度付き対応リスト

### P0: 即時対応（1週間以内）

| ID | 対策 | 工数目安 |
|----|------|---------|
| NEW-02 | `IngestionEngine.handle()` にasync mutex追加 | 2h |
| NEW-04 | `error-utils.ts` PII_PATTERNSから `/g` フラグ除去 | 15min |
| NEW-05 | remote/dualモードでマスキング済みログを送信 | 1h |
| NEW-03 | `IngestionEngine` でログ全体をマスク対象に | 1h |

### P1: 高優先度（2週間以内）

| ID | 対策 | 工数目安 |
|----|------|---------|
| NEW-01 | `verifyHash` に `timingSafeEqual` 導入 | 30min |
| NEW-06 | `rawLog` を安全なサブセットに変更 | 1h |
| NEW-08 | hash chain更新をパイプライン最後に移動 | 1h |
| NEW-07 | `isJsonValue` でNaN/Infinity拒否 | 30min |

### P2: 通常対応（1ヶ月以内）

| ID | 対策 | 工数目安 |
|----|------|---------|
| NEW-09 | config deep-merge + Object.freeze | 1h |
| NEW-10 | agentBackLog型定義の統一 | 30min |
| NEW-11 | message必須チェック追加 | 15min |
| NEW-13 | `safe()` リトライ上限追加 | 15min |
| NEW-14 | `reset()` で内部状態清掃 | 30min |
| NEW-15 | KEY_MATCHの大文字小文字正規化 | 30min |
| NEW-12 | `.npmignore` に `*.map` 追加 | 5min |

---

## 第1回→第2回の変化

| 項目 | 第1回 (ツール主体) | 第2回 (手動精査) |
|------|-------------------|-----------------|
| 検出数 | 22件 | +15件 = 37件 |
| CRITICALクラス | 3件 | +4件 = 7件 |
| モジュール間連携の問題 | 0件 | **5件** (NEW-02,03,05,06,08) |
| ステートフル性の問題 | 0件 | **2件** (NEW-02,04) |
| データフロー横断の問題 | 0件 | **3件** (NEW-03,05,06) |

**所見:** ツール単体では各ファイル内の静的パターンは検出できるが、モジュール間のデータフロー・状態管理・並行性の問題は人間のレビューが不可欠。特にNEW-02（レースコンディション）とNEW-05（マスク前送信）は、2つ以上のモジュールの責務を横断して理解しないと発見できない。
