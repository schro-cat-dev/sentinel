# SDK 正規表現 ReDoS 脆弱性分析

## 概要

ReDoS (Regular Expression Denial of Service) はユーザ定義の正規表現パターンがカタストロフィックバックトラッキングを引き起こし、CPUを長時間占有する攻撃手法。SDKにはユーザ定義正規表現を受け入れる箇所が複数存在する。

---

## チェック箇所一覧

### 1. config-loader.ts — REGEX型マスキングルールの `new RegExp()` 生成

**ファイル**: `src/configs/config-loader.ts:311`

```typescript
pattern: new RegExp(raw.pattern!, raw.description?.includes("global") ? "g" : ""),
```

| チェック項目 | 判定 | 詳細 |
|-------------|------|------|
| パターン長制限 | **OK（修正済み）** | `config-loader.ts:320-322` — 256文字制限 |
| ReDoSパターン検出 | **OK（修正済み）** | `config-loader.ts:324-343` — ネスト量指定子(`+`,`*`,`?`,`{n,m}`)の検出 |
| コンパイル例外ハンドリング | **OK** | `new RegExp()` が例外を投げた場合はそのまま伝播 |
| フラグ制限 | **部分的** | global以外の危険なフラグ（`u` の一部パターンで問題あり）はチェックなし |

**攻撃シナリオ**:
```yaml
# sentinel.config.yaml
masking:
  rules:
    - type: REGEX
      pattern: "(a+)+$"  # ReDoS脆弱パターン
      replacement: "[MASKED]"
```

上記設定でSDKを初期化し、`"aaaaaaaaaaaaaaaaaaaaaaaaaaab"` のようなメッセージをingestすると、`masking-service.ts:174` の `result.replace(globalPattern, replacement)` でCPUが長時間ブロックされる。

**重大度**: **HIGH**

**リスク評価**:
- 攻撃前提: 設定ファイルを操作できる攻撃者（設定ファイルの書き換え or マルチテナント環境での悪意ある設定投入）
- 影響範囲: SDK全体のログ処理がブロック。Node.jsのシングルスレッド特性上、サーバ全体がフリーズする可能性
- 設定ファイルへのアクセスが必要なため、直接的な外部攻撃のリスクは低い。ただし、設定をAPIや管理画面で受け付ける運用の場合はリスクが高い

**推奨パッチ**:
```typescript
// config-loader.ts の convertMaskingRule 関数内
function convertMaskingRule(raw: RawMaskingRule, index: number): MaskingRule {
    if (raw.type === "REGEX") {
        // パターン長制限
        if (raw.pattern!.length > 256) {
            throw new ConfigLoadError(
                `masking.rules[${index}].pattern`,
                `pattern too long (${raw.pattern!.length} > 256)`
            );
        }
        // ReDoSヒューリスティック検出
        if (detectReDoSRisk(raw.pattern!)) {
            throw new ConfigLoadError(
                `masking.rules[${index}].pattern`,
                "potentially unsafe regex pattern (ReDoS risk)"
            );
        }
        return {
            type: "REGEX",
            pattern: new RegExp(raw.pattern!, raw.description?.includes("global") ? "g" : ""),
            replacement: raw.replacement ?? "[REDACTED]",
            description: raw.description ?? "",
        };
    }
    // ...
}

function detectReDoSRisk(pattern: string): boolean {
    // ネスト量指定子の検出: (x+)+ , (x*)+ , (x+)* 等
    let depth = 0;
    let hasQuantifierInGroup = false;
    for (const ch of pattern) {
        if (ch === '(') {
            if (hasQuantifierInGroup) return true; // 外側にも量指定子がある
            depth++;
            hasQuantifierInGroup = false;
        } else if (ch === ')') {
            depth--;
        } else if ((ch === '+' || ch === '*') && depth > 0) {
            hasQuantifierInGroup = true;
        } else if ((ch === '+' || ch === '*') && hasQuantifierInGroup) {
            return true; // ネスト量指定子
        }
    }
    // 過度な繰り返しの検出
    const repetition = pattern.match(/\{(\d+)/);
    if (repetition && parseInt(repetition[1]) > 1000) return true;
    return false;
}
```

### 2. config-loader.ts — detection rule の messagePattern

**ファイル**: `src/configs/config-loader.ts:355`

```typescript
if (raw.conditions.message_pattern) conditions.messagePattern = new RegExp(raw.conditions.message_pattern);
```

| チェック項目 | 判定 | 詳細 |
|-------------|------|------|
| パターン長制限 | **OK（修正済み）** | `config-loader.ts:417` — `validateRegexPattern()` で256文字制限を適用 |
| ReDoSパターン検出 | **OK（修正済み）** | `config-loader.ts:417` — ネスト量指定子検出を適用 |
| フラグ制限 | **OK** | フラグなしで生成されるため `global` / `sticky` のリスクなし |

**攻撃シナリオ**: 悪意ある検出ルールの `message_pattern` にReDoSパターンを設定すると、`event-detector.ts:153` の `.test(log.message)` でCPUがブロックされる。

**重大度**: **HIGH**（マスキングと同じ理由）

**推奨パッチ**: マスキングルールと同じ `detectReDoSRisk()` + パターン長制限を適用。

```typescript
function convertDetectionRule(raw: RawDetectionRule): DetectionRule {
    const conditions: DetectionRuleConditions = {};
    if (raw.conditions) {
        if (raw.conditions.message_pattern) {
            if (raw.conditions.message_pattern.length > 256) {
                throw new ConfigLoadError(
                    `detection_rules.message_pattern`,
                    "pattern too long"
                );
            }
            if (detectReDoSRisk(raw.conditions.message_pattern)) {
                throw new ConfigLoadError(
                    `detection_rules.message_pattern`,
                    "potentially unsafe regex (ReDoS risk)"
                );
            }
            conditions.messagePattern = new RegExp(raw.conditions.message_pattern);
        }
        // ...
    }
}
```

### 3. masking-service.ts — regex 実行時の保護

**ファイル**: `src/security/masking-service.ts:170-177`

```typescript
const globalPattern = new RegExp(rule.pattern.source, originalFlags + "g");
result = result.replace(globalPattern, rule.replacement);
```

| チェック項目 | 判定 | 詳細 |
|-------------|------|------|
| 実行タイムアウト | **NG** | `replace()` にタイムアウト機構がない |
| パターン変換の安全性 | **OK** | `source` の再取得は安全（フラグのみ変更） |
| フラグ正規化 | **OK** | `y` と `g` を除去してから `g` を追加 |

**補足**: マスキングルールの `pattern` は初期化時に `new RegExp()` でコンパイル済みだが、`source` を取り出して別フラグで再コンパイルしている。パターン自体の安全性は上流（config-loader）で担保する必要がある。

### 4. event-detector.ts — messagePattern.test() の実行

**ファイル**: `src/core/detection/event-detector.ts:153`

```typescript
if (conditions.messagePattern && !conditions.messagePattern.test(log.message)) {
```

| チェック項目 | 判定 | 詳細 |
|-------------|------|------|
| global/sticky フラグ拒否 | **OK** | `event-detector.ts:31-36` でコンストラクタ時に検証 |
| 実行タイムアウト | **NG** | `.test()` にタイムアウト機構がない |

---

## Go サーバとの比較

| 項目 | SDK (TypeScript) | Server (Go) | 整合 |
|------|-----------------|-------------|------|
| パターン長制限 | **あり（修正済み）** (256文字) | **あり** (256文字) | **一致** |
| ReDoS検出ヒューリスティック | **あり（修正済み）** (ネスト量指定子+繰り返し) | **あり** (ネスト量指定子、繰り返し回数) | **一致** |
| コンパイル検証 | `new RegExp()` 例外 | `regexp.Compile()` | **一致** |
| global/sticky フラグ制限 | 検出ルールのみ | N/A (Go regexp にgフラグなし) | — |

**修正後**: SDK と Go サーバの ReDoS 保護は同等レベルに整合。`detectReDoSRisk()` は `+`, `*`, `?`, `{n,m}` の全量指定子をネスト検出対象とし、Go サーバと同等の保護を提供。

---

## 組込みPIIパターンの安全性

SDK内蔵のPIIパターン（`masking-service.ts:12-19`）はハードコードされた定数であり、ユーザが変更できない。以下のパターンについてReDoSリスクを個別検証した：

| パターン | ReDoSリスク | 根拠 |
|---------|------------|------|
| `CREDIT_CARD`: `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b` | **安全** | ネスト量指定子なし。固定回数繰り返し |
| `PHONE`: `(\+81\|0)[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{4}` | **安全** | 交互の範囲が固定 |
| `EMAIL`: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | **要注意** | `[a-zA-Z0-9._%+-]+` と `[a-zA-Z0-9.-]+` で重複文字クラスがあるが、`@` による分離で実質安全 |
| `GOVERNMENT_ID`: `\b\d{12}\b` | **安全** | 固定長 |
| `JAPAN_ACCOUNT`: `\d{3}[-]\d{7}\|\d{4}[-]\d{7}` | **安全** | 固定長 |
| `POSTAL_CODE`: `(?:〒?\s?)?\d{3}[-]?\d{4}` | **安全** | 短い固定パターン |
| `DRIVER_LICENSE`: `\b[1-9]\d{5,7}[0-9\\*]\d{2,4}\b` | **安全** | 固定範囲 |
| `HEALTH_INSURANCE`: `\b\d{2}\s?\d{2}\s?\d{6}\b` | **安全** | 固定長 |

**結論**: 組込みパターンにReDoSリスクはない。EMAILパターンは理論上の重複があるが、`@` 記号によるアンカー効果で実用上安全。

---

## 総合判定

**評価: A-（修正済み — ヒューリスティック検出実装完了）**

| 脆弱性ID | 重大度 | 箇所 | ステータス |
|----------|--------|------|-----------|
| REDOS-001 | HIGH | config-loader.ts マスキングルールパターン | **✅ 対策済み** — `validateRegexPattern()` + `detectReDoSRisk()` |
| REDOS-002 | HIGH | config-loader.ts 検出ルールパターン | **✅ 対策済み** — 同上 |
| REDOS-003 | MEDIUM | masking-service.ts:174 replace() タイムアウト | **残課題** |
| REDOS-004 | LOW | event-detector.ts:153 test() タイムアウト | **残課題** |

**修正内容（2026-04-02）**:
- `detectReDoSRisk()`: ネスト量指定子検出に `?` と `{n,m}` を追加。`+`, `*`, `?`, `{` の全量指定子をグループ外部の量指定子として検出
- パターン長制限: 256文字
- 繰り返し回数制限: `{n}` で n > 1000 を拒否
- テスト: `tests/security/sdk-audit-fixes.test.ts` — 17テストケース（`(a+)+`, `(a*)*`, `(a?)+`, `(a+){2,}`, `([a-zA-Z]+)+`, `(.*a)+` 等）

**残課題**:
1. REDOS-003/004: `re2` パッケージ（線形時間正規表現エンジン）の導入を検討。ただしゼロ依存方針との兼ね合い
2. ドキュメント: ユーザ向けに「カスタム正規表現パターンのガイドライン」を提供し、ネスト量指定子を避けるよう記載
