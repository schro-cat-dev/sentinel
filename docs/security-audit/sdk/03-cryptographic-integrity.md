# SDK 暗号化・ハッシュチェーン完全性監査

## 概要

SDK のハッシュチェーンはログの改竄検知を目的とする。`IntegritySigner` クラスが SHA-256 によるチェーン管理を担当する。

---

## チェック項目一覧

### 1. ハッシュアルゴリズム

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| アルゴリズム選択 | **OK** | `integrity-signer.ts:44` — `createHash("sha256")` (node:crypto) |
| 標準ライブラリ使用 | **OK** | Node.js 組込み crypto モジュール使用。カスタム実装なし |
| HMAC使用 | **注意** | SDK側は **HMAC未使用**（素のSHA-256）。Goサーバ側はHMAC-SHA256 |

**ギャップ分析**:
- SDK: `createHash("sha256").update(data + previousHash).digest("hex")` — キーなしハッシュ
- Go: `hmac.New(sha256.New, key)` + `h.Write([]byte(serialized + previousHash))` — HMACハッシュ

**影響**: SDK（ローカルモード）で生成したハッシュはGoサーバで検証できない（アルゴリズム不一致）。ただし、`remote` / `dual` モードではGoサーバが独自にハッシュを再計算するため、実運用上の問題は発生しない。ローカルモードのみの利用ではハッシュの改竄耐性がHMACより弱い（キーがなければ攻撃者もハッシュを再計算可能）。

**推奨対策**:
- ローカルモードの用途を理解している場合は現状維持で問題なし（ログの順序整合性の検証が目的）
- ハッシュの改竄耐性が必要な場合は、SDKにもHMACサポートを追加

```typescript
// オプションでHMACキーを受け取る拡張案
public static calculateHash(log: Log, previousHash: string, hmacKey?: string): string {
    const immutableParts = IntegritySigner.omit(log, ["hash", "signature"]);
    const serializedData = IntegritySigner.deterministicStringify(immutableParts);

    if (hmacKey) {
        return createHmac("sha256", hmacKey)
            .update(serializedData + previousHash)
            .digest("hex");
    }
    return createHash("sha256")
        .update(serializedData + previousHash)
        .digest("hex");
}
```

### 2. タイミング攻撃対策

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| constant-time comparison | **OK** | `integrity-signer.ts:58` — `timingSafeEqual()` 使用 |
| Buffer長チェック | **OK** | `integrity-signer.ts:57` — `a.length !== b.length` で事前チェック |
| Buffer エンコーディング | **OK** | `Buffer.from(computed, "utf8")` — hex 文字列のUTF-8エンコードで一貫性あり |

### 3. 決定論的シリアライゼーション

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| キーソート | **OK** | `integrity-signer.ts:79` — `Object.keys(obj).sort()` |
| undefined処理 | **OK** | `integrity-signer.ts:84-85` — `undefined` を `"null"` に変換 |
| Infinity/NaN検出 | **OK** | `integrity-signer.ts:96` — `Number.isFinite()` で非有限数を拒否 |
| 循環参照検出 | **OK** | `integrity-signer.ts:103` — `Object.prototype.toString.call(val) !== "[object Object]"` で非プレーンオブジェクトを除外 |
| 配列シリアライズ | **OK** | `integrity-signer.ts:73-75` — 再帰的にシリアライズ |
| hash/signature除外 | **OK** | `integrity-signer.ts:41` — `omit(log, ["hash", "signature"])` |

**Go サーバとの互換性**:

SDK の `deterministicStringify()` と Go の `sortedJSON()` は同じアルゴリズム（キーソート + JSON表現）を使用しているが、以下の差異がある：

| 処理 | SDK | Go |
|------|-----|-----|
| シリアライズ | カスタム再帰関数 | `json.Marshal` → `json.Unmarshal` → カスタム再帰関数 |
| undefined | `"null"` に変換 | Go に undefined 概念なし（json.Marshal で省略） |
| NaN/Infinity | `isJsonValue()` で `false` 返却 → `"null"` | `json.Marshal` が `+Inf` 等でエラー |
| ハッシュアルゴリズム | SHA-256 (キーなし) | HMAC-SHA256 (キー付き) |

**結論**: SDK とGoサーバのハッシュは**互換性がない**（意図的設計）。`remote` / `dual` モードではGoサーバが独自にハッシュを再計算する。

### 4. ハッシュチェーン状態管理

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| インメモリ管理 | **OK** | `integrity-signer.ts:14` — `previousHash` フィールド |
| 排他制御 | **OK** | `ingestion-engine.ts:204-214` — async mutex でチェーン更新をシリアライズ |
| リセット機能 | **OK** | `integrity-signer.ts:33-35` — `resetChain()` |
| **永続化** | **注意** | ハッシュチェーン状態はプロセス再起動で消失 |

**永続化の欠如について**:

- プロセス再起動後、`previousHash` が空文字列にリセットされる
- 再起動前のチェーンとの連続性が失われる
- **影響**: チェーン切断を検知できない（再起動が正当なのか、攻撃なのか判別不能）

**推奨対策（将来検討）**:
```typescript
interface ChainPersistence {
    save(hash: string): Promise<void>;
    load(): Promise<string | null>;
}

// IntegritySignerのコンストラクタに注入
constructor(private persistence?: ChainPersistence) {
    if (persistence) {
        persistence.load().then(h => { if (h) this.previousHash = h; });
    }
}
```

**現時点の判定**: SDK はローカルの軽量ライブラリとして設計されているため、永続化の欠如は許容範囲内。ユーザが必要に応じてGoサーバ（SQLite永続化あり）を使用すべき。

### 5. キーローテーション

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| SDK側のキーローテーション | **N/A** | SDKはキーなしハッシュのため不要 |
| Go側のキーローテーション | **OK** | `signer.go:85-110` — `AddPreviousKey()` + `VerifyHashWithRotation()` |

---

## 総合判定

**評価: A-（良好、軽微な改善余地あり）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| タイミング攻撃対策 | — | **OK** | `timingSafeEqual` 使用 |
| 決定論的シリアライズ | — | **OK** | キーソート、型安全性確保 |
| HMAC非使用（SDK側） | LOW | **設計上の選択** | ローカルモード用途では問題なし |
| チェーン永続化なし | LOW | **設計上の選択** | Goサーバで補完 |
| SDK/Go ハッシュ互換性なし | INFO | **意図的** | remoteモードでは問題なし |
