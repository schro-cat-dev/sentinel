import { createHash, createSign } from "node:crypto";
import { Log } from "../types/log";

/**
 * ログに含めることが可能な値の厳格な定義
 */
type JsonPrimitive = string | number | boolean | null;
type JsonObject = { [key: string]: JsonValue };
type JsonArray = JsonValue[];
type JsonValue = JsonPrimitive | JsonObject | JsonArray;

export class IntegritySigner {
    /**
     * 前のハッシュと現在のログを結合して SHA-256 ハッシュを計算
     */
    public static calculateHash(log: Log, previousHash: string): string {
        // 整合性チェック対象外のフィールドを除外
        const immutableParts = this.omit(log, ["hash", "signature"]);

        // 決定論的シリアライズ
        const serializedData = this.deterministicStringify(immutableParts);

        return createHash("sha256")
            .update(serializedData + previousHash)
            .digest("hex");
    }

    /**
     * 決定論的なシリアライズ
     * 型ガードを用いて JsonValue であることを保証した上で処理
     */
    private static deterministicStringify(val: unknown): string {
        // 1. 型ガードによる検証
        if (!this.isJsonValue(val)) {
            // JsonValue でない場合（undefined や Symbol 等）は、
            // 決定論的ハッシュを壊さないための既定値に変換するか例外を投げる
            return "null";
        }

        // 2. プリミティブ値の処理
        if (val === null || typeof val !== "object") {
            return JSON.stringify(val);
        }

        // 3. 配列の処理
        if (Array.isArray(val)) {
            const items = val.map((item) => this.deterministicStringify(item));
            return `[${items.join(",")}]`;
        }

        // 4. オブジェクトの処理（キーをソート）
        const obj = val as JsonObject;
        const sortedKeys = Object.keys(obj).sort();

        const kvPairs = sortedKeys.map((key) => {
            const value = obj[key];
            // JSON.stringify は undefined をキーごと消すが、
            // ハッシュ計算では明示的に null 扱いにするか、一貫したルールが必要
            const safeValue =
                value === undefined
                    ? "null"
                    : this.deterministicStringify(value);
            return `${JSON.stringify(key)}:${safeValue}`;
        });

        return `{${kvPairs.join(",")}}`;
    }

    /**
     * 再帰的な型ガード: 与えられた値が JsonValue であるかを確認
     */
    private static isJsonValue(val: unknown): val is JsonValue {
        if (val === null) return true;
        const type = typeof val;
        if (type === "string" || type === "number" || type === "boolean")
            return true;

        if (Array.isArray(val)) {
            return val.every((item) => this.isJsonValue(item));
        }

        if (type === "object") {
            // プロトタイプが Object でないもの（関数やクラスインスタンス）を除外
            if (Object.prototype.toString.call(val) !== "[object Object]")
                return false;

            return Object.values(val as Record<string, unknown>).every((item) =>
                this.isJsonValue(item),
            );
        }

        return false;
    }

    /**
     * 特定のプロパティを型安全に除外
     */
    private static omit<T extends object, K extends keyof T>(
        obj: T,
        keys: K[],
    ): Omit<T, K> {
        const result = { ...obj };
        for (const key of keys) {
            delete result[key];
        }
        return result as Omit<T, K>;
    }

    /**
     * 秘密鍵による署名
     */
    public static sign(logHash: string, privateKey: string): string {
        const signer = createSign("SHA256");
        signer.update(logHash);
        return signer.sign(privateKey, "hex");
    }
}
