import { createHash } from "node:crypto";
import { Log } from "../types/log";

type JsonPrimitive = string | number | boolean | null;
type JsonObject = { [key: string]: JsonValue };
type JsonArray = JsonValue[];
type JsonValue = JsonPrimitive | JsonObject | JsonArray;

/**
 * ハッシュチェーン管理（インメモリ）
 * H_n = SHA256(L_n || H_{n-1})
 */
export class IntegritySigner {
    private previousHash = "";

    /**
     * 現在のチェーンの最新ハッシュを取得
     */
    public getPreviousHash(): string {
        return this.previousHash;
    }

    /**
     * チェーンの最新ハッシュを更新
     */
    public updateChain(hash: string): void {
        this.previousHash = hash;
    }

    /**
     * チェーンをリセット
     */
    public resetChain(): void {
        this.previousHash = "";
    }

    /**
     * 前のハッシュと現在のログを結合して SHA-256 ハッシュを計算
     */
    public static calculateHash(log: Log, previousHash: string): string {
        const immutableParts = IntegritySigner.omit(log, ["hash", "signature"]);
        const serializedData = IntegritySigner.deterministicStringify(immutableParts);

        return createHash("sha256")
            .update(serializedData + previousHash)
            .digest("hex");
    }

    /**
     * 指定されたログのハッシュを検証
     */
    public static verifyHash(log: Log, expectedPreviousHash: string): boolean {
        if (!log.hash) return false;
        const computed = IntegritySigner.calculateHash(log, expectedPreviousHash);
        return computed === log.hash;
    }

    /**
     * 決定論的なシリアライズ
     */
    private static deterministicStringify(val: unknown): string {
        if (!IntegritySigner.isJsonValue(val)) {
            return "null";
        }

        if (val === null || typeof val !== "object") {
            return JSON.stringify(val);
        }

        if (Array.isArray(val)) {
            const items = val.map((item) => IntegritySigner.deterministicStringify(item));
            return `[${items.join(",")}]`;
        }

        const obj = val as JsonObject;
        const sortedKeys = Object.keys(obj).sort();

        const kvPairs = sortedKeys.map((key) => {
            const value = obj[key];
            const safeValue =
                value === undefined
                    ? "null"
                    : IntegritySigner.deterministicStringify(value);
            return `${JSON.stringify(key)}:${safeValue}`;
        });

        return `{${kvPairs.join(",")}}`;
    }

    private static isJsonValue(val: unknown): val is JsonValue {
        if (val === null) return true;
        const type = typeof val;
        if (type === "string" || type === "number" || type === "boolean") return true;

        if (Array.isArray(val)) {
            return val.every((item) => IntegritySigner.isJsonValue(item));
        }

        if (type === "object") {
            if (Object.prototype.toString.call(val) !== "[object Object]") return false;
            return Object.values(val as Record<string, unknown>).every((item) =>
                IntegritySigner.isJsonValue(item),
            );
        }

        return false;
    }

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
}
