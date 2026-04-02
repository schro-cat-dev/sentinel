import { createHash, createHmac, timingSafeEqual } from "node:crypto";
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
    private readonly signingKeyId: string;
    private readonly hmacKey: string;

    constructor(signingKeyId?: string, hmacKey?: string) {
        this.signingKeyId = signingKeyId ?? "";
        this.hmacKey = hmacKey ?? "";
    }

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
     * 前のハッシュと現在のログを結合してハッシュを計算。
     * hmacKey が指定されている場合は HMAC-SHA256、未指定時は SHA-256 フォールバック。
     * HMAC モードでは Go Server (signer.go) と同一のアルゴリズム:
     *   HMAC-SHA256(serialized + previousHash, key)
     */
    public static calculateHash(log: Log, previousHash: string, signingKeyId = "", hmacKey = ""): string {
        const immutableParts = IntegritySigner.omit(log, ["hash", "signature"]);
        const serializedData = IntegritySigner.deterministicStringify(immutableParts);

        if (hmacKey) {
            return createHmac("sha256", hmacKey)
                .update(serializedData + previousHash)
                .digest("hex");
        }

        return createHash("sha256")
            .update(serializedData + previousHash + signingKeyId)
            .digest("hex");
    }

    /** このSignerのkeyIdを取得 */
    public getSigningKeyId(): string {
        return this.signingKeyId;
    }

    /** HMAC鍵を取得（Phase 1-E） */
    public getHmacKey(): string {
        return this.hmacKey;
    }

    /**
     * 指定されたログのハッシュを検証
     */
    public static verifyHash(log: Log, expectedPreviousHash: string, hmacKey = ""): boolean {
        if (!log.hash) return false;
        const computed = IntegritySigner.calculateHash(log, expectedPreviousHash, "", hmacKey);
        const a = Buffer.from(computed, "utf8");
        const b = Buffer.from(log.hash, "utf8");
        if (a.length !== b.length) return false;
        return timingSafeEqual(a, b);
    }

    /**
     * 決定論的なシリアライズ
     */
    private static deterministicStringify(val: JsonValue | Readonly<Record<string, unknown>>): string {
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

        // isJsonValue ガード通過後: 全 value は JsonValue（undefined は含まれない）
        const kvPairs = sortedKeys.map((key) => {
            const value = obj[key];
            return `${JSON.stringify(key)}:${IntegritySigner.deterministicStringify(value)}`;
        });

        return `{${kvPairs.join(",")}}`;
    }

    private static isJsonValue(val: unknown): val is JsonValue {
        if (val === null) return true;
        if (typeof val === "string" || typeof val === "boolean") return true;
        if (typeof val === "number") return Number.isFinite(val);

        if (Array.isArray(val)) {
            return val.every((item: unknown) => IntegritySigner.isJsonValue(item));
        }

        if (typeof val === "object") {
            if (Object.prototype.toString.call(val) !== "[object Object]") return false;
            return Object.values(val as JsonObject).every((item) =>
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
