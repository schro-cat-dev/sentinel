import { describe, it, expect } from "vitest";
import {
    isPiiSafe,
    maskPiiContext,
    safeContext,
    serializeForAudit,
    classifyError,
    getErrorMessage,
    DEFAULT_ERROR_SEVERITY,
} from "../../../src/shared/utils/error-utils";
import type { ErrorPayloadProtocol } from "../../../src/shared/errors/error-payload-protocol";

// =========================================================================
// isPiiSafe
// =========================================================================
describe("isPiiSafe", () => {
    it("returns true for empty string", () => {
        expect(isPiiSafe("")).toBe(true);
    });

    it("returns true for strings shorter than 3 characters", () => {
        expect(isPiiSafe("ab")).toBe(true);
        expect(isPiiSafe("JP")).toBe(true);
    });

    it("returns true for safe general strings", () => {
        expect(isPiiSafe("hello world")).toBe(true);
        expect(isPiiSafe("system_error_code_42")).toBe(true);
        expect(isPiiSafe("status: OK")).toBe(true);
    });

    it("returns true for 3-character safe string (boundary)", () => {
        expect(isPiiSafe("abc")).toBe(true);
    });

    it("detects email addresses as PII", () => {
        expect(isPiiSafe("user@example.com")).toBe(false);
        expect(isPiiSafe("alice.bob@corp.co.jp")).toBe(false);
    });

    it("detects credit card numbers as PII", () => {
        expect(isPiiSafe("4111-1111-1111-1111")).toBe(false);
        expect(isPiiSafe("4111111111111111")).toBe(false);
    });

    it("detects Japanese phone numbers as PII", () => {
        expect(isPiiSafe("090-1234-5678")).toBe(false);
        expect(isPiiSafe("03-1234-5678")).toBe(false);
    });

    it("detects international phone numbers as PII", () => {
        expect(isPiiSafe("+819012345678")).toBe(false);
    });

    it("detects IBAN as PII", () => {
        expect(isPiiSafe("DE89370400440532013000")).toBe(false);
    });

    it("detects Japanese bank account numbers as PII", () => {
        expect(isPiiSafe("001-1234567-1234567")).toBe(false);
    });

    it("detects personal name patterns as PII", () => {
        expect(isPiiSafe("john.smith")).toBe(false);
        expect(isPiiSafe("tanaka.taro")).toBe(false);
    });

    it("detects postal codes as PII", () => {
        expect(isPiiSafe("〒123-4567")).toBe(false);
        expect(isPiiSafe("123-4567")).toBe(false);
    });
});

// =========================================================================
// maskPiiContext
// =========================================================================
describe("maskPiiContext", () => {
    it("returns unchanged object when no PII present", () => {
        const input = { status: "ok", count: 42, active: true, note: null };
        const result = maskPiiContext(input);
        expect(result).toEqual({ status: "ok", count: 42, active: true, note: null });
    });

    it("masks string values containing PII", () => {
        const input = { email: "user@example.com", safe: "hello" };
        const result = maskPiiContext(input);
        expect(result.safe).toBe("hello");
        expect(result.email).toBe("***_email_MASKED***");
    });

    it("masks keys containing PII patterns", () => {
        const input: Record<string, string | number | boolean | null> = {
            "john.smith": "some value",
        };
        const result = maskPiiContext(input);
        expect(result["john.smith"]).toBeUndefined();
        // Key is replaced with masked key
        const maskedKeys = Object.keys(result).filter((k) => k.includes("MASKED"));
        expect(maskedKeys).toHaveLength(1);
    });

    it("handles empty object", () => {
        expect(maskPiiContext({})).toEqual({});
    });

    it("does not follow prototype chain (prototype pollution guard)", () => {
        const proto = { injected: "evil" };
        const obj = Object.create(proto) as Record<string, string | number | boolean | null>;
        obj.safe = "value";
        const result = maskPiiContext(obj);
        expect(result.safe).toBe("value");
        expect(result.injected).toBeUndefined();
    });
});

// =========================================================================
// safeContext
// =========================================================================
describe("safeContext", () => {
    it("skips keys longer than 50 characters", () => {
        const longKey = "a".repeat(51);
        const result = safeContext({ [longKey]: "value", short: "ok" });
        expect(result[longKey]).toBeUndefined();
        expect(result.short).toBe("ok");
    });

    it("converts null and undefined values to null", () => {
        const result = safeContext({ a: null, b: undefined });
        expect(result.a).toBeNull();
        expect(result.b).toBeNull();
    });

    it("converts arrays to their length (capped at 1000)", () => {
        const result = safeContext({ arr: [1, 2, 3] });
        expect(result.arr).toBe(3);
    });

    it("caps array length at 1000", () => {
        const bigArr = new Array(5000).fill(0);
        const result = safeContext({ arr: bigArr });
        expect(result.arr).toBe(1000);
    });

    it("converts objects to key count", () => {
        const result = safeContext({ obj: { a: 1, b: 2 } });
        expect(result.obj).toBe(2);
    });

    it("truncates strings longer than 50 characters", () => {
        const longStr = "x".repeat(60);
        const result = safeContext({ msg: longStr });
        expect(result.msg).toBe("x".repeat(47) + "...");
    });

    it("keeps strings 50 characters or shorter as-is", () => {
        const str50 = "x".repeat(50);
        const result = safeContext({ msg: str50 });
        expect(result.msg).toBe(str50);
    });

    it("floors numbers and replaces Infinity/NaN with 0", () => {
        const result = safeContext({ a: 3.7, b: Infinity, c: NaN, d: -Infinity });
        expect(result.a).toBe(3);
        expect(result.b).toBe(0);
        expect(result.c).toBe(0);
        expect(result.d).toBe(0);
    });

    it("passes booleans through unchanged", () => {
        const result = safeContext({ flag: true, off: false });
        expect(result.flag).toBe(true);
        expect(result.off).toBe(false);
    });

    it("converts unknown types to null", () => {
        const result = safeContext({ sym: Symbol("test") as unknown as string });
        expect(result.sym).toBeNull();
    });

    it("applies PII masking to the result", () => {
        const result = safeContext({ contact: "user@example.com" });
        expect(result.contact).toBe("***_contact_MASKED***");
    });
});

// =========================================================================
// serializeForAudit
// =========================================================================
describe("serializeForAudit", () => {
    const baseError: ErrorPayloadProtocol = {
        kind: "DbConnection",
        detailKind: "pool",
        code: "DB_CONNECTION_FAILED",
        message: "Connection refused",
        meta: {
            traceId: "trace-001",
            layer: "Database",
            entityType: "Connection",
            context: { host: "db-01", port: 5432 },
        },
    };

    it("returns valid JSON with expected fields", () => {
        const json = serializeForAudit(baseError);
        const parsed: Record<string, unknown> = JSON.parse(json);
        expect(parsed.kind).toBe("DbConnection");
        expect(parsed.code).toBe("DB_CONNECTION_FAILED");
        expect(parsed.traceId).toBe("trace-001");
        expect(parsed.layer).toBe("Database");
        expect(parsed.entityType).toBe("Connection");
        expect(typeof parsed.timestamp).toBe("string");
    });

    it("filters out PII keys from context", () => {
        const errorWithPii: ErrorPayloadProtocol = {
            ...baseError,
            meta: {
                ...baseError.meta,
                context: { safe: "ok", "john.smith": "secret" },
            },
        };
        const json = serializeForAudit(errorWithPii);
        const parsed: Record<string, unknown> = JSON.parse(json);
        // contextKeyCount should only count safe keys
        expect(parsed.contextKeyCount).toBe(1);
    });

    it("limits context keys to 10", () => {
        const context: Record<string, string> = {};
        for (let i = 0; i < 20; i++) {
            context[`key${i}`] = `val${i}`;
        }
        const error: ErrorPayloadProtocol = {
            ...baseError,
            meta: { ...baseError.meta, context },
        };
        const json = serializeForAudit(error);
        const parsed: Record<string, unknown> = JSON.parse(json);
        expect(parsed.contextKeyCount).toBeLessThanOrEqual(10);
    });

    it("handles missing traceId", () => {
        const error: ErrorPayloadProtocol = {
            ...baseError,
            meta: { context: {} },
        };
        const json = serializeForAudit(error);
        const parsed: Record<string, unknown> = JSON.parse(json);
        expect(parsed.traceId).toBe("unknown");
    });
});

// =========================================================================
// classifyError
// =========================================================================
describe("classifyError", () => {
    const makeError = (kind: string): ErrorPayloadProtocol => ({
        kind,
        detailKind: "test",
        code: "TEST",
        message: "test",
        meta: { context: {} },
    });

    it("classifies CRITICAL kinds", () => {
        expect(classifyError(makeError("DbConnection"))).toBe("CRITICAL");
        expect(classifyError(makeError("WalCrypto"))).toBe("CRITICAL");
        expect(classifyError(makeError("External"))).toBe("CRITICAL");
    });

    it("classifies WARNING kinds", () => {
        expect(classifyError(makeError("DbQuery"))).toBe("WARNING");
        expect(classifyError(makeError("DbConstraint"))).toBe("WARNING");
        expect(classifyError(makeError("DbTimeout"))).toBe("WARNING");
    });

    it("classifies unknown kinds as INFO", () => {
        expect(classifyError(makeError("SomethingElse"))).toBe("INFO");
    });

    it("accepts custom config", () => {
        const config = { CRITICAL: ["Custom"], WARNING: [] as string[] };
        expect(classifyError(makeError("Custom"), config)).toBe("CRITICAL");
    });
});

// =========================================================================
// getErrorMessage
// =========================================================================
describe("getErrorMessage", () => {
    const makeError = (code: string): ErrorPayloadProtocol => ({
        kind: "Test",
        detailKind: "test",
        code,
        message: "fallback message",
        meta: { context: {} },
    });

    it("returns Japanese message for known code", () => {
        expect(getErrorMessage(makeError("DB_CONSTRAINT_VIOLATION"), "ja")).toBe("データベース制約違反");
    });

    it("returns English message for known code", () => {
        expect(getErrorMessage(makeError("DB_CONSTRAINT_VIOLATION"), "en")).toBe("Database constraint violation");
    });

    it("falls back to error.message for unknown code", () => {
        expect(getErrorMessage(makeError("UNKNOWN_CODE"), "ja")).toBe("fallback message");
    });

    it("defaults to Japanese locale", () => {
        expect(getErrorMessage(makeError("DB_DUPLICATE_KEY"))).toBe("データベース重複キー違反");
    });
});
