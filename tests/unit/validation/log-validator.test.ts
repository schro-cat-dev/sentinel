import { describe, it, expect } from "vitest";
import { validateLogInput, ValidationError } from "../../../src/validation/log-validator";

describe("validateLogInput", () => {
    // --- message ---
    it("accepts valid message", () => {
        expect(() => validateLogInput({ message: "hello" })).not.toThrow();
    });

    it("rejects empty message", () => {
        expect(() => validateLogInput({ message: "   " })).toThrow(ValidationError);
    });

    it("rejects message exceeding max length", () => {
        expect(() => validateLogInput({ message: "x".repeat(65537) })).toThrow(ValidationError);
    });

    it("rejects message with null bytes", () => {
        expect(() => validateLogInput({ message: "hello\x00world" })).toThrow(ValidationError);
    });

    it("rejects non-string message", () => {
        expect(() => validateLogInput({ message: 123 as unknown as string })).toThrow(ValidationError);
    });

    // --- type ---
    it("accepts valid log types", () => {
        for (const t of ["SYSTEM", "SECURITY", "COMPLIANCE", "INFRA", "SLA", "DEBUG", "BUSINESS-AUDIT"]) {
            expect(() => validateLogInput({ message: "test", type: t as any })).not.toThrow();
        }
    });

    it("rejects invalid log type", () => {
        expect(() => validateLogInput({ message: "test", type: "INVALID" as any })).toThrow(ValidationError);
    });

    // --- level ---
    it("accepts valid levels 1-6", () => {
        for (let l = 1; l <= 6; l++) {
            expect(() => validateLogInput({ message: "test", level: l as any })).not.toThrow();
        }
    });

    it("rejects level 0", () => {
        expect(() => validateLogInput({ message: "test", level: 0 as any })).toThrow(ValidationError);
    });

    it("rejects level 7", () => {
        expect(() => validateLogInput({ message: "test", level: 7 as any })).toThrow(ValidationError);
    });

    it("rejects non-integer level", () => {
        expect(() => validateLogInput({ message: "test", level: 3.5 as any })).toThrow(ValidationError);
    });

    // --- origin ---
    it("accepts SYSTEM origin", () => {
        expect(() => validateLogInput({ message: "test", origin: "SYSTEM" })).not.toThrow();
    });

    it("accepts AI_AGENT origin", () => {
        expect(() => validateLogInput({ message: "test", origin: "AI_AGENT" })).not.toThrow();
    });

    it("rejects invalid origin", () => {
        expect(() => validateLogInput({ message: "test", origin: "HACK" as any })).toThrow(ValidationError);
    });

    // --- isCritical ---
    it("rejects non-boolean isCritical", () => {
        expect(() => validateLogInput({ message: "test", isCritical: "yes" as any })).toThrow(ValidationError);
    });

    // --- tags ---
    it("accepts valid tags", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "ip", category: "10.0.0.1" }],
        })).not.toThrow();
    });

    it("rejects too many tags", () => {
        const tags = Array.from({ length: 101 }, (_, i) => ({ key: `k${i}`, category: "v" }));
        expect(() => validateLogInput({ message: "test", tags })).toThrow(ValidationError);
    });

    it("rejects tag with key too long", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "x".repeat(129), category: "v" }],
        })).toThrow(ValidationError);
    });

    it("rejects non-array tags", () => {
        expect(() => validateLogInput({ message: "test", tags: "bad" as any })).toThrow(ValidationError);
    });

    // --- resourceIds ---
    it("rejects too many resourceIds", () => {
        const ids = Array.from({ length: 101 }, (_, i) => `r${i}`);
        expect(() => validateLogInput({ message: "test", resourceIds: ids })).toThrow(ValidationError);
    });

    // --- aiContext ---
    it("accepts valid aiContext", () => {
        expect(() => validateLogInput({
            message: "test",
            aiContext: { agentId: "a1", taskId: "t1", loopDepth: 0 },
        })).not.toThrow();
    });

    it("rejects negative loopDepth", () => {
        expect(() => validateLogInput({
            message: "test",
            aiContext: { agentId: "a1", taskId: "t1", loopDepth: -1 },
        })).toThrow(ValidationError);
    });

    // --- ValidationError properties ---
    it("error has field name", () => {
        try {
            validateLogInput({ message: "valid", type: "INVALID" as any });
        } catch (e) {
            expect(e).toBeInstanceOf(ValidationError);
            expect((e as ValidationError).field).toBe("type");
        }
    });

    // --- undefined message passes (normalizer will catch) ---
    it("passes undefined message through to normalizer", () => {
        expect(() => validateLogInput({})).not.toThrow();
    });
});
