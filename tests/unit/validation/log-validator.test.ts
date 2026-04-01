import { describe, it, expect } from "vitest";
import { validateLogInput, ValidationError } from "../../../src/validation/log-validator";
import type { LogType, LogLevel, LogTag, Log } from "../../../src/types/log";

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
            expect(() => validateLogInput({ message: "test", type: t as unknown as LogType })).not.toThrow();
        }
    });

    it("rejects invalid log type", () => {
        expect(() => validateLogInput({ message: "test", type: "INVALID" as unknown as LogType })).toThrow(ValidationError);
    });

    // --- level ---
    it("accepts valid levels 1-6", () => {
        for (let l = 1; l <= 6; l++) {
            expect(() => validateLogInput({ message: "test", level: l as unknown as LogLevel })).not.toThrow();
        }
    });

    it("rejects level 0", () => {
        expect(() => validateLogInput({ message: "test", level: 0 as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("rejects level 7", () => {
        expect(() => validateLogInput({ message: "test", level: 7 as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("rejects non-integer level", () => {
        expect(() => validateLogInput({ message: "test", level: 3.5 as unknown as LogLevel })).toThrow(ValidationError);
    });

    // --- origin ---
    it("accepts SYSTEM origin", () => {
        expect(() => validateLogInput({ message: "test", origin: "SYSTEM" })).not.toThrow();
    });

    it("accepts AI_AGENT origin", () => {
        expect(() => validateLogInput({ message: "test", origin: "AI_AGENT" })).not.toThrow();
    });

    it("rejects invalid origin", () => {
        expect(() => validateLogInput({ message: "test", origin: "HACK" as unknown as Log["origin"] })).toThrow(ValidationError);
    });

    // --- isCritical ---
    it("rejects non-boolean isCritical", () => {
        expect(() => validateLogInput({ message: "test", isCritical: "yes" as unknown as boolean })).toThrow(ValidationError);
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
        expect(() => validateLogInput({ message: "test", tags: "bad" as unknown as LogTag[] })).toThrow(ValidationError);
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
            validateLogInput({ message: "valid", type: "INVALID" as unknown as LogType });
        } catch (e) {
            expect(e).toBeInstanceOf(ValidationError);
            expect((e as ValidationError).field).toBe("type");
        }
    });

    // --- resourceIds[i] non-string (line 162) ---
    it("rejects non-string element in resourceIds", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: [42 as unknown as string],
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            resourceIds: [42 as unknown as string],
        })).toThrow("resourceIds[0]");
    });

    // --- details non-string (line 176) ---
    it("rejects non-string details", () => {
        expect(() => validateLogInput({
            message: "test",
            details: 123 as unknown as string,
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            details: 123 as unknown as string,
        })).toThrow("details");
    });

    // --- undefined message is now rejected at validator boundary (NEW-11 fix) ---
    it("rejects undefined message", () => {
        expect(() => validateLogInput({})).toThrow(ValidationError);
    });

    // --- estimateJsonSize: array branch (lines 240-243) ---
    it("accepts input with nested arrays (exercises estimateJsonSize array branch)", () => {
        expect(() => validateLogInput({
            message: "test",
            input: { data: [1, "two", [3, 4], { nested: true }] },
        })).not.toThrow();
    });

    // --- estimateJsonSize: non-object/non-primitive fallback (line 254) ---
    it("accepts input containing a Symbol-like value (exercises estimateJsonSize fallback)", () => {
        // Symbol values are not standard JSON, but estimateJsonSize should handle them gracefully
        const input = { val: Symbol("test") };
        expect(() => validateLogInput({
            message: "test",
            input: input as unknown as Record<string, unknown>,
        })).not.toThrow();
    });

    // --- large agentBackLog/aiContext exercises object branch of estimateJsonSize ---
    it("accepts log with large agentBackLog object (exercises estimateJsonSize object branch)", () => {
        const largeObj: Record<string, string> = {};
        for (let i = 0; i < 50; i++) {
            largeObj[`key${i}`] = `value${i}`;
        }
        expect(() => validateLogInput({
            message: "test",
            agentBackLog: largeObj as unknown as Record<string, unknown>,
        })).not.toThrow();
    });

    it("accepts log with aiContext containing various fields (exercises estimateJsonSize)", () => {
        expect(() => validateLogInput({
            message: "test",
            aiContext: {
                agentId: "a1",
                taskId: "t1",
                loopDepth: 5,
                modelId: "gpt-4",
                prompt: "analyze this data",
            },
        })).not.toThrow();
    });

    // --- validateStringField: typeof value !== "string" (line 218-219) ---
    it("rejects non-string actorId at runtime (exercises validateStringField type check)", () => {
        expect(() => validateLogInput({
            message: "test",
            actorId: 12345 as unknown as string,
        })).toThrow(ValidationError);
    });

    // --- validateStringField: exceeds max length (line 221-222) ---
    it("rejects actorId exceeding max string field length", () => {
        expect(() => validateLogInput({
            message: "test",
            actorId: "x".repeat(513),
        })).toThrow(ValidationError);
    });

    // --- validateStringField: contains null bytes (line 224-225) ---
    it("rejects traceId containing null bytes", () => {
        expect(() => validateLogInput({
            message: "test",
            traceId: "trace\x00id",
        })).toThrow(ValidationError);
    });
});
