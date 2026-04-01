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

    // --- resourceIds[i] exceeding max length (line 164) ---
    it("rejects resourceId exceeding max length", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: ["x".repeat(513)],
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            resourceIds: ["x".repeat(513)],
        })).toThrow("resourceIds[0]");
    });

    // --- resourceIds[i] with null bytes (line 167) ---
    it("rejects resourceId containing null bytes", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: ["res\x00id"],
        })).toThrow(ValidationError);
    });

    // --- non-array resourceIds (line 154-155) ---
    it("rejects non-array resourceIds", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: "bad" as unknown as string[],
        })).toThrow(ValidationError);
    });

    // --- tag.category too long (line 143) ---
    it("rejects tag with category too long", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "k", category: "x".repeat(1025) }],
        })).toThrow(ValidationError);
    });

    // --- tag.key with null bytes (line 140-141) ---
    it("rejects tag key with null bytes", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "k\x00ey", category: "v" }],
        })).toThrow(ValidationError);
    });

    // --- tag.category with null bytes (line 146-147) ---
    it("rejects tag category with null bytes", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "k", category: "v\x00al" }],
        })).toThrow(ValidationError);
    });

    // --- details exceeding max length (line 178-179) ---
    it("rejects details exceeding max length", () => {
        expect(() => validateLogInput({
            message: "test",
            details: "x".repeat(65537),
        })).toThrow(ValidationError);
    });

    // --- details with null bytes (line 181-182) ---
    it("rejects details with null bytes", () => {
        expect(() => validateLogInput({
            message: "test",
            details: "hello\x00world",
        })).toThrow(ValidationError);
    });

    // --- agentBackLog non-object (line 196) ---
    it("rejects non-object agentBackLog (array)", () => {
        expect(() => validateLogInput({
            message: "test",
            agentBackLog: [1, 2, 3] as unknown as Record<string, unknown>,
        })).toThrow(ValidationError);
    });

    // --- agentBackLog exceeding maxInputSize (line 209) ---
    it("rejects agentBackLog exceeding maxInputSize (few keys but large values)", () => {
        // キー数は100以下だがサイズが大きい（L204のキー数制限を通過してL208に到達）
        const largeBackLog: Record<string, string> = {};
        for (let i = 0; i < 10; i++) {
            largeBackLog[`k${i}`] = "x".repeat(1000);
        }
        expect(() => validateLogInput(
            { message: "test", agentBackLog: largeBackLog as never },
            { maxInputSize: 100 },
        )).toThrow(ValidationError);
        expect(() => validateLogInput(
            { message: "test", agentBackLog: largeBackLog as never },
            { maxInputSize: 100 },
        )).toThrow("agentBackLog");
    });

    // --- total size exceeding maxTotalLogSize (line 211) ---
    it("rejects log exceeding total max size", () => {
        // A log with a huge message that fits within message limit but exceeds total log limit
        expect(() => validateLogInput(
            { message: "x".repeat(65000), details: "y".repeat(65000), input: { data: "z".repeat(900000) } },
            { maxTotalLogSize: 500 },
        )).toThrow(ValidationError);
    });

    // --- estimateLogSize: tags with nullish key/category (line 267 branch) ---
    it("validates log where estimateLogSize handles tags (size estimation)", () => {
        // Exercise the estimateLogSize tag loop with valid tags
        expect(() => validateLogInput({
            message: "test",
            tags: [
                { key: "k1", category: "c1" },
                { key: "k2", category: "c2" },
            ],
            traceInfo: "span-info",
            actorId: "user-1",
            boundary: "service-1",
            traceId: "trace-1",
        })).not.toThrow();
    });

    // --- estimateLogSize: resourceIds with strings (line 272 branch) ---
    it("validates log where estimateLogSize handles resourceIds", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: ["res-1", "res-2", "res-3"],
        })).not.toThrow();
    });

    // --- input exceeding maxInputSize (line 189) ---
    it("rejects input exceeding maxInputSize", () => {
        expect(() => validateLogInput(
            { message: "test", input: { data: "x".repeat(2_000_000) } },
            { maxInputSize: 100 },
        )).toThrow(ValidationError);
    });

    // --- aiContext with non-number loopDepth (line 204) ---
    it("rejects aiContext with non-number loopDepth", () => {
        expect(() => validateLogInput({
            message: "test",
            aiContext: { agentId: "a1", taskId: "t1", loopDepth: "5" as unknown as number },
        })).toThrow(ValidationError);
    });

    // --- tag.key non-string (line 137 first condition) ---
    it("rejects tag with non-string key", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: 123 as unknown as string, category: "v" }],
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: 123 as unknown as string, category: "v" }],
        })).toThrow("tags[0].key");
    });

    // --- tag.category non-string (line 143 first condition) ---
    it("rejects tag with non-string category", () => {
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "k", category: 456 as unknown as string }],
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            tags: [{ key: "k", category: 456 as unknown as string }],
        })).toThrow("tags[0].category");
    });

    // --- agentBackLog non-object (plain non-object, non-array) (line 196) ---
    it("rejects agentBackLog that is a primitive", () => {
        expect(() => validateLogInput({
            message: "test",
            agentBackLog: "bad" as unknown as Record<string, unknown>,
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            agentBackLog: "bad" as unknown as Record<string, unknown>,
        })).toThrow("agentBackLog");
    });

    // --- exercising estimateLogSize with all optional fields populated ---
    it("validates log with all optional fields for size estimation", () => {
        expect(() => validateLogInput({
            message: "test message for size",
            details: "some details",
            traceInfo: "trace-info",
            actorId: "actor-1",
            boundary: "svc:module",
            traceId: "trace-id-1",
            tags: [{ key: "k1", category: "c1" }],
            resourceIds: ["res-1", "res-2"],
            input: { data: "value" },
            agentBackLog: { agentId: "a1" } as unknown as Record<string, unknown>,
            aiContext: { agentId: "a1", taskId: "t1", loopDepth: 0 },
        })).not.toThrow();
    });

    // --- null message (line 79 — null vs undefined) ---
    it("rejects null message", () => {
        expect(() => validateLogInput({ message: null as unknown as string })).toThrow(ValidationError);
        expect(() => validateLogInput({ message: null as unknown as string })).toThrow("message");
    });

    // --- estimateJsonSize: depth > 20 branch (line 232) ---
    it("handles deeply nested input without crashing (exercises depth guard)", () => {
        // Build an object nested more than 20 levels
        let obj: Record<string, unknown> = { leaf: "value" };
        for (let i = 0; i < 25; i++) {
            obj = { nested: obj };
        }
        expect(() => validateLogInput({
            message: "test",
            input: obj as unknown as Record<string, unknown>,
        })).not.toThrow();
    });

    // --- estimateJsonSize: circular reference in input (line 237) ---
    it("handles circular reference in input field (exercises WeakSet guard)", () => {
        const circular: Record<string, unknown> = { a: 1 };
        circular.self = circular;
        expect(() => validateLogInput({
            message: "test",
            input: circular as unknown as Record<string, unknown>,
        })).not.toThrow();
    });

    // --- estimateJsonSize: null value inside input (line 233 true branch) ---
    it("handles input with null values (exercises null branch in estimateJsonSize)", () => {
        expect(() => validateLogInput({
            message: "test",
            input: { data: null, nested: { inner: null } },
        })).not.toThrow();
    });

    // --- estimateJsonSize: undefined value inside input (line 233 undefined branch) ---
    it("handles input with undefined values in estimateJsonSize", () => {
        expect(() => validateLogInput({
            message: "test",
            input: { data: undefined } as unknown as Record<string, unknown>,
        })).not.toThrow();
    });
});
