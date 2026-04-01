/**
 * Exhaustive Validation & Normalizer Edge Case Tests
 *
 * validateLogInput: 全フィールドのバリデーションルールを網羅的に検証。
 * LogNormalizer: 防御的デフォルト注入・パススルー・エッジケースを網羅的に検証。
 */
import { describe, it, expect } from "vitest";
import { validateLogInput, ValidationError } from "../../src/validation/log-validator";
import { LogNormalizer } from "../../src/core/engine/log-normalizer";
import type { Log, LogType, LogLevel } from "../../src/types/log";
import { createTestLog } from "../helpers/fixtures";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid input for validateLogInput (only required field: message). */
const validInput = (overrides: Partial<Log> = {}): Partial<Log> => ({
    message: "valid message",
    ...overrides,
});

const expectValidationError = (field: string, input: Partial<Log>) => {
    try {
        validateLogInput(input);
        throw new Error(`Expected ValidationError for field "${field}" but none was thrown`);
    } catch (err) {
        expect(err).toBeInstanceOf(ValidationError);
        expect((err as ValidationError).field).toBe(field);
    }
};

const expectNoValidationError = (input: Partial<Log>) => {
    expect(() => validateLogInput(input)).not.toThrow();
};

// ---------------------------------------------------------------------------
// validateLogInput
// ---------------------------------------------------------------------------

describe("validateLogInput", () => {
    // === message ===
    describe("message field", () => {
        it("throws when message is undefined", () => {
            expectValidationError("message", {} as Partial<Log>);
        });

        it("throws when message is null", () => {
            expectValidationError("message", { message: null } as unknown as Partial<Log>);
        });

        it("throws when message is not a string (number)", () => {
            expectValidationError("message", { message: 123 } as unknown as Partial<Log>);
        });

        it("throws when message is not a string (boolean)", () => {
            expectValidationError("message", { message: true } as unknown as Partial<Log>);
        });

        it("throws when message is not a string (object)", () => {
            expectValidationError("message", { message: {} } as unknown as Partial<Log>);
        });

        it("throws when message is empty string", () => {
            expectValidationError("message", { message: "" });
        });

        it("throws when message is whitespace only", () => {
            expectValidationError("message", { message: "   \t\n  " });
        });

        it("throws when message exceeds max length (65536)", () => {
            expectValidationError("message", { message: "a".repeat(65537) });
        });

        it("accepts message at exactly max length (65536)", () => {
            expectNoValidationError({ message: "a".repeat(65536) });
        });

        it("throws at max+1 length (65537)", () => {
            expectValidationError("message", { message: "a".repeat(65537) });
        });

        it("throws when message contains null bytes", () => {
            expectValidationError("message", { message: "hello\x00world" });
        });

        it("accepts a normal message string", () => {
            expectNoValidationError({ message: "Hello world" });
        });
    });

    // === type ===
    describe("type field", () => {
        const validTypes: LogType[] = [
            "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
        ];

        it.each(validTypes)("accepts valid type: %s", (type) => {
            expectNoValidationError(validInput({ type }));
        });

        it("throws on invalid type", () => {
            expectValidationError("type", validInput({ type: "INVALID" as LogType }));
        });

        it("accepts undefined type (optional)", () => {
            expectNoValidationError(validInput({ type: undefined }));
        });

        it("throws on empty string type", () => {
            expectValidationError("type", validInput({ type: "" as LogType }));
        });

        it("throws on lowercase valid type name", () => {
            expectValidationError("type", validInput({ type: "system" as LogType }));
        });
    });

    // === level ===
    describe("level field", () => {
        const validLevels: LogLevel[] = [1, 2, 3, 4, 5, 6];

        it.each(validLevels)("accepts valid level: %d", (level) => {
            expectNoValidationError(validInput({ level }));
        });

        it("throws on level 0", () => {
            expectValidationError("level", validInput({ level: 0 as LogLevel }));
        });

        it("throws on level 7", () => {
            expectValidationError("level", validInput({ level: 7 as LogLevel }));
        });

        it("throws on float level (3.5)", () => {
            expectValidationError("level", validInput({ level: 3.5 as unknown as LogLevel }));
        });

        it("throws on negative level (-1)", () => {
            expectValidationError("level", validInput({ level: -1 as LogLevel }));
        });

        it("throws on string type level", () => {
            expectValidationError("level", validInput({ level: "3" as unknown as LogLevel }));
        });

        it("accepts undefined level (optional)", () => {
            expectNoValidationError(validInput({ level: undefined }));
        });

        it("throws on NaN level", () => {
            expectValidationError("level", validInput({ level: NaN as unknown as LogLevel }));
        });

        it("throws on Infinity level", () => {
            expectValidationError("level", validInput({ level: Infinity as unknown as LogLevel }));
        });
    });

    // === origin ===
    describe("origin field", () => {
        it("accepts SYSTEM", () => {
            expectNoValidationError(validInput({ origin: "SYSTEM" }));
        });

        it("accepts AI_AGENT", () => {
            expectNoValidationError(validInput({ origin: "AI_AGENT" }));
        });

        it("throws on invalid origin", () => {
            expectValidationError("origin", validInput({ origin: "HUMAN" as any }));
        });

        it("accepts undefined origin (optional)", () => {
            expectNoValidationError(validInput({ origin: undefined }));
        });

        it("throws on lowercase 'system'", () => {
            expectValidationError("origin", validInput({ origin: "system" as any }));
        });
    });

    // === isCritical ===
    describe("isCritical field", () => {
        it("accepts true", () => {
            expectNoValidationError(validInput({ isCritical: true }));
        });

        it("accepts false", () => {
            expectNoValidationError(validInput({ isCritical: false }));
        });

        it("throws on non-boolean (string 'true')", () => {
            expectValidationError("isCritical", validInput({ isCritical: "true" as unknown as boolean }));
        });

        it("throws on non-boolean (number 1)", () => {
            expectValidationError("isCritical", validInput({ isCritical: 1 as unknown as boolean }));
        });

        it("accepts undefined (optional)", () => {
            expectNoValidationError(validInput({ isCritical: undefined }));
        });
    });

    // === tags ===
    describe("tags field", () => {
        it("accepts valid tags array", () => {
            expectNoValidationError(validInput({
                tags: [{ key: "env", category: "production" }],
            }));
        });

        it("accepts empty tags array", () => {
            expectNoValidationError(validInput({ tags: [] }));
        });

        it("accepts max tag count (100)", () => {
            const tags = Array.from({ length: 100 }, (_, i) => ({
                key: `key-${i}`,
                category: `cat-${i}`,
            }));
            expectNoValidationError(validInput({ tags }));
        });

        it("throws on 101 tags", () => {
            const tags = Array.from({ length: 101 }, (_, i) => ({
                key: `key-${i}`,
                category: `cat-${i}`,
            }));
            expectValidationError("tags", validInput({ tags }));
        });

        it("throws when tag key exceeds max length (129 chars)", () => {
            expectValidationError("tags[0].key", validInput({
                tags: [{ key: "k".repeat(129), category: "c" }],
            }));
        });

        it("accepts tag key at max length (128 chars)", () => {
            expectNoValidationError(validInput({
                tags: [{ key: "k".repeat(128), category: "c" }],
            }));
        });

        it("throws when tag category exceeds max length (1025 chars)", () => {
            expectValidationError("tags[0].category", validInput({
                tags: [{ key: "k", category: "c".repeat(1025) }],
            }));
        });

        it("accepts tag category at max length (1024 chars)", () => {
            expectNoValidationError(validInput({
                tags: [{ key: "k", category: "c".repeat(1024) }],
            }));
        });

        it("throws when tags is not an array (object)", () => {
            expectValidationError("tags", validInput({
                tags: { key: "k", category: "c" } as any,
            }));
        });

        it("throws when tags is not an array (string)", () => {
            expectValidationError("tags", validInput({ tags: "invalid" as any }));
        });

        it("throws when tag key is not a string", () => {
            expectValidationError("tags[0].key", validInput({
                tags: [{ key: 123 as any, category: "c" }],
            }));
        });

        it("throws when tag category is not a string", () => {
            expectValidationError("tags[0].category", validInput({
                tags: [{ key: "k", category: 456 as any }],
            }));
        });
    });

    // === resourceIds ===
    describe("resourceIds field", () => {
        it("accepts valid resourceIds array", () => {
            expectNoValidationError(validInput({ resourceIds: ["res-1", "res-2"] }));
        });

        it("accepts empty resourceIds array", () => {
            expectNoValidationError(validInput({ resourceIds: [] }));
        });

        it("accepts max resourceIds count (100)", () => {
            const resourceIds = Array.from({ length: 100 }, (_, i) => `res-${i}`);
            expectNoValidationError(validInput({ resourceIds }));
        });

        it("throws on 101 resourceIds", () => {
            const resourceIds = Array.from({ length: 101 }, (_, i) => `res-${i}`);
            expectValidationError("resourceIds", validInput({ resourceIds }));
        });

        it("throws when resourceIds is not an array (string)", () => {
            expectValidationError("resourceIds", validInput({ resourceIds: "res-1" as any }));
        });

        it("throws when resourceIds is not an array (object)", () => {
            expectValidationError("resourceIds", validInput({ resourceIds: {} as any }));
        });

        it("accepts undefined resourceIds (optional)", () => {
            expectNoValidationError(validInput({ resourceIds: undefined }));
        });
    });

    // === details ===
    describe("details field", () => {
        it("accepts valid details string", () => {
            expectNoValidationError(validInput({ details: "some details" }));
        });

        it("accepts details at max length (65536)", () => {
            expectNoValidationError(validInput({ details: "d".repeat(65536) }));
        });

        it("throws when details exceeds max length (65537)", () => {
            expectValidationError("details", validInput({ details: "d".repeat(65537) }));
        });

        it("accepts undefined details (optional)", () => {
            expectNoValidationError(validInput({ details: undefined }));
        });

        it("accepts null details", () => {
            expectNoValidationError(validInput({ details: null as unknown as string }));
        });
    });

    // === agentBackLog ===
    describe("agentBackLog field", () => {
        it("accepts valid agentBackLog object", () => {
            expectNoValidationError(validInput({
                agentBackLog: {
                    agentId: "agent-1",
                    taskId: "task-1",
                    actionType: "analyze",
                    model: "gpt-4o",
                    inputHash: "abc123",
                    isAsynchronous: false,
                    generatedAt: "2026-01-01T00:00:00Z",
                    processorInfo: {
                        resourceInfo: {
                            cpu: { quantity: 4, unit: "cores" },
                            memory: { quantity: 8, unit: "GB" },
                            outerStorage: { quantity: 100, unit: "GB" },
                            serviceInfo: {
                                serviceId: "svc-1",
                                instanceId: "pod-1",
                                version: "1.0.0",
                                deployment: "prod",
                            },
                        },
                    },
                    status: "success",
                },
            }));
        });

        it("throws when agentBackLog is an array", () => {
            expectValidationError("agentBackLog", validInput({ agentBackLog: [] as any }));
        });

        it("throws when agentBackLog is a non-object (string)", () => {
            expectValidationError("agentBackLog", validInput({ agentBackLog: "invalid" as any }));
        });

        it("throws when agentBackLog is a non-object (number)", () => {
            expectValidationError("agentBackLog", validInput({ agentBackLog: 42 as any }));
        });

        it("accepts undefined agentBackLog (optional)", () => {
            expectNoValidationError(validInput({ agentBackLog: undefined }));
        });

        it("accepts null agentBackLog", () => {
            expectNoValidationError(validInput({ agentBackLog: null as any }));
        });
    });

    // === aiContext ===
    describe("aiContext field", () => {
        it("accepts valid aiContext", () => {
            expectNoValidationError(validInput({
                aiContext: { agentId: "a1", taskId: "t1", loopDepth: 0 },
            }));
        });

        it("throws when loopDepth is negative", () => {
            expectValidationError("aiContext.loopDepth", validInput({
                aiContext: { agentId: "a1", taskId: "t1", loopDepth: -1 },
            }));
        });

        it("throws when loopDepth is a string", () => {
            expectValidationError("aiContext.loopDepth", validInput({
                aiContext: { agentId: "a1", taskId: "t1", loopDepth: "5" as any },
            }));
        });

        it("accepts aiContext with loopDepth 0", () => {
            expectNoValidationError(validInput({
                aiContext: { agentId: "a1", taskId: "t1", loopDepth: 0 },
            }));
        });

        it("accepts aiContext with large loopDepth", () => {
            expectNoValidationError(validInput({
                aiContext: { agentId: "a1", taskId: "t1", loopDepth: 9999 },
            }));
        });

        it("accepts undefined aiContext (optional)", () => {
            expectNoValidationError(validInput({ aiContext: undefined }));
        });

        it("accepts null aiContext", () => {
            expectNoValidationError(validInput({ aiContext: null as any }));
        });
    });
});

// ---------------------------------------------------------------------------
// LogNormalizer
// ---------------------------------------------------------------------------

describe("LogNormalizer", () => {
    const SERVICE_ID = "normalizer-test-service";
    const normalizer = new LogNormalizer(SERVICE_ID);

    // === message ===
    describe("message normalization", () => {
        it("returns empty string when message is undefined", () => {
            const result = normalizer.normalize({});
            expect(result.message).toBe("");
        });

        it("trims whitespace message to empty string", () => {
            const result = normalizer.normalize({ message: "   \t\n  " });
            expect(result.message).toBe("");
        });

        it("trims leading/trailing whitespace", () => {
            const result = normalizer.normalize({ message: "  hello  " });
            expect(result.message).toBe("hello");
        });

        it("returns empty string when message is non-string (number)", () => {
            const result = normalizer.normalize({ message: 123 as any });
            expect(result.message).toBe("");
        });

        it("preserves valid message content", () => {
            const result = normalizer.normalize({ message: "valid message" });
            expect(result.message).toBe("valid message");
        });
    });

    // === traceId ===
    describe("traceId normalization", () => {
        it("generates UUID when traceId is missing", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.traceId).toBeDefined();
            expect(result.traceId).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
            );
        });

        it("generates UUID when traceId is empty string", () => {
            const result = normalizer.normalize({ message: "test", traceId: "" });
            expect(result.traceId).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
            );
        });

        it("preserves provided traceId", () => {
            const result = normalizer.normalize({ message: "test", traceId: "my-trace-id" });
            expect(result.traceId).toBe("my-trace-id");
        });
    });

    // === timestamp ===
    describe("timestamp normalization", () => {
        it("generates timestamp when missing", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.timestamp).toBeDefined();
            expect(result.timestamp.length).toBeGreaterThan(0);
            // Should be valid ISO string
            expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp);
        });

        it("generates timestamp when empty string", () => {
            const result = normalizer.normalize({ message: "test", timestamp: "" });
            expect(result.timestamp).toBeDefined();
            expect(result.timestamp.length).toBeGreaterThan(0);
        });

        it("preserves provided timestamp", () => {
            const ts = "2026-01-15T12:00:00.000Z";
            const result = normalizer.normalize({ message: "test", timestamp: ts });
            expect(result.timestamp).toBe(ts);
        });
    });

    // === boundary ===
    describe("boundary normalization", () => {
        it("defaults to 'unknown' when missing", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.boundary).toBe("unknown");
        });

        it("defaults to 'unknown' when empty string", () => {
            const result = normalizer.normalize({ message: "test", boundary: "" });
            expect(result.boundary).toBe("unknown");
        });

        it("preserves provided boundary", () => {
            const result = normalizer.normalize({ message: "test", boundary: "my-service:handler" });
            expect(result.boundary).toBe("my-service:handler");
        });
    });

    // === type ===
    describe("type normalization", () => {
        const allTypes: LogType[] = [
            "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
        ];

        it.each(allTypes)("preserves valid type: %s", (type) => {
            const result = normalizer.normalize({ message: "test", type });
            expect(result.type).toBe(type);
        });

        it("defaults invalid type to SYSTEM", () => {
            const result = normalizer.normalize({ message: "test", type: "INVALID" as LogType });
            expect(result.type).toBe("SYSTEM");
        });

        it("defaults undefined type to SYSTEM", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.type).toBe("SYSTEM");
        });
    });

    // === level ===
    describe("level normalization", () => {
        const allLevels: LogLevel[] = [1, 2, 3, 4, 5, 6];

        it.each(allLevels)("preserves valid level: %d", (level) => {
            const result = normalizer.normalize({ message: "test", level });
            expect(result.level).toBe(level);
        });

        it("defaults invalid level (0) to 3", () => {
            const result = normalizer.normalize({ message: "test", level: 0 as LogLevel });
            expect(result.level).toBe(3);
        });

        it("defaults invalid level (7) to 3", () => {
            const result = normalizer.normalize({ message: "test", level: 7 as LogLevel });
            expect(result.level).toBe(3);
        });

        it("defaults undefined level to 3", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.level).toBe(3);
        });

        it("defaults NaN level to 3", () => {
            const result = normalizer.normalize({ message: "test", level: NaN as LogLevel });
            expect(result.level).toBe(3);
        });
    });

    // === origin ===
    describe("origin normalization", () => {
        it("preserves AI_AGENT origin", () => {
            const result = normalizer.normalize({ message: "test", origin: "AI_AGENT" });
            expect(result.origin).toBe("AI_AGENT");
        });

        it("preserves SYSTEM origin", () => {
            const result = normalizer.normalize({ message: "test", origin: "SYSTEM" });
            expect(result.origin).toBe("SYSTEM");
        });

        it("defaults invalid origin to SYSTEM", () => {
            const result = normalizer.normalize({ message: "test", origin: "HUMAN" as any });
            expect(result.origin).toBe("SYSTEM");
        });

        it("defaults undefined origin to SYSTEM", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.origin).toBe("SYSTEM");
        });
    });

    // === isCritical ===
    describe("isCritical normalization", () => {
        it("defaults to false when undefined", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.isCritical).toBe(false);
        });

        it("preserves true", () => {
            const result = normalizer.normalize({ message: "test", isCritical: true });
            expect(result.isCritical).toBe(true);
        });

        it("preserves false", () => {
            const result = normalizer.normalize({ message: "test", isCritical: false });
            expect(result.isCritical).toBe(false);
        });
    });

    // === triggerAgent ===
    describe("triggerAgent normalization", () => {
        it("defaults to false when undefined", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.triggerAgent).toBe(false);
        });

        it("preserves true", () => {
            const result = normalizer.normalize({ message: "test", triggerAgent: true });
            expect(result.triggerAgent).toBe(true);
        });

        it("preserves false", () => {
            const result = normalizer.normalize({ message: "test", triggerAgent: false });
            expect(result.triggerAgent).toBe(false);
        });
    });

    // === tags ===
    describe("tags normalization", () => {
        it("defaults to empty array when undefined", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.tags).toEqual([]);
        });

        it("preserves provided tags", () => {
            const tags = [{ key: "env", category: "prod" }];
            const result = normalizer.normalize({ message: "test", tags });
            expect(result.tags).toEqual(tags);
        });
    });

    // === agentBackLog ===
    describe("agentBackLog passthrough", () => {
        it("passes through valid agentBackLog object", () => {
            const backlog = {
                agentId: "agent-1",
                taskId: "task-1",
                actionType: "analyze",
                model: "gpt-4o",
                inputHash: "hash",
                isAsynchronous: false,
                generatedAt: "2026-01-01T00:00:00Z",
                processorInfo: {
                    resourceInfo: {
                        cpu: { quantity: 4, unit: "cores" },
                        memory: { quantity: 8, unit: "GB" },
                        outerStorage: { quantity: 100, unit: "GB" },
                        serviceInfo: {
                            serviceId: "svc-1",
                            instanceId: "pod-1",
                            version: "1.0.0",
                            deployment: "prod",
                        },
                    },
                },
                status: "success" as const,
            };
            const result = normalizer.normalize({ message: "test", agentBackLog: backlog });
            expect(result.agentBackLog).toEqual(backlog);
        });

        it("passes through undefined agentBackLog", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.agentBackLog).toBeUndefined();
        });
    });

    // === traceInfo ===
    describe("traceInfo passthrough", () => {
        it("passes through provided traceInfo", () => {
            const result = normalizer.normalize({ message: "test", traceInfo: "trace-data" });
            expect(result.traceInfo).toBe("trace-data");
        });

        it("passes through undefined traceInfo", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.traceInfo).toBeUndefined();
        });
    });

    // === aiContext ===
    describe("aiContext passthrough", () => {
        it("passes through provided aiContext", () => {
            const aiContext = { agentId: "a1", taskId: "t1", loopDepth: 5 };
            const result = normalizer.normalize({ message: "test", aiContext });
            expect(result.aiContext).toEqual(aiContext);
        });

        it("passes through undefined aiContext", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.aiContext).toBeUndefined();
        });
    });

    // === input ===
    describe("input passthrough", () => {
        it("passes through object input", () => {
            const input = { key: "value" };
            const result = normalizer.normalize({ message: "test", input });
            expect(result.input).toEqual(input);
        });

        it("passes through array input", () => {
            const input = [1, 2, 3];
            const result = normalizer.normalize({ message: "test", input });
            expect(result.input).toEqual(input);
        });

        it("passes through string input", () => {
            const result = normalizer.normalize({ message: "test", input: "raw-string" });
            expect(result.input).toBe("raw-string");
        });

        it("passes through null input", () => {
            const result = normalizer.normalize({ message: "test", input: null });
            expect(result.input).toBeNull();
        });

        it("passes through undefined input", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.input).toBeUndefined();
        });
    });

    // === details ===
    describe("details passthrough", () => {
        it("passes through provided details", () => {
            const result = normalizer.normalize({ message: "test", details: "detail text" });
            expect(result.details).toBe("detail text");
        });

        it("passes through undefined details", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.details).toBeUndefined();
        });
    });

    // === resourceIds ===
    describe("resourceIds passthrough", () => {
        it("passes through provided resourceIds", () => {
            const result = normalizer.normalize({ message: "test", resourceIds: ["r1", "r2"] });
            expect(result.resourceIds).toEqual(["r1", "r2"]);
        });

        it("passes through undefined resourceIds", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.resourceIds).toBeUndefined();
        });
    });

    // === serviceId ===
    describe("serviceId injection", () => {
        it("always uses serviceId from constructor", () => {
            const result = normalizer.normalize({ message: "test", serviceId: "override-attempt" });
            expect(result.serviceId).toBe(SERVICE_ID);
        });

        it("injects serviceId even when input has none", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(result.serviceId).toBe(SERVICE_ID);
        });

        it("different normalizer instances use their own serviceId", () => {
            const other = new LogNormalizer("other-service");
            const result = other.normalize({ message: "test" });
            expect(result.serviceId).toBe("other-service");
        });
    });

    // === logicalClock ===
    describe("logicalClock normalization", () => {
        it("generates logicalClock when missing", () => {
            const result = normalizer.normalize({ message: "test" });
            expect(typeof result.logicalClock).toBe("number");
            expect(result.logicalClock).toBeGreaterThan(0);
        });

        it("preserves provided logicalClock", () => {
            const result = normalizer.normalize({ message: "test", logicalClock: 42 });
            expect(result.logicalClock).toBe(42);
        });
    });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("Edge cases", () => {
    const normalizer = new LogNormalizer("edge-case-service");

    describe("validateLogInput edge cases", () => {
        it("rejects completely empty input {} (message required)", () => {
            expectValidationError("message", {} as Partial<Log>);
        });

        it("accepts input with all optional fields populated", () => {
            expectNoValidationError({
                message: "full input",
                type: "SECURITY",
                level: 5,
                origin: "AI_AGENT",
                isCritical: true,
                tags: [{ key: "env", category: "prod" }],
                resourceIds: ["res-1"],
                details: "detailed info",
                agentBackLog: {
                    agentId: "agent-1",
                    taskId: "task-1",
                    actionType: "analyze",
                    model: "gpt-4o",
                    inputHash: "hash",
                    isAsynchronous: false,
                    generatedAt: "2026-01-01T00:00:00Z",
                    processorInfo: {
                        resourceInfo: {
                            cpu: { quantity: 4, unit: "cores" },
                            memory: { quantity: 8, unit: "GB" },
                            outerStorage: { quantity: 100, unit: "GB" },
                            serviceInfo: {
                                serviceId: "svc-1",
                                instanceId: "pod-1",
                                version: "1.0.0",
                                deployment: "prod",
                            },
                        },
                    },
                    status: "success",
                },
                aiContext: { agentId: "a1", taskId: "t1", loopDepth: 3 },
            });
        });

        it("ignores extra unknown fields in input", () => {
            expectNoValidationError({
                message: "test",
                unknownField: "should be ignored",
                anotherExtra: 42,
            } as any);
        });
    });

    describe("Unicode handling", () => {
        it("validateLogInput accepts Japanese characters in message", () => {
            expectNoValidationError({ message: "ログメッセージ：セキュリティ違反を検出しました" });
        });

        it("validateLogInput accepts emoji in message", () => {
            expectNoValidationError({ message: "Alert triggered 🚨🔥 critical failure" });
        });

        it("validateLogInput accepts mixed Unicode in message", () => {
            expectNoValidationError({ message: "アラート 🚨 triggered for ユーザー user-123" });
        });

        it("LogNormalizer preserves Japanese message", () => {
            const msg = "ログメッセージ：セキュリティ違反を検出しました";
            const result = normalizer.normalize({ message: msg });
            expect(result.message).toBe(msg);
        });

        it("LogNormalizer preserves emoji message", () => {
            const msg = "Alert 🚨🔥 critical";
            const result = normalizer.normalize({ message: msg });
            expect(result.message).toBe(msg);
        });
    });

    describe("LogNormalizer with completely empty input", () => {
        it("produces a valid Log with all defaults from empty object", () => {
            const result = normalizer.normalize({});
            expect(result.message).toBe("");
            expect(result.type).toBe("SYSTEM");
            expect(result.level).toBe(3);
            expect(result.origin).toBe("SYSTEM");
            expect(result.isCritical).toBe(false);
            expect(result.triggerAgent).toBe(false);
            expect(result.tags).toEqual([]);
            expect(result.boundary).toBe("unknown");
            expect(result.serviceId).toBe("edge-case-service");
            expect(result.traceId).toBeDefined();
            expect(result.timestamp).toBeDefined();
            expect(typeof result.logicalClock).toBe("number");
        });
    });

    describe("LogNormalizer with extra unknown fields", () => {
        it("does not include unknown fields in output", () => {
            const result = normalizer.normalize({
                message: "test",
                unknownField: "extra",
            } as any);
            expect((result as any).unknownField).toBeUndefined();
        });
    });
});
