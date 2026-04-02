import { describe, it, expect } from "vitest";
import { LogNormalizer } from "../../../src/core/engine/log-normalizer";
import type { LogType, LogLevel, Log } from "../../../src/types/log";

describe("LogNormalizer", () => {
    const normalizer = new LogNormalizer("test-service");

    describe("defensive defaults (validation is at SDK boundary)", () => {
        it("defaults empty/undefined message to empty string", () => {
            const log = normalizer.normalize({});
            expect(log.message).toBe("");
        });

        it("trims whitespace-only message to empty string", () => {
            const log = normalizer.normalize({ message: "   " });
            expect(log.message).toBe("");
        });

        it("handles very long message without throwing", () => {
            const longMsg = "x".repeat(65537);
            const log = normalizer.normalize({ message: longMsg });
            expect(log.message).toBe(longMsg);
        });

        it("accepts message at exactly max length", () => {
            const maxMsg = "x".repeat(65536);
            const log = normalizer.normalize({ message: maxMsg });
            expect(log.message).toBe(maxMsg);
        });
    });

    describe("defaults", () => {
        it("generates traceId if not provided", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.traceId).toMatch(/^[0-9a-f-]{36}$/);
        });

        it("uses provided traceId", () => {
            const log = normalizer.normalize({ message: "test", traceId: "my-trace" });
            expect(log.traceId).toBe("my-trace");
        });

        it("defaults type to SYSTEM", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.type).toBe("SYSTEM");
        });

        it("defaults level to 3", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.level).toBe(3);
        });

        it("defaults origin to SYSTEM", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.origin).toBe("SYSTEM");
        });

        it("defaults isCritical to false", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.isCritical).toBe(false);
        });

        it("defaults triggerAgent to false", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.triggerAgent).toBe(false);
        });

        it("defaults tags to empty array", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.tags).toEqual([]);
        });

        it("defaults boundary to unknown", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.boundary).toBe("unknown");
        });

        it("sets serviceId from config", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.serviceId).toBe("test-service");
        });

        it("generates timestamp if not provided", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(log.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });

        it("generates logicalClock if not provided", () => {
            const log = normalizer.normalize({ message: "test" });
            expect(typeof log.logicalClock).toBe("number");
            expect(log.logicalClock).toBeGreaterThan(0);
        });
    });

    describe("type validation", () => {
        it("preserves valid log types", () => {
            const types = ["BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG"] as const;
            for (const type of types) {
                const log = normalizer.normalize({ message: "test", type });
                expect(log.type).toBe(type);
            }
        });

        it("falls back to SYSTEM for invalid type", () => {
            const log = normalizer.normalize({ message: "test", type: "INVALID" as unknown as LogType });
            expect(log.type).toBe("SYSTEM");
        });

        it("preserves valid log levels", () => {
            for (const level of [1, 2, 3, 4, 5, 6] as const) {
                const log = normalizer.normalize({ message: "test", level });
                expect(log.level).toBe(level);
            }
        });

        it("falls back to 3 for invalid level", () => {
            const log = normalizer.normalize({ message: "test", level: 99 as unknown as LogLevel });
            expect(log.level).toBe(3);
        });

        it("preserves AI_AGENT origin", () => {
            const log = normalizer.normalize({ message: "test", origin: "AI_AGENT" });
            expect(log.origin).toBe("AI_AGENT");
        });

        it("falls back to SYSTEM for invalid origin", () => {
            const log = normalizer.normalize({ message: "test", origin: "UNKNOWN" as unknown as Log["origin"] });
            expect(log.origin).toBe("SYSTEM");
        });
    });

    describe("defensive type coercion (A-03)", () => {
        it("falls back to ISO string when timestamp is a number", () => {
            const log = normalizer.normalize({ message: "test", timestamp: 1234567890 as never });
            expect(typeof log.timestamp).toBe("string");
            expect(log.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });

        it("falls back to ISO string when timestamp is a boolean", () => {
            const log = normalizer.normalize({ message: "test", timestamp: true as never });
            expect(typeof log.timestamp).toBe("string");
            expect(log.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });

        it("falls back to ISO string when timestamp is an object", () => {
            const log = normalizer.normalize({ message: "test", timestamp: {} as never });
            expect(typeof log.timestamp).toBe("string");
            expect(log.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });

        it("preserves valid ISO8601 timestamp string", () => {
            const ts = "2024-04-02T10:30:00.000Z";
            const log = normalizer.normalize({ message: "test", timestamp: ts });
            expect(log.timestamp).toBe(ts);
        });

        it("falls back to auto-clock when logicalClock is a string", () => {
            const log = normalizer.normalize({ message: "test", logicalClock: "123" as never });
            expect(typeof log.logicalClock).toBe("number");
            expect(log.logicalClock).toBeGreaterThan(0);
        });

        it("falls back to auto-clock when logicalClock is NaN", () => {
            const log = normalizer.normalize({ message: "test", logicalClock: NaN as never });
            expect(typeof log.logicalClock).toBe("number");
            expect(Number.isFinite(log.logicalClock)).toBe(true);
        });

        it("falls back to auto-clock when logicalClock is negative", () => {
            const log = normalizer.normalize({ message: "test", logicalClock: -5 as never });
            expect(typeof log.logicalClock).toBe("number");
            expect(log.logicalClock).toBeGreaterThanOrEqual(0);
        });

        it("preserves valid logicalClock number", () => {
            const log = normalizer.normalize({ message: "test", logicalClock: 42 });
            expect(log.logicalClock).toBe(42);
        });

        it("falls back to false when triggerAgent is string 'true'", () => {
            const log = normalizer.normalize({ message: "test", triggerAgent: "true" as never });
            expect(log.triggerAgent).toBe(false);
        });

        it("falls back to false when triggerAgent is string 'false'", () => {
            const log = normalizer.normalize({ message: "test", triggerAgent: "false" as never });
            expect(log.triggerAgent).toBe(false);
        });

        it("falls back to false when triggerAgent is number 1", () => {
            const log = normalizer.normalize({ message: "test", triggerAgent: 1 as never });
            expect(log.triggerAgent).toBe(false);
        });

        it("preserves valid boolean triggerAgent", () => {
            const log = normalizer.normalize({ message: "test", triggerAgent: true });
            expect(log.triggerAgent).toBe(true);
        });
    });

    describe("message trimming", () => {
        it("trims leading/trailing whitespace", () => {
            const log = normalizer.normalize({ message: "  hello world  " });
            expect(log.message).toBe("hello world");
        });
    });

    describe("optional fields passthrough", () => {
        it("preserves spanId", () => {
            const log = normalizer.normalize({ message: "test", spanId: "span-1" });
            expect(log.spanId).toBe("span-1");
        });

        it("preserves aiContext", () => {
            const ctx = { agentId: "a1", taskId: "t1", loopDepth: 2 };
            const log = normalizer.normalize({ message: "test", aiContext: ctx });
            expect(log.aiContext).toEqual(ctx);
        });

        it("preserves tags", () => {
            const tags = [{ key: "env", category: "prod" }];
            const log = normalizer.normalize({ message: "test", tags });
            expect(log.tags).toEqual(tags);
        });
    });
});
