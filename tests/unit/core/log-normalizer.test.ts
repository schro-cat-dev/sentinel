import { describe, it, expect } from "vitest";
import { LogNormalizer } from "../../../src/core/engine/log-normalizer";

describe("LogNormalizer", () => {
    const normalizer = new LogNormalizer("test-service");

    describe("validation", () => {
        it("throws on empty message", () => {
            expect(() => normalizer.normalize({})).toThrow("Log message is required");
        });

        it("throws on whitespace-only message", () => {
            expect(() => normalizer.normalize({ message: "   " })).toThrow("Log message is required");
        });

        it("throws on message exceeding max length", () => {
            const longMsg = "x".repeat(65537);
            expect(() => normalizer.normalize({ message: longMsg })).toThrow("exceeds maximum length");
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
            const log = normalizer.normalize({ message: "test", type: "INVALID" as any });
            expect(log.type).toBe("SYSTEM");
        });

        it("preserves valid log levels", () => {
            for (const level of [1, 2, 3, 4, 5, 6] as const) {
                const log = normalizer.normalize({ message: "test", level });
                expect(log.level).toBe(level);
            }
        });

        it("falls back to 3 for invalid level", () => {
            const log = normalizer.normalize({ message: "test", level: 99 as any });
            expect(log.level).toBe(3);
        });

        it("preserves AI_AGENT origin", () => {
            const log = normalizer.normalize({ message: "test", origin: "AI_AGENT" });
            expect(log.origin).toBe("AI_AGENT");
        });

        it("falls back to SYSTEM for invalid origin", () => {
            const log = normalizer.normalize({ message: "test", origin: "UNKNOWN" as any });
            expect(log.origin).toBe("SYSTEM");
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
