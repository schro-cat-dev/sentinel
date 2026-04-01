/**
 * Size Limits Tests
 *
 * 全フィールドのサイズ制限が正しく機能することを検証。
 * デフォルト制限 + カスタムオーバーライドの両方をテスト。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig, validateLogInput, ValidationError, DEFAULT_VALIDATION_LIMITS } from "../../src/index";
import type { ValidationLimits } from "../../src/validation/log-validator";

describe("Size Limits: defaults", () => {
    it("DEFAULT_VALIDATION_LIMITS has sensible values", () => {
        expect(DEFAULT_VALIDATION_LIMITS.maxMessageLength).toBe(65536);
        expect(DEFAULT_VALIDATION_LIMITS.maxDetailsLength).toBe(65536);
        expect(DEFAULT_VALIDATION_LIMITS.maxTagCount).toBe(100);
        expect(DEFAULT_VALIDATION_LIMITS.maxTagKeyLength).toBe(128);
        expect(DEFAULT_VALIDATION_LIMITS.maxTagValueLength).toBe(1024);
        expect(DEFAULT_VALIDATION_LIMITS.maxResourceIds).toBe(100);
        expect(DEFAULT_VALIDATION_LIMITS.maxResourceIdLength).toBe(512);
        expect(DEFAULT_VALIDATION_LIMITS.maxStringFieldLength).toBe(512);
        expect(DEFAULT_VALIDATION_LIMITS.maxInputSize).toBe(1_048_576);
        expect(DEFAULT_VALIDATION_LIMITS.maxTotalLogSize).toBe(2_097_152);
    });
});

describe("Size Limits: string fields", () => {
    it("rejects actorId exceeding maxStringFieldLength", () => {
        expect(() => validateLogInput({
            message: "test",
            actorId: "a".repeat(513),
        })).toThrow(ValidationError);
    });

    it("accepts actorId at exactly maxStringFieldLength", () => {
        expect(() => validateLogInput({
            message: "test",
            actorId: "a".repeat(512),
        })).not.toThrow();
    });

    it("rejects traceId exceeding limit", () => {
        expect(() => validateLogInput({
            message: "test",
            traceId: "t".repeat(513),
        })).toThrow(ValidationError);
    });

    it("rejects spanId exceeding limit", () => {
        expect(() => validateLogInput({
            message: "test",
            spanId: "s".repeat(513),
        })).toThrow(ValidationError);
    });

    it("rejects parentSpanId exceeding limit", () => {
        expect(() => validateLogInput({
            message: "test",
            parentSpanId: "p".repeat(513),
        })).toThrow(ValidationError);
    });

    it("rejects boundary exceeding limit", () => {
        expect(() => validateLogInput({
            message: "test",
            boundary: "b".repeat(513),
        })).toThrow(ValidationError);
    });

    it("rejects traceInfo exceeding limit", () => {
        expect(() => validateLogInput({
            message: "test",
            traceInfo: "i".repeat(513),
        })).toThrow(ValidationError);
    });

    it("undefined string fields pass validation", () => {
        expect(() => validateLogInput({ message: "test" })).not.toThrow();
    });
});

describe("Size Limits: resourceIds element length", () => {
    it("rejects resourceId element exceeding limit", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: ["r".repeat(513)],
        })).toThrow(ValidationError);
    });

    it("accepts resourceId at exactly limit", () => {
        expect(() => validateLogInput({
            message: "test",
            resourceIds: ["r".repeat(512)],
        })).not.toThrow();
    });
});

describe("Size Limits: input field (JSON size)", () => {
    it("rejects input exceeding maxInputSize", () => {
        const bigInput = { data: "x".repeat(1_048_577) };
        expect(() => validateLogInput({
            message: "test",
            input: bigInput,
        })).toThrow(ValidationError);
    });

    it("accepts input within maxInputSize", () => {
        const smallInput = { data: "x".repeat(1000) };
        expect(() => validateLogInput({
            message: "test",
            input: smallInput,
        })).not.toThrow();
    });

    it("handles deeply nested input within size limit", () => {
        let obj: Record<string, unknown> = { value: "leaf" };
        for (let i = 0; i < 15; i++) obj = { nested: obj };
        expect(() => validateLogInput({
            message: "test",
            input: obj,
        })).not.toThrow();
    });

    it("null input passes", () => {
        expect(() => validateLogInput({
            message: "test",
            input: null,
        })).not.toThrow();
    });
});

describe("Size Limits: total log size", () => {
    it("rejects log that exceeds maxTotalLogSize", () => {
        expect(() => validateLogInput({
            message: "m".repeat(65536),
            details: { data: "d".repeat(65536) },
            input: { data: "x".repeat(1_048_576) },
        })).toThrow(ValidationError);
    });

    it("accepts log within total size limit", () => {
        expect(() => validateLogInput({
            message: "small message",
            details: { info: "small details" },
        })).not.toThrow();
    });
});

describe("Size Limits: custom overrides", () => {
    it("allows increasing maxMessageLength", () => {
        const bigMessage = "m".repeat(100_000);
        expect(() => validateLogInput(
            { message: bigMessage },
            { maxMessageLength: 200_000 },
        )).not.toThrow();
    });

    it("allows decreasing maxMessageLength", () => {
        expect(() => validateLogInput(
            { message: "m".repeat(101) },
            { maxMessageLength: 100 },
        )).toThrow(ValidationError);
    });

    it("allows increasing maxStringFieldLength", () => {
        expect(() => validateLogInput(
            { message: "test", actorId: "a".repeat(1000) },
            { maxStringFieldLength: 2000 },
        )).not.toThrow();
    });

    it("allows increasing maxInputSize", () => {
        const bigInput = { data: "x".repeat(2_000_000) };
        expect(() => validateLogInput(
            { message: "test", input: bigInput },
            { maxInputSize: 5_000_000, maxTotalLogSize: 10_000_000 },
        )).not.toThrow();
    });

    it("allows increasing maxTotalLogSize", () => {
        expect(() => validateLogInput(
            { message: "m".repeat(65536), details: { data: "d".repeat(65536) }, input: { data: "x".repeat(1_048_576) } },
            { maxInputSize: 5_000_000, maxTotalLogSize: 10_000_000 },
        )).not.toThrow();
    });

    it("partial overrides preserve other defaults", () => {
        // Only override maxMessageLength, all others should use defaults
        expect(() => validateLogInput(
            { message: "test", actorId: "a".repeat(513) },
            { maxMessageLength: 200_000 },
        )).toThrow(ValidationError); // actorId still limited to 512
    });
});

describe("Size Limits: via SentinelConfig.validationLimits", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("custom validationLimits in config are passed to validator", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p",
            serviceId: "s",
            security: { enableHashChain: false },
            validationLimits: { maxMessageLength: 100 },
        }));

        await expect(sentinel.ingest({
            message: "m".repeat(101),
            level: 3,
        })).rejects.toThrow(ValidationError);
    });

    it("default limits apply when validationLimits not set", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p",
            serviceId: "s",
            security: { enableHashChain: false },
        }));

        // 65536 is default max, should pass
        const result = await sentinel.ingest({
            message: "m".repeat(65536),
            level: 3,
        });
        expect(result.traceId).toBeDefined();
    });
});
