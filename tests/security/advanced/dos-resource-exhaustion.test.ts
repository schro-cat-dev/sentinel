/**
 * Security Test: DoS and Resource Exhaustion
 *
 * Tests that the SDK handles extreme inputs gracefully without memory exhaustion,
 * CPU starvation, or pipeline deadlocks.
 *
 * CWE-400: Uncontrolled Resource Consumption
 * CWE-770: Allocation of Resources Without Limits or Throttling
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { MaskingService } from "../../../src/security/masking-service";
import { validateLogInput, ValidationError } from "../../../src/validation/log-validator";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { createTestLog, createTestConfig, createTestTaskRule } from "../../helpers/fixtures";
import type { MaskingRule } from "../../../src/configs/masking-rule";

const ALL_PII_RULES: MaskingRule[] = [
    { type: "PII_TYPE", category: "CREDIT_CARD" },
    { type: "PII_TYPE", category: "PHONE" },
    { type: "PII_TYPE", category: "EMAIL" },
    { type: "PII_TYPE", category: "GOVERNMENT_ID" },
];

const TIMING_LIMIT_MS = 5000;

function assertTiming(startMs: number, label: string): void {
    const elapsed = performance.now() - startMs;
    expect(elapsed, `${label} took ${elapsed.toFixed(1)}ms`).toBeLessThan(TIMING_LIMIT_MS);
}

describe("Security: DoS and Resource Exhaustion", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    // =========================================================================
    // Memory exhaustion via masking
    // =========================================================================
    describe("Memory exhaustion via masking", () => {
        it("handles object with 10000 keys", () => {
            const obj: Record<string, string> = {};
            for (let i = 0; i < 10000; i++) {
                obj[`key_${i}`] = `value_${i}`;
            }
            const start = performance.now();
            const result = MaskingService.mask(obj, ALL_PII_RULES);
            assertTiming(start, "10000 keys");
            expect(typeof result).toBe("object");
            expect(result).not.toBeNull();
            expect(Object.keys(result as Record<string, unknown>).length).toBe(10000);
        });

        it("handles array with 10000 string elements", () => {
            const arr = Array.from({ length: 10000 }, (_, i) => `element_${i}`);
            const start = performance.now();
            const result = MaskingService.mask(arr, ALL_PII_RULES);
            assertTiming(start, "10000 element array");
            expect(Array.isArray(result)).toBe(true);
            // デフォルトmaxArrayLengthで切り詰められるが、配列として返る
            expect((result as unknown[]).length).toBeGreaterThan(0);
        });

        it("handles 1MB message string with PII patterns throughout", () => {
            const piiBlock = "user@example.com 4111-1111-1111-1111 090-1234-5678 ";
            const repetitions = Math.ceil(1_000_000 / piiBlock.length);
            const bigMessage = piiBlock.repeat(repetitions);
            const start = performance.now();
            const result = MaskingService.mask(bigMessage, ALL_PII_RULES);
            assertTiming(start, "1MB PII message");
            expect(typeof result).toBe("string");
            expect(result as string).not.toContain("user@example.com");
        });

        it("handles deeply nested object (50 levels) with PII at every level", () => {
            let obj: Record<string, unknown> = { email: "deep@example.com" };
            for (let i = 0; i < 50; i++) {
                obj = { [`level_${i}`]: obj, email: `level${i}@example.com` };
            }
            const start = performance.now();
            const result = MaskingService.mask(obj, ALL_PII_RULES);
            assertTiming(start, "50-level nesting");
            expect(typeof result).toBe("object");
            expect(result).not.toBeNull();
        });

        it("truncates safely with maxDepth=1 on deep object", () => {
            let obj: Record<string, unknown> = { data: "leaf" };
            for (let i = 0; i < 20; i++) {
                obj = { nested: obj };
            }
            const start = performance.now();
            const result = MaskingService.mask(obj, ALL_PII_RULES, [], { maxDepth: 1 }) as Record<string, unknown>;
            assertTiming(start, "maxDepth=1");
            expect(result.nested).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
        });

        it("truncates safely with maxArrayLength=1 on long array", () => {
            const arr = Array.from({ length: 5000 }, (_, i) => `item_${i}`);
            const start = performance.now();
            const result = MaskingService.mask(arr, ALL_PII_RULES, [], { maxArrayLength: 1 }) as unknown[];
            assertTiming(start, "maxArrayLength=1");
            expect(result.length).toBe(1);
        });

        it("handles object with circular reference through multiple paths", () => {
            const a: Record<string, unknown> = { name: "a", email: "a@test.com" };
            const b: Record<string, unknown> = { name: "b", ref: a };
            const c: Record<string, unknown> = { name: "c", ref: b };
            a.circular = c;
            const start = performance.now();
            const result = MaskingService.mask(a, ALL_PII_RULES);
            assertTiming(start, "multi-path circular");
            expect(typeof result).toBe("object");
            expect(result).not.toBeNull();
            // 循環参照はマーカー文字列で切断されるべき
            const resultObj = result as Record<string, unknown>;
            expect(resultObj.name).toBe("a");
        });

        it("handles object with shared references (same object referenced 100 times)", () => {
            const shared = { secret: "user@example.com" };
            const container: Record<string, unknown> = {};
            for (let i = 0; i < 100; i++) {
                container[`ref_${i}`] = shared;
            }
            const start = performance.now();
            const result = MaskingService.mask(container, ALL_PII_RULES);
            assertTiming(start, "100 shared refs");
            expect(typeof result).toBe("object");
            expect(result).not.toBeNull();
            // email はマスクされているべき
            const resultObj = result as Record<string, Record<string, unknown>>;
            const firstRef = resultObj.ref_0;
            expect(typeof firstRef).toBe("object");
            expect(String(firstRef.secret)).not.toContain("user@example.com");
        });

        it("handles empty object without crash", () => {
            const result = MaskingService.mask({}, ALL_PII_RULES);
            expect(result).toEqual({});
        });

        it("handles empty array without crash", () => {
            const result = MaskingService.mask([], ALL_PII_RULES);
            expect(result).toEqual([]);
        });

        it("handles object with mixed value types at scale", () => {
            const obj: Record<string, unknown> = {};
            for (let i = 0; i < 5000; i++) {
                obj[`str_${i}`] = `user${i}@example.com`;
                obj[`num_${i}`] = i;
                obj[`bool_${i}`] = i % 2 === 0;
                obj[`null_${i}`] = null;
            }
            const start = performance.now();
            const result = MaskingService.mask(obj, ALL_PII_RULES);
            assertTiming(start, "20000 mixed keys");
            expect(typeof result).toBe("object");
            expect(result).not.toBeNull();
            expect(Object.keys(result as Record<string, unknown>).length).toBe(20000);
        });

        it("handles deeply nested arrays", () => {
            let arr: unknown = ["leaf@example.com"];
            for (let i = 0; i < 9; i++) {
                arr = [arr, `level${i}@example.com`];
            }
            const start = performance.now();
            const result = MaskingService.mask(arr, ALL_PII_RULES);
            assertTiming(start, "nested arrays");
            expect(Array.isArray(result)).toBe(true);
        });

        it("handles maxDepth=0 (immediately truncates objects)", () => {
            const obj = { a: { b: "test@example.com" } };
            const result = MaskingService.mask(obj, ALL_PII_RULES, [], { maxDepth: 0 });
            expect(result).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
        });

        it("handles alternating object/array nesting to maxDepth", () => {
            let structure: unknown = "deep@example.com";
            for (let i = 0; i < 9; i++) {
                structure = i % 2 === 0 ? { data: structure } : [structure];
            }
            const result = MaskingService.mask(structure, ALL_PII_RULES);
            // 最外層は奇数回（8）のイテレーションで { data: ... } になる
            expect(typeof result === "object" || Array.isArray(result)).toBe(true);
            expect(result).not.toBeNull();
        });
    });

    // =========================================================================
    // CPU exhaustion
    // =========================================================================
    describe("CPU exhaustion", () => {
        it("handles 100 masking rules applied to 1KB message", () => {
            const rules: MaskingRule[] = [];
            for (let i = 0; i < 100; i++) {
                rules.push({
                    type: "REGEX",
                    pattern: new RegExp(`pattern_${i}`),
                    replacement: `[REDACTED_${i}]`,
                    description: `Rule ${i}`,
                });
            }
            const message = "A".repeat(1024);
            const start = performance.now();
            const result = MaskingService.mask(message, rules);
            assertTiming(start, "100 regex rules on 1KB");
            expect(typeof result).toBe("string");
        });

        it("handles 10 PII + 10 REGEX + 10 KEY_MATCH rules combined", () => {
            const rules: MaskingRule[] = [
                { type: "PII_TYPE", category: "CREDIT_CARD" },
                { type: "PII_TYPE", category: "PHONE" },
                { type: "PII_TYPE", category: "EMAIL" },
                { type: "PII_TYPE", category: "GOVERNMENT_ID" },
                { type: "PII_TYPE", category: "CREDIT_CARD" },
                { type: "PII_TYPE", category: "PHONE" },
                { type: "PII_TYPE", category: "EMAIL" },
                { type: "PII_TYPE", category: "GOVERNMENT_ID" },
                { type: "PII_TYPE", category: "CREDIT_CARD" },
                { type: "PII_TYPE", category: "PHONE" },
                ...Array.from({ length: 10 }, (_, i) => ({
                    type: "REGEX" as const,
                    pattern: new RegExp(`secret_${i}`, "g"),
                    replacement: `[SECRET_${i}]`,
                    description: `Regex rule ${i}`,
                })),
                ...Array.from({ length: 10 }, (_, i) => ({
                    type: "KEY_MATCH" as const,
                    sensitiveKeys: [`sensitive_key_${i}`],
                })),
            ];
            const obj: Record<string, string> = {};
            for (let i = 0; i < 50; i++) {
                obj[`field_${i}`] = `user${i}@example.com secret_${i % 10} 4111-1111-1111-1111`;
                obj[`sensitive_key_${i % 10}`] = `secret_value_${i}`;
            }
            const start = performance.now();
            const result = MaskingService.mask(obj, rules);
            assertTiming(start, "30 mixed rules on 50 fields");
            expect(typeof result).toBe("object");
            expect(result).not.toBeNull();
            // sensitive_key はマスクされているべき
            const resultObj = result as Record<string, unknown>;
            expect(resultObj["sensitive_key_0"]).toBe("[MASKED_KEY]");
        });

        it("handles KEY_MATCH with 1000 sensitive keys", () => {
            const sensitiveKeys = Array.from({ length: 1000 }, (_, i) => `secret_${i}`);
            const rules: MaskingRule[] = [{ type: "KEY_MATCH", sensitiveKeys }];
            const obj: Record<string, string> = {};
            for (let i = 0; i < 1000; i++) {
                obj[`secret_${i}`] = `value_${i}`;
            }
            const start = performance.now();
            const result = MaskingService.mask(obj, rules) as Record<string, unknown>;
            assertTiming(start, "1000 KEY_MATCH keys");
            for (let i = 0; i < 1000; i++) {
                expect(result[`secret_${i}`]).toBe("[MASKED_KEY]");
            }
        });

        it("handles long message (64KB) with every PII pattern", () => {
            const piiSample = "card: 4111-1111-1111-1111 email: user@test.com phone: 090-1234-5678 id: 123456789012 ";
            const bigMessage = piiSample.repeat(Math.ceil(65536 / piiSample.length)).slice(0, 65536);
            const start = performance.now();
            const result = MaskingService.mask(bigMessage, ALL_PII_RULES);
            assertTiming(start, "64KB PII message");
            expect(typeof result).toBe("string");
            expect(result as string).not.toContain("user@test.com");
        });

        it("handles message that almost matches ReDoS pattern but doesn't", () => {
            // Crafted string with many near-matches to stress regex backtracking
            const nearMatch = "1234 5678 9012 345X ".repeat(500);
            const start = performance.now();
            const result = MaskingService.mask(nearMatch, ALL_PII_RULES);
            assertTiming(start, "ReDoS near-miss");
            expect(typeof result).toBe("string");
        });

        it("handles REGEX rule with complex pattern on large input", () => {
            const rules: MaskingRule[] = [{
                type: "REGEX",
                pattern: /\b[A-Z]{2,}\d+[A-Z]+\b/,
                replacement: "[COMPLEX]",
                description: "complex pattern",
            }];
            const input = "AB12CD EF34GH " .repeat(5000);
            const start = performance.now();
            const result = MaskingService.mask(input, rules);
            assertTiming(start, "complex regex on large input");
            expect(typeof result).toBe("string");
        });

        it("handles multiple PII types in single field value", () => {
            const multiPii = "Contact user@test.com at 090-1234-5678, card 4111-1111-1111-1111, gov 123456789012";
            const start = performance.now();
            const result = MaskingService.mask(multiPii, ALL_PII_RULES) as string;
            assertTiming(start, "multi-PII single field");
            expect(result).not.toContain("user@test.com");
            expect(result).not.toContain("090-1234-5678");
        });

        it("handles regex rules that produce longer replacements than input", () => {
            const rules: MaskingRule[] = [{
                type: "REGEX",
                pattern: /a/,
                replacement: "[REPLACED_WITH_VERY_LONG_STRING]",
                description: "expanding rule",
            }];
            const input = "a".repeat(10000);
            const start = performance.now();
            const result = MaskingService.mask(input, rules);
            assertTiming(start, "expanding replacements");
            expect(typeof result).toBe("string");
        });

        it("handles empty rules array on large input efficiently", () => {
            const largeInput = "x".repeat(100000);
            const start = performance.now();
            const result = MaskingService.mask(largeInput, []);
            assertTiming(start, "no rules large input");
            expect(result).toBe(largeInput);
        });

        it("handles PII_TYPE with unknown category gracefully", () => {
            const rules: MaskingRule[] = [
                { type: "PII_TYPE", category: "NONEXISTENT" as never },
            ];
            const result = MaskingService.mask("some text", rules);
            expect(result).toBe("some text");
        });
    });

    // =========================================================================
    // Pipeline throughput
    // =========================================================================
    describe("Pipeline throughput", () => {
        function createSentinelWithTaskRules(): Sentinel {
            const config = createDefaultConfig({
                projectName: "dos-test",
                serviceId: "dos-test-svc",
                environment: "test",
                masking: {
                    enabled: true,
                    rules: ALL_PII_RULES,
                    preserveFields: ["traceId"],
                },
                security: { enableHashChain: true },
                taskRules: [createTestTaskRule()],
            });
            return Sentinel.initialize(config);
        }

        it("handles 100 sequential ingests with full pipeline", async () => {
            const sentinel = createSentinelWithTaskRules();
            const start = performance.now();
            for (let i = 0; i < 100; i++) {
                await sentinel.ingest({
                    message: `Sequential log ${i} from user${i}@example.com`,
                    type: "SYSTEM",
                    level: 3,
                    boundary: "test:seq",
                });
            }
            assertTiming(start, "100 sequential ingests");
        });

        it("handles 100 concurrent ingests", async () => {
            Sentinel.reset();
            const sentinel = createSentinelWithTaskRules();
            const start = performance.now();
            const promises = Array.from({ length: 100 }, (_, i) =>
                sentinel.ingest({
                    message: `Concurrent log ${i}`,
                    type: "SYSTEM",
                    level: 3,
                    boundary: "test:concurrent",
                }),
            );
            const results = await Promise.all(promises);
            assertTiming(start, "100 concurrent ingests");
            expect(results).toHaveLength(100);
            for (const r of results) {
                expect(r.traceId).toBeDefined();
            }
        });

        it("handles alternating critical/normal logs", async () => {
            Sentinel.reset();
            const sentinel = createSentinelWithTaskRules();
            const start = performance.now();
            for (let i = 0; i < 100; i++) {
                await sentinel.ingest({
                    message: `Alternating log ${i}`,
                    type: "SYSTEM",
                    level: i % 2 === 0 ? 3 : 6,
                    isCritical: i % 2 !== 0,
                    boundary: "test:alternating",
                });
            }
            assertTiming(start, "100 alternating critical/normal");
        });

        it("handles all ingests triggering task generation", async () => {
            Sentinel.reset();
            const config = createDefaultConfig({
                projectName: "dos-task-test",
                serviceId: "dos-task-svc",
                environment: "test",
                masking: { enabled: true, rules: ALL_PII_RULES, preserveFields: [] },
                security: { enableHashChain: true },
                taskRules: [createTestTaskRule()],
            });
            const sentinel = Sentinel.initialize(config);
            const start = performance.now();
            const results = [];
            for (let i = 0; i < 100; i++) {
                const result = await sentinel.ingest({
                    message: `Critical failure ${i}`,
                    type: "SYSTEM",
                    level: 6,
                    isCritical: true,
                    boundary: "test:all-tasks",
                });
                results.push(result);
            }
            assertTiming(start, "100 ingests all triggering tasks");
            for (const r of results) {
                expect(r.detection).not.toBeNull();
            }
        });

        it("handles rapid sequential ingests with PII masking", async () => {
            Sentinel.reset();
            const sentinel = createSentinelWithTaskRules();
            const start = performance.now();
            for (let i = 0; i < 50; i++) {
                await sentinel.ingest({
                    message: `PII: card 4111-1111-1111-1111, email test${i}@example.com`,
                    type: "SYSTEM",
                    level: 3,
                    boundary: "test:pii-rapid",
                });
            }
            assertTiming(start, "50 rapid PII ingests");
        });

        it("handles concurrent ingests with hash chain integrity", async () => {
            Sentinel.reset();
            const sentinel = createSentinelWithTaskRules();
            const results = await Promise.all(
                Array.from({ length: 50 }, (_, i) =>
                    sentinel.ingest({
                        message: `Hash chain test ${i}`,
                        type: "SYSTEM",
                        level: 3,
                        boundary: "test:hash-concurrent",
                    }),
                ),
            );
            for (const r of results) {
                expect(r.hashChainValid).toBe(true);
            }
        });

        it("handles mixed log types under load", async () => {
            Sentinel.reset();
            const sentinel = createSentinelWithTaskRules();
            const types = ["SYSTEM", "SECURITY", "COMPLIANCE", "INFRA", "DEBUG", "SLA", "BUSINESS-AUDIT"] as const;
            const start = performance.now();
            for (let i = 0; i < 70; i++) {
                await sentinel.ingest({
                    message: `Mixed type log ${i}`,
                    type: types[i % types.length],
                    level: ((i % 6) + 1) as 1 | 2 | 3 | 4 | 5 | 6,
                    boundary: "test:mixed",
                });
            }
            assertTiming(start, "70 mixed type ingests");
        });
        it("handles 1000 sequential ingests with stable timing (sustained throughput)", async () => {
            Sentinel.reset();
            const sentinel = createSentinelWithTaskRules();
            const batchSize = 200;
            const batches = 5; // 5 × 200 = 1000 ingests
            const batchTimings: number[] = [];

            for (let batch = 0; batch < batches; batch++) {
                const batchStart = performance.now();
                for (let i = 0; i < batchSize; i++) {
                    await sentinel.ingest({
                        message: `Sustained log batch=${batch} i=${i}`,
                        type: "SYSTEM",
                        level: 3,
                        boundary: "test:sustained",
                    });
                }
                batchTimings.push(performance.now() - batchStart);
            }

            // 全バッチが制限時間内
            for (let b = 0; b < batches; b++) {
                expect(batchTimings[b], `batch ${b} took ${batchTimings[b].toFixed(0)}ms`).toBeLessThan(TIMING_LIMIT_MS);
            }

            // 後半バッチが前半の5倍以上遅くなっていないこと（メモリリーク/性能劣化チェック）
            const firstBatch = batchTimings[0];
            const lastBatch = batchTimings[batches - 1];
            expect(lastBatch, `last batch (${lastBatch.toFixed(0)}ms) vs first (${firstBatch.toFixed(0)}ms)`).toBeLessThan(firstBatch * 5);
        });
    });

    // =========================================================================
    // Validator exhaustion
    // =========================================================================
    describe("Validator exhaustion", () => {
        it("handles 100 tags each at max key length", () => {
            const tags = Array.from({ length: 100 }, (_, i) => ({
                key: "k".repeat(128),
                category: `cat_${i}`,
            }));
            expect(() => validateLogInput({
                message: "test",
                tags,
            })).not.toThrow();
        });

        it("handles 100 tags each at max category length", () => {
            const tags = Array.from({ length: 100 }, (_, i) => ({
                key: `key_${i}`,
                category: "c".repeat(1024),
            }));
            expect(() => validateLogInput({
                message: "test",
                tags,
            })).not.toThrow();
        });

        it("handles 100 tags each at max key AND category length", () => {
            const tags = Array.from({ length: 100 }, () => ({
                key: "k".repeat(128),
                category: "c".repeat(1024),
            }));
            const start = performance.now();
            expect(() => validateLogInput({ message: "test", tags })).not.toThrow();
            assertTiming(start, "100 max-length tags");
        });

        it("handles 100 resourceIds", () => {
            const resourceIds = Array.from({ length: 100 }, (_, i) => `resource-${i}`);
            expect(() => validateLogInput({
                message: "test",
                resourceIds,
            })).not.toThrow();
        });

        it("rejects more than 100 resourceIds", () => {
            const resourceIds = Array.from({ length: 101 }, (_, i) => `resource-${i}`);
            expect(() => validateLogInput({
                message: "test",
                resourceIds,
            })).toThrow(ValidationError);
        });

        it("handles message at exactly 65536 characters", () => {
            const message = "x".repeat(65536);
            expect(() => validateLogInput({ message })).not.toThrow();
        });

        it("rejects message at 65537 characters", () => {
            const message = "x".repeat(65537);
            expect(() => validateLogInput({ message })).toThrow(ValidationError);
        });

        it("handles input field with 1MB JSON string", () => {
            const bigJson = JSON.stringify({ data: "x".repeat(1_000_000) });
            // input is not length-validated by the validator, should not crash
            expect(() => validateLogInput({
                message: "test",
                input: bigJson,
            } as never)).not.toThrow();
        });

        it("rejects more than 100 tags", () => {
            const tags = Array.from({ length: 101 }, (_, i) => ({
                key: `key_${i}`,
                category: `cat_${i}`,
            }));
            expect(() => validateLogInput({
                message: "test",
                tags,
            })).toThrow(ValidationError);
        });

        it("handles tag key at exactly 128 characters (boundary)", () => {
            expect(() => validateLogInput({
                message: "test",
                tags: [{ key: "k".repeat(128), category: "cat" }],
            })).not.toThrow();
        });

        it("rejects tag key exceeding 128 characters", () => {
            expect(() => validateLogInput({
                message: "test",
                tags: [{ key: "k".repeat(129), category: "cat" }],
            })).toThrow(ValidationError);
        });

        it("handles tag category at exactly 1024 characters (boundary)", () => {
            expect(() => validateLogInput({
                message: "test",
                tags: [{ key: "key", category: "c".repeat(1024) }],
            })).not.toThrow();
        });

        it("rejects tag category exceeding 1024 characters", () => {
            expect(() => validateLogInput({
                message: "test",
                tags: [{ key: "key", category: "c".repeat(1025) }],
            })).toThrow(ValidationError);
        });

        it("handles large details string at max length", () => {
            expect(() => validateLogInput({
                message: "test",
                details: "d".repeat(65536),
            })).not.toThrow();
        });

        it("rejects details string exceeding max length", () => {
            expect(() => validateLogInput({
                message: "test",
                details: "d".repeat(65537),
            })).toThrow(ValidationError);
        });

        it("handles empty tags array", () => {
            expect(() => validateLogInput({
                message: "test",
                tags: [],
            })).not.toThrow();
        });

        it("handles empty resourceIds array", () => {
            expect(() => validateLogInput({
                message: "test",
                resourceIds: [],
            })).not.toThrow();
        });

        it("handles all optional fields at maximum valid values simultaneously", () => {
            const start = performance.now();
            expect(() => validateLogInput({
                message: "x".repeat(65536),
                type: "SYSTEM",
                level: 6,
                origin: "SYSTEM",
                isCritical: true,
                tags: Array.from({ length: 100 }, () => ({
                    key: "k".repeat(128),
                    category: "c".repeat(1024),
                })),
                resourceIds: Array.from({ length: 100 }, (_, i) => `r-${i}`),
                details: "d".repeat(65536),
            })).not.toThrow();
            assertTiming(start, "all fields at max");
        });

        it("validates rapidly: 1000 sequential validations", () => {
            const start = performance.now();
            for (let i = 0; i < 1000; i++) {
                validateLogInput({ message: `message ${i}` });
            }
            assertTiming(start, "1000 sequential validations");
        });
    });
});
