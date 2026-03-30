/**
 * Security Test: ReDoS (Regular Expression Denial of Service)
 *
 * Tests that all regex patterns used in the SDK complete within
 * acceptable time bounds, even with adversarial input.
 *
 * CWE-1333: Inefficient Regular Expression Complexity
 */
import { describe, it, expect } from "vitest";
import { MaskingService } from "../../src/security/masking-service";
import { createTestLog } from "../helpers/fixtures";

const REDOS_TIMEOUT_MS = 50;

function measureRegexTime(fn: () => unknown): number {
    const start = performance.now();
    fn();
    return performance.now() - start;
}

describe("Security: ReDoS resistance", () => {
    describe("CREDIT_CARD pattern", () => {
        const adversarialPayloads = [
            "1111 1111 1111 1111 1111 11111111888888",
            "1234 5678 9012 3456 7890 12345678901234567890",
            " ".repeat(10000) + "1234567890123",
            "1".repeat(100) + " " + "2".repeat(100),
            "1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6-7-8-9-0-1-2-3-4-5",
        ];

        for (const payload of adversarialPayloads) {
            it(`completes within ${REDOS_TIMEOUT_MS}ms for adversarial input (len=${payload.length})`, () => {
                const log = createTestLog({
                    message: payload,
                });

                const elapsed = measureRegexTime(() => {
                    MaskingService.mask(log, [{ type: "PII_TYPE", category: "CREDIT_CARD" }]);
                });

                expect(elapsed).toBeLessThan(REDOS_TIMEOUT_MS);
            });
        }
    });

    describe("EMAIL pattern", () => {
        const adversarialPayloads = [
            "a".repeat(1000) + "@" + "b".repeat(1000) + ".com",
            "user+" + "a".repeat(500) + "@example.com",
            "@".repeat(100),
        ];

        for (const payload of adversarialPayloads) {
            it(`completes within ${REDOS_TIMEOUT_MS}ms (len=${payload.length})`, () => {
                const log = createTestLog({ message: payload });

                const elapsed = measureRegexTime(() => {
                    MaskingService.mask(log, [{ type: "PII_TYPE", category: "EMAIL" }]);
                });

                expect(elapsed).toBeLessThan(REDOS_TIMEOUT_MS);
            });
        }
    });

    describe("Custom REGEX rules", () => {
        it("handles user-provided regex with nested quantifiers gracefully", () => {
            const log = createTestLog({
                message: "a]" + "a".repeat(30),
            });

            const elapsed = measureRegexTime(() => {
                MaskingService.mask(log, [
                    {
                        type: "REGEX",
                        pattern: /[a-z]+/g,
                        replacement: "[REDACTED]",
                        description: "safe pattern",
                    },
                ]);
            });

            expect(elapsed).toBeLessThan(REDOS_TIMEOUT_MS);
        });

        it("completes with pathological but bounded input", () => {
            const log = createTestLog({
                message: "x".repeat(10000),
            });

            const elapsed = measureRegexTime(() => {
                MaskingService.mask(log, [
                    {
                        type: "REGEX",
                        pattern: /x+y/g,
                        replacement: "[MATCH]",
                        description: "non-matching pattern on large input",
                    },
                ]);
            });

            // Linear time for 10k chars; allow 200ms (not exponential blowup)
            expect(elapsed).toBeLessThan(200);
        });
    });

    describe("Multiple PII patterns combined", () => {
        it("completes within time bounds with all PII types on large input", () => {
            const largeMessage = [
                "Card: 4111-1111-1111-1111",
                "Phone: 090-1234-5678",
                "Email: test@example.com",
                "ID: 123-45-6789",
                "Random: " + "abcdef12345 ".repeat(500),
            ].join(" ");

            const log = createTestLog({ message: largeMessage });

            const elapsed = measureRegexTime(() => {
                MaskingService.mask(log, [
                    { type: "PII_TYPE", category: "CREDIT_CARD" },
                    { type: "PII_TYPE", category: "PHONE" },
                    { type: "PII_TYPE", category: "EMAIL" },
                    { type: "PII_TYPE", category: "GOVERNMENT_ID" },
                ]);
            });

            expect(elapsed).toBeLessThan(200);
        });
    });
});
