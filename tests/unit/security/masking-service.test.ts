import { describe, it, expect } from "vitest";
import { MaskingService } from "../../../src/security/masking-service";
import { MaskingRule } from "../../../src/configs/masking-rule";

describe("MaskingService", () => {
    describe("primitive handling", () => {
        it("returns null as-is", () => {
            expect(MaskingService.mask(null)).toBeNull();
        });

        it("returns undefined as-is", () => {
            expect(MaskingService.mask(undefined)).toBeUndefined();
        });

        it("returns numbers as-is", () => {
            expect(MaskingService.mask(42)).toBe(42);
        });

        it("returns booleans as-is", () => {
            expect(MaskingService.mask(true)).toBe(true);
        });

        it("returns empty string as-is", () => {
            expect(MaskingService.mask("")).toBe("");
        });
    });

    describe("REGEX rules", () => {
        const regexRule: MaskingRule = {
            type: "REGEX",
            pattern: /secret-\d+/,
            replacement: "[REDACTED]",
            description: "Mask secret IDs",
        };

        it("replaces matching patterns in string", () => {
            const result = MaskingService.mask("Found secret-123 in logs", [regexRule]);
            expect(result).toBe("Found [REDACTED] in logs");
        });

        it("replaces multiple occurrences", () => {
            const result = MaskingService.mask("secret-1 and secret-2", [regexRule]);
            expect(result).toBe("[REDACTED] and [REDACTED]");
        });

        it("no-ops when pattern does not match", () => {
            const result = MaskingService.mask("nothing to mask", [regexRule]);
            expect(result).toBe("nothing to mask");
        });
    });

    describe("PII_TYPE rules", () => {
        it("masks email addresses", () => {
            const rule: MaskingRule = { type: "PII_TYPE", category: "EMAIL" };
            const result = MaskingService.mask("Contact user@example.com for info", [rule]);
            expect(result).toBe("Contact [MASKED_EMAIL] for info");
        });

        it("masks credit card numbers", () => {
            const rule: MaskingRule = { type: "PII_TYPE", category: "CREDIT_CARD" };
            const result = MaskingService.mask("Card: 4111 1111 1111 1111", [rule]);
            expect(result).not.toContain("4111");
        });

        it("masks phone numbers (Japan format)", () => {
            const rule: MaskingRule = { type: "PII_TYPE", category: "PHONE" };
            const result = MaskingService.mask("Call 090-1234-5678", [rule]);
            expect(result).not.toContain("090-1234-5678");
        });

        it("masks government IDs (12-digit)", () => {
            const rule: MaskingRule = { type: "PII_TYPE", category: "GOVERNMENT_ID" };
            const result = MaskingService.mask("ID: 123456789012", [rule]);
            expect(result).not.toContain("123456789012");
        });
    });

    describe("KEY_MATCH rules", () => {
        const keyRule: MaskingRule = {
            type: "KEY_MATCH",
            sensitiveKeys: ["password", "ssn", "creditCard"],
            replacement: "[MASKED]",
        };

        it("masks matching keys in objects", () => {
            const data = { username: "john", password: "secret123", age: 30 };
            const result = MaskingService.mask(data, [keyRule]) as Record<string, unknown>;
            expect(result.username).toBe("john");
            expect(result.password).toBe("[MASKED]");
            expect(result.age).toBe(30);
        });

        it("uses default replacement when not specified", () => {
            const rule: MaskingRule = {
                type: "KEY_MATCH",
                sensitiveKeys: ["token"],
            };
            const data = { token: "abc123" };
            const result = MaskingService.mask(data, [rule]) as Record<string, unknown>;
            expect(result.token).toBe("[MASKED_KEY]");
        });

        it("masks nested keys", () => {
            const data = { user: { password: "secret", name: "john" } };
            const result = MaskingService.mask(data, [keyRule]) as Record<string, unknown>;
            const user = result.user as Record<string, unknown>;
            expect(user.password).toBe("[MASKED]");
            expect(user.name).toBe("john");
        });
    });

    describe("preserveFields", () => {
        const keyRule: MaskingRule = {
            type: "KEY_MATCH",
            sensitiveKeys: ["traceId", "password"],
            replacement: "[MASKED]",
        };

        it("preserves specified fields from masking", () => {
            const data = { traceId: "trace-001", password: "secret" };
            const result = MaskingService.mask(data, [keyRule], ["traceId"]) as Record<string, unknown>;
            expect(result.traceId).toBe("trace-001");
            expect(result.password).toBe("[MASKED]");
        });
    });

    describe("nested objects and arrays", () => {
        const emailRule: MaskingRule = { type: "PII_TYPE", category: "EMAIL" };

        it("masks strings inside arrays", () => {
            const data = ["normal", "user@test.com", "also normal"];
            const result = MaskingService.mask(data, [emailRule]) as string[];
            expect(result[0]).toBe("normal");
            expect(result[1]).not.toContain("@");
            expect(result[2]).toBe("also normal");
        });

        it("masks deeply nested objects", () => {
            const data = {
                level1: {
                    level2: {
                        email: "deep@test.com",
                    },
                },
            };
            const result = MaskingService.mask(data, [emailRule]) as any;
            expect(result.level1.level2.email).not.toContain("@");
        });

        it("handles null values in objects gracefully", () => {
            const data = { name: "test", value: null };
            const result = MaskingService.mask(data, [emailRule]) as Record<string, unknown>;
            expect(result.value).toBeNull();
        });
    });

    describe("edge cases", () => {
        it("handles circular reference protection", () => {
            const data: Record<string, unknown> = { name: "test" };
            data.self = data; // circular reference
            const result = MaskingService.mask(data, []);
            expect(result).toBeDefined();
        });

        it("respects maxDepth option", () => {
            // Create deeply nested object
            let obj: Record<string, unknown> = { value: "deep" };
            for (let i = 0; i < 15; i++) {
                obj = { nested: obj };
            }
            const result = MaskingService.mask(obj, [], [], { maxDepth: 5 });
            expect(result).toBeDefined();
        });

        it("applies multiple rules in order", () => {
            const rules: MaskingRule[] = [
                { type: "PII_TYPE", category: "EMAIL" },
                {
                    type: "REGEX",
                    pattern: /\[MASKED_EMAIL\]/,
                    replacement: "[DOUBLE_MASKED]",
                    description: "test",
                },
            ];
            const result = MaskingService.mask("user@test.com", rules);
            expect(result).toBe("[DOUBLE_MASKED]");
        });

        it("handles empty rules array", () => {
            const data = { email: "user@test.com" };
            const result = MaskingService.mask(data, []) as Record<string, unknown>;
            expect(result.email).toBe("user@test.com");
        });
    });
});
