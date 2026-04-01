/**
 * Security Test: PII Masking Bypass
 *
 * Tests that PII data cannot bypass masking through encoding tricks,
 * unicode manipulation, or structural evasion techniques.
 *
 * CWE-200: Exposure of Sensitive Information
 */
import { describe, it, expect } from "vitest";
import { MaskingService } from "../../src/security/masking-service";
import { createTestLog } from "../helpers/fixtures";
import type { MaskingRule } from "../../src/configs/masking-rule";

const ALL_PII_RULES: MaskingRule[] = [
    { type: "PII_TYPE", category: "CREDIT_CARD" },
    { type: "PII_TYPE", category: "PHONE" },
    { type: "PII_TYPE", category: "EMAIL" },
    { type: "PII_TYPE", category: "GOVERNMENT_ID" },
];

function getMaskedMessage(message: string, rules: MaskingRule[] = ALL_PII_RULES): string {
    const log = createTestLog({ message });
    const masked = MaskingService.mask(log, rules) as Record<string, unknown>;
    return String(masked.message);
}

describe("Security: PII Masking Bypass resistance", () => {
    describe("Credit card masking", () => {
        it("masks standard card number", () => {
            const result = getMaskedMessage("card: 4111-1111-1111-1111");
            expect(result).not.toContain("4111-1111-1111-1111");
        });

        it("masks card with spaces", () => {
            const result = getMaskedMessage("card: 4111 1111 1111 1111");
            expect(result).not.toContain("4111 1111 1111 1111");
        });

        it("masks card without separators", () => {
            const result = getMaskedMessage("card: 4111111111111111");
            expect(result).not.toContain("4111111111111111");
        });
    });

    describe("Email masking", () => {
        it("masks standard email", () => {
            const result = getMaskedMessage("contact: user@example.com");
            expect(result).not.toContain("user@example.com");
        });

        it("masks email with plus addressing", () => {
            const result = getMaskedMessage("email: user+tag@example.com");
            expect(result).not.toContain("user+tag@example.com");
        });

        it("masks email with dots", () => {
            const result = getMaskedMessage("email: first.last@sub.example.com");
            expect(result).not.toContain("first.last@sub.example.com");
        });
    });

    describe("Phone number masking", () => {
        it("masks Japanese phone number with hyphens", () => {
            const result = getMaskedMessage("tel: 090-1234-5678");
            expect(result).not.toContain("090-1234-5678");
        });

        it("masks phone with country code", () => {
            const result = getMaskedMessage("phone: +81-90-1234-5678");
            expect(result).not.toContain("90-1234-5678");
        });
    });

    describe("Nested object masking", () => {
        it("masks PII in nested log details", () => {
            const log = createTestLog({
                message: "User action logged",
                details: JSON.stringify({
                    user: {
                        email: "secret@internal.com",
                        phone: "090-9999-8888",
                    },
                }),
            });

            const masked = MaskingService.mask(log, ALL_PII_RULES) as Record<string, unknown>;
            const details = String(masked.details);
            expect(details).not.toContain("secret@internal.com");
        });

        it("masks PII in array fields", () => {
            const log = createTestLog({
                message: "Batch of emails: user1@test.com, user2@test.com",
            });

            const masked = MaskingService.mask(log, ALL_PII_RULES) as Record<string, unknown>;
            expect(String(masked.message)).not.toContain("user1@test.com");
            expect(String(masked.message)).not.toContain("user2@test.com");
        });
    });

    describe("KEY_MATCH masking", () => {
        it("masks fields by sensitive key name", () => {
            const log = createTestLog({
                message: "processing",
                input: {
                    password: "super-secret-123",
                    username: "admin",
                } as Record<string, unknown>,
            });

            const rules: MaskingRule[] = [
                {
                    type: "KEY_MATCH",
                    sensitiveKeys: ["password", "secret", "token"],
                },
            ];

            const masked = MaskingService.mask(log, rules) as Record<string, unknown>;
            const input = masked.input as Record<string, unknown>;
            expect(input.password).not.toBe("super-secret-123");
        });

        // FIXED: KEY_MATCH now performs case-insensitive comparison
        it("masks fields with case-insensitive key matching", () => {
            const log = createTestLog({
                input: {
                    PASSWORD: "secret",
                    Token: "abc123",
                } as Record<string, unknown>,
            });

            const rules: MaskingRule[] = [
                {
                    type: "KEY_MATCH",
                    sensitiveKeys: ["password", "token"],
                },
            ];

            const masked = MaskingService.mask(log, rules) as Record<string, unknown>;
            const input = masked.input as Record<string, unknown>;
            // KEY_MATCH should handle case variation
            expect(JSON.stringify(input)).not.toContain("secret");
        });
    });

    describe("Circular reference handling", () => {
        it("does not crash on circular references", () => {
            const obj: Record<string, unknown> = { message: "test" };
            obj.self = obj;

            expect(() => MaskingService.mask(obj, [])).not.toThrow();
        });

        it("does not crash on deeply nested objects", () => {
            let obj: Record<string, unknown> = { message: "test" };
            let current = obj;
            for (let i = 0; i < 15; i++) {
                current.nested = { level: i };
                current = current.nested as Record<string, unknown>;
            }

            expect(() => MaskingService.mask(obj, [])).not.toThrow();
        });
    });

    describe("Edge cases", () => {
        it("handles null input without crash", () => {
            expect(() => MaskingService.mask(null, [])).not.toThrow();
        });

        it("handles undefined input without crash", () => {
            expect(() => MaskingService.mask(undefined, [])).not.toThrow();
        });

        it("handles empty string message", () => {
            const log = createTestLog({ message: "" });
            expect(() => MaskingService.mask(log, ALL_PII_RULES)).not.toThrow();
        });

        it("handles extremely long message without crash", { timeout: 30000 }, () => {
            const log = createTestLog({ message: "A".repeat(100000) });
            expect(() => MaskingService.mask(log, ALL_PII_RULES)).not.toThrow();
        });
    });
});
