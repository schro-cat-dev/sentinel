/**
 * Masking Rules Exhaustive Tests
 *
 * MaskingService の全マスキングルール種別 (PII_TYPE, REGEX, KEY_MATCH) を
 * 網羅的にテスト。エッジケース、組み合わせ、深いネスト、循環参照を含む。
 */
import { describe, it, expect } from "vitest";
import { MaskingService } from "../../src/security/masking-service";
import { MaskingRule } from "../../src/configs/masking-rule";
import { createTestLog } from "../helpers/fixtures";

// ---------------------------------------------------------------------------
// PII_TYPE rules
// ---------------------------------------------------------------------------
describe("MaskingService — PII_TYPE rules", () => {
    // -----------------------------------------------------------------------
    // CREDIT_CARD
    // -----------------------------------------------------------------------
    describe("CREDIT_CARD", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "CREDIT_CARD" }];

        it("masks standard card with hyphens (4111-1111-1111-1111)", () => {
            const result = MaskingService.mask("Card: 4111-1111-1111-1111", rules);
            expect(result).toBe("Card: [MASKED_CREDIT_CARD]");
        });

        it("masks card with spaces (4111 1111 1111 1111)", () => {
            const result = MaskingService.mask("Card: 4111 1111 1111 1111", rules);
            expect(result).toBe("Card: [MASKED_CREDIT_CARD]");
        });

        it("masks card with no separators (4111111111111111)", () => {
            const result = MaskingService.mask("Card: 4111111111111111", rules);
            expect(result).toBe("Card: [MASKED_CREDIT_CARD]");
        });

        it("masks 13-digit card number (Visa old format)", () => {
            // Pattern: \b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b
            // 13 digits = 4+4+4+1 -> should match
            const result = MaskingService.mask("Card: 4111111111111", rules);
            expect(result).toBe("Card: [MASKED_CREDIT_CARD]");
        });

        it("masks 19-digit card number (extended)", () => {
            // 4+4+4+7 = 19 digits -> \d{1,7} captures up to 7
            const result = MaskingService.mask("Card: 4111111111111111111", rules);
            expect(result).toBe("Card: [MASKED_CREDIT_CARD]");
        });

        it("masks multiple card numbers in one string", () => {
            const input = "Primary: 4111-1111-1111-1111, Secondary: 5500-0000-0000-0004";
            const result = MaskingService.mask(input, rules);
            expect(result).not.toContain("4111");
            expect(result).not.toContain("5500");
            expect(result).toContain("[MASKED_CREDIT_CARD]");
        });

        it("does not mask strings that are not card numbers", () => {
            const result = MaskingService.mask("Order: ABC-1234", rules);
            expect(result).toBe("Order: ABC-1234");
        });
    });

    // -----------------------------------------------------------------------
    // PHONE
    // -----------------------------------------------------------------------
    describe("PHONE", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "PHONE" }];

        it("masks Japanese phone with hyphens (090-1234-5678)", () => {
            const result = MaskingService.mask("Tel: 090-1234-5678", rules);
            expect(result).toBe("Tel: [MASKED_PHONE]");
        });

        it("masks +81 prefix (+81-90-1234-5678)", () => {
            const result = MaskingService.mask("Tel: +81-90-1234-5678", rules);
            expect(result).toBe("Tel: [MASKED_PHONE]");
        });

        it("masks phone without hyphens (09012345678)", () => {
            const result = MaskingService.mask("Tel: 09012345678", rules);
            expect(result).toBe("Tel: [MASKED_PHONE]");
        });

        it("masks 0X0 mobile format (080-1111-2222)", () => {
            const result = MaskingService.mask("Tel: 080-1111-2222", rules);
            expect(result).toBe("Tel: [MASKED_PHONE]");
        });

        it("masks landline format (03-1234-5678)", () => {
            const result = MaskingService.mask("Tel: 03-1234-5678", rules);
            expect(result).toBe("Tel: [MASKED_PHONE]");
        });

        it("masks phone with spaces instead of hyphens", () => {
            const result = MaskingService.mask("Tel: 090 1234 5678", rules);
            expect(result).toBe("Tel: [MASKED_PHONE]");
        });

        it("does not mask short numbers", () => {
            const result = MaskingService.mask("Code: 1234", rules);
            expect(result).toBe("Code: 1234");
        });
    });

    // -----------------------------------------------------------------------
    // EMAIL
    // -----------------------------------------------------------------------
    describe("EMAIL", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];

        it("masks standard email", () => {
            const result = MaskingService.mask("Contact: user@example.com", rules);
            expect(result).toBe("Contact: [MASKED_EMAIL]");
        });

        it("masks plus addressing (user+tag@example.com)", () => {
            const result = MaskingService.mask("Email: user+tag@example.com", rules);
            expect(result).toBe("Email: [MASKED_EMAIL]");
        });

        it("masks subdomain email (user@mail.example.co.jp)", () => {
            const result = MaskingService.mask("Email: user@mail.example.co.jp", rules);
            expect(result).toBe("Email: [MASKED_EMAIL]");
        });

        it("masks email with dots in local part (first.last@example.com)", () => {
            const result = MaskingService.mask("Email: first.last@example.com", rules);
            expect(result).toBe("Email: [MASKED_EMAIL]");
        });

        it("masks email with percent and underscore (a%b_c@example.com)", () => {
            const result = MaskingService.mask("Email: a%b_c@example.com", rules);
            expect(result).toBe("Email: [MASKED_EMAIL]");
        });

        it("masks multiple emails in one string", () => {
            const input = "From: a@b.com, To: c@d.org";
            const result = MaskingService.mask(input, rules) as string;
            expect(result).not.toContain("a@b.com");
            expect(result).not.toContain("c@d.org");
        });

        it("does not mask text without @ sign", () => {
            const result = MaskingService.mask("No email here", rules);
            expect(result).toBe("No email here");
        });
    });

    // -----------------------------------------------------------------------
    // GOVERNMENT_ID
    // -----------------------------------------------------------------------
    describe("GOVERNMENT_ID", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "GOVERNMENT_ID" }];

        it("masks a 12-digit number (My Number)", () => {
            const result = MaskingService.mask("ID: 123456789012", rules);
            expect(result).toBe("ID: [MASKED_GOVERNMENT_ID]");
        });

        it("masks 12-digit number surrounded by spaces", () => {
            const result = MaskingService.mask("Your ID is 123456789012 here", rules);
            expect(result).toBe("Your ID is [MASKED_GOVERNMENT_ID] here");
        });

        it("does not mask 11-digit number", () => {
            const result = MaskingService.mask("ID: 12345678901", rules);
            expect(result).toBe("ID: 12345678901");
        });

        it("does not mask 13-digit number as a single GOVERNMENT_ID", () => {
            // \b\d{12}\b requires exactly 12 digits at a word boundary
            const input = "ID: 1234567890123";
            const result = MaskingService.mask(input, rules) as string;
            // A 13-digit number should NOT be matched by the 12-digit pattern as a whole
            // (the pattern may match the first 12 if boundaries allow, but
            // the trailing digit breaks \b)
            expect(result).toBe(input);
        });
    });
});

// ---------------------------------------------------------------------------
// REGEX rules
// ---------------------------------------------------------------------------
describe("MaskingService — REGEX rules", () => {
    it("replaces matching pattern with replacement string", () => {
        const rules: MaskingRule[] = [
            {
                type: "REGEX",
                pattern: /secret-[a-z0-9]+/,
                replacement: "[REDACTED]",
                description: "mask secrets",
            },
        ];
        const result = MaskingService.mask("Key: secret-abc123", rules);
        expect(result).toBe("Key: [REDACTED]");
    });

    it("replaces all occurrences (global)", () => {
        const rules: MaskingRule[] = [
            {
                type: "REGEX",
                pattern: /token_\w+/,
                replacement: "[TOKEN]",
                description: "mask tokens",
            },
        ];
        const result = MaskingService.mask("A: token_abc, B: token_xyz", rules);
        expect(result).toBe("A: [TOKEN], B: [TOKEN]");
    });

    it("supports capture groups in replacement ($1)", () => {
        const rules: MaskingRule[] = [
            {
                type: "REGEX",
                pattern: /user:(\w+)/,
                replacement: "user:***$1***",
                description: "wrap username",
            },
        ];
        const result = MaskingService.mask("Login user:admin OK", rules);
        expect(result).toBe("Login user:***admin*** OK");
    });

    it("leaves string unchanged when pattern does not match", () => {
        const rules: MaskingRule[] = [
            {
                type: "REGEX",
                pattern: /DOES_NOT_EXIST/,
                replacement: "[GONE]",
                description: "no match",
            },
        ];
        const result = MaskingService.mask("Normal text", rules);
        expect(result).toBe("Normal text");
    });

    it("supports empty replacement string (deletion)", () => {
        const rules: MaskingRule[] = [
            {
                type: "REGEX",
                pattern: /DEBUG:\s*/,
                replacement: "",
                description: "strip debug prefix",
            },
        ];
        const result = MaskingService.mask("DEBUG: some message", rules);
        expect(result).toBe("some message");
    });

    it("handles special regex characters in pattern", () => {
        const rules: MaskingRule[] = [
            {
                type: "REGEX",
                pattern: /\$\d+\.\d{2}/,
                replacement: "$XX.XX",
                description: "mask dollar amounts",
            },
        ];
        const result = MaskingService.mask("Price: $99.99 total", rules);
        expect(result).toBe("Price: $XX.XX total");
    });
});

// ---------------------------------------------------------------------------
// KEY_MATCH rules
// ---------------------------------------------------------------------------
describe("MaskingService — KEY_MATCH rules", () => {
    it("masks value for exact lowercase key match", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const result = MaskingService.mask({ password: "s3cret" }, rules);
        expect(result).toEqual({ password: "[MASKED_KEY]" });
    });

    it("matches case-insensitively (PASSWORD vs password)", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const result = MaskingService.mask({ PASSWORD: "s3cret" }, rules);
        expect(result).toEqual({ PASSWORD: "[MASKED_KEY]" });
    });

    it("matches case-insensitively (Password mixed case)", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const result = MaskingService.mask({ Password: "s3cret" }, rules);
        expect(result).toEqual({ Password: "[MASKED_KEY]" });
    });

    it("masks multiple sensitive keys", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password", "secret", "apiKey"] },
        ];
        const result = MaskingService.mask(
            { password: "abc", secret: "xyz", apiKey: "key-123", name: "safe" },
            rules,
        );
        expect(result).toEqual({
            password: "[MASKED_KEY]",
            secret: "[MASKED_KEY]",
            apiKey: "[MASKED_KEY]",
            name: "safe",
        });
    });

    it("uses custom replacement string when provided", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["token"], replacement: "***REDACTED***" },
        ];
        const result = MaskingService.mask({ token: "abc-123" }, rules);
        expect(result).toEqual({ token: "***REDACTED***" });
    });

    it("uses default [MASKED_KEY] when no replacement specified", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["ssn"] },
        ];
        const result = MaskingService.mask({ ssn: "111-22-3333" }, rules);
        expect(result).toEqual({ ssn: "[MASKED_KEY]" });
    });

    it("masks nested object keys", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const result = MaskingService.mask(
            { user: { name: "Alice", password: "s3cret" } },
            rules,
        );
        expect(result).toEqual({ user: { name: "Alice", password: "[MASKED_KEY]" } });
    });

    it("masks deeply nested keys", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["secret"] },
        ];
        const data = { a: { b: { c: { secret: "hidden" } } } };
        const result = MaskingService.mask(data, rules);
        expect(result).toEqual({ a: { b: { c: { secret: "[MASKED_KEY]" } } } });
    });

    it("masks key regardless of value type (number, boolean, object)", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["secret"] },
        ];
        expect(MaskingService.mask({ secret: 42 }, rules)).toEqual({ secret: "[MASKED_KEY]" });
        expect(MaskingService.mask({ secret: true }, rules)).toEqual({ secret: "[MASKED_KEY]" });
        expect(MaskingService.mask({ secret: { nested: "val" } }, rules)).toEqual({
            secret: "[MASKED_KEY]",
        });
    });

    it("does not mask non-matching keys", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const result = MaskingService.mask({ username: "alice" }, rules);
        expect(result).toEqual({ username: "alice" });
    });

    it("KEY_MATCH does not affect plain strings (only objects)", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const result = MaskingService.mask("password is secret", rules);
        // KEY_MATCH is a no-op inside maskString
        expect(result).toBe("password is secret");
    });
});

// ---------------------------------------------------------------------------
// Combined rules
// ---------------------------------------------------------------------------
describe("MaskingService — combined rules", () => {
    it("applies PII_TYPE + KEY_MATCH together", () => {
        const rules: MaskingRule[] = [
            { type: "PII_TYPE", category: "EMAIL" },
            { type: "KEY_MATCH", sensitiveKeys: ["password"] },
        ];
        const data = {
            email: "user@example.com",
            password: "s3cret",
            note: "Contact user@example.com for details",
        };
        const result = MaskingService.mask(data, rules) as Record<string, unknown>;
        expect(result.email).toBe("[MASKED_EMAIL]");
        expect(result.password).toBe("[MASKED_KEY]");
        expect(result.note).toBe("Contact [MASKED_EMAIL] for details");
    });

    it("applies REGEX + PII_TYPE together", () => {
        const rules: MaskingRule[] = [
            { type: "PII_TYPE", category: "CREDIT_CARD" },
            {
                type: "REGEX",
                pattern: /CVV:\s*\d{3}/,
                replacement: "CVV: [REDACTED]",
                description: "mask CVV",
            },
        ];
        const input = "Card: 4111-1111-1111-1111, CVV: 123";
        const result = MaskingService.mask(input, rules);
        expect(result).toBe("Card: [MASKED_CREDIT_CARD], CVV: [REDACTED]");
    });

    it("applies multiple rule types in sequence on an object", () => {
        const rules: MaskingRule[] = [
            { type: "PII_TYPE", category: "PHONE" },
            { type: "PII_TYPE", category: "EMAIL" },
            {
                type: "REGEX",
                pattern: /API_KEY_\w+/,
                replacement: "[REDACTED_KEY]",
                description: "mask api keys",
            },
            { type: "KEY_MATCH", sensitiveKeys: ["secret"] },
        ];
        const data = {
            contact: "Call 090-1234-5678 or email admin@example.com",
            config: "Use API_KEY_abc123",
            secret: "top-secret-value",
            safe: "nothing sensitive here",
        };
        const result = MaskingService.mask(data, rules) as Record<string, unknown>;
        expect(result.contact).toBe("Call [MASKED_PHONE] or email [MASKED_EMAIL]");
        expect(result.config).toBe("Use [REDACTED_KEY]");
        expect(result.secret).toBe("[MASKED_KEY]");
        expect(result.safe).toBe("nothing sensitive here");
    });

    it("KEY_MATCH takes precedence over PII_TYPE for matched keys", () => {
        // When a key matches KEY_MATCH, the entire value is replaced
        // so PII_TYPE never gets to process the string value
        const rules: MaskingRule[] = [
            { type: "PII_TYPE", category: "EMAIL" },
            { type: "KEY_MATCH", sensitiveKeys: ["email"] },
        ];
        const data = { email: "user@example.com" };
        const result = MaskingService.mask(data, rules) as Record<string, unknown>;
        // KEY_MATCH replaces the whole value before PII_TYPE can act on the string
        expect(result.email).toBe("[MASKED_KEY]");
    });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------
describe("MaskingService — edge cases", () => {
    it("returns empty string unchanged", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        expect(MaskingService.mask("", rules)).toBe("");
    });

    it("returns null unchanged", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        expect(MaskingService.mask(null, rules)).toBeNull();
    });

    it("returns undefined unchanged", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        expect(MaskingService.mask(undefined, rules)).toBeUndefined();
    });

    it("returns numbers unchanged", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "CREDIT_CARD" }];
        expect(MaskingService.mask(42, rules)).toBe(42);
    });

    it("returns booleans unchanged", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        expect(MaskingService.mask(true, rules)).toBe(true);
    });

    it("handles deeply nested objects up to maxDepth", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        // Build an object 12 levels deep; default maxDepth is 10
        let obj: Record<string, unknown> = { value: "user@example.com" };
        for (let i = 0; i < 12; i++) {
            obj = { nested: obj };
        }
        const result = MaskingService.mask(obj, rules) as Record<string, unknown>;
        // Traverse down — at depth 10, it should become [CIRCULAR_REFERENCE_OR_TOO_DEEP]
        let current: unknown = result;
        for (let i = 0; i < 10; i++) {
            expect(current).toHaveProperty("nested");
            current = (current as Record<string, unknown>).nested;
        }
        expect(current).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
    });

    it("handles custom maxDepth option", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const obj = { a: { b: { value: "user@example.com" } } };
        const result = MaskingService.mask(obj, rules, [], { maxDepth: 2 });
        // depth 0 -> obj, depth 1 -> a, depth 2 -> b becomes too deep
        expect((result as Record<string, Record<string, unknown>>).a.b).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
    });

    it("handles circular references safely", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const obj: Record<string, unknown> = { name: "test" };
        obj.self = obj; // circular
        const result = MaskingService.mask(obj, rules) as Record<string, unknown>;
        expect(result.name).toBe("test");
        expect(result.self).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
    });

    it("truncates arrays beyond maxArrayLength (default 50)", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const arr = Array.from({ length: 100 }, (_, i) => `item-${i}`);
        const result = MaskingService.mask(arr, rules) as unknown[];
        expect(result).toHaveLength(50);
    });

    it("respects custom maxArrayLength option", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const arr = Array.from({ length: 200 }, (_, i) => `item-${i}`);
        const result = MaskingService.mask(arr, rules, [], { maxArrayLength: 10 }) as unknown[];
        expect(result).toHaveLength(10);
    });

    it("masks strings inside arrays", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const arr = ["hello", "user@example.com", "world"];
        const result = MaskingService.mask(arr, rules) as string[];
        expect(result[0]).toBe("hello");
        expect(result[1]).toBe("[MASKED_EMAIL]");
        expect(result[2]).toBe("world");
    });

    it("handles null and undefined items in arrays", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const arr = [null, undefined, "user@example.com"];
        const result = MaskingService.mask(arr, rules) as unknown[];
        expect(result[0]).toBeNull();
        expect(result[1]).toBeUndefined();
        expect(result[2]).toBe("[MASKED_EMAIL]");
    });

    it("handles numeric items in arrays (pass through)", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const arr = [1, 2, 3];
        const result = MaskingService.mask(arr, rules) as number[];
        expect(result).toEqual([1, 2, 3]);
    });

    it("preserveFields skips masking for specified keys", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password", "token"] },
        ];
        const data = { password: "s3cret", token: "abc-123", name: "Alice" };
        const result = MaskingService.mask(data, rules, ["password"]) as Record<string, unknown>;
        // password is preserved, token is masked
        expect(result.password).toBe("s3cret");
        expect(result.token).toBe("[MASKED_KEY]");
        expect(result.name).toBe("Alice");
    });

    it("preserveFields skips PII masking on preserved keys", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const data = { contactEmail: "user@example.com", message: "Email: user@example.com" };
        const result = MaskingService.mask(data, rules, ["contactEmail"]) as Record<
            string,
            unknown
        >;
        expect(result.contactEmail).toBe("user@example.com"); // preserved
        expect(result.message).toBe("Email: [MASKED_EMAIL]"); // masked
    });

    it("handles Unicode strings", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const input = "連絡先: user@example.com まで";
        const result = MaskingService.mask(input, rules);
        expect(result).toBe("連絡先: [MASKED_EMAIL] まで");
    });

    it("handles Unicode with KEY_MATCH", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["パスワード"] },
        ];
        const data = { パスワード: "秘密", 名前: "太郎" };
        const result = MaskingService.mask(data, rules) as Record<string, unknown>;
        expect(result["パスワード"]).toBe("[MASKED_KEY]");
        expect(result["名前"]).toBe("太郎");
    });

    it("handles empty rules array (no masking applied)", () => {
        const data = { email: "user@example.com", password: "s3cret" };
        const result = MaskingService.mask(data, []);
        expect(result).toEqual(data);
    });

    it("handles empty object", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const result = MaskingService.mask({}, rules);
        expect(result).toEqual({});
    });

    it("handles empty array", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const result = MaskingService.mask([], rules);
        expect(result).toEqual([]);
    });

    it("handles null values in object properties", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const result = MaskingService.mask({ a: null, b: undefined }, rules);
        expect(result).toEqual({ a: null, b: undefined });
    });
});

// ---------------------------------------------------------------------------
// Full log object masking
// ---------------------------------------------------------------------------
describe("MaskingService — full log object masking", () => {
    it("masks PII in log message field", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const log = createTestLog({ message: "User user@example.com logged in" });
        const result = MaskingService.mask(log, rules) as Record<string, unknown>;
        expect(result.message).toBe("User [MASKED_EMAIL] logged in");
    });

    it("masks PII in log input field", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "PHONE" }];
        const log = createTestLog({
            input: "Customer called from 090-1111-2222",
        });
        const result = MaskingService.mask(log, rules) as Record<string, unknown>;
        expect(result.input).toBe("Customer called from [MASKED_PHONE]");
    });

    it("masks PII in log details field (object)", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "CREDIT_CARD" }];
        const log = createTestLog({
            details: { card: "4111-1111-1111-1111", amount: 100 },
        });
        const result = MaskingService.mask(log, rules) as Record<string, unknown>;
        const details = result.details as Record<string, unknown>;
        expect(details.card).toBe("[MASKED_CREDIT_CARD]");
        expect(details.amount).toBe(100);
    });

    it("masks PII in log tags field (array of objects)", () => {
        const rules: MaskingRule[] = [{ type: "PII_TYPE", category: "EMAIL" }];
        const log = createTestLog({
            tags: [
                { key: "user", category: "admin@example.com" },
                { key: "action", category: "login" },
            ],
        });
        const result = MaskingService.mask(log, rules) as Record<string, unknown>;
        const tags = result.tags as Array<Record<string, unknown>>;
        expect(tags[0].category).toBe("[MASKED_EMAIL]");
        expect(tags[1].category).toBe("login");
    });

    it("masks sensitive keys in log object", () => {
        const rules: MaskingRule[] = [
            { type: "KEY_MATCH", sensitiveKeys: ["password", "token"] },
        ];
        const log = createTestLog({
            details: { password: "abc123", token: "tok-xyz", action: "login" },
        });
        const result = MaskingService.mask(log, rules) as Record<string, unknown>;
        const details = result.details as Record<string, unknown>;
        expect(details.password).toBe("[MASKED_KEY]");
        expect(details.token).toBe("[MASKED_KEY]");
        expect(details.action).toBe("login");
    });

    it("applies combined rules across all log fields", () => {
        const rules: MaskingRule[] = [
            { type: "PII_TYPE", category: "EMAIL" },
            { type: "PII_TYPE", category: "PHONE" },
            { type: "KEY_MATCH", sensitiveKeys: ["secret"] },
        ];
        const log = createTestLog({
            message: "Contact admin@example.com or call 090-1234-5678",
            details: { secret: "hidden", info: "Contact support@test.com" },
        });
        const result = MaskingService.mask(log, rules) as Record<string, unknown>;
        expect(result.message).toBe(
            "Contact [MASKED_EMAIL] or call [MASKED_PHONE]",
        );
        const details = result.details as Record<string, unknown>;
        expect(details.secret).toBe("[MASKED_KEY]");
        expect(details.info).toBe("Contact [MASKED_EMAIL]");
    });
});
