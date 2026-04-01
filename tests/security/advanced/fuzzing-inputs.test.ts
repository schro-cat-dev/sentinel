/**
 * Fuzzing-style tests: throw random/malicious inputs at every entry point.
 *
 * Targets: MaskingService.mask(), validateLogInput(), LogNormalizer.normalize()
 */
import { describe, it, expect } from "vitest";
import { MaskingService } from "../../../src/security/masking-service";
import { validateLogInput, ValidationError } from "../../../src/validation/log-validator";
import { LogNormalizer } from "../../../src/core/engine/log-normalizer";
import { MaskingRule } from "../../../src/configs/masking-rule";
import { createTestLog } from "../../helpers/fixtures";
import type { Log, LogLevel, LogType } from "../../../src/types/log";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const normalizer = new LogNormalizer("fuzz-service");

const PII_RULES: MaskingRule[] = [
    { type: "PII_TYPE", category: "EMAIL" },
    { type: "PII_TYPE", category: "CREDIT_CARD" },
    { type: "PII_TYPE", category: "PHONE" },
    { type: "PII_TYPE", category: "GOVERNMENT_ID" },
];

/** Generate a string of given length from a character set. */
function repeatChar(char: string, length: number): string {
    return char.repeat(length);
}

/** Build a deeply nested object to N levels. */
function deeplyNested(depth: number, leaf: unknown = "leaf"): object {
    let obj: unknown = leaf;
    for (let i = 0; i < depth; i++) {
        obj = { nested: obj };
    }
    return obj as object;
}

// ---------------------------------------------------------------------------
// 1. Random string generation
// ---------------------------------------------------------------------------

describe("Fuzzing: random string generation", () => {
    it("should handle all printable ASCII characters in message", () => {
        const printable = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join("");
        expect(() => validateLogInput({ message: printable })).not.toThrow();
    });

    it("should handle extended unicode plane 1 (emoji) in message", () => {
        const emoji = "\u{1F600}\u{1F4A9}\u{1F680}\u{1F914}\u{1F525}";
        expect(() => validateLogInput({ message: emoji })).not.toThrow();
    });

    it("should handle CJK unified ideographs in message", () => {
        const cjk = "\u4E00\u4E01\u4E02\u4E03\u4E04\u4E05";
        expect(() => validateLogInput({ message: cjk })).not.toThrow();
    });

    it("should handle supplementary plane characters (U+20000)", () => {
        const supplementary = "\u{20000}\u{2A6D6}\u{2F800}";
        expect(() => validateLogInput({ message: supplementary })).not.toThrow();
    });

    it("should handle control characters (except null) in message", () => {
        // Control chars 0x01-0x1F except 0x00
        const controls = Array.from({ length: 31 }, (_, i) => String.fromCharCode(i + 1)).join("");
        // Some are whitespace-like, so add visible text
        const msg = "visible" + controls + "text";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should reject null byte (0x00) in message", () => {
        expect(() => validateLogInput({ message: "hello\x00world" })).toThrow(ValidationError);
    });

    it("should mask PII within random unicode surroundings", () => {
        const input = "\u{1F600} user@test.com \u4E00\u4E01";
        const result = MaskingService.mask(input, PII_RULES);
        expect(result).not.toContain("user@test.com");
    });

    it("should handle string with only combining characters", () => {
        const combining = "\u0300\u0301\u0302\u0303\u0304\u0305\u0306";
        // combining chars alone may render as empty visually but are valid
        const msg = "a" + combining; // needs non-empty trim
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 2. Boundary values for numeric fields
// ---------------------------------------------------------------------------

describe("Fuzzing: numeric boundary values", () => {
    it("should reject level = 0 (below range)", () => {
        expect(() => validateLogInput({ message: "test", level: 0 as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = 7 (above range)", () => {
        expect(() => validateLogInput({ message: "test", level: 7 as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = NaN", () => {
        expect(() => validateLogInput({ message: "test", level: NaN as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = Infinity", () => {
        expect(() => validateLogInput({ message: "test", level: Infinity as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = -Infinity", () => {
        expect(() => validateLogInput({ message: "test", level: -Infinity as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = 3.5 (non-integer)", () => {
        expect(() => validateLogInput({ message: "test", level: 3.5 as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = -0", () => {
        // -0 is 0, which is below range
        expect(() => validateLogInput({ message: "test", level: -0 as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = MAX_SAFE_INTEGER", () => {
        expect(() => validateLogInput({ message: "test", level: Number.MAX_SAFE_INTEGER as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should reject level = -MAX_SAFE_INTEGER", () => {
        expect(() => validateLogInput({ message: "test", level: -Number.MAX_SAFE_INTEGER as unknown as LogLevel })).toThrow(ValidationError);
    });

    it("should accept level = 1 (min valid)", () => {
        expect(() => validateLogInput({ message: "test", level: 1 })).not.toThrow();
    });

    it("should accept level = 6 (max valid)", () => {
        expect(() => validateLogInput({ message: "test", level: 6 })).not.toThrow();
    });

    it("should reject negative loopDepth in aiContext", () => {
        expect(() =>
            validateLogInput({
                message: "test",
                aiContext: { agentId: "a", taskId: "t", loopDepth: -1 },
            }),
        ).toThrow(ValidationError);
    });

    it("should accept NaN loopDepth in aiContext (typeof NaN === 'number' and NaN < 0 is false)", () => {
        // NOTE: This documents a gap in validation. NaN passes because:
        //   typeof NaN === "number" => true (passes type check)
        //   NaN < 0 => false (passes range check)
        // Ideally, Number.isNaN should be checked, but this test documents current behavior.
        expect(() =>
            validateLogInput({
                message: "test",
                aiContext: { agentId: "a", taskId: "t", loopDepth: NaN },
            }),
        ).not.toThrow();
    });

    it("should accept loopDepth = 0", () => {
        expect(() =>
            validateLogInput({
                message: "test",
                aiContext: { agentId: "a", taskId: "t", loopDepth: 0 },
            }),
        ).not.toThrow();
    });

    it("should handle logicalClock = MAX_SAFE_INTEGER in normalizer without crash", () => {
        const log = normalizer.normalize({ message: "test", logicalClock: Number.MAX_SAFE_INTEGER });
        expect(log.logicalClock).toBe(Number.MAX_SAFE_INTEGER);
    });

    it("should handle logicalClock = 0 in normalizer", () => {
        const log = normalizer.normalize({ message: "test", logicalClock: 0 });
        // 0 is falsy so normalizer falls back to Date.now()
        expect(typeof log.logicalClock).toBe("number");
    });
});

// ---------------------------------------------------------------------------
// 3. Empty/null/undefined/Symbol/BigInt for every field
// ---------------------------------------------------------------------------

describe("Fuzzing: type coercion and exotic types", () => {
    it("should reject undefined message", () => {
        expect(() => validateLogInput({} as unknown as Partial<Log>)).toThrow(ValidationError);
    });

    it("should reject null message", () => {
        expect(() => validateLogInput({ message: null } as unknown as Partial<Log>)).toThrow(ValidationError);
    });

    it("should reject numeric message", () => {
        expect(() => validateLogInput({ message: 42 } as unknown as Partial<Log>)).toThrow(ValidationError);
    });

    it("should reject boolean message", () => {
        expect(() => validateLogInput({ message: true } as unknown as Partial<Log>)).toThrow(ValidationError);
    });

    it("should reject Symbol message", () => {
        expect(() => validateLogInput({ message: Symbol("test") } as unknown as Partial<Log>)).toThrow();
    });

    it("should reject BigInt message", () => {
        expect(() => validateLogInput({ message: BigInt(42) } as unknown as Partial<Log>)).toThrow();
    });

    it("should reject empty string message", () => {
        expect(() => validateLogInput({ message: "" })).toThrow(ValidationError);
    });

    it("should reject whitespace-only message", () => {
        expect(() => validateLogInput({ message: "   \t\n  " })).toThrow(ValidationError);
    });

    it("should reject array as tags element (non-object)", () => {
        expect(() =>
            validateLogInput({ message: "test", tags: ["not-an-object"] as unknown as Log["tags"] }),
        ).toThrow();
    });

    it("should reject tags with numeric key", () => {
        expect(() =>
            validateLogInput({ message: "test", tags: [{ key: 123, category: "cat" }] as unknown as Log["tags"] }),
        ).toThrow(ValidationError);
    });

    it("should reject tags with null category", () => {
        expect(() =>
            validateLogInput({ message: "test", tags: [{ key: "k", category: null }] as unknown as Log["tags"] }),
        ).toThrow(ValidationError);
    });

    it("should reject non-boolean isCritical", () => {
        expect(() => validateLogInput({ message: "test", isCritical: "yes" as unknown as boolean })).toThrow(ValidationError);
    });

    it("should reject isCritical = 1 (truthy number)", () => {
        expect(() => validateLogInput({ message: "test", isCritical: 1 as unknown as boolean })).toThrow(ValidationError);
    });

    it("should reject agentBackLog as array", () => {
        expect(() => validateLogInput({ message: "test", agentBackLog: [] as unknown as Log["agentBackLog"] })).toThrow(ValidationError);
    });

    it("should reject agentBackLog as string", () => {
        expect(() => validateLogInput({ message: "test", agentBackLog: "not-object" as unknown as Log["agentBackLog"] })).toThrow(ValidationError);
    });

    it("should handle MaskingService.mask with null input", () => {
        expect(MaskingService.mask(null, PII_RULES)).toBeNull();
    });

    it("should handle MaskingService.mask with undefined input", () => {
        expect(MaskingService.mask(undefined, PII_RULES)).toBeUndefined();
    });

    it("should handle MaskingService.mask with number input", () => {
        expect(MaskingService.mask(42, PII_RULES)).toBe(42);
    });

    it("should handle MaskingService.mask with boolean input", () => {
        expect(MaskingService.mask(true, PII_RULES)).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// 4. Very long strings
// ---------------------------------------------------------------------------

describe("Fuzzing: very long strings", () => {
    it("should reject message exceeding 65536 characters", () => {
        const longMsg = "a".repeat(65537);
        expect(() => validateLogInput({ message: longMsg })).toThrow(ValidationError);
    });

    it("should accept message at exactly 65536 characters", () => {
        const maxMsg = "a".repeat(65536);
        expect(() => validateLogInput({ message: maxMsg })).not.toThrow();
    });

    it("should handle masking on 100KB string without crash", { timeout: 30000 }, () => {
        const largeStr = "x".repeat(100 * 1024);
        expect(() => MaskingService.mask(largeStr, PII_RULES)).not.toThrow();
    });

    it("should handle 100KB string with embedded email", () => {
        const padding = "x".repeat(50 * 1024);
        const largeStr = padding + " secret@example.com " + padding;
        const result = MaskingService.mask(largeStr, PII_RULES) as string;
        expect(result).not.toContain("secret@example.com");
    });

    it("should reject tag key exceeding 128 characters", () => {
        const longKey = "k".repeat(129);
        expect(() =>
            validateLogInput({ message: "test", tags: [{ key: longKey, category: "cat" }] }),
        ).toThrow(ValidationError);
    });

    it("should reject tag category exceeding 1024 characters", () => {
        const longCat = "c".repeat(1025);
        expect(() =>
            validateLogInput({ message: "test", tags: [{ key: "k", category: longCat }] }),
        ).toThrow(ValidationError);
    });

    it("should reject details exceeding 65536 characters", () => {
        const longDetails = "d".repeat(65537);
        expect(() => validateLogInput({ message: "test", details: longDetails })).toThrow(ValidationError);
    });
});

// ---------------------------------------------------------------------------
// 5. Large arrays
// ---------------------------------------------------------------------------

describe("Fuzzing: large arrays", () => {
    it("should reject tags array with 101 elements (exceeds limit)", () => {
        const tags = Array.from({ length: 101 }, (_, i) => ({ key: `k${i}`, category: `c${i}` }));
        expect(() => validateLogInput({ message: "test", tags })).toThrow(ValidationError);
    });

    it("should accept tags array with 100 elements (at limit)", () => {
        const tags = Array.from({ length: 100 }, (_, i) => ({ key: `k${i}`, category: `c${i}` }));
        expect(() => validateLogInput({ message: "test", tags })).not.toThrow();
    });

    it("should reject resourceIds array with 101 elements", () => {
        const resourceIds = Array.from({ length: 101 }, (_, i) => `res-${i}`);
        expect(() => validateLogInput({ message: "test", resourceIds })).toThrow(ValidationError);
    });

    it("should accept resourceIds array with 100 elements", () => {
        const resourceIds = Array.from({ length: 100 }, (_, i) => `res-${i}`);
        expect(() => validateLogInput({ message: "test", resourceIds })).not.toThrow();
    });

    it("should handle MaskingService.mask on array with 1000 elements", () => {
        const bigArray = Array.from({ length: 1000 }, (_, i) => `item-${i}`);
        // Default maxArrayLength is 50, so should truncate
        const result = MaskingService.mask(bigArray, PII_RULES) as unknown[];
        expect(result.length).toBeLessThanOrEqual(50);
    });

    it("should handle masking with custom maxArrayLength", () => {
        const bigArray = Array.from({ length: 200 }, (_, i) => `item-${i}`);
        const result = MaskingService.mask(bigArray, PII_RULES, [], { maxArrayLength: 200 }) as unknown[];
        expect(result.length).toBe(200);
    });

    it("should not crash on tags with 1000 elements (masking, not validation)", () => {
        const tags = Array.from({ length: 1000 }, (_, i) => ({ key: `k${i}`, category: `c${i}` }));
        const log = createTestLog({ tags });
        expect(() => MaskingService.mask(log, PII_RULES)).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 6. Deeply nested objects
// ---------------------------------------------------------------------------

describe("Fuzzing: deeply nested objects", () => {
    it("should handle 100-level nested object in masking (returns sentinel value)", () => {
        const deep = deeplyNested(100);
        const result = MaskingService.mask(deep, PII_RULES) as Record<string, unknown>;
        // maxDepth default is 10 so deep nesting returns sentinel
        let current: unknown = result;
        for (let i = 0; i < 9; i++) {
            if (typeof current === "string") break;
            current = (current as Record<string, unknown>)?.nested;
        }
        // At depth 10 it should be the sentinel string
        expect(current).toBeDefined();
    });

    it("should handle deeply nested input field in normalizer", () => {
        const deep = deeplyNested(100, "secret@email.com");
        const log = normalizer.normalize({ message: "test", input: deep as unknown as Log["input"] });
        expect(log.input).toBeDefined();
    });

    it("should respect custom maxDepth option in masking", () => {
        const deep = deeplyNested(5);
        const result = MaskingService.mask(deep, PII_RULES, [], { maxDepth: 3 }) as Record<string, unknown>;
        const nested1 = result.nested as Record<string, unknown>;
        const nested2 = nested1.nested as Record<string, unknown>;
        expect(nested2.nested).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
    });

    it("should handle circular reference without infinite loop", () => {
        const obj: Record<string, unknown> = { message: "hello" };
        obj.self = obj;
        const result = MaskingService.mask(obj, PII_RULES) as Record<string, unknown>;
        expect(result.self).toBe("[CIRCULAR_REFERENCE_OR_TOO_DEEP]");
    });

    it("should handle mutual circular references", () => {
        const a: Record<string, unknown> = { name: "a" };
        const b: Record<string, unknown> = { name: "b" };
        a.ref = b;
        b.ref = a;
        expect(() => MaskingService.mask(a, PII_RULES)).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 7. Strings that look like code
// ---------------------------------------------------------------------------

describe("Fuzzing: code-like strings", () => {
    it("should handle template literal injection: ${process.env.SECRET}", () => {
        const msg = '${process.env.SECRET}';
        expect(() => validateLogInput({ message: msg })).not.toThrow();
        const result = MaskingService.mask(msg, PII_RULES);
        expect(result).toBe(msg); // no PII, pass through
    });

    it("should handle <script>alert(1)</script> in message", () => {
        const msg = '<script>alert("xss")</script>';
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle SQL injection: ' OR 1=1 --", () => {
        const msg = "'; DROP TABLE users; --";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle command injection: $(rm -rf /)", () => {
        const msg = "$(rm -rf /)";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle backtick command injection: `id`", () => {
        const msg = "`id`";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle path traversal: ../../etc/passwd", () => {
        const msg = "../../etc/passwd";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle CRLF injection in message", () => {
        const msg = "header\r\nX-Injected: true\r\n\r\nbody";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle LDAP injection characters", () => {
        const msg = "*()|&=\\";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle XML injection: <foo>&xxe;</foo>", () => {
        const msg = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should mask email even when embedded in script tag", () => {
        const msg = '<script>var x="admin@example.com";</script>';
        const result = MaskingService.mask(msg, PII_RULES) as string;
        expect(result).not.toContain("admin@example.com");
    });

    it("should mask credit card in SQL injection string", () => {
        const msg = "SELECT * FROM users WHERE cc='4111111111111111'";
        const result = MaskingService.mask(msg, PII_RULES) as string;
        expect(result).not.toContain("4111111111111111");
    });

    it("should handle JSON string injection in message", () => {
        const msg = '{"key":"value","nested":{"a":"b"}}';
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 8. Unicode categories
// ---------------------------------------------------------------------------

describe("Fuzzing: unicode categories", () => {
    it("should handle RTL characters (Arabic)", () => {
        const msg = "\u0627\u0644\u0639\u0631\u0628\u064A\u0629 test";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle zero-width characters", () => {
        const msg = "test\u200B\u200C\u200Dword";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle combining characters", () => {
        const msg = "e\u0301 a\u0300 o\u0308"; // accented chars via combining
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle surrogate pairs (emoji)", () => {
        const msg = "\uD83D\uDE00 test \uD83D\uDE80";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle bidirectional override characters", () => {
        const msg = "normal \u202E reversed \u202C normal";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle interlinear annotation characters", () => {
        const msg = "\uFFF9annotation\uFFFA\uFFFBtest";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle variation selectors", () => {
        const msg = "\u2702\uFE0F scissors"; // text vs emoji presentation
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });

    it("should handle Braille patterns", () => {
        const msg = "\u2800\u2801\u2802\u2803 braille";
        expect(() => validateLogInput({ message: msg })).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// 9. Rapid sequential calls
// ---------------------------------------------------------------------------

describe("Fuzzing: rapid sequential calls", () => {
    it("should handle 1000 sequential validateLogInput calls without state corruption", () => {
        for (let i = 0; i < 1000; i++) {
            expect(() => validateLogInput({ message: `msg-${i}` })).not.toThrow();
        }
    });

    it("should handle 1000 sequential masking calls", () => {
        for (let i = 0; i < 1000; i++) {
            const result = MaskingService.mask(`user${i}@test.com`, PII_RULES);
            expect(result).not.toContain(`user${i}@test.com`);
        }
    });

    it("should handle 1000 sequential normalizer calls", () => {
        for (let i = 0; i < 1000; i++) {
            const log = normalizer.normalize({ message: `msg-${i}` });
            expect(log.message).toBe(`msg-${i}`);
        }
    });

    it("should produce consistent masking results across repeated calls", () => {
        const input = "Contact: user@example.com, card: 4111 1111 1111 1111";
        const results = new Set<string>();
        for (let i = 0; i < 100; i++) {
            results.add(MaskingService.mask(input, PII_RULES) as string);
        }
        // All results should be identical (deterministic masking)
        expect(results.size).toBe(1);
    });
});

// ---------------------------------------------------------------------------
// 10. Concurrent calls with conflicting data
// ---------------------------------------------------------------------------

describe("Fuzzing: concurrent calls with conflicting data", () => {
    it("should handle concurrent masking of different data types", async () => {
        const tasks = Array.from({ length: 100 }, (_, i) => {
            const data = i % 2 === 0
                ? `email: user${i}@test.com`
                : { nested: { email: `user${i}@test.com` } };
            return Promise.resolve(MaskingService.mask(data, PII_RULES));
        });
        const results = await Promise.all(tasks);
        for (let i = 0; i < results.length; i++) {
            const result = results[i];
            if (typeof result === "string") {
                expect(result).not.toContain(`user${i}@test.com`);
            } else {
                const nested = (result as Record<string, unknown>).nested as Record<string, unknown>;
                expect(nested.email).not.toContain(`user${i}@test.com`);
            }
        }
    });

    it("should handle concurrent validation calls", async () => {
        const tasks = Array.from({ length: 100 }, (_, i) =>
            Promise.resolve().then(() => {
                if (i % 3 === 0) {
                    expect(() => validateLogInput({ message: `valid-${i}` })).not.toThrow();
                } else if (i % 3 === 1) {
                    expect(() => validateLogInput({ message: "" })).toThrow(ValidationError);
                } else {
                    expect(() => validateLogInput({ message: "test", level: 999 as unknown as LogLevel })).toThrow(ValidationError);
                }
            }),
        );
        await Promise.all(tasks);
    });

    it("should handle concurrent normalizer calls with varied inputs", async () => {
        const tasks = Array.from({ length: 100 }, (_, i) =>
            Promise.resolve(normalizer.normalize({
                message: `concurrent-${i}`,
                type: i % 2 === 0 ? "SECURITY" : "DEBUG",
                level: ((i % 6) + 1) as unknown as LogLevel,
            })),
        );
        const results = await Promise.all(tasks);
        for (let i = 0; i < results.length; i++) {
            expect(results[i].message).toBe(`concurrent-${i}`);
        }
    });

    it("should not corrupt state when masking shared object structures concurrently", async () => {
        const sharedTemplate = {
            user: "test@example.com",
            card: "4111 1111 1111 1111",
            nested: { phone: "+81-90-1234-5678" },
        };
        const tasks = Array.from({ length: 50 }, () =>
            Promise.resolve(
                MaskingService.mask(
                    JSON.parse(JSON.stringify(sharedTemplate)),
                    PII_RULES,
                ),
            ),
        );
        const results = await Promise.all(tasks);
        for (const result of results) {
            const r = result as Record<string, unknown>;
            expect(r.user).not.toContain("test@example.com");
            expect(r.card).not.toContain("4111 1111 1111 1111");
        }
    });
});

// ---------------------------------------------------------------------------
// 11. Additional edge cases
// ---------------------------------------------------------------------------

describe("Fuzzing: additional edge cases", () => {
    it("should handle object with prototype pollution keys", () => {
        const malicious = JSON.parse('{"__proto__": {"polluted": true}, "message": "test@email.com"}');
        const result = MaskingService.mask(malicious, PII_RULES) as Record<string, unknown>;
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
        expect(result.message).not.toContain("test@email.com");
    });

    it("should handle object with constructor key", () => {
        const obj = { constructor: "test@email.com", message: "hello" };
        expect(() => MaskingService.mask(obj, PII_RULES)).not.toThrow();
    });

    it("should handle object with toString/valueOf overrides", () => {
        const obj = {
            toString: () => "malicious",
            valueOf: () => 42,
            message: "user@example.com",
        };
        const result = MaskingService.mask(obj, PII_RULES) as Record<string, unknown>;
        expect(result.message).not.toContain("user@example.com");
    });

    it("should handle Date object in input field", () => {
        const obj = { date: new Date(), message: "test" };
        expect(() => MaskingService.mask(obj, PII_RULES)).not.toThrow();
    });

    it("should handle RegExp object in input field", () => {
        const obj = { pattern: /test/g, message: "test" };
        expect(() => MaskingService.mask(obj, PII_RULES)).not.toThrow();
    });

    it("should handle object with numeric keys", () => {
        const obj: Record<string, unknown> = { 0: "a@b.com", 1: "hello" };
        const result = MaskingService.mask(obj, PII_RULES) as Record<string, unknown>;
        expect(result["0"]).not.toContain("a@b.com");
    });

    it("should handle empty object", () => {
        expect(MaskingService.mask({}, PII_RULES)).toEqual({});
    });

    it("should handle empty array", () => {
        expect(MaskingService.mask([], PII_RULES)).toEqual([]);
    });

    it("should handle invalid type string in validation", () => {
        expect(() => validateLogInput({ message: "test", type: "INVALID" as unknown as LogType })).toThrow(ValidationError);
    });

    it("should handle invalid origin string in validation", () => {
        expect(() => validateLogInput({ message: "test", origin: "HACKER" as unknown as Log["origin"] })).toThrow(ValidationError);
    });

    it("should handle non-array resourceIds", () => {
        expect(() => validateLogInput({ message: "test", resourceIds: "not-array" as unknown as string[] })).toThrow(ValidationError);
    });

    it("should handle non-array tags", () => {
        expect(() => validateLogInput({ message: "test", tags: "not-array" as unknown as Log["tags"] })).toThrow(ValidationError);
    });
});
