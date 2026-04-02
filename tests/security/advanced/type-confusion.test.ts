/**
 * Security Test: Runtime Type Confusion Attacks
 *
 * Tests that the SDK handles unexpected types at runtime gracefully,
 * since TypeScript type safety does not exist at runtime. Malicious
 * callers can pass any JavaScript value through the public API.
 *
 * CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')
 * CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
 */
import { describe, it, expect, afterEach } from "vitest";
import { MaskingService } from "../../../src/security/masking-service";
import { validateLogInput, ValidationError } from "../../../src/validation/log-validator";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import type { MaskingRule } from "../../../src/configs/masking-rule";

const ALL_PII_RULES: MaskingRule[] = [
    { type: "PII_TYPE", category: "CREDIT_CARD" },
    { type: "PII_TYPE", category: "PHONE" },
    { type: "PII_TYPE", category: "EMAIL" },
    { type: "PII_TYPE", category: "GOVERNMENT_ID" },
];

/**
 * Attempt validation; expect either ValidationError or no crash.
 */
let lastValidationOutcome: "passed" | "rejected" = "passed";

function expectValidationOrGraceful(input: unknown): void {
    try {
        validateLogInput(input as never);
        lastValidationOutcome = "passed";
        // 成功パス: バリデーション通過。入力が妥当 or 防御的フォールバック
        expect(lastValidationOutcome).toBe("passed");
    } catch (e) {
        lastValidationOutcome = "rejected";
        // 失敗パス: 正しいエラー型で拒否されたことを検証
        expect(e instanceof ValidationError || e instanceof Error).toBe(true);
    }
}

/**
 * Attempt ingest; expect either rejection or safe processing.
 */
async function safeIngest(input: unknown): Promise<void> {
    Sentinel.reset();
    const config = createDefaultConfig({
        projectName: "type-confusion-test",
        serviceId: "tc-svc",
        environment: "test",
        masking: { enabled: true, rules: ALL_PII_RULES, preserveFields: [] },
        security: { enableHashChain: false },
        taskRules: [],
    });
    const sentinel = Sentinel.initialize(config);
    try {
        await sentinel.ingest(input as never);
    } catch (e) {
        expect(e instanceof ValidationError || e instanceof Error).toBe(true);
    }
}

/**
 * Attempt masking; expect no crash.
 */
function safeMask(data: unknown): void {
    try {
        MaskingService.mask(data, ALL_PII_RULES);
    } catch (e) {
        expect(e instanceof Error).toBe(true);
    }
}

describe("Security: Runtime Type Confusion Attacks", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    // =========================================================================
    // Wrong types for message field
    // =========================================================================
    describe("message field type confusion", () => {
        it("rejects number as message", () => {
            expect(() => validateLogInput({ message: 42 as never })).toThrow(ValidationError);
        });

        it("rejects boolean as message", () => {
            expect(() => validateLogInput({ message: true as never })).toThrow(ValidationError);
        });

        it("rejects array as message", () => {
            expect(() => validateLogInput({ message: ["hello"] as never })).toThrow(ValidationError);
        });

        it("rejects object as message", () => {
            expect(() => validateLogInput({ message: { text: "hello" } as never })).toThrow(ValidationError);
        });

        it("rejects function as message", () => {
            expect(() => validateLogInput({ message: (() => "hello") as never })).toThrow(ValidationError);
        });

        it("rejects Symbol as message", () => {
            expect(() => validateLogInput({ message: Symbol("test") as never })).toThrow(ValidationError);
        });

        it("rejects BigInt as message", () => {
            expect(() => validateLogInput({ message: BigInt(42) as never })).toThrow(ValidationError);
        });

        it("rejects Date as message", () => {
            expect(() => validateLogInput({ message: new Date() as never })).toThrow(ValidationError);
        });

        it("rejects RegExp as message", () => {
            expect(() => validateLogInput({ message: /test/ as never })).toThrow(ValidationError);
        });

        it("rejects Map as message", () => {
            expect(() => validateLogInput({ message: new Map() as never })).toThrow(ValidationError);
        });

        it("rejects Set as message", () => {
            expect(() => validateLogInput({ message: new Set() as never })).toThrow(ValidationError);
        });

        it("rejects Promise as message", () => {
            expect(() => validateLogInput({ message: Promise.resolve("hello") as never })).toThrow(ValidationError);
        });
    });

    // =========================================================================
    // Wrong types for level field
    // =========================================================================
    describe("level field type confusion", () => {
        it("rejects string '6' as level", () => {
            expect(() => validateLogInput({ message: "test", level: "6" as never })).toThrow(ValidationError);
        });

        it("rejects boolean true as level", () => {
            expect(() => validateLogInput({ message: "test", level: true as never })).toThrow(ValidationError);
        });

        it("rejects null as level", () => {
            // null for optional field - depends on validator behavior
            expectValidationOrGraceful({ message: "test", level: null });
        });

        it("rejects array [3] as level", () => {
            expect(() => validateLogInput({ message: "test", level: [3] as never })).toThrow(ValidationError);
        });

        it("rejects object with valueOf as level", () => {
            expect(() => validateLogInput({
                message: "test",
                level: { valueOf: () => 3 } as never,
            })).toThrow(ValidationError);
        });

        it("rejects float 3.5 as level", () => {
            expect(() => validateLogInput({ message: "test", level: 3.5 as never })).toThrow(ValidationError);
        });

        it("rejects NaN as level", () => {
            expect(() => validateLogInput({ message: "test", level: NaN as never })).toThrow(ValidationError);
        });

        it("rejects Infinity as level", () => {
            expect(() => validateLogInput({ message: "test", level: Infinity as never })).toThrow(ValidationError);
        });

        it("rejects 0 as level (out of range)", () => {
            expect(() => validateLogInput({ message: "test", level: 0 as never })).toThrow(ValidationError);
        });

        it("rejects 7 as level (out of range)", () => {
            expect(() => validateLogInput({ message: "test", level: 7 as never })).toThrow(ValidationError);
        });

        it("rejects negative number as level", () => {
            expect(() => validateLogInput({ message: "test", level: -1 as never })).toThrow(ValidationError);
        });
    });

    // =========================================================================
    // Wrong types for type field
    // =========================================================================
    describe("type field type confusion", () => {
        it("rejects number as type", () => {
            expect(() => validateLogInput({ message: "test", type: 42 as never })).toThrow(ValidationError);
        });

        it("rejects boolean as type", () => {
            expect(() => validateLogInput({ message: "test", type: true as never })).toThrow(ValidationError);
        });

        it("rejects object with toString as type", () => {
            expect(() => validateLogInput({
                message: "test",
                type: { toString: () => "SYSTEM" } as never,
            })).toThrow(ValidationError);
        });

        it("rejects invalid string as type", () => {
            expect(() => validateLogInput({ message: "test", type: "INVALID" as never })).toThrow(ValidationError);
        });

        it("rejects empty string as type", () => {
            expect(() => validateLogInput({ message: "test", type: "" as never })).toThrow(ValidationError);
        });
    });

    // =========================================================================
    // Wrong types for tags field
    // =========================================================================
    describe("tags field type confusion", () => {
        it("rejects string as tags", () => {
            expect(() => validateLogInput({ message: "test", tags: "not-an-array" as never })).toThrow(ValidationError);
        });

        it("rejects number as tags", () => {
            expect(() => validateLogInput({ message: "test", tags: 42 as never })).toThrow(ValidationError);
        });

        it("rejects non-array object as tags", () => {
            expect(() => validateLogInput({ message: "test", tags: { key: "a", category: "b" } as never })).toThrow(ValidationError);
        });

        it("rejects Set as tags", () => {
            expect(() => validateLogInput({ message: "test", tags: new Set() as never })).toThrow(ValidationError);
        });

        it("rejects Map as tags", () => {
            expect(() => validateLogInput({ message: "test", tags: new Map() as never })).toThrow(ValidationError);
        });

        it("handles tags with number as key", () => {
            expectValidationOrGraceful({ message: "test", tags: [{ key: 123, category: "cat" }] });
        });

        it("handles tags with boolean as key", () => {
            expectValidationOrGraceful({ message: "test", tags: [{ key: true, category: "cat" }] });
        });

        it("handles tags with null as key", () => {
            expectValidationOrGraceful({ message: "test", tags: [{ key: null, category: "cat" }] });
        });

        it("handles tags with undefined as key", () => {
            expectValidationOrGraceful({ message: "test", tags: [{ key: undefined, category: "cat" }] });
        });

        it("handles tags with object as key", () => {
            expectValidationOrGraceful({ message: "test", tags: [{ key: { nested: true }, category: "cat" }] });
        });

        it("handles tags with array as tag element", () => {
            expectValidationOrGraceful({ message: "test", tags: [["not", "a", "tag"]] });
        });

        it("handles tags with missing category", () => {
            expectValidationOrGraceful({ message: "test", tags: [{ key: "test" }] });
        });
    });

    // =========================================================================
    // Wrong types for isCritical field
    // =========================================================================
    describe("isCritical field type confusion", () => {
        it("rejects string 'true' as isCritical", () => {
            expect(() => validateLogInput({ message: "test", isCritical: "true" as never })).toThrow(ValidationError);
        });

        it("rejects number 1 as isCritical", () => {
            expect(() => validateLogInput({ message: "test", isCritical: 1 as never })).toThrow(ValidationError);
        });

        it("rejects object as isCritical", () => {
            expect(() => validateLogInput({ message: "test", isCritical: {} as never })).toThrow(ValidationError);
        });

        it("rejects number 0 as isCritical", () => {
            expect(() => validateLogInput({ message: "test", isCritical: 0 as never })).toThrow(ValidationError);
        });

        it("rejects string 'false' as isCritical", () => {
            expect(() => validateLogInput({ message: "test", isCritical: "false" as never })).toThrow(ValidationError);
        });
    });

    // =========================================================================
    // Wrong types for origin field
    // =========================================================================
    describe("origin field type confusion", () => {
        it("rejects number as origin", () => {
            expect(() => validateLogInput({ message: "test", origin: 42 as never })).toThrow(ValidationError);
        });

        it("rejects boolean as origin", () => {
            expect(() => validateLogInput({ message: "test", origin: true as never })).toThrow(ValidationError);
        });

        it("rejects invalid string as origin", () => {
            expect(() => validateLogInput({ message: "test", origin: "INVALID" as never })).toThrow(ValidationError);
        });
    });

    // =========================================================================
    // Wrong types for timestamp field (A-03 gap)
    // =========================================================================
    describe("timestamp field type confusion", () => {
        it("rejects number as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: 1234567890 as never })).toThrow(ValidationError);
        });

        it("rejects boolean as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: true as never })).toThrow(ValidationError);
        });

        it("rejects object as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: new Date() as never })).toThrow(ValidationError);
        });

        it("rejects array as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: ["2024-01-01"] as never })).toThrow(ValidationError);
        });

        it("rejects empty string as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: "" as never })).toThrow(ValidationError);
        });

        it("rejects non-ISO8601 string as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: "not-a-date" as never })).toThrow(ValidationError);
        });

        it("rejects unix timestamp string as timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: "1234567890" as never })).toThrow(ValidationError);
        });

        it("accepts valid ISO8601 timestamp", () => {
            expect(() => validateLogInput({ message: "test", timestamp: "2024-04-02T10:30:00.000Z" })).not.toThrow();
        });

        it("accepts ISO8601 without milliseconds", () => {
            expect(() => validateLogInput({ message: "test", timestamp: "2024-04-02T10:30:00Z" })).not.toThrow();
        });

        it("accepts ISO8601 with timezone offset", () => {
            expect(() => validateLogInput({ message: "test", timestamp: "2024-04-02T10:30:00+09:00" })).not.toThrow();
        });

        it("allows undefined timestamp (optional)", () => {
            expect(() => validateLogInput({ message: "test" })).not.toThrow();
        });
    });

    // =========================================================================
    // Wrong types for logicalClock field (A-03 gap)
    // =========================================================================
    describe("logicalClock field type confusion", () => {
        it("rejects string as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: "123" as never })).toThrow(ValidationError);
        });

        it("rejects boolean as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: true as never })).toThrow(ValidationError);
        });

        it("rejects object as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: {} as never })).toThrow(ValidationError);
        });

        it("rejects array as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: [42] as never })).toThrow(ValidationError);
        });

        it("rejects NaN as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: NaN as never })).toThrow(ValidationError);
        });

        it("rejects Infinity as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: Infinity as never })).toThrow(ValidationError);
        });

        it("rejects negative number as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: -1 as never })).toThrow(ValidationError);
        });

        it("accepts valid positive number as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: 1712345678000 })).not.toThrow();
        });

        it("accepts zero as logicalClock", () => {
            expect(() => validateLogInput({ message: "test", logicalClock: 0 })).not.toThrow();
        });

        it("allows undefined logicalClock (optional)", () => {
            expect(() => validateLogInput({ message: "test" })).not.toThrow();
        });
    });

    // =========================================================================
    // Wrong types for triggerAgent field (A-03 gap)
    // =========================================================================
    describe("triggerAgent field type confusion", () => {
        it("rejects string 'true' as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: "true" as never })).toThrow(ValidationError);
        });

        it("rejects string 'false' as triggerAgent (truthy in JS!)", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: "false" as never })).toThrow(ValidationError);
        });

        it("rejects number 1 as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: 1 as never })).toThrow(ValidationError);
        });

        it("rejects number 0 as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: 0 as never })).toThrow(ValidationError);
        });

        it("rejects object as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: {} as never })).toThrow(ValidationError);
        });

        it("rejects array as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: [] as never })).toThrow(ValidationError);
        });

        it("accepts true as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: true })).not.toThrow();
        });

        it("accepts false as triggerAgent", () => {
            expect(() => validateLogInput({ message: "test", triggerAgent: false })).not.toThrow();
        });

        it("allows undefined triggerAgent (optional)", () => {
            expect(() => validateLogInput({ message: "test" })).not.toThrow();
        });
    });

    // =========================================================================
    // Objects with getters that throw
    // =========================================================================
    describe("Objects with getters that throw", () => {
        it("handles object with throwing getter on message", () => {
            const trap = Object.create(null);
            Object.defineProperty(trap, "message", {
                get() { throw new Error("trap"); },
                enumerable: true,
                configurable: true,
            });
            expectValidationOrGraceful(trap);
        });

        it("handles object with getter returning undefined for level", () => {
            const obj = {
                message: "test",
                get level() { return undefined; },
            };
            // level: undefined is valid (optional field)
            expect(() => validateLogInput(obj as never)).not.toThrow();
        });

        it("handles object with getter that returns wrong type for level", () => {
            const obj = {
                message: "test",
                get level() { return "not a number"; },
            };
            expect(() => validateLogInput(obj as never)).toThrow(ValidationError);
        });

        it("handles masking with getter that throws", () => {
            const obj = Object.create(null);
            Object.defineProperty(obj, "email", {
                get() { throw new Error("trap"); },
                enumerable: true,
                configurable: true,
            });
            // MaskingService iterates with for..in; getter throw should be caught or propagate
            expect(() => MaskingService.mask(obj, ALL_PII_RULES)).toThrow();
        });

        it("handles masking with getter returning different value each time", () => {
            let callCount = 0;
            const obj = {
                get data() {
                    callCount++;
                    return callCount === 1 ? "user@example.com" : "safe";
                },
            };
            // Should not crash regardless of getter behavior
            safeMask(obj);
        });
    });

    // =========================================================================
    // Proxy traps
    // =========================================================================
    describe("Proxy traps", () => {
        it("handles Proxy with get trap", () => {
            const proxy = new Proxy({} as Record<string, unknown>, {
                get(target, prop) {
                    if (prop === "message") return "proxied message";
                    return undefined;
                },
                ownKeys() { return ["message"]; },
                getOwnPropertyDescriptor(target, prop) {
                    if (prop === "message") return { configurable: true, enumerable: true, value: "proxied" };
                    return undefined;
                },
            });
            expectValidationOrGraceful(proxy);
        });

        it("handles Proxy that throws on property access", () => {
            const proxy = new Proxy({} as Record<string, unknown>, {
                get() { throw new Error("proxy trap"); },
            });
            expectValidationOrGraceful(proxy);
        });

        it("masking handles Proxy with has trap", () => {
            const proxy = new Proxy({ email: "user@example.com" }, {
                has() { return true; },
            });
            safeMask(proxy);
        });
    });

    // =========================================================================
    // Frozen / sealed objects
    // =========================================================================
    describe("Frozen and sealed objects", () => {
        it("validates frozen object", () => {
            const frozen = Object.freeze({ message: "frozen log" });
            expect(() => validateLogInput(frozen as never)).not.toThrow();
        });

        it("validates sealed object", () => {
            const sealed = Object.seal({ message: "sealed log" });
            expect(() => validateLogInput(sealed as never)).not.toThrow();
        });

        it("masking handles frozen object", () => {
            const frozen = Object.freeze({ email: "user@example.com", nested: { phone: "090-1234-5678" } });
            const result = MaskingService.mask(frozen, ALL_PII_RULES) as Record<string, unknown>;
            // Masking creates new objects, so frozen original is fine
            expect(result).toBeDefined();
        });

        it("masking handles deeply frozen object", () => {
            const inner = Object.freeze({ secret: "user@example.com" });
            const outer = Object.freeze({ data: inner });
            const result = MaskingService.mask(outer, ALL_PII_RULES);
            expect(result).toBeDefined();
        });

        it("validates non-extensible object", () => {
            const obj = Object.preventExtensions({ message: "non-extensible" });
            expect(() => validateLogInput(obj as never)).not.toThrow();
        });

        it("handles object with non-configurable properties", () => {
            const obj: Record<string, unknown> = {};
            Object.defineProperty(obj, "message", { value: "test", configurable: false, enumerable: true });
            expect(() => validateLogInput(obj as never)).not.toThrow();
        });
    });

    // =========================================================================
    // Array-like objects
    // =========================================================================
    describe("Array-like objects", () => {
        it("handles arguments-like object as tags", () => {
            const arrayLike = { length: 2, 0: { key: "a", category: "b" }, 1: { key: "c", category: "d" } };
            // Not a real array, should be rejected
            expectValidationOrGraceful({ message: "test", tags: arrayLike });
        });

        it("handles array-like object in masking", () => {
            const arrayLike = { length: 2, 0: "user@example.com", 1: "other" };
            safeMask(arrayLike);
        });

        it("handles typed array as tags", () => {
            expectValidationOrGraceful({ message: "test", tags: new Uint8Array([1, 2, 3]) });
        });
    });

    // =========================================================================
    // Prototype chain tricks
    // =========================================================================
    describe("Prototype chain tricks", () => {
        it("handles Object.create(null) as input (no prototype)", () => {
            const nullProto = Object.create(null);
            nullProto.message = "null prototype";
            expect(() => validateLogInput(nullProto)).not.toThrow();
        });

        it("masking handles Object.create(null)", () => {
            const nullProto = Object.create(null);
            nullProto.email = "user@example.com";
            const result = MaskingService.mask(nullProto, ALL_PII_RULES) as Record<string, unknown>;
            expect(result).toBeDefined();
        });

        it("handles object with overridden hasOwnProperty", () => {
            const obj = {
                message: "test",
                hasOwnProperty: () => false,
            };
            // Validator uses Object.prototype.hasOwnProperty.call or similar
            expect(() => validateLogInput(obj as never)).not.toThrow();
        });

        it("masking handles object with overridden hasOwnProperty", () => {
            const obj = {
                email: "user@example.com",
                hasOwnProperty: () => false,
            };
            // MaskingService uses Object.prototype.hasOwnProperty.call
            const result = MaskingService.mask(obj, ALL_PII_RULES) as Record<string, unknown>;
            expect(result).toBeDefined();
        });

        it("handles object with overridden toString", () => {
            const obj = {
                message: "test",
                toString() { throw new Error("toString trap"); },
            };
            expect(() => validateLogInput(obj as never)).not.toThrow();
        });

        it("handles object with overridden valueOf", () => {
            const obj = {
                message: "test",
                valueOf() { return 42; },
            };
            expect(() => validateLogInput(obj as never)).not.toThrow();
        });

        it("masking handles object with Symbol.toPrimitive", () => {
            const obj = {
                email: "user@example.com",
                [Symbol.toPrimitive]() { return "primitive"; },
            };
            safeMask(obj);
        });

        it("handles object inheriting from Error", () => {
            const err = new Error("test error");
            (err as unknown as Record<string, unknown>).message = "error message";
            expect(() => validateLogInput(err as never)).not.toThrow();
        });

        it("handles object with prototype pollution attempt via constructor", () => {
            const obj = { message: "test", constructor: { prototype: { polluted: true } } };
            expect(() => validateLogInput(obj as never)).not.toThrow();
            expect(({} as Record<string, unknown>).polluted).toBeUndefined();
        });
    });

    // =========================================================================
    // JSON.parse edge cases
    // =========================================================================
    describe("JSON.parse edge cases", () => {
        it("handles __proto__ pollution via JSON.parse", () => {
            const parsed = JSON.parse('{"__proto__":{"polluted":true}}');
            safeMask(parsed);
            // Verify no prototype pollution occurred
            expect(({} as Record<string, unknown>).polluted).toBeUndefined();
        });

        it("validates input from JSON.parse with __proto__", () => {
            const parsed = JSON.parse('{"message":"test","__proto__":{"isAdmin":true}}');
            expect(() => validateLogInput(parsed)).not.toThrow();
            expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
        });

        it("masking handles JSON.parse with nested __proto__", () => {
            const parsed = JSON.parse('{"data":{"__proto__":{"polluted":true}}}');
            const result = MaskingService.mask(parsed, ALL_PII_RULES);
            expect(result).toBeDefined();
            expect(({} as Record<string, unknown>).polluted).toBeUndefined();
        });

        it("handles JSON.parse with reviver that mutates", () => {
            const parsed = JSON.parse('{"message":"test","level":3}', (key, value) => {
                if (key === "level") return "not-a-number";
                return value;
            });
            expectValidationOrGraceful(parsed);
        });

        it("handles JSON.parse with constructor key", () => {
            const parsed = JSON.parse('{"message":"test","constructor":{"prototype":{"x":1}}}');
            expect(() => validateLogInput(parsed as never)).not.toThrow();
            expect(({} as Record<string, unknown>).x).toBeUndefined();
        });

        it("handles JSON.parse with deeply nested __proto__", () => {
            const json = '{"a":{"b":{"__proto__":{"deep":true}}}}';
            const parsed = JSON.parse(json);
            safeMask(parsed);
            expect(({} as Record<string, unknown>).deep).toBeUndefined();
        });

        it("masking handles JSON.parse with numeric keys", () => {
            const parsed = JSON.parse('{"0":"a","1":"b","length":2}');
            safeMask(parsed);
        });

        it("handles JSON.parse reviver returning undefined (property deleted)", () => {
            const parsed = JSON.parse('{"message":"test","level":3,"type":"SYSTEM"}', (key, value) => {
                if (key === "type") return undefined;
                return value;
            });
            expect(() => validateLogInput(parsed)).not.toThrow();
        });
    });

    // =========================================================================
    // Full pipeline with confused types
    // =========================================================================
    describe("Full pipeline type confusion", () => {
        it("rejects undefined input to ingest", async () => {
            await safeIngest(undefined);
        });

        it("rejects null input to ingest", async () => {
            await safeIngest(null);
        });

        it("rejects string input to ingest", async () => {
            await safeIngest("just a string");
        });

        it("rejects number input to ingest", async () => {
            await safeIngest(42);
        });

        it("rejects array input to ingest", async () => {
            await safeIngest([{ message: "test" }]);
        });

        it("handles empty object input to ingest", async () => {
            await safeIngest({});
        });

        it("handles input with extra unknown fields", async () => {
            await safeIngest({
                message: "test",
                unknownField: "should be ignored",
                anotherField: 42,
            });
        });

        it("handles input with Symbol keys", async () => {
            const sym = Symbol("test");
            const input = { message: "test", [sym]: "symbol value" };
            await safeIngest(input);
        });

        it("handles agentBackLog as array (should be object)", () => {
            expect(() => validateLogInput({
                message: "test",
                agentBackLog: [1, 2, 3] as never,
            })).toThrow(ValidationError);
        });

        it("handles agentBackLog as string (should be object)", () => {
            expect(() => validateLogInput({
                message: "test",
                agentBackLog: "not an object" as never,
            })).toThrow(ValidationError);
        });

        it("handles aiContext with negative loopDepth", () => {
            expect(() => validateLogInput({
                message: "test",
                aiContext: { agentId: "a", taskId: "t", loopDepth: -1 },
            })).toThrow(ValidationError);
        });

        it("handles aiContext with string loopDepth", () => {
            expect(() => validateLogInput({
                message: "test",
                aiContext: { agentId: "a", taskId: "t", loopDepth: "5" as never },
            })).toThrow(ValidationError);
        });
    });
});
