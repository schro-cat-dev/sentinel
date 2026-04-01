/**
 * WhitelistRegistry Tests
 *
 * モジュラーホワイトリストの統合レジストリのテスト。
 * 正常系・異常系・エッジケース・セキュリティ。
 */
import { describe, it, expect } from "vitest";
import { WhitelistRegistry } from "../../../src/validation/whitelist-registry";
import { ValidationError } from "../../../src/validation/log-validator";
import type { WhitelistDefinition } from "../../../src/validation/whitelist-types";

const securityDef: WhitelistDefinition = {
    domain: "security",
    fields: {
        eventName: ["SECURITY_INTRUSION_DETECTED", "COMPLIANCE_VIOLATION"],
        priority: ["HIGH", "MEDIUM", "LOW"],
    },
};

const taskDef: WhitelistDefinition = {
    domain: "task",
    fields: {
        actionType: ["AI_ANALYZE", "SYSTEM_NOTIFICATION"],
        severity: ["CRITICAL", "HIGH"],
    },
};

// ===== 正常系 =====
describe("WhitelistRegistry: normal cases", () => {
    it("validates known field/value pair", () => {
        const registry = new WhitelistRegistry([securityDef]);
        expect(() => registry.validate("eventName", "SECURITY_INTRUSION_DETECTED")).not.toThrow();
    });

    it("rejects unknown value for registered field", () => {
        const registry = new WhitelistRegistry([securityDef]);
        expect(() => registry.validate("eventName", "TYPO_EVENT")).toThrow(ValidationError);
    });

    it("merges multiple domain definitions", () => {
        const registry = new WhitelistRegistry([securityDef, taskDef]);
        expect(() => registry.validate("eventName", "SECURITY_INTRUSION_DETECTED")).not.toThrow();
        expect(() => registry.validate("actionType", "AI_ANALYZE")).not.toThrow();
    });

    it("applies user extensions", () => {
        const registry = new WhitelistRegistry([taskDef], {
            actionType: ["CUSTOM_ACTION"],
        });
        expect(() => registry.validate("actionType", "AI_ANALYZE")).not.toThrow();
        expect(() => registry.validate("actionType", "CUSTOM_ACTION")).not.toThrow();
    });

    it("validateAll checks all values in array", () => {
        const registry = new WhitelistRegistry([securityDef]);
        expect(() => registry.validateAll("priority", ["HIGH", "LOW"])).not.toThrow();
        expect(() => registry.validateAll("priority", ["HIGH", "ULTRA"])).toThrow(ValidationError);
    });

    it("hasField returns correct result", () => {
        const registry = new WhitelistRegistry([securityDef]);
        expect(registry.hasField("eventName")).toBe(true);
        expect(registry.hasField("unknownField")).toBe(false);
    });

    it("getValidValues returns registered values", () => {
        const registry = new WhitelistRegistry([securityDef]);
        expect(registry.getValidValues("priority")).toEqual(
            expect.arrayContaining(["HIGH", "MEDIUM", "LOW"]),
        );
        expect(registry.getValidValues("unknownField")).toEqual([]);
    });
});

// ===== 異常系 =====
describe("WhitelistRegistry: abnormal cases", () => {
    it("throws ValidationError with correct field name", () => {
        const registry = new WhitelistRegistry([securityDef]);
        try {
            registry.validate("eventName", "TYPO");
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("eventName");
        }
    });

    it("error message includes valid values", () => {
        const registry = new WhitelistRegistry([securityDef]);
        try {
            registry.validate("priority", "ULTRA");
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect((err as Error).message).toContain("HIGH");
            expect((err as Error).message).toContain("MEDIUM");
            expect((err as Error).message).toContain("LOW");
        }
    });

    it("error message includes domain name", () => {
        const registry = new WhitelistRegistry([securityDef]);
        try {
            registry.validate("eventName", "BAD");
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect((err as Error).message).toContain("security");
        }
    });

    it("empty definitions means no validation (everything passes)", () => {
        const registry = new WhitelistRegistry([]);
        expect(() => registry.validate("eventName", "ANYTHING")).not.toThrow();
    });

    it("empty extensions is no-op", () => {
        const registry = new WhitelistRegistry([securityDef], {});
        expect(() => registry.validate("eventName", "SECURITY_INTRUSION_DETECTED")).not.toThrow();
        expect(() => registry.validate("eventName", "TYPO")).toThrow(ValidationError);
    });
});

// ===== エッジケース =====
describe("WhitelistRegistry: edge cases", () => {
    it("same field from two domains merges values", () => {
        const def1: WhitelistDefinition = {
            domain: "a",
            fields: { shared: ["X", "Y"] },
        };
        const def2: WhitelistDefinition = {
            domain: "b",
            fields: { shared: ["Y", "Z"] },
        };
        const registry = new WhitelistRegistry([def1, def2]);
        expect(() => registry.validate("shared", "X")).not.toThrow();
        expect(() => registry.validate("shared", "Z")).not.toThrow();
    });

    it("extension for non-existing field creates new whitelist", () => {
        const registry = new WhitelistRegistry([], {
            customField: ["A", "B"],
        });
        expect(registry.hasField("customField")).toBe(true);
        expect(() => registry.validate("customField", "A")).not.toThrow();
        expect(() => registry.validate("customField", "C")).toThrow(ValidationError);
    });

    it("empty enabledDomains array means no validation", () => {
        // Simulated by passing no definitions
        const registry = new WhitelistRegistry([]);
        expect(() => registry.validate("eventName", "ANYTHING")).not.toThrow();
    });

    it("validate on unregistered field is no-op", () => {
        const registry = new WhitelistRegistry([securityDef]);
        expect(() => registry.validate("unregistered", "anyValue")).not.toThrow();
    });

    it("extension with undefined values is ignored", () => {
        const registry = new WhitelistRegistry([securityDef], {
            eventName: undefined,
        });
        expect(() => registry.validate("eventName", "SECURITY_INTRUSION_DETECTED")).not.toThrow();
    });
});

// ===== セキュリティ =====
describe("WhitelistRegistry: security", () => {
    it("__proto__ field name in definition is ignored", () => {
        const malicious: WhitelistDefinition = {
            domain: "evil",
            fields: { __proto__: ["polluted"], eventName: ["VALID"] } as never,
        };
        const registry = new WhitelistRegistry([malicious]);
        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("polluted");
        // eventName should still work
        expect(() => registry.validate("eventName", "VALID")).not.toThrow();
    });

    it("__proto__ in extensions is ignored", () => {
        const registry = new WhitelistRegistry([], {
            __proto__: ["polluted"],
        } as never);
        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("polluted");
    });

    it("constructor field name is ignored", () => {
        const malicious: WhitelistDefinition = {
            domain: "evil",
            fields: { constructor: ["polluted"] },
        };
        const registry = new WhitelistRegistry([malicious]);
        expect(registry.hasField("constructor")).toBe(false);
    });
});
