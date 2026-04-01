/**
 * Pollution Guard Tests
 *
 * 発見1: error-utils.ts の for...in に hasOwnProperty ガード欠如
 * 発見2: DetectionRule.messagePattern に string が渡された場合のランタイム防御
 *
 * TDD: テストを先に書き、実装で通す。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { maskPiiContext } from "../../../src/shared/utils/error-utils";
import { EventDetector } from "../../../src/core/detection/event-detector";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { createTestLog } from "../../helpers/fixtures";
import type { DetectionRule } from "../../../src/types/event";

// ===== 発見1: error-utils.ts for...in prototype pollution guard =====
describe("error-utils: maskPiiContext prototype pollution guard", () => {
    const originalProto = { ...Object.getOwnPropertyDescriptors(Object.prototype) };

    afterEach(() => {
        // テスト後にprototypeをクリーン
        delete (Object.prototype as Record<string, unknown>)["polluted_key"];
        delete (Object.prototype as Record<string, unknown>)["__injected__"];
    });

    it("does not iterate prototype-polluted keys", () => {
        // Simulate global prototype pollution
        (Object.prototype as Record<string, unknown>)["polluted_key"] = "evil_value";

        const input = { username: "alice", amount: 100 } as Record<string, string | number | boolean | null>;
        const result = maskPiiContext(input);

        // polluted_key should NOT appear as own property in result
        expect(Object.prototype.hasOwnProperty.call(result, "polluted_key")).toBe(false);
        // original keys should still work
        expect(Object.prototype.hasOwnProperty.call(result, "username")).toBe(true);
    });

    it("does not iterate __proto__ injected keys", () => {
        (Object.prototype as Record<string, unknown>)["__injected__"] = "attack";

        const input = { safe: "data" } as Record<string, string | number | boolean | null>;
        const result = maskPiiContext(input);

        // __injected__ should NOT be an own property of result
        expect(Object.prototype.hasOwnProperty.call(result, "__injected__")).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(result, "safe")).toBe(true);
    });

    it("normal operation unchanged — PII values are still masked", () => {
        const input = { email: "alice@secret.com" } as Record<string, string | number | boolean | null>;
        const result = maskPiiContext(input);

        // email value contains PII → should be masked
        expect(result.email).toContain("MASKED");
    });

    it("normal operation unchanged — clean values pass through", () => {
        const input = { status: "ok", count: 42 } as Record<string, string | number | boolean | null>;
        const result = maskPiiContext(input);

        expect(result.status).toBe("ok");
        expect(result.count).toBe(42);
    });
});

// ===== 発見2: messagePattern string guard =====
describe("EventDetector: messagePattern type validation", () => {
    it("rejects string messagePattern at initialization with helpful error", () => {
        // JSON.parse produces strings, not RegExp
        const rules: DetectionRule[] = [{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                messagePattern: "failed.*login" as unknown as RegExp,  // string from JSON parse
            },
        }];

        expect(() => new EventDetector(rules)).toThrow(/messagePattern.*RegExp/i);
    });

    it("accepts valid RegExp messagePattern", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                messagePattern: /failed.*login/i,
            },
        }];

        expect(() => new EventDetector(rules)).not.toThrow();
    });

    it("accepts rules without messagePattern", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: { minLevel: 5 },
        }];

        expect(() => new EventDetector(rules)).not.toThrow();
    });

    it("rejects number as messagePattern", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                messagePattern: 12345 as unknown as RegExp,
            },
        }];

        expect(() => new EventDetector(rules)).toThrow(/messagePattern.*RegExp/i);
    });

    it("rejects object (non-RegExp) as messagePattern", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                messagePattern: { source: "test" } as unknown as RegExp,
            },
        }];

        expect(() => new EventDetector(rules)).toThrow(/messagePattern.*RegExp/i);
    });
});

// ===== Sentinel.initialize 統合テスト =====
describe("Sentinel.initialize: messagePattern validation", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("rejects config with string messagePattern at initialization", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                detectionRules: [{
                    ruleId: "r1",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: {
                        messagePattern: "sql.*injection" as unknown as RegExp,
                    },
                }],
            })),
        ).toThrow(/messagePattern.*RegExp/i);
    });

    it("accepts config with valid RegExp messagePattern", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                detectionRules: [{
                    ruleId: "r1",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: { messagePattern: /sql.*injection/i },
                }],
            })),
        ).not.toThrow();
    });
});
