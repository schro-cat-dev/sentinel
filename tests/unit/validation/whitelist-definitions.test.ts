/**
 * Whitelist Definition Tests
 *
 * 各ドメインのWhitelistDefinitionが正しい値を持つことを検証。
 * ソースオブトゥルース（型定義・定数）と一致することを保証。
 */
import { describe, it, expect } from "vitest";
import { SECURITY_WHITELIST } from "../../../src/validation/whitelists/security-whitelist";
import { TASK_WHITELIST } from "../../../src/validation/whitelists/task-whitelist";
import { PRIVACY_WHITELIST, VALID_PII_CATEGORIES } from "../../../src/validation/whitelists/privacy-whitelist";
import { TASK_ACTION_TYPES, TASK_SEVERITIES } from "../../../src/types/task";

describe("SecurityWhitelist definition", () => {
    it("has correct domain", () => {
        expect(SECURITY_WHITELIST.domain).toBe("security");
    });

    it("has eventName and detectionPriority fields", () => {
        expect(SECURITY_WHITELIST.fields).toHaveProperty("eventName");
        expect(SECURITY_WHITELIST.fields).toHaveProperty("detectionPriority");
    });

    it("eventName contains all SystemEventMap keys", () => {
        const expected = [
            "SECURITY_INTRUSION_DETECTED",
            "COMPLIANCE_VIOLATION",
            "SYSTEM_CRITICAL_FAILURE",
            "AI_ACTION_REQUIRED",
        ];
        for (const name of expected) {
            expect(SECURITY_WHITELIST.fields.eventName).toContain(name);
        }
    });

    it("detectionPriority contains HIGH/MEDIUM/LOW", () => {
        expect(SECURITY_WHITELIST.fields.detectionPriority).toEqual(
            expect.arrayContaining(["HIGH", "MEDIUM", "LOW"]),
        );
    });
});

describe("TaskWhitelist definition", () => {
    it("has correct domain", () => {
        expect(TASK_WHITELIST.domain).toBe("task");
    });

    it("actionType matches TASK_ACTION_TYPES source of truth", () => {
        expect([...TASK_WHITELIST.fields.actionType]).toEqual([...TASK_ACTION_TYPES]);
    });

    it("severity matches TASK_SEVERITIES source of truth", () => {
        expect([...TASK_WHITELIST.fields.severity]).toEqual([...TASK_SEVERITIES]);
    });

    it("executionLevel contains all valid levels", () => {
        expect(TASK_WHITELIST.fields.executionLevel).toEqual(
            expect.arrayContaining(["AUTO", "SEMI_AUTO", "MANUAL", "MONITOR"]),
        );
    });
});

describe("PrivacyWhitelist definition", () => {
    it("has correct domain", () => {
        expect(PRIVACY_WHITELIST.domain).toBe("privacy");
    });

    it("piiCategory contains all 8 PII categories", () => {
        expect(VALID_PII_CATEGORIES).toHaveLength(8);
        const expected = [
            "CREDIT_CARD", "PHONE", "EMAIL", "GOVERNMENT_ID",
            "JAPAN_ACCOUNT", "POSTAL_CODE", "DRIVER_LICENSE", "HEALTH_INSURANCE",
        ];
        for (const cat of expected) {
            expect(PRIVACY_WHITELIST.fields.piiCategory).toContain(cat);
        }
    });
});
