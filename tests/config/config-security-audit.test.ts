/**
 * Config Security Audit Tests (TDD)
 *
 * F-08: RegExp g/y flag rejection
 * F-14: errorRouting.rules whitelist validation
 * F-15: detectionRules.conditions.logTypes/origin validation
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../src/index";
import { EventDetector } from "../../src/core/detection/event-detector";
import type { DetectionRule } from "../../src/types/event";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== F-08: RegExp g/y flag =====
describe("F-08: RegExp global/sticky flag rejected", () => {
    it("rejects /pattern/g", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
            conditions: { messagePattern: /test/g },
        }];
        expect(() => new EventDetector(rules)).toThrow(/global|sticky/i);
    });

    it("rejects /pattern/y", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
            conditions: { messagePattern: /test/y },
        }];
        expect(() => new EventDetector(rules)).toThrow(/global|sticky/i);
    });

    it("rejects /pattern/gi", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
            conditions: { messagePattern: /test/gi },
        }];
        expect(() => new EventDetector(rules)).toThrow(/global|sticky/i);
    });

    it("accepts /pattern/i", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
            conditions: { messagePattern: /test/i },
        }];
        expect(() => new EventDetector(rules)).not.toThrow();
    });

    it("accepts /pattern/ (no flags)", () => {
        const rules: DetectionRule[] = [{
            ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
            conditions: { messagePattern: /test/ },
        }];
        expect(() => new EventDetector(rules)).not.toThrow();
    });
});

// ===== F-14: errorRouting.rules whitelist =====
describe("F-14: errorRouting.rules validated by whitelist", () => {
    it("rejects invalid severity in errorRouting rule", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                errorRouting: {
                    enabled: true,
                    rules: [{ match: { severity: "MEGA" as never }, decisions: [] }],
                },
            })),
        ).toThrow(ValidationError);
    });

    it("rejects invalid destination in errorRouting rule", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                errorRouting: {
                    enabled: true,
                    rules: [{
                        match: { severity: "CRITICAL" },
                        decisions: [{ destination: "VOID" as never, action: "record", priority: 1 }],
                    }],
                },
            })),
        ).toThrow(ValidationError);
    });

    it("rejects invalid action in errorRouting rule", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                errorRouting: {
                    enabled: true,
                    rules: [{
                        match: { severity: "CRITICAL" },
                        decisions: [{ destination: "log", action: "DESTROY" as never, priority: 1 }],
                    }],
                },
            })),
        ).toThrow(ValidationError);
    });

    it("accepts valid errorRouting rules", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                errorRouting: {
                    enabled: true,
                    rules: [{
                        match: { severity: "CRITICAL" },
                        decisions: [{ destination: "audit_sink", action: "record", priority: 1 }],
                    }],
                },
            })),
        ).not.toThrow();
    });

    it("skips validation when errorRouting not set", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
            })),
        ).not.toThrow();
    });
});

// ===== F-15: detectionRules.conditions validation =====
describe("F-15: detectionRules.conditions.logTypes/origin validated", () => {
    it("rejects invalid logType in conditions", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                detectionRules: [{
                    ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
                    conditions: { logTypes: ["INVALID_TYPE"] },
                }],
            })),
        ).toThrow(ValidationError);
    });

    it("rejects partially invalid logTypes", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                detectionRules: [{
                    ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
                    conditions: { logTypes: ["SECURITY", "FAKE"] },
                }],
            })),
        ).toThrow(ValidationError);
    });

    it("rejects invalid origin in conditions", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                detectionRules: [{
                    ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
                    conditions: { origin: "HACKER" },
                }],
            })),
        ).toThrow(ValidationError);
    });

    it("accepts valid logTypes", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                detectionRules: [{
                    ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
                    conditions: { logTypes: ["SECURITY", "COMPLIANCE"] },
                }],
            })),
        ).not.toThrow();
    });

    it("accepts valid origin", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                detectionRules: [{
                    ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
                    conditions: { origin: "SYSTEM" },
                }],
            })),
        ).not.toThrow();
    });

    it("skips when conditions has no logTypes/origin", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                detectionRules: [{
                    ruleId: "r1", eventName: "SECURITY_INTRUSION_DETECTED", priority: "HIGH",
                    conditions: { minLevel: 5 },
                }],
            })),
        ).not.toThrow();
    });
});
