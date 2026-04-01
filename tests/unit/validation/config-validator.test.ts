/**
 * Config Validator Tests
 *
 * SentinelConfig のホワイトリスト検証テスト。
 * 正常系・異常系・設定変更動作テスト・パイプライン統合。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { validateConfigWhitelists } from "../../../src/validation/config-validator";
import { createTestTaskRule } from "../../helpers/fixtures";

const baseConfig = () =>
    createDefaultConfig({
        projectName: "test",
        serviceId: "test-svc",
        security: { enableHashChain: false },
    });

// ===== 正常系 =====
describe("Config Validator: normal cases", () => {
    it("valid config with no rules passes", () => {
        expect(() => validateConfigWhitelists(baseConfig())).not.toThrow();
    });

    it("valid config with all rule types passes", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            security: { enableHashChain: false },
            detectionRules: [{
                ruleId: "r1",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: { minLevel: 5 },
            }],
            taskRules: [createTestTaskRule({
                eventName: "SECURITY_INTRUSION_DETECTED",
                actionType: "SYSTEM_NOTIFICATION",
                severity: "HIGH",
                executionLevel: "AUTO",
            })],
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: [],
            },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("config with user extensions allows custom values", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "CUSTOM_EVENT" as never,
                actionType: "CUSTOM_ACTION" as never,
            })],
            whitelist: {
                extensions: {
                    eventName: ["CUSTOM_EVENT"],
                    actionType: ["CUSTOM_ACTION"],
                },
            },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });
});

// ===== 異常系: 各フィールドの不正値 =====
describe("Config Validator: invalid values", () => {
    it("rejects invalid eventName in taskRules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ eventName: "TYPO_EVENT" as never })],
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("eventName");
        }
    });

    it("rejects invalid severity in taskRules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ severity: "ULTRA" as never })],
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("severity");
        }
    });

    it("rejects invalid actionType in taskRules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ actionType: "INVALID_ACTION" as never })],
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("actionType");
        }
    });

    it("rejects invalid executionLevel in taskRules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ executionLevel: "FAST" as never })],
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("executionLevel");
        }
    });

    it("rejects invalid eventName in detectionRules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            detectionRules: [{
                ruleId: "r1",
                eventName: "TYPO_EVENT" as never,
                priority: "HIGH",
                conditions: {},
            }],
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("eventName");
        }
    });

    it("rejects invalid priority in detectionRules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            detectionRules: [{
                ruleId: "r1",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "ULTRA" as never,
                conditions: {},
            }],
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("detectionPriority");
        }
    });

    it("rejects invalid PII category in masking rules", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "SSN" as never }],
                preserveFields: [],
            },
        });
        try {
            validateConfigWhitelists(config);
            throw new Error("Expected ValidationError");
        } catch (err) {
            expect(err).toBeInstanceOf(ValidationError);
            expect((err as ValidationError).field).toBe("piiCategory");
        }
    });

    it("accepts all 8 valid PII categories", () => {
        const categories = [
            "CREDIT_CARD", "PHONE", "EMAIL", "GOVERNMENT_ID",
            "JAPAN_ACCOUNT", "POSTAL_CODE", "DRIVER_LICENSE", "HEALTH_INSURANCE",
        ] as const;
        for (const category of categories) {
            const config = createDefaultConfig({
                projectName: "test",
                serviceId: "test-svc",
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category }],
                    preserveFields: [],
                },
            });
            expect(() => validateConfigWhitelists(config)).not.toThrow();
        }
    });
});

// ===== 異常系: whitelist.level =====
describe("Config Validator: invalid whitelist level", () => {
    it("rejects invalid whitelist.level value", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            whitelist: {
                level: "ultra_strict" as unknown as "strict",
            },
        });
        expect(() => validateConfigWhitelists(config)).toThrow(ValidationError);
        expect(() => validateConfigWhitelists(config)).toThrow("whitelist.level");
    });
});

// ===== 設定変更動作テスト =====
describe("Config Validator: config toggle behavior", () => {
    it("disabling security domain allows invalid eventName", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ eventName: "CUSTOM_UNKNOWN" as never })],
            whitelist: {
                enabledDomains: ["task"],  // security disabled → eventName not validated
            },
        });
        // eventName comes from security domain, disabled here
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("disabling task domain allows invalid actionType", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ actionType: "CUSTOM_ACTION" as never })],
            whitelist: {
                enabledDomains: ["security", "privacy"],  // task disabled
            },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("disabling privacy domain allows invalid PII category", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "SSN" as never }],
                preserveFields: [],
            },
            whitelist: {
                enabledDomains: ["security", "task"],  // privacy disabled
            },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("empty enabledDomains disables all validation", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({
                eventName: "BAD" as never,
                actionType: "BAD" as never,
                severity: "BAD" as never,
                executionLevel: "BAD" as never,
            })],
            whitelist: { enabledDomains: [] },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("extensions override allows previously invalid value", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [createTestTaskRule({ eventName: "CUSTOM_BUSINESS_EVENT" as never })],
            whitelist: {
                extensions: { eventName: ["CUSTOM_BUSINESS_EVENT"] },
            },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("extensions do not override — they extend", () => {
        const config = createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            taskRules: [
                createTestTaskRule({ eventName: "SECURITY_INTRUSION_DETECTED" }),
                createTestTaskRule({ ruleId: "r2", eventName: "CUSTOM_EVENT" as never }),
            ],
            whitelist: {
                extensions: { eventName: ["CUSTOM_EVENT"] },
            },
        });
        // Both built-in and custom values should pass
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });
});

// ===== パイプライン統合: Sentinel.initialize() =====
describe("Config Validator: pipeline integration", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("Sentinel.initialize() rejects config with invalid taskRule", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "test",
                serviceId: "test-svc",
                taskRules: [createTestTaskRule({ actionType: "TYPO" as never })],
            })),
        ).toThrow(ValidationError);
    });

    it("Sentinel.initialize() accepts valid config", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "test",
                serviceId: "test-svc",
                security: { enableHashChain: false },
                taskRules: [createTestTaskRule()],
            })),
        ).not.toThrow();
    });

    it("onTaskAction rejects invalid actionType at runtime", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            security: { enableHashChain: false },
        }));
        expect(() =>
            sentinel.onTaskAction("INVALID_TYPE", async () => ({ status: "completed" })),
        ).toThrow(ValidationError);
    });

    it("onTaskAction accepts valid actionType", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            security: { enableHashChain: false },
        }));
        expect(() =>
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => ({ status: "completed" })),
        ).not.toThrow();
    });

    it("onTaskAction accepts custom actionType via extensions", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "test",
            serviceId: "test-svc",
            security: { enableHashChain: false },
            whitelist: {
                extensions: { actionType: ["CUSTOM_HANDLER"] },
            },
        }));
        expect(() =>
            sentinel.onTaskAction("CUSTOM_HANDLER", async () => ({ status: "completed" })),
        ).not.toThrow();
    });
});
