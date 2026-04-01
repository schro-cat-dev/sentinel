/**
 * YAML/JSON Config → Whitelist Validation Tests
 *
 * YAMLやJSONから読み込んだ設定がホワイトリスト検証を正しく通過/拒否するかテスト。
 * 設定ファイルを変えて期待通り動くことを確認する。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { validateConfigWhitelists } from "../../../src/validation/config-validator";
import type { SentinelConfig } from "../../../src/index";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

/**
 * YAML → JS Object をシミュレート。
 * 実際のYAML parserの出力と同等のplain objectを作る。
 */
function parseYamlConfig(yamlLikeObj: Record<string, unknown>): Partial<SentinelConfig> {
    return yamlLikeObj as Partial<SentinelConfig>;
}

// ===== YAML設定変更テスト =====
describe("Whitelist: YAML config simulation", () => {
    it("valid YAML config with all domains enabled (default)", () => {
        const yamlConfig = parseYamlConfig({
            projectName: "production-api",
            serviceId: "payment-service",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "alert-intrusion",
                eventName: "SECURITY_INTRUSION_DETECTED",
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
                priority: 1,
                description: "Alert on intrusion",
                executionParams: { notificationChannel: "#security" },
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
            detectionRules: [{
                ruleId: "sql-injection",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: { messagePattern: /sql.*injection/i },
            }],
        });

        const config = createDefaultConfig(yamlConfig as Parameters<typeof createDefaultConfig>[0]);
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("YAML config with typo in eventName is rejected", () => {
        const yamlConfig = parseYamlConfig({
            projectName: "production-api",
            serviceId: "payment-service",
            taskRules: [{
                ruleId: "alert",
                eventName: "SECURITY_INTRUSION_DETECTD",  // typo!
                severity: "CRITICAL",
                actionType: "SYSTEM_NOTIFICATION",
                executionLevel: "AUTO",
                priority: 1,
                description: "Alert",
                executionParams: {},
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
        });

        const config = createDefaultConfig(yamlConfig as Parameters<typeof createDefaultConfig>[0]);
        expect(() => validateConfigWhitelists(config)).toThrow(ValidationError);
    });

    it("YAML config with custom extensions passes for extended values", () => {
        const yamlConfig = parseYamlConfig({
            projectName: "custom-app",
            serviceId: "custom-svc",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "custom-rule",
                eventName: "CUSTOM_BUSINESS_EVENT",
                severity: "HIGH",
                actionType: "CUSTOM_TICKET",
                executionLevel: "MANUAL",
                priority: 2,
                description: "Custom business rule",
                executionParams: {},
                guardrails: { requireHumanApproval: true, timeoutMs: 60000, maxRetries: 1 },
            }],
            whitelist: {
                extensions: {
                    eventName: ["CUSTOM_BUSINESS_EVENT"],
                    actionType: ["CUSTOM_TICKET"],
                },
            },
        });

        const config = createDefaultConfig(yamlConfig as Parameters<typeof createDefaultConfig>[0]);
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("YAML config with specific domains enabled", () => {
        const yamlConfig = parseYamlConfig({
            projectName: "relaxed-app",
            serviceId: "dev-svc",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "rule",
                eventName: "ANYTHING_GOES",
                severity: "HIGH",
                actionType: "AI_ANALYZE",
                executionLevel: "AUTO",
                priority: 1,
                description: "test",
                executionParams: {},
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
            whitelist: {
                enabledDomains: ["task"],  // security disabled → eventName free
            },
        });

        const config = createDefaultConfig(yamlConfig as Parameters<typeof createDefaultConfig>[0]);
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("YAML config with masking PII validation", () => {
        const validConfig = parseYamlConfig({
            projectName: "pii-app",
            serviceId: "pii-svc",
            masking: {
                enabled: true,
                rules: [
                    { type: "PII_TYPE", category: "CREDIT_CARD" },
                    { type: "PII_TYPE", category: "JAPAN_ACCOUNT" },
                ],
                preserveFields: ["traceId"],
            },
        });

        const config = createDefaultConfig(validConfig as Parameters<typeof createDefaultConfig>[0]);
        expect(() => validateConfigWhitelists(config)).not.toThrow();

        // Invalid PII category
        const invalidConfig = parseYamlConfig({
            projectName: "pii-app",
            serviceId: "pii-svc",
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "SSN" }],
                preserveFields: [],
            },
        });

        const badConfig = createDefaultConfig(invalidConfig as Parameters<typeof createDefaultConfig>[0]);
        expect(() => validateConfigWhitelists(badConfig)).toThrow(ValidationError);
    });
});

// ===== 設定ファイル切替シナリオ =====
describe("Whitelist: config switching scenarios", () => {
    it("switching from strict to relaxed config", () => {
        // Strict: all domains enabled (default)
        const strictConfig = createDefaultConfig({
            projectName: "app",
            serviceId: "svc",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "r1",
                eventName: "SECURITY_INTRUSION_DETECTED",
                severity: "CRITICAL",
                actionType: "KILL_SWITCH",
                executionLevel: "AUTO",
                priority: 1,
                description: "strict",
                executionParams: {},
                guardrails: { requireHumanApproval: true, timeoutMs: 5000, maxRetries: 0 },
            }],
        });
        expect(() => Sentinel.initialize(strictConfig)).not.toThrow();

        Sentinel.reset();

        // Relaxed: only task domain, with extensions
        const relaxedConfig = createDefaultConfig({
            projectName: "app",
            serviceId: "svc",
            security: { enableHashChain: false },
            taskRules: [{
                ruleId: "r1",
                eventName: "CUSTOM_EVENT",
                severity: "HIGH",
                actionType: "CUSTOM_ACTION",
                executionLevel: "MANUAL",
                priority: 3,
                description: "relaxed",
                executionParams: {},
                guardrails: { requireHumanApproval: false, timeoutMs: 30000, maxRetries: 3 },
            }],
            whitelist: {
                enabledDomains: ["task"],
                extensions: { actionType: ["CUSTOM_ACTION"] },
            },
        });
        expect(() => Sentinel.initialize(relaxedConfig)).not.toThrow();
    });

    it("production config with full validation", () => {
        const prodConfig = createDefaultConfig({
            projectName: "prod-system",
            serviceId: "core-api",
            environment: "production",
            security: { enableHashChain: true },
            masking: {
                enabled: true,
                rules: [
                    { type: "PII_TYPE", category: "CREDIT_CARD" },
                    { type: "PII_TYPE", category: "EMAIL" },
                    { type: "PII_TYPE", category: "PHONE" },
                ],
                preserveFields: ["traceId"],
            },
            detectionRules: [
                {
                    ruleId: "brute-force",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    priority: "HIGH",
                    conditions: {
                        logTypes: ["SECURITY"],
                        messagePattern: /failed.*login/i,
                    },
                },
                {
                    ruleId: "data-exfil",
                    eventName: "COMPLIANCE_VIOLATION",
                    priority: "MEDIUM",
                    conditions: {
                        logTypes: ["BUSINESS-AUDIT"],
                        messagePattern: /bulk.*export/i,
                    },
                },
            ],
            taskRules: [
                {
                    ruleId: "intrusion-alert",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    severity: "CRITICAL",
                    actionType: "ESCALATE",
                    executionLevel: "AUTO",
                    priority: 1,
                    description: "Escalate intrusion",
                    executionParams: { notificationChannel: "#security-critical" },
                    guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 1 },
                },
                {
                    ruleId: "compliance-notify",
                    eventName: "COMPLIANCE_VIOLATION",
                    severity: "HIGH",
                    actionType: "SYSTEM_NOTIFICATION",
                    executionLevel: "SEMI_AUTO",
                    priority: 2,
                    description: "Notify compliance team",
                    executionParams: { notificationChannel: "#compliance" },
                    guardrails: { requireHumanApproval: true, timeoutMs: 30000, maxRetries: 3 },
                },
            ],
        });

        expect(() => validateConfigWhitelists(prodConfig)).not.toThrow();
        expect(() => Sentinel.initialize(prodConfig)).not.toThrow();
    });
});

// ===== ペネトレーション: 設定インジェクション =====
describe("Whitelist: config injection attacks", () => {
    it("JSON-parsed config with __proto__ in whitelist.extensions is safe", () => {
        const malicious = JSON.parse(
            '{"projectName":"p","serviceId":"s","whitelist":{"extensions":{"__proto__":["evil"]}}}',
        );
        const config = createDefaultConfig(malicious);
        expect(() => validateConfigWhitelists(config)).not.toThrow();

        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("evil");
    });

    it("JSON-parsed config with prototype pollution in enabledDomains is safe", () => {
        const malicious = JSON.parse(
            '{"projectName":"p","serviceId":"s","whitelist":{"enabledDomains":["security","__proto__"]}}',
        );
        const config = createDefaultConfig(malicious);
        // Unknown domain is filtered out, no crash
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });
});
