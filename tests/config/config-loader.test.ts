/**
 * Config Loader Tests — YAML → SentinelConfig
 *
 * 正常系・異常系・ペネトレーション・設定反映を網羅。
 * ファイルI/O不要の parseConfigYaml() でテスト可能。
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
    parseConfigYaml,
    loadConfigFromYaml,
    ConfigLoadError,
} from "../../src/configs/config-loader";
import { Sentinel } from "../../src/index";

// =========================================================================
// Helper
// =========================================================================

const MINIMAL_YAML = `
project_name: test-project
service_id: test-service
`;

const FULL_YAML = `
project_name: my-project
service_id: my-service
environment: production

masking:
  enabled: true
  rules:
    - type: PII_TYPE
      category: EMAIL
    - type: PII_TYPE
      category: CREDIT_CARD
    - type: PII_TYPE
      category: PHONE
    - type: REGEX
      pattern: "secret_[a-z]+"
      replacement: "[REDACTED]"
      description: "mask secrets"
    - type: KEY_MATCH
      sensitive_keys:
        - password
        - api_key
  preserve_fields:
    - traceId
    - spanId

security:
  enable_hash_chain: true
  signing_key_id: key-001

task_rules:
  - rule_id: crit-notify
    event_name: SYSTEM_CRITICAL_FAILURE
    severity: CRITICAL
    action_type: SYSTEM_NOTIFICATION
    execution_level: AUTO
    priority: 1
    description: "Notify on critical failure"
    guardrails:
      require_human_approval: false
      timeout_ms: 30000
      max_retries: 3

detection_rules:
  - rule_id: custom-detect-1
    event_name: SYSTEM_CRITICAL_FAILURE
    priority: HIGH
    conditions:
      log_types:
        - SYSTEM
        - INFRA
      min_level: 5
      message_pattern: "fatal|panic"
      is_critical: true

whitelist:
  level: strict
  enabled_domains:
    - security
    - task
`;

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// =========================================================================
// 正常系
// =========================================================================
describe("parseConfigYaml — normal cases", () => {
    it("parses minimal config with defaults", () => {
        const config = parseConfigYaml(MINIMAL_YAML);
        expect(config.projectName).toBe("test-project");
        expect(config.serviceId).toBe("test-service");
        expect(config.environment).toBe("development");
        expect(config.masking.enabled).toBe(false);
        expect(config.security.enableHashChain).toBe(true);
        expect(config.taskRules).toEqual([]);
    });

    it("parses full config with all fields", () => {
        const config = parseConfigYaml(FULL_YAML);
        expect(config.projectName).toBe("my-project");
        expect(config.serviceId).toBe("my-service");
        expect(config.environment).toBe("production");
        expect(config.masking.enabled).toBe(true);
        expect(config.masking.rules).toHaveLength(5);
        expect(config.masking.preserveFields).toEqual(["traceId", "spanId"]);
        expect(config.security.enableHashChain).toBe(true);
        expect(config.security.signingKeyId).toBe("key-001");
        expect(config.taskRules).toHaveLength(1);
        expect(config.taskRules[0].ruleId).toBe("crit-notify");
        expect(config.taskRules[0].guardrails.timeoutMs).toBe(30000);
        expect(config.detectionRules).toHaveLength(1);
        expect(config.detectionRules![0].conditions.minLevel).toBe(5);
        expect(config.whitelist?.level).toBe("strict");
    });

    it("all 5 environments accepted", () => {
        for (const env of ["production", "staging", "development", "local", "test"]) {
            const yaml = `project_name: p\nservice_id: s\nenvironment: ${env}`;
            const config = parseConfigYaml(yaml);
            expect(config.environment).toBe(env);
        }
    });

    it("all 8 PII categories accepted", () => {
        const categories = [
            "CREDIT_CARD", "PHONE", "EMAIL", "GOVERNMENT_ID",
            "JAPAN_ACCOUNT", "POSTAL_CODE", "DRIVER_LICENSE", "HEALTH_INSURANCE",
        ];
        for (const cat of categories) {
            const yaml = `project_name: p\nservice_id: s\nmasking:\n  rules:\n    - type: PII_TYPE\n      category: ${cat}`;
            const config = parseConfigYaml(yaml);
            expect(config.masking.rules).toHaveLength(1);
        }
    });

    it("REGEX masking rule creates RegExp", () => {
        const yaml = `
project_name: p
service_id: s
masking:
  rules:
    - type: REGEX
      pattern: "test_\\\\d+"
      replacement: "[REDACTED]"
      description: "test pattern"
`;
        const config = parseConfigYaml(yaml);
        const rule = config.masking.rules[0];
        expect(rule.type).toBe("REGEX");
        if (rule.type === "REGEX") {
            expect(rule.pattern).toBeInstanceOf(RegExp);
        }
    });

    it("KEY_MATCH masking rule preserves sensitive keys", () => {
        const yaml = `
project_name: p
service_id: s
masking:
  rules:
    - type: KEY_MATCH
      sensitive_keys:
        - password
        - api_key
`;
        const config = parseConfigYaml(yaml);
        const rule = config.masking.rules[0];
        expect(rule.type).toBe("KEY_MATCH");
        if (rule.type === "KEY_MATCH") {
            expect(rule.sensitiveKeys).toEqual(["password", "api_key"]);
        }
    });
});

// =========================================================================
// 環境変数展開
// =========================================================================
describe("parseConfigYaml — environment variable expansion", () => {
    it("expands ${VAR_NAME} from envSource", () => {
        const yaml = `
project_name: \${MY_PROJECT}
service_id: \${MY_SERVICE}
`;
        const config = parseConfigYaml(yaml, {
            envSource: { MY_PROJECT: "env-project", MY_SERVICE: "env-service" },
        });
        expect(config.projectName).toBe("env-project");
        expect(config.serviceId).toBe("env-service");
    });

    it("expands ${VAR:-default} when var is not set", () => {
        const yaml = `
project_name: \${MISSING_VAR:-fallback-project}
service_id: \${MISSING_SVC:-fallback-svc}
`;
        const config = parseConfigYaml(yaml, { envSource: {} });
        expect(config.projectName).toBe("fallback-project");
        expect(config.serviceId).toBe("fallback-svc");
    });

    it("prefers env var over default value", () => {
        const yaml = `
project_name: \${MY_PROJECT:-default}
service_id: svc
`;
        const config = parseConfigYaml(yaml, {
            envSource: { MY_PROJECT: "from-env" },
        });
        expect(config.projectName).toBe("from-env");
    });

    it("expandEnv=false disables expansion", () => {
        const yaml = `
project_name: "\${MY_PROJECT}"
service_id: svc
`;
        const config = parseConfigYaml(yaml, {
            expandEnv: false,
            envSource: { MY_PROJECT: "from-env" },
        });
        expect(config.projectName).toBe("${MY_PROJECT}");
    });

    it("unset var without default expands to empty string", () => {
        const yaml = `
project_name: prefix-\${MISSING}-suffix
service_id: svc
`;
        const config = parseConfigYaml(yaml, { envSource: {} });
        expect(config.projectName).toBe("prefix--suffix");
    });
});

// =========================================================================
// 異常系（バリデーションエラー）
// =========================================================================
describe("parseConfigYaml — validation errors", () => {
    it("throws on missing project_name", () => {
        expect(() => parseConfigYaml("service_id: s")).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml("service_id: s")).toThrow("project_name");
    });

    it("throws on missing service_id", () => {
        expect(() => parseConfigYaml("project_name: p")).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml("project_name: p")).toThrow("service_id");
    });

    it("throws on invalid environment", () => {
        const yaml = "project_name: p\nservice_id: s\nenvironment: invalid";
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("environment");
    });

    it("throws on invalid masking rule type", () => {
        const yaml = `
project_name: p
service_id: s
masking:
  rules:
    - type: INVALID_TYPE
`;
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("masking.rules[0].type");
    });

    it("throws on PII_TYPE with invalid category", () => {
        const yaml = `
project_name: p
service_id: s
masking:
  rules:
    - type: PII_TYPE
      category: INVALID_CAT
`;
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("category");
    });

    it("throws on REGEX without pattern", () => {
        const yaml = `
project_name: p
service_id: s
masking:
  rules:
    - type: REGEX
      replacement: "[X]"
`;
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("pattern");
    });

    it("throws on KEY_MATCH without sensitive_keys", () => {
        const yaml = `
project_name: p
service_id: s
masking:
  rules:
    - type: KEY_MATCH
`;
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("sensitive_keys");
    });

    it("throws on invalid whitelist level", () => {
        const yaml = `
project_name: p
service_id: s
whitelist:
  level: ultra_strict
`;
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("whitelist.level");
    });

    it("throws on task rule without rule_id", () => {
        const yaml = `
project_name: p
service_id: s
task_rules:
  - event_name: SYSTEM_CRITICAL_FAILURE
    action_type: SYSTEM_NOTIFICATION
    severity: HIGH
    execution_level: AUTO
    priority: 1
`;
        expect(() => parseConfigYaml(yaml)).toThrow(ConfigLoadError);
        expect(() => parseConfigYaml(yaml)).toThrow("rule_id");
    });

    it("throws on invalid YAML syntax", () => {
        expect(() => parseConfigYaml("{{invalid: yaml::")).toThrow();
    });
});

// =========================================================================
// ファイルI/O (loadConfigFromYaml)
// =========================================================================
describe("loadConfigFromYaml — file loading", () => {
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = mkdtempSync(join(tmpdir(), "sentinel-config-test-"));
    });
    afterEach(() => {
        rmSync(tmpDir, { recursive: true, force: true });
    });

    it("loads config from a YAML file", () => {
        const filePath = join(tmpDir, "sentinel.yaml");
        writeFileSync(filePath, MINIMAL_YAML);
        const config = loadConfigFromYaml(filePath);
        expect(config.projectName).toBe("test-project");
    });

    it("throws on non-existent file", () => {
        expect(() => loadConfigFromYaml("/nonexistent/path.yaml")).toThrow();
    });

    it("expands env vars from file content", () => {
        const filePath = join(tmpDir, "sentinel.yaml");
        writeFileSync(filePath, `
project_name: \${TEST_PROJECT_NAME:-file-default}
service_id: file-svc
`);
        const config = loadConfigFromYaml(filePath, {
            envSource: { TEST_PROJECT_NAME: "from-env" },
        });
        expect(config.projectName).toBe("from-env");
    });
});

// =========================================================================
// ペネトレーションテスト（YAMLインジェクション）
// =========================================================================
describe("parseConfigYaml — injection/security", () => {
    it("env var expansion does not execute commands $()", () => {
        const yaml = `
project_name: "\$(rm -rf /)"
service_id: svc
`;
        // $(command) is NOT a valid env var pattern, should be kept as literal
        const config = parseConfigYaml(yaml, { envSource: {} });
        expect(config.projectName).toBe("$(rm -rf /)");
    });

    it("env var expansion does not support nested ${${VAR}}", () => {
        const yaml = `
project_name: "\${\${INNER}}"
service_id: svc
`;
        // Should not recursively expand
        const config = parseConfigYaml(yaml, {
            envSource: { INNER: "nested", nested: "evil" },
        });
        // The outer ${...} won't match valid var name pattern
        expect(config.projectName).not.toBe("evil");
    });

    it("prototype pollution via __proto__ in YAML is not injected", () => {
        const yaml = `
project_name: p
service_id: s
__proto__:
  polluted: true
`;
        const before = Object.keys(Object.prototype);
        parseConfigYaml(yaml);
        const after = Object.keys(Object.prototype);
        expect(after).toEqual(before);
    });

    it("constructor pollution via YAML is safe", () => {
        const yaml = `
project_name: p
service_id: s
constructor:
  prototype:
    polluted: true
`;
        const config = parseConfigYaml(yaml);
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
        expect(config.projectName).toBe("p");
    });

    it("extremely long project_name does not crash", () => {
        const longName = "a".repeat(100000);
        const yaml = `project_name: "${longName}"\nservice_id: s`;
        const config = parseConfigYaml(yaml);
        expect(config.projectName).toBe(longName);
    });

    it("null bytes in YAML values are preserved (not executed)", () => {
        const yaml = `
project_name: "test\\x00hidden"
service_id: svc
`;
        // YAML parser handles escape sequences
        const config = parseConfigYaml(yaml);
        expect(typeof config.projectName).toBe("string");
    });

    it("SQL injection in project_name is treated as plain string", () => {
        const yaml = `
project_name: "'; DROP TABLE logs; --"
service_id: svc
`;
        const config = parseConfigYaml(yaml);
        expect(config.projectName).toBe("'; DROP TABLE logs; --");
    });

    it("YAML anchor/alias abuse does not cause issues", () => {
        const yaml = `
project_name: &anchor p
service_id: *anchor
`;
        const config = parseConfigYaml(yaml);
        expect(config.projectName).toBe("p");
        expect(config.serviceId).toBe("p");
    });
});

// =========================================================================
// 設定反映テスト（YAML → Sentinel.initialize → 動作確認）
// =========================================================================
describe("Config reflection — YAML config drives pipeline behavior", () => {
    it("masking.enabled=true masks PII in pipeline", async () => {
        const yaml = `
project_name: reflect-test
service_id: reflect-svc
environment: test
masking:
  enabled: true
  rules:
    - type: PII_TYPE
      category: EMAIL
`;
        const config = parseConfigYaml(yaml);
        const sentinel = Sentinel.initialize(config);
        let processedLog: Record<string, unknown> | null = null;
        sentinel.updateCallbacks({
            onLogProcessed: (log) => { processedLog = log as unknown as Record<string, unknown>; },
        });

        await sentinel.ingest({ message: "contact user@example.com for info" });
        expect(processedLog).not.toBeNull();
        expect(String(processedLog!.message)).not.toContain("user@example.com");
        expect(String(processedLog!.message)).toContain("[MASKED_EMAIL]");
    });

    it("masking.enabled=false does NOT mask PII", async () => {
        const yaml = `
project_name: reflect-test
service_id: reflect-svc
environment: test
masking:
  enabled: false
`;
        const config = parseConfigYaml(yaml);
        const sentinel = Sentinel.initialize(config);
        let processedLog: Record<string, unknown> | null = null;
        sentinel.updateCallbacks({
            onLogProcessed: (log) => { processedLog = log as unknown as Record<string, unknown>; },
        });

        await sentinel.ingest({ message: "contact user@example.com" });
        expect(String(processedLog!.message)).toContain("user@example.com");
    });

    it("security.enable_hash_chain=true generates hash chain", async () => {
        const yaml = `
project_name: hash-test
service_id: hash-svc
environment: test
security:
  enable_hash_chain: true
`;
        const config = parseConfigYaml(yaml);
        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({ message: "hash test", level: 3 });
        expect(result.hashChainValid).toBe(true);
    });

    it("task_rules generate tasks when events match", async () => {
        const yaml = `
project_name: task-test
service_id: task-svc
environment: test
security:
  enable_hash_chain: false
task_rules:
  - rule_id: test-rule
    event_name: SYSTEM_CRITICAL_FAILURE
    severity: CRITICAL
    action_type: SYSTEM_NOTIFICATION
    execution_level: AUTO
    priority: 1
    description: "Test rule"
    guardrails:
      require_human_approval: false
      timeout_ms: 30000
      max_retries: 3
`;
        const config = parseConfigYaml(yaml);
        const sentinel = Sentinel.initialize(config);
        const result = await sentinel.ingest({
            message: "critical failure",
            isCritical: true,
            level: 6,
        });
        expect(result.tasksGenerated.length).toBeGreaterThan(0);
        expect(result.tasksGenerated[0].ruleId).toBe("test-rule");
    });

    it("detection_rules with conditions filter correctly", async () => {
        const yaml = `
project_name: detect-test
service_id: detect-svc
environment: test
security:
  enable_hash_chain: false
detection_rules:
  - rule_id: custom-1
    event_name: SYSTEM_CRITICAL_FAILURE
    priority: HIGH
    conditions:
      min_level: 5
      is_critical: true
task_rules:
  - rule_id: task-1
    event_name: SYSTEM_CRITICAL_FAILURE
    severity: CRITICAL
    action_type: SYSTEM_NOTIFICATION
    execution_level: AUTO
    priority: 1
    description: "Test"
    guardrails:
      require_human_approval: false
      timeout_ms: 30000
      max_retries: 3
`;
        const config = parseConfigYaml(yaml);
        const sentinel = Sentinel.initialize(config);

        // level 3, not critical → should NOT match custom rule
        const r1 = await sentinel.ingest({ message: "low level", level: 3 });
        expect(r1.detection).toBeNull();

        // level 6, critical → should match
        Sentinel.reset();
        const sentinel2 = Sentinel.initialize(config);
        const r2 = await sentinel2.ingest({
            message: "high level critical",
            level: 6,
            isCritical: true,
        });
        expect(r2.detection).not.toBeNull();
    });

    it("whitelist.level=strict is reflected in config", () => {
        const yaml = `
project_name: wl-test
service_id: wl-svc
environment: test
whitelist:
  level: strict
  enabled_domains:
    - security
    - task
`;
        const config = parseConfigYaml(yaml);
        expect(config.whitelist?.level).toBe("strict");
        expect(config.whitelist?.enabledDomains).toEqual(["security", "task"]);
    });

    it("multiple masking rules (PII + REGEX + KEY_MATCH) work together", async () => {
        const yaml = `
project_name: combo-test
service_id: combo-svc
environment: test
masking:
  enabled: true
  rules:
    - type: PII_TYPE
      category: EMAIL
    - type: REGEX
      pattern: "secret_[a-z]+"
      replacement: "[REDACTED]"
      description: "mask secrets"
    - type: KEY_MATCH
      sensitive_keys:
        - password
`;
        const config = parseConfigYaml(yaml);
        const sentinel = Sentinel.initialize(config);
        let processedLog: Record<string, unknown> | null = null;
        sentinel.updateCallbacks({
            onLogProcessed: (log) => { processedLog = log as unknown as Record<string, unknown>; },
        });

        await sentinel.ingest({ message: "email user@test.com secret_abc" });
        const msg = String(processedLog!.message);
        expect(msg).not.toContain("user@test.com");
        expect(msg).toContain("[MASKED_EMAIL]");
        expect(msg).not.toContain("secret_abc");
        expect(msg).toContain("[REDACTED]");
    });
});
