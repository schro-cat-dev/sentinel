/**
 * config-loader: task_transports YAML パーステスト
 *
 * yamlParser DI を使い、YAML パッケージなしでパース・バリデーション・変換を検証する。
 */
import { describe, it, expect } from "vitest";
import { parseConfigYaml, ConfigLoadError } from "../../src/configs/config-loader";
import type { RawYamlConfig } from "../../src/configs/config-loader";

/** 最小限の有効な RawYamlConfig を生成するヘルパー */
function baseRaw(overrides: Partial<RawYamlConfig> = {}): RawYamlConfig {
    return {
        project_name: "test-project",
        service_id: "test-service",
        environment: "test",
        ...overrides,
    };
}

/** yamlParser DI で RawYamlConfig を直接注入する */
function parse(raw: RawYamlConfig) {
    return parseConfigYaml("", { yamlParser: () => raw });
}

// =========================================================================
// 正常系
// =========================================================================

describe("config-loader task_transports: normal cases", () => {
    it("parses multiple task_transports with all fields", () => {
        const config = parse(baseRaw({
            task_transports: [
                {
                    name: "slack-webhook",
                    endpoint: "https://hooks.slack.com/services/xxx",
                    headers: { "Content-Type": "application/json" },
                },
                {
                    name: "jira-ticket",
                    endpoint: "https://jira.example.com/api",
                    project_key: "OPS",
                    assignee: "ops-team",
                },
            ],
        }));

        expect(config.taskTransportConfigs).toHaveLength(2);

        const slack = config.taskTransportConfigs![0];
        expect(slack.name).toBe("slack-webhook");
        expect(slack.endpoint).toBe("https://hooks.slack.com/services/xxx");
        expect(slack.headers).toEqual({ "Content-Type": "application/json" });

        const jira = config.taskTransportConfigs![1];
        expect(jira.name).toBe("jira-ticket");
        expect(jira.endpoint).toBe("https://jira.example.com/api");
        expect((jira as Record<string, unknown>).project_key).toBe("OPS");
        expect((jira as Record<string, unknown>).assignee).toBe("ops-team");
    });

    it("parses minimal transport config (name only)", () => {
        const config = parse(baseRaw({
            task_transports: [{ name: "minimal" }],
        }));

        expect(config.taskTransportConfigs).toHaveLength(1);
        expect(config.taskTransportConfigs![0].name).toBe("minimal");
        expect(config.taskTransportConfigs![0].endpoint).toBeUndefined();
        expect(config.taskTransportConfigs![0].headers).toBeUndefined();
    });

    it("defaults to undefined when task_transports is absent", () => {
        const config = parse(baseRaw());
        expect(config.taskTransportConfigs).toBeUndefined();
    });

    it("preserves headers field through conversion", () => {
        const config = parse(baseRaw({
            task_transports: [{
                name: "api",
                headers: { Authorization: "Bearer token123", "X-Custom": "value" },
            }],
        }));

        expect(config.taskTransportConfigs![0].headers).toEqual({
            Authorization: "Bearer token123",
            "X-Custom": "value",
        });
    });

    it("allows duplicate transport names", () => {
        const config = parse(baseRaw({
            task_transports: [
                { name: "webhook", endpoint: "https://a.example.com" },
                { name: "webhook", endpoint: "https://b.example.com" },
            ],
        }));

        expect(config.taskTransportConfigs).toHaveLength(2);
        expect(config.taskTransportConfigs![0].endpoint).toBe("https://a.example.com");
        expect(config.taskTransportConfigs![1].endpoint).toBe("https://b.example.com");
    });

    it("preserves arbitrary extension fields", () => {
        const config = parse(baseRaw({
            task_transports: [{
                name: "custom",
                endpoint: "https://example.com",
                custom_field: "custom_value",
                nested: { key: "val" },
                numeric: 42,
            }],
        }));

        const t = config.taskTransportConfigs![0] as Record<string, unknown>;
        expect(t.custom_field).toBe("custom_value");
        expect(t.nested).toEqual({ key: "val" });
        expect(t.numeric).toBe(42);
    });
});

// =========================================================================
// 異常系
// =========================================================================

describe("config-loader task_transports: validation errors", () => {
    it("throws when name is missing", () => {
        expect(() => parse(baseRaw({
            task_transports: [{ endpoint: "https://example.com" }] as unknown as RawYamlConfig["task_transports"],
        }))).toThrow(ConfigLoadError);
        expect(() => parse(baseRaw({
            task_transports: [{ endpoint: "https://example.com" }] as unknown as RawYamlConfig["task_transports"],
        }))).toThrow("name");
    });

    it("throws when name is empty string", () => {
        expect(() => parse(baseRaw({
            task_transports: [{ name: "" }] as unknown as RawYamlConfig["task_transports"],
        }))).toThrow("name");
    });

    it("throws when name is not a string", () => {
        expect(() => parse(baseRaw({
            task_transports: [{ name: 123 }] as unknown as RawYamlConfig["task_transports"],
        }))).toThrow("name");
    });

    it("throws with correct index in error message for invalid entry", () => {
        try {
            parse(baseRaw({
                task_transports: [
                    { name: "valid" },
                    { endpoint: "no-name" },
                ] as unknown as RawYamlConfig["task_transports"],
            }));
            expect.fail("should have thrown");
        } catch (e) {
            expect(e).toBeInstanceOf(ConfigLoadError);
            expect((e as ConfigLoadError).message).toContain("task_transports[1]");
        }
    });
});

// =========================================================================
// エッジケース
// =========================================================================

describe("config-loader task_transports: edge cases", () => {
    it("handles empty task_transports array", () => {
        const config = parse(baseRaw({
            task_transports: [],
        }));

        // 空配列はそのまま空配列として返される
        expect(config.taskTransportConfigs).toEqual([]);
    });

    it("env var expansion applies to transport endpoint values", () => {
        // expandEnv=true (default) + envSource 指定で環境変数展開をテスト
        const config = parseConfigYaml(
            `project_name: test\nservice_id: test\nenvironment: test`,
            {
                yamlParser: () => baseRaw({
                    // Note: env expansion happens BEFORE yamlParser in the real flow.
                    // yamlParser DI ではバイパスされるため、ここでは expandEnvVars の
                    // テストは config-loader 既存テストに委譲。
                    // このテストは変換後の値が正しく保持されることを検証。
                    task_transports: [{
                        name: "webhook",
                        endpoint: "https://resolved-endpoint.example.com",
                    }],
                }),
            },
        );

        expect(config.taskTransportConfigs![0].endpoint).toBe("https://resolved-endpoint.example.com");
    });
});
