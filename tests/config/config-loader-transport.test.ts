/**
 * config-loader: task_transports YAML パーステスト
 */
import { describe, it, expect } from "vitest";
import { parseConfigYaml } from "../../src/configs/config-loader";

const BASE_YAML = `
project_name: test-project
service_id: test-service
environment: test
`;

describe("config-loader: task_transports", () => {
    it("parses task_transports from YAML", () => {
        const yaml = `${BASE_YAML}
task_transports:
  - name: slack-webhook
    endpoint: https://hooks.slack.com/services/xxx
  - name: jira-ticket
    endpoint: https://jira.example.com/api
    project_key: OPS
`;
        const config = parseConfigYaml(yaml, {
            yamlParser: (content) => {
                // 簡易パーサー: yamlパッケージ不要でテスト可能
                const lines = content.split("\n");
                const result: Record<string, unknown> = {};
                let currentTransport: Record<string, unknown> | null = null;
                const transports: Record<string, unknown>[] = [];

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (trimmed.startsWith("project_name:")) result.project_name = trimmed.split(": ")[1];
                    if (trimmed.startsWith("service_id:")) result.service_id = trimmed.split(": ")[1];
                    if (trimmed.startsWith("environment:")) result.environment = trimmed.split(": ")[1];
                    if (trimmed === "task_transports:") continue;
                    if (trimmed.startsWith("- name:")) {
                        if (currentTransport) transports.push(currentTransport);
                        currentTransport = { name: trimmed.replace("- name: ", "") };
                    } else if (currentTransport && trimmed.startsWith("endpoint:")) {
                        currentTransport.endpoint = trimmed.replace("endpoint: ", "");
                    } else if (currentTransport && trimmed.startsWith("project_key:")) {
                        currentTransport.project_key = trimmed.replace("project_key: ", "");
                    }
                }
                if (currentTransport) transports.push(currentTransport);
                if (transports.length > 0) result.task_transports = transports;
                return result as ReturnType<typeof parseConfigYaml extends (y: string, o: unknown) => infer R ? never : never> & Record<string, unknown>;
            },
        });

        expect(config.taskTransportConfigs).toHaveLength(2);
        expect(config.taskTransportConfigs![0].name).toBe("slack-webhook");
        expect(config.taskTransportConfigs![0].endpoint).toBe("https://hooks.slack.com/services/xxx");
        expect(config.taskTransportConfigs![1].name).toBe("jira-ticket");
        expect(config.taskTransportConfigs![1].endpoint).toBe("https://jira.example.com/api");
        expect((config.taskTransportConfigs![1] as Record<string, unknown>).project_key).toBe("OPS");
    });

    it("defaults to undefined when task_transports is absent", () => {
        const config = parseConfigYaml(BASE_YAML, {
            yamlParser: () => ({
                project_name: "test-project",
                service_id: "test-service",
                environment: "test",
            }),
        });

        expect(config.taskTransportConfigs).toBeUndefined();
    });

    it("validates task_transport name is required", () => {
        expect(() => {
            parseConfigYaml("", {
                yamlParser: () => ({
                    project_name: "test-project",
                    service_id: "test-service",
                    task_transports: [{ endpoint: "https://example.com" }] as unknown[],
                }),
            });
        }).toThrow("name");
    });
});
