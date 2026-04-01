/**
 * Configuration Matrix Tests
 *
 * 全設定パターンの正常系・異常系・エッジケースを網羅的にテスト。
 * createDefaultConfig の deep-merge 挙動、各設定フィールドのパイプラインへの反映を検証。
 */
import { describe, it, expect } from "vitest";
import { createDefaultConfig } from "../../src/configs/sentinel-config";
import type { SentinelConfig } from "../../src/configs/sentinel-config";

describe("createDefaultConfig", () => {
    describe("required fields", () => {
        it("requires projectName and serviceId", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.projectName).toBe("p");
            expect(config.serviceId).toBe("s");
        });
    });

    describe("defaults", () => {
        it("defaults environment to development", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.environment).toBe("development");
        });

        it("defaults masking.enabled to false", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.masking.enabled).toBe(false);
        });

        it("defaults masking.rules to empty array", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.masking.rules).toEqual([]);
        });

        it("defaults masking.preserveFields to traceId and spanId", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.masking.preserveFields).toEqual(["traceId", "spanId"]);
        });

        it("defaults security.enableHashChain to true", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.security.enableHashChain).toBe(true);
        });

        it("defaults taskRules to empty array", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.taskRules).toEqual([]);
        });

        it("defaults callbacks to undefined", () => {
            const config = createDefaultConfig({ projectName: "p", serviceId: "s" });
            expect(config.onLogProcessed).toBeUndefined();
            expect(config.onTaskGenerated).toBeUndefined();
            expect(config.onTaskDispatched).toBeUndefined();
            expect(config.onError).toBeUndefined();
            expect(config.logger).toBeUndefined();
        });
    });

    describe("deep-merge: masking", () => {
        it("preserves default preserveFields when only enabled is overridden", () => {
            const config = createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                masking: { enabled: true },
            } as Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">);
            expect(config.masking.enabled).toBe(true);
            expect(config.masking.preserveFields).toEqual(["traceId", "spanId"]);
            expect(config.masking.rules).toEqual([]);
        });

        it("allows overriding preserveFields while keeping enabled default", () => {
            const config = createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                masking: { preserveFields: ["custom"] },
            } as Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">);
            expect(config.masking.enabled).toBe(false);
            expect(config.masking.preserveFields).toEqual(["custom"]);
        });

        it("overrides rules without affecting preserveFields", () => {
            const config = createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                masking: {
                    enabled: true,
                    rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                },
            } as Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">);
            expect(config.masking.rules).toHaveLength(1);
            expect(config.masking.preserveFields).toEqual(["traceId", "spanId"]);
        });
    });

    describe("deep-merge: security", () => {
        it("preserves enableHashChain when only signingKeyId is set", () => {
            const config = createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                security: { signingKeyId: "key-1" },
            } as Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">);
            expect(config.security.enableHashChain).toBe(true);
            expect(config.security.signingKeyId).toBe("key-1");
        });

        it("allows disabling hash chain explicitly", () => {
            const config = createDefaultConfig({
                projectName: "p",
                serviceId: "s",
                security: { enableHashChain: false },
            } as Partial<SentinelConfig> & Pick<SentinelConfig, "projectName" | "serviceId">);
            expect(config.security.enableHashChain).toBe(false);
        });
    });

    describe("environment variants", () => {
        const envs = ["production", "staging", "development", "local", "test"] as const;
        for (const env of envs) {
            it(`accepts environment: "${env}"`, () => {
                const config = createDefaultConfig({
                    projectName: "p", serviceId: "s", environment: env,
                });
                expect(config.environment).toBe(env);
            });
        }
    });
});
