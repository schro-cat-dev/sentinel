/**
 * Config Edge Cases & Error Path Tests
 *
 * 設定内容を変えた場合に設定通りに動くかの正常系・異常系・エッジケース。
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig, parseConfigYaml } from "../../src/index";
import type { RemoteTransport } from "../../src/transport/transport";
import type { ServerManagementTransport } from "../../src/transport/server-management-transport";
import type { IngestionResult } from "../../src/core/engine/types";
import type { Log } from "../../src/types/log";

afterEach(() => Sentinel.reset());

// =========================================================================
// 正常系: 設定通りに動くか
// =========================================================================

describe("Config: 正常系 — 設定値がパイプラインに反映される", () => {
    it("enableHashChain=true: hash が計算される", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true },
        }));
        const result = await sentinel.ingest({ message: "hash test" });
        expect(result.hashChainValid).toBe(true);
    });

    it("enableHashChain=false: hash が計算されない", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));
        const result = await sentinel.ingest({ message: "no hash" });
        expect(result.hashChainValid).toBe(false);
    });

    it("masking.enabled=true: PII がマスクされる", async () => {
        let processedLog: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: true, rules: [{ type: "PII_TYPE", category: "EMAIL" }], preserveFields: [] },
            onLogProcessed: (log) => { processedLog = log; },
        }));
        await sentinel.ingest({ message: "contact user@example.com" });
        expect(processedLog!.message).not.toContain("user@example.com");
    });

    it("masking.enabled=false: PII がそのまま", async () => {
        let processedLog: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: false, rules: [], preserveFields: [] },
            onLogProcessed: (log) => { processedLog = log; },
        }));
        await sentinel.ingest({ message: "contact user@example.com" });
        expect(processedLog!.message).toContain("user@example.com");
    });

    it("hmacKey 設定時: HMAC ハッシュが生成される", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true, hmacKey: "test-hmac-key-32-bytes-long!!!!!" },
        }));
        const result = await sentinel.ingest({ message: "hmac" });
        expect(result.hashChainValid).toBe(true);
    });

    it("projectName がログに含まれる", async () => {
        let processedLog: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "my-project", serviceId: "my-svc",
            onLogProcessed: (log) => { processedLog = log; },
        }));
        await sentinel.ingest({ message: "project test" });
        expect(processedLog!.projectName).toBe("my-project");
        expect(processedLog!.serviceId).toBe("my-svc");
    });

    it("environment が config に保持される", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            environment: "production",
        }));
        expect(sentinel.getConfig().environment).toBe("production");
    });
});

// =========================================================================
// 異常系: 不正な設定・状態での動作
// =========================================================================

describe("Config: 異常系 — 不正操作でエラーになる", () => {
    it("shutdown 後の ingest でエラー", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
        }));
        await sentinel.shutdown();
        await expect(sentinel.ingest({ message: "after shutdown" })).rejects.toThrow("shutdown");
    });

    it("shutdown 後の onTaskAction でエラー", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
        }));
        await sentinel.shutdown();
        expect(() => sentinel.onTaskAction("TEST", vi.fn())).toThrow("shutdown");
    });

    it("shutdown 後の approveTask でエラー", async () => {
        const mgmt: ServerManagementTransport = {
            approveTask: vi.fn(), rejectTask: vi.fn(), getTaskStatus: vi.fn(),
            listTasks: vi.fn(), listPendingBlocks: vi.fn(), approveBlock: vi.fn(), rejectBlock: vi.fn(),
        };
        const sentinel = Sentinel.initialize(
            createDefaultConfig({ projectName: "p", serviceId: "s", integration: { taskApprovalEnabled: true } }),
            { management: mgmt },
        );
        await sentinel.shutdown();
        await expect(sentinel.approveTask("t", "a", "r")).rejects.toThrow("shutdown");
    });

    it("management なしで approveTask はエラー", async () => {
        const sentinel = Sentinel.initialize(
            createDefaultConfig({ projectName: "p", serviceId: "s", integration: { taskApprovalEnabled: true } }),
        );
        await expect(sentinel.approveTask("t", "a", "r")).rejects.toThrow("ServerManagementTransport");
    });

    it("integration 未設定で management API はエラー", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({ projectName: "p", serviceId: "s" }));
        await expect(sentinel.approveTask("t", "a", "r")).rejects.toThrow("not enabled");
        await expect(sentinel.getTaskStatus("t")).rejects.toThrow("not enabled");
    });
});

// =========================================================================
// エッジケース
// =========================================================================

describe("Config: エッジケース", () => {
    it("空の taskRules でもパイプラインは動く", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s", taskRules: [],
        }));
        const result = await sentinel.ingest({ message: "no rules" });
        expect(result.tasksGenerated).toEqual([]);
    });

    it("空の masking.rules でマスキング有効 → マスクされない", async () => {
        let processedLog: Log | null = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            masking: { enabled: true, rules: [], preserveFields: [] },
            onLogProcessed: (log) => { processedLog = log; },
        }));
        await sentinel.ingest({ message: "user@example.com" });
        // No rules → no masking even though enabled
        expect(processedLog!.message).toContain("user@example.com");
    });

    it("二重初期化は既存インスタンスを返す", () => {
        const s1 = Sentinel.initialize(createDefaultConfig({ projectName: "p", serviceId: "s" }));
        const s2 = Sentinel.initialize(createDefaultConfig({ projectName: "other", serviceId: "other" }));
        expect(s1).toBe(s2);
        expect(s2.getConfig().projectName).toBe("p"); // 最初の設定が保持
    });

    it("config は deepFreeze されている", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({ projectName: "p", serviceId: "s" }));
        const config = sentinel.getConfig();
        expect(() => { (config as Record<string, unknown>).projectName = "hacked"; }).toThrow();
    });

    it("YAML の integration 部分設定 → 未設定フィールドは undefined", () => {
        const config = parseConfigYaml(`
project_name: test
service_id: svc
integration:
  threat_response_enabled: true
`);
        expect(config.integration!.threatResponseEnabled).toBe(true);
        expect(config.integration!.taskApprovalEnabled).toBeUndefined();
        expect(config.integration!.taskStatusEnabled).toBeUndefined();
        expect(config.integration!.syncDetectionRules).toBeUndefined();
        expect(config.integration!.configValidation).toBeUndefined();
    });

    it("hmacKey が空文字列 → SHA-256 フォールバック", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: true, hmacKey: "" },
        }));
        const result = await sentinel.ingest({ message: "empty key" });
        expect(result.hashChainValid).toBe(true);
    });

    it("remote mode + transport 未設定 → local として動作", async () => {
        const sentinel = Sentinel.initialize(
            createDefaultConfig({ projectName: "p", serviceId: "s" }),
            { transport: { mode: "remote" } }, // transport 未設定
        );
        const result = await sentinel.ingest({ message: "no transport" });
        // transport がないので local パスに入る
        expect(result.traceId).toBeDefined();
    });
});
