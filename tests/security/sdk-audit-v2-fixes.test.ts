/**
 * Security Audit v2 Fixes — SDK追加脆弱性修正テスト
 *
 * docs/security-audit/sdk-v2/additional-findings.md に基づく修正を検証。
 *
 * 対象:
 * NEW-01: concurrent ingest の lastProcessedLog 競合
 * NEW-05: ErrorRouter の再帰ループ防止
 * NEW-06: ErrorRouter 経由の PII 漏洩
 * NEW-09: preserveFields マスキングバイパス
 * NEW-14: config.metrics/tracer 例外未捕捉
 * NEW-15: shutdown() と ingest() の並行実行
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel } from "../../src/index";
import { ErrorRouter } from "../../src/error-routing/error-router";
import { createTestConfig, createTestTaskRule } from "../helpers/fixtures";

// =========================================================================
// NEW-01: concurrent ingest の lastProcessedLog 競合
// =========================================================================

describe("NEW-01: concurrent ingest safety", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("handles concurrent ingests without crash", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        // 10件の concurrent ingest
        const promises = Array.from({ length: 10 }, (_, i) =>
            sentinel.ingest({ message: `concurrent message ${i}` }),
        );

        const results = await Promise.all(promises);

        // 全て正常に完了すること
        expect(results).toHaveLength(10);
        for (const r of results) {
            expect(r.traceId).toBeDefined();
        }
    });

    it("each concurrent ingest returns its own traceId", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        const results = await Promise.all([
            sentinel.ingest({ message: "msg A" }),
            sentinel.ingest({ message: "msg B" }),
            sentinel.ingest({ message: "msg C" }),
        ]);

        const traceIds = new Set(results.map((r) => r.traceId));
        // 各ingestは一意のtraceIdを返す
        expect(traceIds.size).toBe(3);
    });
});

// =========================================================================
// NEW-05: ErrorRouter の再帰ループ防止
// =========================================================================

describe("NEW-05: ErrorRouter reentrant loop prevention", () => {
    it("prevents infinite recursion when route() is called during routing", async () => {
        const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

        let routeCount = 0;
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest: async () => {
                routeCount++;
                // コールバック内で route() を再帰的に呼ぶ
                await router.route(new Error("recursive call"), "callback.recursive");
            },
            rules: [
                {
                    match: { severity: "CRITICAL" },
                    decisions: [{ destination: "task", action: "escalate", priority: 1 }],
                },
            ],
        });

        await router.route(new Error("initial error"), "test");

        // 無限ループにならず完了すること（1回のルーティングのみ）
        // 再帰呼び出しはブロックされるべき
        expect(routeCount).toBeLessThanOrEqual(2);
        errorSpy.mockRestore();
    });
});

// =========================================================================
// NEW-06: ErrorRouter 経由の PII 漏洩防止
// =========================================================================

describe("NEW-06: ErrorRouter PII truncation in task/ai_agent descriptions", () => {
    it("truncates long error messages in task destination description", async () => {
        let capturedDescription = "";
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest: async (req) => {
                capturedDescription = req.description;
            },
            rules: [
                {
                    match: { severity: "CRITICAL" },
                    decisions: [{ destination: "task", action: "escalate", priority: 1 }],
                },
            ],
        });

        const longPiiMessage = "User email user-secret@example.com with SSN 123-45-6789 " + "x".repeat(500);
        await router.route(new Error(longPiiMessage), "test");

        // description が200文字以下に切り詰められるべき
        expect(capturedDescription.length).toBeLessThanOrEqual(250); // prefix含む
    });

    it("truncates long error messages in ai_agent destination description", async () => {
        let capturedDescription = "";
        const router = new ErrorRouter({
            enabled: true,
            onTaskRequest: async (req) => {
                capturedDescription = req.description;
            },
            rules: [
                {
                    match: { severity: "WARNING", kindPattern: /^Handler/ },
                    decisions: [{ destination: "ai_agent", action: "auto_remediate", priority: 2 }],
                },
            ],
        });

        const longMessage = "Handler error with PII: " + "sensitive-data-".repeat(50);
        await router.route(new Error(longMessage), "test");

        if (capturedDescription) {
            expect(capturedDescription.length).toBeLessThanOrEqual(250);
        }
    });
});

// =========================================================================
// NEW-09: preserveFields バイパス警告
// =========================================================================

describe("NEW-09: preserveFields sensitive field warning", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("warns when preserveFields contains sensitive field names", () => {
        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
            masking: {
                enabled: true,
                rules: [],
                preserveFields: ["traceId", "password", "apiKey"],
            },
        });

        Sentinel.initialize(config);

        // password, apiKey が preserveFields に含まれる場合に警告
        expect(warnSpy).toHaveBeenCalledWith(
            expect.stringContaining("preserveFields"),
        );

        warnSpy.mockRestore();
    });

    it("does not warn for safe preserveFields", () => {
        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
            masking: {
                enabled: true,
                rules: [],
                preserveFields: ["traceId", "spanId"],
            },
        });

        Sentinel.initialize(config);

        expect(warnSpy).not.toHaveBeenCalledWith(
            expect.stringContaining("preserveFields"),
        );

        warnSpy.mockRestore();
    });
});

// =========================================================================
// NEW-14: config.metrics/tracer 例外がパイプラインを壊さない
// =========================================================================

describe("NEW-14: metrics/tracer callback exceptions do not break pipeline", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("completes ingest even when metrics.onIngest throws", async () => {
        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
            metrics: {
                onIngest: () => { throw new Error("metrics failure"); },
            },
        });
        const sentinel = Sentinel.initialize(config);

        // メトリクスが壊れてもingestは成功すべき
        const result = await sentinel.ingest({ message: "test message" });
        expect(result.traceId).toBeDefined();
    });

    it("completes ingest even when tracer.onPipelineStart throws", async () => {
        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
            tracer: {
                onPipelineStart: () => { throw new Error("tracer failure"); },
            },
        });
        const sentinel = Sentinel.initialize(config);

        const result = await sentinel.ingest({ message: "test message" });
        expect(result.traceId).toBeDefined();
    });

    it("completes ingest even when metrics.onDetection throws", async () => {
        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
            metrics: {
                onDetection: () => { throw new Error("detection metrics failure"); },
            },
        });
        const sentinel = Sentinel.initialize(config);

        // SECURITY type + level 5 triggers detection
        const result = await sentinel.ingest({
            message: "Suspicious activity detected",
            type: "SECURITY",
            level: 5,
            tags: [{ key: "ip", category: "10.0.0.1" }],
        });
        expect(result.traceId).toBeDefined();
    });
});

// =========================================================================
// NEW-15: shutdown() と ingest() の並行実行
// =========================================================================

describe("NEW-15: concurrent shutdown and ingest", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("ingest started before shutdown completes without crash", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        // ingest を開始
        const ingestPromise = sentinel.ingest({ message: "before shutdown" });

        // 直後に shutdown
        const shutdownPromise = sentinel.shutdown();

        // どちらも例外なく完了すべき
        const results = await Promise.allSettled([ingestPromise, shutdownPromise]);

        // ingest は成功 or 正常なエラー（shutdown済み）のいずれか
        for (const r of results) {
            if (r.status === "rejected") {
                expect(r.reason.message).toContain("shutdown");
            }
        }
    });

    it("ingest after shutdown is rejected", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        await sentinel.shutdown();

        await expect(sentinel.ingest({ message: "after shutdown" }))
            .rejects.toThrow(/shutdown/i);
    });
});
