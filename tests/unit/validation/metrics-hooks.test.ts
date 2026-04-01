/**
 * Metrics Hooks Tests (TDD)
 *
 * F-02: 軽量メトリクスフック。
 * SentinelConfig.metrics に MetricsCollector を注入すると、
 * パイプラインの各ステージで呼ばれる。未設定時はゼロオーバーヘッド。
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { createTestTaskRule } from "../../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

describe("F-02: Metrics hooks", () => {
    it("calls onIngest for each log ingested", async () => {
        const onIngest = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            metrics: { onIngest },
        }));

        await sentinel.ingest({ message: "test", level: 3 });
        expect(onIngest).toHaveBeenCalledTimes(1);
    });

    it("calls onDetection when event is detected", async () => {
        const onDetection = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            metrics: { onDetection },
        }));

        await sentinel.ingest({ message: "fail", isCritical: true, level: 6 });
        expect(onDetection).toHaveBeenCalledTimes(1);
        expect(onDetection).toHaveBeenCalledWith(
            expect.objectContaining({ eventName: "SYSTEM_CRITICAL_FAILURE" }),
        );
    });

    it("does not call onDetection when no event detected", async () => {
        const onDetection = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            metrics: { onDetection },
        }));

        await sentinel.ingest({ message: "normal", level: 2 });
        expect(onDetection).not.toHaveBeenCalled();
    });

    it("calls onTaskDispatch for each task dispatched", async () => {
        const onTaskDispatch = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            metrics: { onTaskDispatch },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                executionLevel: "AUTO",
            })],
        }));
        sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn());

        await sentinel.ingest({ message: "fail", isCritical: true, level: 6 });
        expect(onTaskDispatch).toHaveBeenCalledTimes(1);
    });

    it("no metrics config means zero overhead (no errors)", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        // No metrics configured — should work fine with no errors
        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
    });

    it("metrics callback throwing does not crash pipeline", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            metrics: {
                onIngest: () => { throw new Error("metrics boom"); },
            },
        }));

        // Pipeline should still work
        const result = await sentinel.ingest({ message: "test", level: 3 });
        expect(result.traceId).toBeDefined();
    });
});
