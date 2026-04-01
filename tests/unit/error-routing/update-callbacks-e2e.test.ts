/**
 * updateCallbacks E2E Tests — Gap 6 remediation
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { createTestTaskRule } from "../../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

describe("updateCallbacks E2E", () => {
    it("replaced onLogProcessed is called on ingest", async () => {
        const original = vi.fn();
        const replaced = vi.fn();

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: original,
        }));

        sentinel.updateCallbacks({ onLogProcessed: replaced });

        await sentinel.ingest({ message: "test", level: 3 });

        expect(replaced).toHaveBeenCalled();
        expect(original).not.toHaveBeenCalled();
    });

    it("replaced onTaskGenerated is called on task creation", async () => {
        const replaced = vi.fn();

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "SYSTEM_CRITICAL_FAILURE",
                severity: "CRITICAL",
                executionLevel: "AUTO",
            })],
        }));

        sentinel.updateCallbacks({ onTaskGenerated: replaced });

        await sentinel.ingest({ message: "fail", isCritical: true, level: 6 });

        expect(replaced).toHaveBeenCalled();
    });

    it("null clears callback — not called on ingest", async () => {
        const original = vi.fn();

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: original,
        }));

        sentinel.updateCallbacks({ onLogProcessed: null });

        await sentinel.ingest({ message: "test", level: 3 });

        expect(original).not.toHaveBeenCalled();
    });

    it("shutdown clears overrides — re-init uses fresh config", async () => {
        const override = vi.fn();
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));
        sentinel.updateCallbacks({ onLogProcessed: override });
        await sentinel.shutdown();

        const fresh = vi.fn();
        const sentinel2 = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: fresh,
        }));
        await sentinel2.ingest({ message: "test", level: 3 });

        expect(fresh).toHaveBeenCalled();
        expect(override).not.toHaveBeenCalled();
    });

    it("override takes priority over config callback", async () => {
        const configCb = vi.fn();
        const overrideCb = vi.fn();

        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            onLogProcessed: configCb,
        }));

        sentinel.updateCallbacks({ onLogProcessed: overrideCb });
        await sentinel.ingest({ message: "test", level: 3 });

        expect(overrideCb).toHaveBeenCalledTimes(1);
        expect(configCb).not.toHaveBeenCalled();
    });
});
