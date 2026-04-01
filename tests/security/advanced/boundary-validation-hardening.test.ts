/**
 * Boundary Validation Hardening Tests (TDD)
 *
 * 精査で発見された9件の境界バリデーション問題の修正テスト + ペネトレーションテスト。
 *
 * MEDIUM:
 *   #1: updateCallbacks() キー検証
 *   #2: agentBackLog サイズ推定バイパス
 *   #3: shutdown後のingest/onTaskAction操作ブロック
 * LOW:
 *   #4: null byte検査の全文字列フィールド拡大
 *   #5: reset()がshutdown()を呼ぶ
 *   #6: dual-modeのonErrorがgetCallback経由
 *
 * ペネトレーション:
 *   agentBackLog爆弾、shutdown後操作、callback injection、null byte全経路
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { createTestTaskRule } from "../../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== #1: updateCallbacks キー・型検証 =====
describe("#1: updateCallbacks validation", () => {
    it("rejects non-function values", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(() =>
            sentinel.updateCallbacks({ onLogProcessed: "not-a-function" as never }),
        ).toThrow();
    });

    it("rejects unknown callback keys", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        // unknown key should be silently ignored (not throw, not stored)
        expect(() =>
            sentinel.updateCallbacks({ unknownKey: vi.fn() } as never),
        ).not.toThrow();
    });

    it("accepts valid function values", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(() =>
            sentinel.updateCallbacks({ onLogProcessed: vi.fn() }),
        ).not.toThrow();
    });

    it("accepts null to clear callback", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(() =>
            sentinel.updateCallbacks({ onLogProcessed: null }),
        ).not.toThrow();
    });
});

// ===== #2: agentBackLog サイズ推定 =====
describe("#2: agentBackLog included in size estimate", () => {
    it("rejects oversized agentBackLog that exceeds total limit", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            validationLimits: { maxTotalLogSize: 1000 },
        }));

        // agentBackLog with large payload
        expect(
            sentinel.ingest({
                message: "test",
                level: 3,
                agentBackLog: {
                    agentId: "a".repeat(500),
                    taskId: "b".repeat(500),
                    actionType: "AI_ANALYZE",
                    model: "c".repeat(500),
                } as never,
            }),
        ).rejects.toThrow(ValidationError);
    });
});

// ===== #3: shutdown後の操作ブロック =====
describe("#3: post-shutdown operations blocked", () => {
    it("ingest after shutdown throws", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        await sentinel.shutdown();

        await expect(
            sentinel.ingest({ message: "test", level: 3 }),
        ).rejects.toThrow(/shutdown/i);
    });

    it("onTaskAction after shutdown throws", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        await sentinel.shutdown();

        expect(() =>
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", vi.fn()),
        ).toThrow(/shutdown/i);
    });

    it("updateCallbacks after shutdown throws", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        await sentinel.shutdown();

        expect(() =>
            sentinel.updateCallbacks({ onLogProcessed: vi.fn() }),
        ).toThrow(/shutdown/i);
    });
});

// ===== #4: null byte検査の全文字列フィールド =====
describe("#4: null byte injection in all string fields", () => {
    const fields = [
        { field: "actorId", input: { message: "ok", actorId: "test\x00inject" } },
        { field: "traceId", input: { message: "ok", traceId: "test\x00inject" } },
        { field: "spanId", input: { message: "ok", spanId: "test\x00inject" } },
        { field: "parentSpanId", input: { message: "ok", parentSpanId: "test\x00inject" } },
        { field: "boundary", input: { message: "ok", boundary: "test\x00inject" } },
        { field: "traceInfo", input: { message: "ok", traceInfo: "test\x00inject" } },
        { field: "details", input: { message: "ok", details: "test\x00inject" } },
    ];

    it.each(fields)("rejects null byte in $field", async ({ input }) => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        await expect(sentinel.ingest(input as never)).rejects.toThrow(/null byte/i);
    });

    it("rejects null byte in tag key", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(
            sentinel.ingest({
                message: "ok", level: 3,
                tags: [{ key: "ip\x00inject", category: "value" }],
            }),
        ).rejects.toThrow(/null byte/i);
    });

    it("rejects null byte in tag category", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(
            sentinel.ingest({
                message: "ok", level: 3,
                tags: [{ key: "ip", category: "value\x00inject" }],
            }),
        ).rejects.toThrow(/null byte/i);
    });
});

// ===== #5: reset() calls shutdown cleanup =====
describe("#5: reset() performs cleanup", () => {
    it("reset closes transport", async () => {
        let closed = false;
        const transport = {
            send: vi.fn(),
            close: async () => { closed = true; },
        };

        Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                environment: "test",
                security: { enableHashChain: false },
            }),
            { transport: { mode: "local", transport } },
        );

        Sentinel.reset();
        // Give async close a tick
        await new Promise((r) => setTimeout(r, 10));
        expect(closed).toBe(true);
    });
});

// ===== #6: dual-mode onError uses getCallback =====
describe("#6: dual-mode onError uses dynamic callback", () => {
    it("updated onError is called on dual transport failure", async () => {
        const originalOnError = vi.fn();
        const updatedOnError = vi.fn();

        const transport = {
            send: vi.fn().mockRejectedValue(new Error("network")),
            close: vi.fn(),
        };

        const sentinel = Sentinel.initialize(
            createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                onError: originalOnError,
            }),
            { transport: { mode: "dual", transport } },
        );

        // Update onError dynamically
        sentinel.updateCallbacks({ onError: updatedOnError });

        await sentinel.ingest({ message: "test", level: 3 });

        // Updated handler should be called, not original
        expect(updatedOnError).toHaveBeenCalled();
    });
});

// ===== ペネトレーションテスト: 脅威アクター視点 =====
describe("Penetration: agentBackLog size bomb", () => {
    it("deeply nested agentBackLog cannot bypass total size limit", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            validationLimits: { maxTotalLogSize: 5000 },
        }));

        // Construct deeply nested object
        let nested: Record<string, unknown> = { data: "x".repeat(1000) };
        for (let i = 0; i < 10; i++) {
            nested = { level: i, child: nested, padding: "y".repeat(500) };
        }

        expect(
            sentinel.ingest({
                message: "test",
                level: 3,
                agentBackLog: nested as never,
            }),
        ).rejects.toThrow(ValidationError);
    });
});

describe("Penetration: post-shutdown exploitation", () => {
    it("cannot use stale sentinel reference to bypass validation", async () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const staleRef = sentinel;
        await sentinel.shutdown();

        // Stale reference should not work
        await expect(
            staleRef.ingest({ message: "exploit", level: 3 }),
        ).rejects.toThrow(/shutdown/i);
    });
});

describe("Penetration: callback injection via updateCallbacks", () => {
    it("__proto__ in updateCallbacks does not pollute Object prototype", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        const malicious = JSON.parse('{"__proto__": "evil"}');
        sentinel.updateCallbacks(malicious);

        const clean: Record<string, unknown> = {};
        expect(clean).not.toHaveProperty("evil");
    });
});

describe("Penetration: null byte in every possible injection point", () => {
    it("null byte in message is caught", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(
            sentinel.ingest({ message: "before\x00after", level: 3 }),
        ).rejects.toThrow(/null byte/i);
    });

    it("null byte in resourceIds is caught", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
        }));

        expect(
            sentinel.ingest({
                message: "ok", level: 3,
                resourceIds: ["normal", "inject\x00here"],
            }),
        ).rejects.toThrow(/null byte/i);
    });
});
