/**
 * Security Audit Final Pass — 最終パスで発見された脆弱性修正テスト
 *
 * AUDIT-02: details, tags, resourceIds の lone surrogate チェック漏れ
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sentinel, ValidationError } from "../../src/index";
import { createTestConfig, createTestTaskRule } from "../helpers/fixtures";

describe("AUDIT-02: lone surrogate checks on all string fields", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    function initSentinel() {
        return Sentinel.initialize(
            createTestConfig({ taskRules: [createTestTaskRule()] }),
        );
    }

    // --- details ---
    it("rejects details with lone high surrogate", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            details: "some detail\uD800value",
        })).rejects.toThrow(ValidationError);
    });

    it("accepts details with valid emoji", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            details: "detail with emoji 😀",
        })).resolves.toBeDefined();
    });

    // --- tags.key ---
    it("rejects tag key with lone surrogate", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            tags: [{ key: "bad\uD800key", category: "value" }],
        })).rejects.toThrow(ValidationError);
    });

    // --- tags.category ---
    it("rejects tag category with lone surrogate", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            tags: [{ key: "good", category: "bad\uDC00value" }],
        })).rejects.toThrow(ValidationError);
    });

    it("accepts tags with valid content", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            tags: [{ key: "env", category: "production" }],
        })).resolves.toBeDefined();
    });

    // --- resourceIds ---
    it("rejects resourceId with lone surrogate", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            resourceIds: ["valid-id", "bad\uD800id"],
        })).rejects.toThrow(ValidationError);
    });

    it("accepts resourceIds with valid content", async () => {
        const sentinel = initSentinel();
        await expect(sentinel.ingest({
            message: "ok",
            resourceIds: ["res-1", "res-2"],
        })).resolves.toBeDefined();
    });
});
