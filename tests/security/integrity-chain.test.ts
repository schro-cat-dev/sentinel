/**
 * Security Test: Hash Chain Integrity
 *
 * Tests that the hash chain cannot be forged, replayed, or manipulated.
 * Verifies tamper detection and ordering guarantees.
 *
 * CWE-354: Improper Validation of Integrity Check Value
 */
import { describe, it, expect } from "vitest";
import { IntegritySigner } from "../../src/security/integrity-signer";
import { createTestLog } from "../helpers/fixtures";

describe("Security: Hash Chain Integrity", () => {
    describe("Tamper detection", () => {
        it("detects message modification", () => {
            const log = createTestLog({ message: "original message" });
            const hash = IntegritySigner.calculateHash(log, "");

            const tampered = { ...log, message: "tampered message" };
            const tamperedHash = IntegritySigner.calculateHash(tampered, "");

            expect(hash).not.toBe(tamperedHash);
        });

        it("detects level modification", () => {
            const log = createTestLog({ level: 3 });
            const hash = IntegritySigner.calculateHash(log, "");

            const tampered = { ...log, level: 6 as const };
            const tamperedHash = IntegritySigner.calculateHash(tampered, "");

            expect(hash).not.toBe(tamperedHash);
        });

        it("detects timestamp modification", () => {
            const log = createTestLog({
                timestamp: "2026-01-01T00:00:00.000Z",
            });
            const hash = IntegritySigner.calculateHash(log, "");

            const tampered = {
                ...log,
                timestamp: "2026-01-01T00:00:01.000Z",
            };
            const tamperedHash = IntegritySigner.calculateHash(tampered, "");

            expect(hash).not.toBe(tamperedHash);
        });

        it("detects tag modification", () => {
            const log = createTestLog({
                tags: [{ key: "env", category: "production" }],
            });
            const hash = IntegritySigner.calculateHash(log, "");

            const tampered = {
                ...log,
                tags: [{ key: "env", category: "staging" }],
            };
            const tamperedHash = IntegritySigner.calculateHash(tampered, "");

            expect(hash).not.toBe(tamperedHash);
        });
    });

    describe("Chain ordering", () => {
        it("produces different hashes with different previous hashes", () => {
            const log = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log, "prev-hash-A");
            const hash2 = IntegritySigner.calculateHash(log, "prev-hash-B");

            expect(hash1).not.toBe(hash2);
        });

        it("detects log reordering via chain dependency", () => {
            const signer = new IntegritySigner();

            const log1 = createTestLog({ message: "first" });
            const log2 = createTestLog({ message: "second" });

            // Correct order: log1 then log2
            const hash1 = IntegritySigner.calculateHash(log1, signer.getPreviousHash());
            signer.updateChain(hash1);
            const hash2 = IntegritySigner.calculateHash(log2, signer.getPreviousHash());

            // Try reversed order: log2 then log1
            const signerReversed = new IntegritySigner();
            const hash2r = IntegritySigner.calculateHash(log2, signerReversed.getPreviousHash());
            signerReversed.updateChain(hash2r);
            const hash1r = IntegritySigner.calculateHash(log1, signerReversed.getPreviousHash());

            // Hashes must differ because chain order changed
            expect(hash1).not.toBe(hash1r);
            expect(hash2).not.toBe(hash2r);
        });
    });

    describe("Hash properties", () => {
        it("produces consistent SHA-256 length hashes", () => {
            const log = createTestLog();
            const hash = IntegritySigner.calculateHash(log, "");

            // SHA-256 hex string = 64 characters
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
        });

        it("is deterministic — same input always produces same hash", () => {
            const log = createTestLog({ message: "deterministic test" });
            const hash1 = IntegritySigner.calculateHash(log, "same-prev");
            const hash2 = IntegritySigner.calculateHash(log, "same-prev");

            expect(hash1).toBe(hash2);
        });

        it("genesis hash (empty previous) is well-defined", () => {
            const log = createTestLog();
            const hash = IntegritySigner.calculateHash(log, "");

            expect(hash).toBeDefined();
            expect(hash.length).toBe(64);
        });
    });

    describe("Verification", () => {
        it("verifies valid hash chain entry", () => {
            // verifyHash uses omit(["hash","signature"]) but previousHash stays in the payload.
            // So we must set previousHash BEFORE calculating the hash.
            const log = createTestLog();
            const logWithPrev = { ...log, previousHash: "" };
            const hash = IntegritySigner.calculateHash(logWithPrev, "");
            const logWithHash = { ...logWithPrev, hash };

            expect(IntegritySigner.verifyHash(logWithHash, "")).toBe(true);
        });

        it("rejects modified log in verification", () => {
            const log = createTestLog({ message: "original" });
            const hash = IntegritySigner.calculateHash(log, "");
            const tampered = { ...log, message: "tampered", hash, previousHash: "" };

            expect(IntegritySigner.verifyHash(tampered, "")).toBe(false);
        });

        it("rejects wrong previous hash in verification", () => {
            const log = createTestLog();
            const hash = IntegritySigner.calculateHash(log, "correct-prev");
            const logWithHash = { ...log, hash, previousHash: "correct-prev" };

            // Verify with wrong expected previous
            expect(IntegritySigner.verifyHash(logWithHash, "wrong-prev")).toBe(false);
        });
    });

    describe("Edge cases", () => {
        it("handles log with all optional fields populated", () => {
            const log = createTestLog({
                spanId: "span-1",
                parentSpanId: "parent-1",
                actorId: "actor-1",
                details: { info: "detailed info" },
                resourceIds: ["r1", "r2"],
                traceInfo: "trace data",
                input: { key: "value" },
            });

            expect(() => IntegritySigner.calculateHash(log, "")).not.toThrow();
        });

        it("handles log with unicode in message", () => {
            const log = createTestLog({
                message: "日本語テスト \u{1F600} émojis",
            });

            const hash = IntegritySigner.calculateHash(log, "");
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
        });

        it("handles extremely large log message", () => {
            const log = createTestLog({
                message: "x".repeat(65536),
            });

            expect(() => IntegritySigner.calculateHash(log, "")).not.toThrow();
        });
    });
});
