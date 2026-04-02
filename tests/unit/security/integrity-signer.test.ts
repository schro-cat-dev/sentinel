import { describe, it, expect, beforeEach } from "vitest";
import { IntegritySigner } from "../../../src/security/integrity-signer";
import { createTestLog } from "../../helpers/fixtures";

describe("IntegritySigner", () => {
    let signer: IntegritySigner;

    beforeEach(() => {
        signer = new IntegritySigner();
    });

    describe("calculateHash", () => {
        it("produces a 64-char hex SHA-256 hash", () => {
            const log = createTestLog();
            const hash = IntegritySigner.calculateHash(log, "");
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
        });

        it("produces different hashes for different logs", () => {
            const log1 = createTestLog({ message: "message A" });
            const log2 = createTestLog({ message: "message B" });
            const hash1 = IntegritySigner.calculateHash(log1, "");
            const hash2 = IntegritySigner.calculateHash(log2, "");
            expect(hash1).not.toBe(hash2);
        });

        it("produces different hashes with different previousHash", () => {
            const log = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log, "aaa");
            const hash2 = IntegritySigner.calculateHash(log, "bbb");
            expect(hash1).not.toBe(hash2);
        });

        it("is deterministic (same input = same output)", () => {
            const log = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log, "prev");
            const hash2 = IntegritySigner.calculateHash(log, "prev");
            expect(hash1).toBe(hash2);
        });

        it("excludes hash and signature fields from computation", () => {
            const log1 = createTestLog({ hash: "should-be-ignored", signature: "also-ignored" });
            const log2 = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log1, "");
            const hash2 = IntegritySigner.calculateHash(log2, "");
            expect(hash1).toBe(hash2);
        });

        it("handles logs with undefined optional fields", () => {
            const log = createTestLog({
                spanId: undefined,
                parentSpanId: undefined,
                actorId: undefined,
                aiContext: undefined,
            });
            const hash = IntegritySigner.calculateHash(log, "");
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
        });

        it("handles object with undefined value deterministically", () => {
            const log1 = createTestLog({ aiContext: undefined });
            const log2 = createTestLog({ aiContext: undefined });
            const hash1 = IntegritySigner.calculateHash(log1, "");
            const hash2 = IntegritySigner.calculateHash(log2, "");
            expect(hash1).toBe(hash2);
            expect(hash1).toMatch(/^[a-f0-9]{64}$/);
        });

        it("handles log with explicitly undefined field in metadata", () => {
            const log = createTestLog({
                metadata: { key1: "value1", key2: undefined as unknown as string },
            });
            const hash1 = IntegritySigner.calculateHash(log, "");
            const hash2 = IntegritySigner.calculateHash(log, "");
            expect(hash1).toBe(hash2);
        });

        it("handles non-plain objects gracefully (Date is not a valid JSON value)", () => {
            // Date object in metadata should not break hashing
            const log = createTestLog({
                metadata: { timestamp: new Date("2026-01-01") as unknown as string },
            });
            // Should not throw
            const hash = IntegritySigner.calculateHash(log, "");
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
        });

        it("object key order does not affect hash (deterministic serialization)", () => {
            const log1 = createTestLog({ message: "test", boundary: "a" });
            const log2 = createTestLog({ boundary: "a", message: "test" });
            const hash1 = IntegritySigner.calculateHash(log1, "");
            const hash2 = IntegritySigner.calculateHash(log2, "");
            expect(hash1).toBe(hash2);
        });
    });

    describe("verifyHash", () => {
        it("returns true for correctly hashed log", () => {
            const log = createTestLog();
            log.hash = IntegritySigner.calculateHash(log, "");
            expect(IntegritySigner.verifyHash(log, "")).toBe(true);
        });

        it("returns false for tampered log", () => {
            const log = createTestLog();
            log.hash = IntegritySigner.calculateHash(log, "");
            log.message = "tampered message";
            expect(IntegritySigner.verifyHash(log, "")).toBe(false);
        });

        it("returns false when hash is missing", () => {
            const log = createTestLog();
            expect(IntegritySigner.verifyHash(log, "")).toBe(false);
        });

        it("returns false with wrong previousHash", () => {
            const log = createTestLog();
            log.hash = IntegritySigner.calculateHash(log, "correct");
            expect(IntegritySigner.verifyHash(log, "wrong")).toBe(false);
        });
    });

    describe("HMAC-SHA256 mode (Phase 1-E)", () => {
        const hmacKey = "a]8kP$2mN!qR9vL#xY5wZ@cF3gH7jT0s"; // 32 bytes

        it("produces a 64-char hex HMAC-SHA256 hash when key provided", () => {
            const log = createTestLog();
            const hash = IntegritySigner.calculateHash(log, "", "", hmacKey);
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
        });

        it("produces different hash than SHA-256 mode for same log", () => {
            const log = createTestLog();
            const sha256Hash = IntegritySigner.calculateHash(log, "");
            const hmacHash = IntegritySigner.calculateHash(log, "", "", hmacKey);
            expect(sha256Hash).not.toBe(hmacHash);
        });

        it("is deterministic with same key", () => {
            const log = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log, "prev", "", hmacKey);
            const hash2 = IntegritySigner.calculateHash(log, "prev", "", hmacKey);
            expect(hash1).toBe(hash2);
        });

        it("produces different hashes with different keys", () => {
            const log = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log, "", "", hmacKey);
            const hash2 = IntegritySigner.calculateHash(log, "", "", "different-key-32-bytes-long!!!!!");
            expect(hash1).not.toBe(hash2);
        });

        it("excludes hash and signature from HMAC computation", () => {
            const log1 = createTestLog({ hash: "ignored", signature: "ignored" });
            const log2 = createTestLog();
            const hash1 = IntegritySigner.calculateHash(log1, "", "", hmacKey);
            const hash2 = IntegritySigner.calculateHash(log2, "", "", hmacKey);
            expect(hash1).toBe(hash2);
        });

        it("verifyHash works with HMAC key", () => {
            const log = createTestLog();
            log.hash = IntegritySigner.calculateHash(log, "", "", hmacKey);
            expect(IntegritySigner.verifyHash(log, "", hmacKey)).toBe(true);
        });

        it("verifyHash fails with wrong HMAC key", () => {
            const log = createTestLog();
            log.hash = IntegritySigner.calculateHash(log, "", "", hmacKey);
            expect(IntegritySigner.verifyHash(log, "", "wrong-key-32-bytes-long!!!!!!!!!")).toBe(false);
        });

        it("HMAC chain of 3 logs is verifiable", () => {
            const hmacSigner = new IntegritySigner("", hmacKey);
            const logs = [
                createTestLog({ message: "first", traceId: "t1" }),
                createTestLog({ message: "second", traceId: "t2" }),
                createTestLog({ message: "third", traceId: "t3" }),
            ];
            const hashes: string[] = [];
            for (const log of logs) {
                const prevHash = hmacSigner.getPreviousHash();
                log.previousHash = prevHash;
                log.hash = IntegritySigner.calculateHash(log, prevHash, "", hmacKey);
                hmacSigner.updateChain(log.hash);
                hashes.push(log.hash);
            }
            expect(new Set(hashes).size).toBe(3);
            expect(IntegritySigner.verifyHash(logs[0], "", hmacKey)).toBe(true);
            expect(IntegritySigner.verifyHash(logs[1], hashes[0], hmacKey)).toBe(true);
            expect(IntegritySigner.verifyHash(logs[2], hashes[1], hmacKey)).toBe(true);
        });

        it("falls back to SHA-256 when hmacKey is empty string", () => {
            const log = createTestLog();
            const hashNoKey = IntegritySigner.calculateHash(log, "");
            const hashEmptyKey = IntegritySigner.calculateHash(log, "", "", "");
            expect(hashNoKey).toBe(hashEmptyKey);
        });
    });

    describe("hash chain (instance state)", () => {
        it("starts with empty previousHash", () => {
            expect(signer.getPreviousHash()).toBe("");
        });

        it("updates chain state", () => {
            signer.updateChain("hash-1");
            expect(signer.getPreviousHash()).toBe("hash-1");
            signer.updateChain("hash-2");
            expect(signer.getPreviousHash()).toBe("hash-2");
        });

        it("resets chain", () => {
            signer.updateChain("hash-1");
            signer.resetChain();
            expect(signer.getPreviousHash()).toBe("");
        });

        it("simulates a full chain of 3 logs", () => {
            const logs = [
                createTestLog({ message: "first", traceId: "t1" }),
                createTestLog({ message: "second", traceId: "t2" }),
                createTestLog({ message: "third", traceId: "t3" }),
            ];

            const hashes: string[] = [];
            for (const log of logs) {
                const prevHash = signer.getPreviousHash();
                log.previousHash = prevHash;
                log.hash = IntegritySigner.calculateHash(log, prevHash);
                signer.updateChain(log.hash);
                hashes.push(log.hash);
            }

            // All hashes are unique
            expect(new Set(hashes).size).toBe(3);

            // Each log can be verified with its predecessor's hash
            expect(IntegritySigner.verifyHash(logs[0], "")).toBe(true);
            expect(IntegritySigner.verifyHash(logs[1], hashes[0])).toBe(true);
            expect(IntegritySigner.verifyHash(logs[2], hashes[1])).toBe(true);

            // Tampering breaks the chain
            logs[1].message = "tampered";
            expect(IntegritySigner.verifyHash(logs[1], hashes[0])).toBe(false);
        });
    });
});
