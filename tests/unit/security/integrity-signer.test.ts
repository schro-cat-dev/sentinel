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
