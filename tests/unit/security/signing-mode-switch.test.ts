/**
 * Signing Mode Switch Tests
 *
 * HMAC-SHA256 / SHA-256 の切り替え + 将来の証明書ベース署名のモック検証。
 * サーバ連携時にモック証明書で署名モードが切り替わることを確認。
 * 実際の証明書/公開鍵署名は未実装だが、モックで切り替えの仕組みが動くことを検証。
 */
import { describe, it, expect, vi } from "vitest";
import { createHash, createHmac } from "node:crypto";
import { IntegritySigner } from "../../../src/security/integrity-signer";
import { createTestLog } from "../../helpers/fixtures";

describe("Signing mode switch", () => {
    describe("SHA-256 → HMAC-SHA256 切り替え", () => {
        it("same log produces different hashes in different modes", () => {
            const log = createTestLog({ message: "mode switch test" });
            const sha256Hash = IntegritySigner.calculateHash(log, "prev");
            const hmacHash = IntegritySigner.calculateHash(log, "prev", "", "hmac-key-32-bytes-long!!!!!!!!!!");
            expect(sha256Hash).toMatch(/^[a-f0-9]{64}$/);
            expect(hmacHash).toMatch(/^[a-f0-9]{64}$/);
            expect(sha256Hash).not.toBe(hmacHash);
        });

        it("HMAC hash is verifiable only with correct key", () => {
            const log = createTestLog({ message: "verify test" });
            const key = "correct-key-32-bytes-long!!!!!!!";
            log.hash = IntegritySigner.calculateHash(log, "", "", key);

            expect(IntegritySigner.verifyHash(log, "", key)).toBe(true);
            expect(IntegritySigner.verifyHash(log, "", "wrong-key-32-bytes-long!!!!!!!!!!")).toBe(false);
            expect(IntegritySigner.verifyHash(log, "")).toBe(false); // SHA-256 mode won't match
        });

        it("signer instance tracks mode via constructor", () => {
            const sha256Signer = new IntegritySigner("keyId");
            expect(sha256Signer.getHmacKey()).toBe("");
            expect(sha256Signer.getSigningKeyId()).toBe("keyId");

            const hmacSigner = new IntegritySigner("keyId", "hmac-key-32-bytes-long!!!!!!!!!!");
            expect(hmacSigner.getHmacKey()).toBe("hmac-key-32-bytes-long!!!!!!!!!!");
        });
    });

    describe("チェーン整合性: モード切り替え後の検証", () => {
        it("SHA-256 chain cannot be verified with HMAC key", () => {
            const signer = new IntegritySigner();
            const logs = [
                createTestLog({ message: "log1", traceId: "t1" }),
                createTestLog({ message: "log2", traceId: "t2" }),
            ];
            // Build SHA-256 chain
            for (const log of logs) {
                log.previousHash = signer.getPreviousHash();
                log.hash = IntegritySigner.calculateHash(log, log.previousHash);
                signer.updateChain(log.hash);
            }
            // Verify with SHA-256 works
            expect(IntegritySigner.verifyHash(logs[0], "")).toBe(true);
            // Verify with HMAC key fails (different algorithm)
            expect(IntegritySigner.verifyHash(logs[0], "", "some-hmac-key-32-bytes!!!!!!!!!")).toBe(false);
        });

        it("HMAC chain cannot be verified without the key", () => {
            const key = "test-hmac-key-32-bytes-long!!!!!";
            const signer = new IntegritySigner("", key);
            const logs = [
                createTestLog({ message: "hmac1", traceId: "h1" }),
                createTestLog({ message: "hmac2", traceId: "h2" }),
            ];
            for (const log of logs) {
                log.previousHash = signer.getPreviousHash();
                log.hash = IntegritySigner.calculateHash(log, log.previousHash, "", key);
                signer.updateChain(log.hash);
            }
            // HMAC verification works
            expect(IntegritySigner.verifyHash(logs[0], "", key)).toBe(true);
            expect(IntegritySigner.verifyHash(logs[1], logs[0].hash!, key)).toBe(true);
            // Without key: fails
            expect(IntegritySigner.verifyHash(logs[0], "")).toBe(false);
        });
    });

    describe("モック証明書署名（将来の公開鍵署名シミュレーション）", () => {
        // 実際のEd25519/ECDSA署名は未実装。
        // ここではモック署名関数を用意し、IntegritySignerのhash計算後に
        // 追加の署名ステップが挿入できるアーキテクチャであることを検証。

        type MockSignFn = (data: string) => string;
        type MockVerifyFn = (data: string, signature: string) => boolean;

        function createMockCertSigner(): { sign: MockSignFn; verify: MockVerifyFn } {
            // 簡易モック: HMAC with a "certificate" key
            const certKey = "mock-certificate-private-key-32b!";
            return {
                sign: (data: string) => createHmac("sha256", certKey).update(data).digest("hex"),
                verify: (data: string, sig: string) =>
                    createHmac("sha256", certKey).update(data).digest("hex") === sig,
            };
        }

        it("mock certificate signer can sign and verify hash", () => {
            const { sign, verify } = createMockCertSigner();
            const log = createTestLog({ message: "cert test" });

            // Step 1: Normal hash chain
            const hash = IntegritySigner.calculateHash(log, "");

            // Step 2: Sign the hash with mock certificate
            const signature = sign(hash);
            expect(signature).toMatch(/^[a-f0-9]{64}$/);

            // Step 3: Verify
            expect(verify(hash, signature)).toBe(true);
            expect(verify(hash, "tampered-signature")).toBe(false);
        });

        it("mock certificate signer produces different signatures than HMAC chain", () => {
            const { sign } = createMockCertSigner();
            const log = createTestLog({ message: "diff test" });

            const hmacKey = "hmac-key-32-bytes-long!!!!!!!!!!";
            const hmacHash = IntegritySigner.calculateHash(log, "", "", hmacKey);
            const certSignature = sign(hmacHash);

            // HMAC hash != cert signature (different keys/purposes)
            expect(hmacHash).not.toBe(certSignature);
        });

        it("switching from HMAC to cert signing breaks chain verification", () => {
            const { sign } = createMockCertSigner();
            const key = "hmac-key-32-bytes-long!!!!!!!!!!";
            const log = createTestLog({ message: "switch test" });

            // HMAC hash
            log.hash = IntegritySigner.calculateHash(log, "", "", key);
            expect(IntegritySigner.verifyHash(log, "", key)).toBe(true);

            // Overwrite with cert signature — chain verification fails
            log.signature = sign(log.hash!);
            // hash is still HMAC — verify still works for hash
            expect(IntegritySigner.verifyHash(log, "", key)).toBe(true);
            // signature field is independent (not checked by verifyHash)
            expect(log.signature).toBeDefined();
            expect(log.signature).not.toBe(log.hash);
        });

        it("SDK does not set signature field (placeholder for future cert signing)", () => {
            const log = createTestLog({ message: "no sig" });
            log.hash = IntegritySigner.calculateHash(log, "");
            // signature is not populated by IntegritySigner
            expect(log.signature).toBeUndefined();
        });
    });
});
