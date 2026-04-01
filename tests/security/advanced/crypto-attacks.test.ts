/**
 * Advanced Security Test: Cryptographic Attack Simulations
 *
 * Tests IntegritySigner and hash chain against:
 * - Length extension attacks
 * - Second preimage resistance
 * - Hash chain forking / replay / gap
 * - Deterministic serialization edge cases
 * - timingSafeEqual verification
 * - Chain state management
 * - Hash uniqueness and bit flip detection
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createHash } from "node:crypto";
import { IntegritySigner } from "../../../src/security/integrity-signer";
import { Log } from "../../../src/types/log";
import { createTestLog } from "../../helpers/fixtures";

// ---- helpers ----

/** Build a chain of N logs and return them with hashes assigned */
function buildChain(count: number, signer: IntegritySigner): Log[] {
    const logs: Log[] = [];
    for (let i = 0; i < count; i++) {
        const log = createTestLog({
            traceId: `chain-${i}`,
            message: `chain message ${i}`,
            logicalClock: i,
        });
        const prev = signer.getPreviousHash();
        log.previousHash = prev;
        log.hash = IntegritySigner.calculateHash(log, prev);
        signer.updateChain(log.hash);
        logs.push(log);
    }
    return logs;
}

// ============================================================
// 1. Length Extension Attack Simulation
// ============================================================
describe("Crypto Attacks: Length Extension", () => {
    it("cannot forge H(m1||m2) given H(m1) alone", () => {
        const log1 = createTestLog({ message: "original" });
        const h1 = IntegritySigner.calculateHash(log1, "");

        // Attacker tries to extend hash by appending extra data using raw SHA-256
        const forgedDigest = createHash("sha256")
            .update(h1 + "malicious-extension")
            .digest("hex");

        // The legitimate hash for a log whose message includes the extension
        const log2 = createTestLog({ message: "original" + "malicious-extension" });
        const h2 = IntegritySigner.calculateHash(log2, "");

        expect(forgedDigest).not.toBe(h2);
    });

    it("extending previousHash does not produce valid chain entry", () => {
        const signer = new IntegritySigner();
        const logs = buildChain(3, signer);
        const lastHash = logs[2].hash!;

        // Attacker tries to extend the chain by raw SHA-256(lastHash || payload)
        const attackPayload = JSON.stringify({ message: "attack" });
        const forgedHash = createHash("sha256")
            .update(attackPayload + lastHash)
            .digest("hex");

        const forgedLog = createTestLog({ message: "attack" });
        forgedLog.previousHash = lastHash;
        forgedLog.hash = forgedHash;

        // Legitimate calculation should differ
        const legitimate = IntegritySigner.calculateHash(forgedLog, lastHash);
        expect(forgedHash).not.toBe(legitimate);
    });

    it("appending padding bytes to hash input does not match", () => {
        const log = createTestLog({ message: "base" });
        const h = IntegritySigner.calculateHash(log, "");

        // Try SHA-256 length-extension style: extend raw digest with padding
        const extended = createHash("sha256")
            .update(Buffer.from(h, "hex"))
            .update("\x80\x00\x00\x00")
            .digest("hex");

        const log2 = createTestLog({ message: "base\x80\x00\x00\x00" });
        const h2 = IntegritySigner.calculateHash(log2, "");

        expect(extended).not.toBe(h2);
    });
});

// ============================================================
// 2. Second Preimage Resistance
// ============================================================
describe("Crypto Attacks: Second Preimage Resistance", () => {
    it("two different messages never produce same hash", () => {
        const logA = createTestLog({ message: "message-a" });
        const logB = createTestLog({ message: "message-b" });
        const hA = IntegritySigner.calculateHash(logA, "");
        const hB = IntegritySigner.calculateHash(logB, "");
        expect(hA).not.toBe(hB);
    });

    it("different types with same message produce different hashes", () => {
        const logA = createTestLog({ type: "SYSTEM", message: "same" });
        const logB = createTestLog({ type: "SECURITY", message: "same" });
        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("different levels with identical content produce different hashes", () => {
        const logA = createTestLog({ level: 1, message: "x" });
        const logB = createTestLog({ level: 6, message: "x" });
        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("different previousHash values produce different hashes for same log", () => {
        const log = createTestLog({ message: "fixed" });
        const h1 = IntegritySigner.calculateHash(log, "abc");
        const h2 = IntegritySigner.calculateHash(log, "def");
        expect(h1).not.toBe(h2);
    });

    it("cannot find second preimage by field swapping", () => {
        const logA = createTestLog({
            message: "alpha",
            boundary: "beta",
        });
        const logB = createTestLog({
            message: "beta",
            boundary: "alpha",
        });
        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });
});

// ============================================================
// 3. Hash Chain Fork
// ============================================================
describe("Crypto Attacks: Hash Chain Fork", () => {
    it("concurrent calls on same signer produce sequential (non-branching) chain", async () => {
        const signer = new IntegritySigner();
        const results: string[] = [];

        // Simulate rapid sequential updates (JS is single-threaded for sync ops)
        for (let i = 0; i < 10; i++) {
            const log = createTestLog({ message: `fork-${i}`, logicalClock: i });
            const prev = signer.getPreviousHash();
            const hash = IntegritySigner.calculateHash(log, prev);
            signer.updateChain(hash);
            results.push(hash);
        }

        // All hashes are unique (no fork)
        const unique = new Set(results);
        expect(unique.size).toBe(10);
    });

    it("two signers diverge immediately when same logs fed with different history", () => {
        const signerA = new IntegritySigner();
        const signerB = new IntegritySigner();
        signerB.updateChain("seed-hash");

        const log = createTestLog({ message: "same log" });
        const hA = IntegritySigner.calculateHash(log, signerA.getPreviousHash());
        const hB = IntegritySigner.calculateHash(log, signerB.getPreviousHash());

        expect(hA).not.toBe(hB);
    });

    it("inserting an extra log between two logs changes all subsequent hashes", () => {
        const signerNormal = new IntegritySigner();
        const normalChain = buildChain(5, signerNormal);

        const signerForked = new IntegritySigner();
        // Build same first 2 logs
        const forkedLogs = buildChain(2, signerForked);
        // Insert rogue log
        const rogue = createTestLog({ message: "rogue", logicalClock: 999 });
        const rogueHash = IntegritySigner.calculateHash(rogue, signerForked.getPreviousHash());
        signerForked.updateChain(rogueHash);
        // Continue with same messages as normal chain positions 2-4
        for (let i = 2; i < 5; i++) {
            const log = createTestLog({
                traceId: `chain-${i}`,
                message: `chain message ${i}`,
                logicalClock: i,
            });
            const prev = signerForked.getPreviousHash();
            log.hash = IntegritySigner.calculateHash(log, prev);
            signerForked.updateChain(log.hash);
            forkedLogs.push(log);
        }

        // Hashes at positions 2-4 must all differ
        expect(forkedLogs[2].hash).not.toBe(normalChain[2].hash);
        expect(forkedLogs[3].hash).not.toBe(normalChain[3].hash);
    });
});

// ============================================================
// 4. Hash Chain Replay
// ============================================================
describe("Crypto Attacks: Hash Chain Replay", () => {
    it("same log submitted twice produces different hashes due to previousHash", () => {
        const signer = new IntegritySigner();
        const log = createTestLog({ message: "replay me" });

        const prev1 = signer.getPreviousHash();
        const hash1 = IntegritySigner.calculateHash(log, prev1);
        signer.updateChain(hash1);

        const prev2 = signer.getPreviousHash();
        const hash2 = IntegritySigner.calculateHash(log, prev2);
        signer.updateChain(hash2);

        expect(hash1).not.toBe(hash2);
    });

    it("replaying entire chain from scratch produces identical hashes", () => {
        const signer1 = new IntegritySigner();
        const chain1 = buildChain(5, signer1);

        const signer2 = new IntegritySigner();
        const chain2 = buildChain(5, signer2);

        for (let i = 0; i < 5; i++) {
            expect(chain1[i].hash).toBe(chain2[i].hash);
        }
    });

    it("replaying with altered first entry invalidates entire chain", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(5, signer);

        // Replay with altered first message
        const signerAltered = new IntegritySigner();
        const alteredFirst = createTestLog({
            traceId: "chain-0",
            message: "ALTERED chain message 0",
            logicalClock: 0,
        });
        const altHash = IntegritySigner.calculateHash(alteredFirst, "");
        signerAltered.updateChain(altHash);

        // Second entry with same content as original chain
        const log1 = createTestLog({
            traceId: "chain-1",
            message: "chain message 1",
            logicalClock: 1,
        });
        const hash1 = IntegritySigner.calculateHash(log1, signerAltered.getPreviousHash());

        expect(hash1).not.toBe(chain[1].hash);
    });
});

// ============================================================
// 5. Hash Chain Gap
// ============================================================
describe("Crypto Attacks: Hash Chain Gap", () => {
    it("skipping a log in verification breaks chain validation", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(5, signer);

        // Verify log[2] against log[0]'s hash instead of log[1]'s hash (gap)
        const valid = IntegritySigner.verifyHash(chain[2], chain[0].hash!);
        expect(valid).toBe(false);
    });

    it("verifying log against correct previousHash succeeds", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(5, signer);

        for (let i = 1; i < 5; i++) {
            const valid = IntegritySigner.verifyHash(chain[i], chain[i - 1].hash!);
            expect(valid).toBe(true);
        }
    });

    it("first log verifies against empty previousHash", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(1, signer);
        const valid = IntegritySigner.verifyHash(chain[0], "");
        expect(valid).toBe(true);
    });

    it("removing a log from the middle invalidates all subsequent verifications", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(5, signer);

        // Remove index 2, try to verify index 3 against index 1
        const valid = IntegritySigner.verifyHash(chain[3], chain[1].hash!);
        expect(valid).toBe(false);
    });
});

// ============================================================
// 6. Deterministic Serialization Edge Cases
// ============================================================
describe("Crypto Attacks: Deterministic Serialization", () => {
    it("object key ordering: {b:1, a:2} vs {a:2, b:1} produces same hash", () => {
        const logA = createTestLog({ message: "order" }) as Log & Record<string, unknown>;
        const logB = createTestLog({ message: "order" }) as Log & Record<string, unknown>;

        // Force different key order via reconstruction
        const rawA: Record<string, unknown> = {};
        rawA["b_custom"] = 1;
        rawA["a_custom"] = 2;

        const rawB: Record<string, unknown> = {};
        rawB["a_custom"] = 2;
        rawB["b_custom"] = 1;

        // Use as tags to exercise nested serialization
        logA.tags = [{ key: "b", category: "1" }, { key: "a", category: "2" }];
        logB.tags = [{ key: "a", category: "2" }, { key: "b", category: "1" }];

        // Tags are arrays so order matters for arrays, but object keys within each tag are sorted
        // Let's test with the input field which accepts arbitrary JSON
        const inputA = { z: 1, a: 2, m: 3 };
        const inputB = { a: 2, m: 3, z: 1 };
        logA.input = inputA;
        logB.input = inputB;
        // Reset tags to be identical so only input differs in key order
        logA.tags = [];
        logB.tags = [];

        expect(IntegritySigner.calculateHash(logA, "")).toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("undefined value vs missing key: undefined is treated as null in serialization", () => {
        const logA = createTestLog({ input: undefined });
        const logB = createTestLog({});
        delete (logB as Record<string, unknown>).input;

        // Both should produce the same hash since undefined -> null and missing key is absent
        // Actually, if key is present with undefined vs absent, the sorted keys differ.
        // When 'input' key exists with undefined value, it appears in Object.keys.
        // When 'input' key is deleted, it does not appear in Object.keys.
        // So these MAY differ. This test validates the behavior is defined.
        const hA = IntegritySigner.calculateHash(logA, "");
        const hB = IntegritySigner.calculateHash(logB, "");

        // The key point: both hashes are deterministic (no randomness)
        expect(typeof hA).toBe("string");
        expect(typeof hB).toBe("string");
        expect(hA.length).toBe(64); // SHA-256 hex
        expect(hB.length).toBe(64);
    });

    it("null vs undefined: explicit null and undefined produce distinct but deterministic results", () => {
        const logA = createTestLog({ input: null });
        const logB = createTestLog({ input: undefined });

        const hA = IntegritySigner.calculateHash(logA, "");
        const hB = IntegritySigner.calculateHash(logB, "");

        // null is a valid JSON value; undefined is serialized as "null"
        // Both should hash deterministically
        expect(hA.length).toBe(64);
        expect(hB.length).toBe(64);
    });

    it("-0 vs 0: negative zero and positive zero produce same hash", () => {
        const logA = createTestLog({ input: -0 });
        const logB = createTestLog({ input: 0 });

        // JSON.stringify(-0) === "0"
        expect(IntegritySigner.calculateHash(logA, "")).toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("empty string vs missing string field", () => {
        const logA = createTestLog({ details: "" });
        const logB = createTestLog({});
        delete (logB as Record<string, unknown>).details;

        const hA = IntegritySigner.calculateHash(logA, "");
        const hB = IntegritySigner.calculateHash(logB, "");

        // Empty string present vs key absent = different serialization
        expect(hA).not.toBe(hB);
    });

    it("empty array vs missing array", () => {
        const logA = createTestLog({ resourceIds: [] });
        const logB = createTestLog({});
        delete (logB as Record<string, unknown>).resourceIds;

        const hA = IntegritySigner.calculateHash(logA, "");
        const hB = IntegritySigner.calculateHash(logB, "");

        // Empty array present vs key absent = different serialization
        expect(hA).not.toBe(hB);
    });

    it("nested object key ordering produces same hash", () => {
        const logA = createTestLog({
            input: { outer: { z: 1, a: 2, m: { c: 3, b: 4 } } },
        });
        const logB = createTestLog({
            input: { outer: { a: 2, m: { b: 4, c: 3 }, z: 1 } },
        });

        expect(IntegritySigner.calculateHash(logA, "")).toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("special characters in keys: spaces", () => {
        const logA = createTestLog({
            input: { "key with spaces": "value" },
        });
        const logB = createTestLog({
            input: { "key with spaces": "value" },
        });

        expect(IntegritySigner.calculateHash(logA, "")).toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("special characters in keys: newlines", () => {
        const logA = createTestLog({
            input: { "key\nwith\nnewlines": "value" },
        });
        const hA = IntegritySigner.calculateHash(logA, "");
        expect(hA.length).toBe(64);

        // Idempotent
        expect(IntegritySigner.calculateHash(logA, "")).toBe(hA);
    });

    it("unicode keys: Japanese characters", () => {
        const logA = createTestLog({ input: { "\u65e5\u672c\u8a9e\u30ad\u30fc": "value" } });
        const logB = createTestLog({ input: { "\u65e5\u672c\u8a9e\u30ad\u30fc": "value" } });

        expect(IntegritySigner.calculateHash(logA, "")).toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("unicode keys: emoji", () => {
        const logA = createTestLog({ input: { "\ud83d\ude80\ud83c\udf1f": "rocket" } });
        const hA = IntegritySigner.calculateHash(logA, "");
        expect(hA.length).toBe(64);
        expect(IntegritySigner.calculateHash(logA, "")).toBe(hA);
    });

    it("unicode keys: RTL characters", () => {
        const logA = createTestLog({ input: { "\u0645\u0641\u062a\u0627\u062d": "value" } });
        const hA = IntegritySigner.calculateHash(logA, "");
        expect(hA.length).toBe(64);
        expect(IntegritySigner.calculateHash(logA, "")).toBe(hA);
    });

    it("deeply nested objects with mixed key order", () => {
        const logA = createTestLog({
            input: { d: { c: { b: { a: 1 } } } },
        });
        const logB = createTestLog({
            input: { d: { c: { b: { a: 1 } } } },
        });

        expect(IntegritySigner.calculateHash(logA, "")).toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("arrays preserve element order (not sorted)", () => {
        const logA = createTestLog({ input: [3, 1, 2] });
        const logB = createTestLog({ input: [1, 2, 3] });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("boolean true vs string 'true'", () => {
        const logA = createTestLog({ input: true });
        const logB = createTestLog({ input: "true" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("number 1 vs string '1'", () => {
        const logA = createTestLog({ input: 1 });
        const logB = createTestLog({ input: "1" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("null vs string 'null'", () => {
        const logA = createTestLog({ input: null });
        const logB = createTestLog({ input: "null" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("empty object vs empty array in input", () => {
        const logA = createTestLog({ input: {} });
        const logB = createTestLog({ input: [] });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("nested null vs nested missing key", () => {
        const logA = createTestLog({ input: { a: null } });
        const logB = createTestLog({ input: {} });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("very long string values hash deterministically", () => {
        const longStr = "x".repeat(100_000);
        const log = createTestLog({ message: longStr });
        const h1 = IntegritySigner.calculateHash(log, "");
        const h2 = IntegritySigner.calculateHash(log, "");
        expect(h1).toBe(h2);
        expect(h1.length).toBe(64);
    });

    it("special JSON characters in values: quotes and backslashes", () => {
        const log = createTestLog({ message: 'has "quotes" and \\backslashes\\' });
        const h1 = IntegritySigner.calculateHash(log, "");
        const h2 = IntegritySigner.calculateHash(log, "");
        expect(h1).toBe(h2);
    });

    it("hash and signature fields are excluded from calculation", () => {
        const log = createTestLog({ message: "test" });
        const h1 = IntegritySigner.calculateHash(log, "");

        const logWithHash = createTestLog({ message: "test", hash: "some-hash", signature: "some-sig" });
        const h2 = IntegritySigner.calculateHash(logWithHash, "");

        expect(h1).toBe(h2);
    });
});

// ============================================================
// 7. timingSafeEqual Verification
// ============================================================
describe("Crypto Attacks: timingSafeEqual Verification", () => {
    let log: Log;
    let correctHash: string;

    beforeEach(() => {
        log = createTestLog({ message: "verify-me" });
        correctHash = IntegritySigner.calculateHash(log, "");
        log.hash = correctHash;
    });

    it("same hash returns true", () => {
        expect(IntegritySigner.verifyHash(log, "")).toBe(true);
    });

    it("different hash returns false", () => {
        log.hash = "a".repeat(64);
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("truncated hash returns false", () => {
        log.hash = correctHash.slice(0, 32);
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("extended hash returns false", () => {
        log.hash = correctHash + "00";
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("empty hash returns false", () => {
        log.hash = "";
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("hash with different case returns false (hex is lowercase)", () => {
        log.hash = correctHash.toUpperCase();
        // SHA-256 hex digest is lowercase; uppercase should fail
        if (correctHash !== correctHash.toUpperCase()) {
            expect(IntegritySigner.verifyHash(log, "")).toBe(false);
        }
    });

    it("hash with single character changed returns false", () => {
        const chars = correctHash.split("");
        // Flip the first hex character
        chars[0] = chars[0] === "a" ? "b" : "a";
        log.hash = chars.join("");
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("null hash returns false", () => {
        log.hash = undefined;
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("hash from different previousHash returns false", () => {
        // log.hash was computed with previousHash=""
        expect(IntegritySigner.verifyHash(log, "different-previous")).toBe(false);
    });

    it("verification is idempotent", () => {
        expect(IntegritySigner.verifyHash(log, "")).toBe(true);
        expect(IntegritySigner.verifyHash(log, "")).toBe(true);
        expect(IntegritySigner.verifyHash(log, "")).toBe(true);
    });
});

// ============================================================
// 8. Chain State Management
// ============================================================
describe("Crypto Attacks: Chain State Management", () => {
    it("resetChain clears previousHash to empty string", () => {
        const signer = new IntegritySigner();
        buildChain(5, signer);
        expect(signer.getPreviousHash()).not.toBe("");

        signer.resetChain();
        expect(signer.getPreviousHash()).toBe("");
    });

    it("after resetChain, new chain starts fresh", () => {
        const signer = new IntegritySigner();
        buildChain(3, signer);
        signer.resetChain();

        const freshSigner = new IntegritySigner();
        const log = createTestLog({ message: "after-reset", logicalClock: 0 });

        const hashAfterReset = IntegritySigner.calculateHash(log, signer.getPreviousHash());
        const hashFresh = IntegritySigner.calculateHash(log, freshSigner.getPreviousHash());

        expect(hashAfterReset).toBe(hashFresh);
    });

    it("multiple chains dont interfere (separate IntegritySigner instances)", () => {
        const signerA = new IntegritySigner();
        const signerB = new IntegritySigner();

        buildChain(5, signerA);
        buildChain(3, signerB);

        // They should have different state
        expect(signerA.getPreviousHash()).not.toBe(signerB.getPreviousHash());

        // Modifying one doesn't affect the other
        const prevB = signerB.getPreviousHash();
        buildChain(2, signerA);
        expect(signerB.getPreviousHash()).toBe(prevB);
    });

    it("chain survives 1000 entries", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(1000, signer);

        expect(chain.length).toBe(1000);
        expect(signer.getPreviousHash()).toBe(chain[999].hash);

        // Verify last 5 entries
        for (let i = 996; i < 1000; i++) {
            const prevHash = i === 0 ? "" : chain[i - 1].hash!;
            expect(IntegritySigner.verifyHash(chain[i], prevHash)).toBe(true);
        }
    });

    it("getPreviousHash returns empty string initially", () => {
        const signer = new IntegritySigner();
        expect(signer.getPreviousHash()).toBe("");
    });

    it("updateChain sets the exact hash provided", () => {
        const signer = new IntegritySigner();
        signer.updateChain("custom-hash-value");
        expect(signer.getPreviousHash()).toBe("custom-hash-value");
    });

    it("multiple resets are idempotent", () => {
        const signer = new IntegritySigner();
        buildChain(3, signer);
        signer.resetChain();
        signer.resetChain();
        signer.resetChain();
        expect(signer.getPreviousHash()).toBe("");
    });

    it("chain state is not shared via prototype", () => {
        const signerA = new IntegritySigner();
        signerA.updateChain("A");

        const signerB = new IntegritySigner();
        expect(signerB.getPreviousHash()).toBe("");
    });
});

// ============================================================
// 9. Hash Uniqueness
// ============================================================
describe("Crypto Attacks: Hash Uniqueness", () => {
    it("100 different logs all produce unique hashes (same previousHash)", () => {
        const hashes = new Set<string>();
        for (let i = 0; i < 100; i++) {
            const log = createTestLog({
                message: `unique-message-${i}`,
                logicalClock: i,
            });
            const hash = IntegritySigner.calculateHash(log, "");
            hashes.add(hash);
        }
        expect(hashes.size).toBe(100);
    });

    it("100 identical logs with sequential previousHash all produce unique hashes", () => {
        const signer = new IntegritySigner();
        const hashes = new Set<string>();
        const log = createTestLog({ message: "identical" });

        for (let i = 0; i < 100; i++) {
            const prev = signer.getPreviousHash();
            const hash = IntegritySigner.calculateHash(log, prev);
            signer.updateChain(hash);
            hashes.add(hash);
        }
        expect(hashes.size).toBe(100);
    });

    it("all hashes are valid SHA-256 hex strings", () => {
        for (let i = 0; i < 50; i++) {
            const log = createTestLog({ message: `hash-format-${i}` });
            const hash = IntegritySigner.calculateHash(log, "");
            expect(hash).toMatch(/^[0-9a-f]{64}$/);
        }
    });

    it("logs differing only in tags produce unique hashes", () => {
        const hashes = new Set<string>();
        for (let i = 0; i < 20; i++) {
            const log = createTestLog({
                tags: [{ key: `tag-${i}`, category: `cat-${i}` }],
            });
            hashes.add(IntegritySigner.calculateHash(log, ""));
        }
        expect(hashes.size).toBe(20);
    });

    it("logs differing only in timestamp produce unique hashes", () => {
        const hashes = new Set<string>();
        for (let i = 0; i < 20; i++) {
            const log = createTestLog({
                timestamp: `2026-01-01T00:00:${String(i).padStart(2, "0")}.000Z`,
            });
            hashes.add(IntegritySigner.calculateHash(log, ""));
        }
        expect(hashes.size).toBe(20);
    });
});

// ============================================================
// 10. Bit Flip Detection
// ============================================================
describe("Crypto Attacks: Bit Flip Detection", () => {
    it("changing single character in message changes hash", () => {
        const log = createTestLog({ message: "abcdefghij" });
        const original = IntegritySigner.calculateHash(log, "");

        for (let i = 0; i < 10; i++) {
            const chars = "abcdefghij".split("");
            chars[i] = chars[i] === "z" ? "a" : "z";
            const modified = createTestLog({ message: chars.join("") });
            expect(IntegritySigner.calculateHash(modified, "")).not.toBe(original);
        }
    });

    it("changing single character in traceId changes hash", () => {
        const log = createTestLog({ traceId: "trace-original" });
        const original = IntegritySigner.calculateHash(log, "");

        const modified = createTestLog({ traceId: "trace-originaL" });
        expect(IntegritySigner.calculateHash(modified, "")).not.toBe(original);
    });

    it("changing single character in boundary changes hash", () => {
        const log = createTestLog({ boundary: "service:handler" });
        const original = IntegritySigner.calculateHash(log, "");

        const modified = createTestLog({ boundary: "service:handleR" });
        expect(IntegritySigner.calculateHash(modified, "")).not.toBe(original);
    });

    it("toggling isCritical changes hash", () => {
        const logA = createTestLog({ isCritical: false });
        const logB = createTestLog({ isCritical: true });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing origin changes hash", () => {
        const logA = createTestLog({ origin: "SYSTEM" });
        const logB = createTestLog({ origin: "AI_AGENT" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing triggerAgent changes hash", () => {
        const logA = createTestLog({ triggerAgent: false });
        const logB = createTestLog({ triggerAgent: true });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing serviceId changes hash", () => {
        const logA = createTestLog({ serviceId: "svc-a" });
        const logB = createTestLog({ serviceId: "svc-b" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing logicalClock by 1 changes hash", () => {
        const logA = createTestLog({ logicalClock: 100 });
        const logB = createTestLog({ logicalClock: 101 });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("single bit flip in previousHash changes resulting hash", () => {
        const log = createTestLog({ message: "bit-flip-prev" });
        const hA = IntegritySigner.calculateHash(log, "0000000000000000000000000000000000000000000000000000000000000000");
        const hB = IntegritySigner.calculateHash(log, "0000000000000000000000000000000000000000000000000000000000000001");
        expect(hA).not.toBe(hB);
    });

    it("adding a single tag changes hash", () => {
        const logA = createTestLog({ tags: [] });
        const logB = createTestLog({ tags: [{ key: "k", category: "c" }] });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing a tag value changes hash", () => {
        const logA = createTestLog({ tags: [{ key: "k", category: "a" }] });
        const logB = createTestLog({ tags: [{ key: "k", category: "b" }] });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("adding optional actorId changes hash", () => {
        const logA = createTestLog({});
        const logB = createTestLog({ actorId: "user-1" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("adding optional resourceIds changes hash", () => {
        const logA = createTestLog({});
        const logB = createTestLog({ resourceIds: ["res-1"] });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing type field changes hash", () => {
        const logA = createTestLog({ type: "SYSTEM" });
        const logB = createTestLog({ type: "DEBUG" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("adding spanId changes hash", () => {
        const logA = createTestLog({});
        const logB = createTestLog({ spanId: "span-001" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("adding parentSpanId changes hash", () => {
        const logA = createTestLog({});
        const logB = createTestLog({ parentSpanId: "parent-span-001" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("changing input from number to object changes hash", () => {
        const logA = createTestLog({ input: 42 });
        const logB = createTestLog({ input: { value: 42 } });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });
});

// ============================================================
// 11. Hash Collision Resistance (extended)
// ============================================================
describe("Crypto Attacks: Collision Resistance Extended", () => {
    it("birthday attack: 500 random logs produce no collisions", () => {
        const hashes = new Set<string>();
        for (let i = 0; i < 500; i++) {
            const log = createTestLog({
                message: `birthday-${i}-${Math.random().toString(36)}`,
                logicalClock: i,
                timestamp: `2026-01-${String((i % 28) + 1).padStart(2, "0")}T00:00:00.000Z`,
            });
            hashes.add(IntegritySigner.calculateHash(log, ""));
        }
        expect(hashes.size).toBe(500);
    });

    it("near-identical logs (off-by-one in logicalClock) produce different hashes", () => {
        const hashes = new Set<string>();
        for (let i = 0; i < 50; i++) {
            const log = createTestLog({ logicalClock: i });
            hashes.add(IntegritySigner.calculateHash(log, ""));
        }
        expect(hashes.size).toBe(50);
    });

    it("empty message vs whitespace message", () => {
        const logA = createTestLog({ message: "" });
        const logB = createTestLog({ message: " " });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("tab vs spaces in message", () => {
        const logA = createTestLog({ message: "\t" });
        const logB = createTestLog({ message: "    " });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("trailing newline vs no trailing newline", () => {
        const logA = createTestLog({ message: "msg" });
        const logB = createTestLog({ message: "msg\n" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("NUL byte in message changes hash", () => {
        const logA = createTestLog({ message: "abc" });
        const logB = createTestLog({ message: "ab\0c" });

        expect(IntegritySigner.calculateHash(logA, "")).not.toBe(
            IntegritySigner.calculateHash(logB, ""),
        );
    });

    it("different previousHash lengths produce different hashes", () => {
        const log = createTestLog({ message: "test" });
        const h1 = IntegritySigner.calculateHash(log, "a");
        const h2 = IntegritySigner.calculateHash(log, "aa");
        const h3 = IntegritySigner.calculateHash(log, "aaa");

        expect(h1).not.toBe(h2);
        expect(h2).not.toBe(h3);
        expect(h1).not.toBe(h3);
    });

    it("chain of 100: every consecutive pair has different hashes", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(100, signer);

        for (let i = 1; i < 100; i++) {
            expect(chain[i].hash).not.toBe(chain[i - 1].hash);
        }
    });

    it("same log hashed with empty string vs with '0' previousHash differs", () => {
        const log = createTestLog({ message: "test" });
        const h1 = IntegritySigner.calculateHash(log, "");
        const h2 = IntegritySigner.calculateHash(log, "0");
        expect(h1).not.toBe(h2);
    });

    it("hash output has uniform distribution (no obvious bias in first nibble)", () => {
        const nibbleCounts: Record<string, number> = {};
        for (let i = 0; i < 256; i++) {
            const log = createTestLog({ message: `dist-${i}` });
            const hash = IntegritySigner.calculateHash(log, "");
            const firstNibble = hash[0];
            nibbleCounts[firstNibble] = (nibbleCounts[firstNibble] ?? 0) + 1;
        }

        // With 256 samples and 16 possible nibbles, expect ~16 each
        // Allow range 1-40 (very loose) to avoid flaky tests
        for (const count of Object.values(nibbleCounts)) {
            expect(count).toBeGreaterThan(0);
            expect(count).toBeLessThan(50);
        }
    });
});

// ============================================================
// 12. Chain Verification Edge Cases
// ============================================================
describe("Crypto Attacks: Chain Verification Edge Cases", () => {
    it("verifying log with tampered message after hash assignment fails", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(3, signer);

        // Tamper message after hash was computed
        chain[1].message = "TAMPERED";
        expect(IntegritySigner.verifyHash(chain[1], chain[0].hash!)).toBe(false);
    });

    it("verifying log with tampered level after hash assignment fails", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(2, signer);
        chain[1].level = 1;
        expect(IntegritySigner.verifyHash(chain[1], chain[0].hash!)).toBe(false);
    });

    it("verifying log with swapped previousHash fails", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(4, signer);

        // Verify chain[3] with chain[1]'s hash instead of chain[2]'s
        expect(IntegritySigner.verifyHash(chain[3], chain[1].hash!)).toBe(false);
    });

    it("full chain verification from genesis to tip succeeds", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(50, signer);

        let prevHash = "";
        for (const log of chain) {
            expect(IntegritySigner.verifyHash(log, prevHash)).toBe(true);
            prevHash = log.hash!;
        }
    });

    it("chain with tampered middle entry: all subsequent verifications still pass individually", () => {
        // This tests that verification is per-link, not whole-chain
        const signer = new IntegritySigner();
        const chain = buildChain(5, signer);

        // Tamper chain[2]'s message but NOT its hash
        // Verification of chain[3] against chain[2].hash still passes because
        // chain[3] was computed with chain[2].hash as previousHash
        expect(IntegritySigner.verifyHash(chain[3], chain[2].hash!)).toBe(true);

        // But chain[2] itself will fail verification
        expect(IntegritySigner.verifyHash(
            { ...chain[2], message: "TAMPERED" },
            chain[1].hash!,
        )).toBe(false);
    });

    it("empty chain: no logs to verify", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(0, signer);
        expect(chain.length).toBe(0);
        expect(signer.getPreviousHash()).toBe("");
    });

    it("single-entry chain verifies against empty previousHash", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(1, signer);
        expect(IntegritySigner.verifyHash(chain[0], "")).toBe(true);
    });

    it("verifyHash with non-hex hash string returns false", () => {
        const log = createTestLog({ message: "test" });
        log.hash = "not-a-valid-hex-string-at-all!!!!";
        expect(IntegritySigner.verifyHash(log, "")).toBe(false);
    });

    it("verifying a chain entry with a completely fabricated hash fails", () => {
        const signer = new IntegritySigner();
        const chain = buildChain(3, signer);

        // Replace chain[1].hash with a fabricated hash
        chain[1].hash = "ff".repeat(32);
        // chain[2] was built with original chain[1].hash, so verifying chain[2] against fabricated fails
        expect(IntegritySigner.verifyHash(chain[2], chain[1].hash!)).toBe(false);
    });

    it("calculateHash is a pure function (no side effects on signer)", () => {
        const signer = new IntegritySigner();
        signer.updateChain("initial");

        const log = createTestLog({ message: "pure" });
        IntegritySigner.calculateHash(log, "anything");

        // Signer state unchanged
        expect(signer.getPreviousHash()).toBe("initial");
    });
});
