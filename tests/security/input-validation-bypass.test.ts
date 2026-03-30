/**
 * Security Test: Input Validation Bypass
 *
 * Tests that the validation layer correctly rejects malicious,
 * malformed, and edge-case inputs at the trust boundary.
 *
 * CWE-20: Improper Input Validation
 * CWE-74: Injection
 */
import { describe, it, expect } from "vitest";
import { validateLogInput, ValidationError } from "../../src/index";
import { createTestLog } from "../helpers/fixtures";
import type { Log } from "../../src/types/log";

describe("Security: Input Validation Bypass resistance", () => {
    describe("Null byte injection (CWE-626)", () => {
        it("rejects null bytes in message", () => {
            const log = createTestLog({
                message: "normal\x00<script>alert(1)</script>",
            });

            expect(() => validateLogInput(log)).toThrow(ValidationError);
        });

        it("rejects null bytes at start of message", () => {
            const log = createTestLog({
                message: "\x00malicious",
            });

            expect(() => validateLogInput(log)).toThrow(ValidationError);
        });

        it("rejects null bytes at end of message", () => {
            const log = createTestLog({
                message: "looks normal\x00",
            });

            expect(() => validateLogInput(log)).toThrow(ValidationError);
        });
    });

    describe("Maximum length enforcement", () => {
        it("rejects messages at exactly max+1 length", () => {
            const log = createTestLog({
                message: "A".repeat(65537),
            });

            expect(() => validateLogInput(log)).toThrow();
        });

        it("accepts messages at exactly max length", () => {
            const log = createTestLog({
                message: "A".repeat(65536),
            });

            expect(() => validateLogInput(log)).not.toThrow();
        });

        it("rejects messages that are long after unicode expansion", () => {
            // Some unicode chars are multi-byte but JS .length counts code units
            const log = createTestLog({
                message: "\u{1F600}".repeat(32769), // Each emoji is 2 code units
            });

            expect(() => validateLogInput(log)).toThrow();
        });
    });

    describe("Type coercion attacks", () => {
        it("rejects numeric message", () => {
            const log = createTestLog();
            (log as Record<string, unknown>).message = 123;

            expect(() => validateLogInput(log as Partial<Log>)).toThrow();
        });

        it("rejects object with toString as message", () => {
            const log = createTestLog();
            (log as Record<string, unknown>).message = {
                toString: () => "injected",
            };

            expect(() => validateLogInput(log as Partial<Log>)).toThrow();
        });

        it("rejects array as message", () => {
            const log = createTestLog();
            (log as Record<string, unknown>).message = ["injected"];

            expect(() => validateLogInput(log as Partial<Log>)).toThrow();
        });

        it("rejects boolean as message", () => {
            const log = createTestLog();
            (log as Record<string, unknown>).message = true;

            expect(() => validateLogInput(log as Partial<Log>)).toThrow();
        });
    });

    describe("Empty / whitespace message", () => {
        it("rejects empty string", () => {
            const log = createTestLog({ message: "" });

            expect(() => validateLogInput(log)).toThrow();
        });

        it("rejects whitespace-only message", () => {
            const log = createTestLog({ message: "   \t\n   " });

            expect(() => validateLogInput(log)).toThrow();
        });

        it("rejects single space", () => {
            const log = createTestLog({ message: " " });

            expect(() => validateLogInput(log)).toThrow();
        });
    });

    describe("Tag injection", () => {
        it("rejects excessive tag count", () => {
            const tags = Array.from({ length: 101 }, (_, i) => ({
                key: `key-${i}`,
                category: "test",
            }));

            const log = createTestLog({ tags });

            expect(() => validateLogInput(log)).toThrow();
        });

        it("rejects tags with excessively long keys", () => {
            const log = createTestLog({
                tags: [{ key: "k".repeat(129), category: "test" }],
            });

            expect(() => validateLogInput(log)).toThrow();
        });

        it("rejects tags with excessively long values", () => {
            const log = createTestLog({
                tags: [{ key: "normal", category: "v".repeat(1025) }],
            });

            expect(() => validateLogInput(log)).toThrow();
        });
    });

    describe("Invalid log type / origin", () => {
        it("rejects unknown log type", () => {
            const log = createTestLog();
            (log as Record<string, unknown>).type = "MALICIOUS_TYPE";

            expect(() => validateLogInput(log as Partial<Log>)).toThrow();
        });

        it("rejects unknown origin", () => {
            const log = createTestLog();
            (log as Record<string, unknown>).origin = "ATTACKER";

            expect(() => validateLogInput(log as Partial<Log>)).toThrow();
        });
    });

    describe("Resource ID limits", () => {
        it("rejects excessive resourceIds count", () => {
            const log = createTestLog({
                resourceIds: Array.from({ length: 101 }, (_, i) => `res-${i}`),
            });

            expect(() => validateLogInput(log)).toThrow();
        });
    });
});
