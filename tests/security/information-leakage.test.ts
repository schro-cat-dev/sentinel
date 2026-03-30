/**
 * Security Test: Information Leakage
 *
 * Tests that internal implementation details, file paths, and
 * sensitive data are not exposed through error messages or outputs.
 *
 * CWE-209: Generation of Error Message Containing Sensitive Information
 */
import { describe, it, expect, vi } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError, validateLogInput } from "../../src/index";
import { MaskingService } from "../../src/security/masking-service";
import { IntegritySigner } from "../../src/security/integrity-signer";
import { createTestLog } from "../helpers/fixtures";
import type { MaskingRule } from "../../src/configs/masking-rule";

describe("Security: Information Leakage prevention", () => {
    describe("Error messages", () => {
        it("ValidationError does not leak internal paths", () => {
            try {
                const log = createTestLog();
                (log as Record<string, unknown>).message = "";
                validateLogInput(log);
                // Should not reach here
                expect.unreachable("Expected validation to throw");
            } catch (e) {
                expect(e).toBeInstanceOf(Error);
                const msg = (e as Error).message;
                // Should not contain file paths
                expect(msg).not.toMatch(/\/Users\//);
                expect(msg).not.toMatch(/node_modules/);
                expect(msg).not.toMatch(/\.ts:/);
            }
        });

        it("ValidationError contains only field name and user-safe message", () => {
            try {
                validateLogInput({ message: "" });
            } catch (e) {
                if (e instanceof ValidationError) {
                    expect(e.field).toBeDefined();
                    expect(e.message).toBeDefined();
                    // Should not contain stack trace snippets in message
                    expect(e.message).not.toMatch(/at\s+\w+\s+\(/);
                }
            }
        });
    });

    describe("Masking service error handling", () => {
        it("does not expose internal state on rule failure", () => {
            const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

            const badRule: MaskingRule = {
                type: "REGEX",
                pattern: /test/g,
                replacement: "$<nonexistent>",
                description: "bad replacement",
            };

            const log = createTestLog({ message: "test data" });
            MaskingService.mask(log, [badRule]);

            // If console.warn was called, check it doesn't contain stack traces
            for (const call of consoleWarnSpy.mock.calls) {
                const args = call.map(String);
                for (const arg of args) {
                    expect(arg).not.toMatch(/\/Users\//);
                    expect(arg).not.toMatch(/node_modules/);
                }
            }

            consoleWarnSpy.mockRestore();
        });
    });

    describe("PII in processed output", () => {
        it("PII is masked before reaching output when masking is enabled", () => {
            Sentinel.reset();

            const config = createDefaultConfig({
                projectName: "test",
                serviceId: "test-svc",
            });
            config.environment = "test";
            config.masking.enabled = true;
            config.masking.rules = [
                { type: "PII_TYPE", category: "EMAIL" },
                { type: "PII_TYPE", category: "CREDIT_CARD" },
            ];

            let processedLog: Record<string, unknown> | null = null;
            config.onLogProcessed = (log) => {
                processedLog = { ...log } as Record<string, unknown>;
            };

            const sentinel = Sentinel.initialize(config);

            sentinel.ingest({
                message:
                    "User alice@secret.com paid with 4111-1111-1111-1111",
                level: 3,
                type: "BUSINESS-AUDIT",
            });

            // Wait for async processing
            return new Promise<void>((resolve) => {
                setTimeout(() => {
                    if (processedLog) {
                        const msg = String(processedLog.message);
                        expect(msg).not.toContain("alice@secret.com");
                        expect(msg).not.toContain("4111-1111-1111-1111");
                    }
                    Sentinel.reset();
                    resolve();
                }, 100);
            });
        });
    });

    describe("Hash values", () => {
        it("hash does not encode plaintext data recoverable by inspection", () => {
            const log = createTestLog({
                message: "SECRET_PASSWORD=hunter2",
            });

            const hash = IntegritySigner.calculateHash(log, "");

            // Hash should be hex-only, not containing any plaintext
            expect(hash).toMatch(/^[a-f0-9]{64}$/);
            expect(hash).not.toContain("hunter2");
            expect(hash).not.toContain("SECRET");
        });
    });
});
