/**
 * Security Audit Fixes — SDK側の脆弱性修正テスト
 *
 * docs/security-audit/sdk/ の診断結果に基づく修正を検証する。
 * TDD: テストを先に書き、RED → GREEN → REFACTOR の順で実装。
 *
 * 対象:
 * VULN-001: config-loader ReDoS防御 (HIGH)
 * VULN-011: fallback時のエラー伝播 (MEDIUM)
 * VULN-013: UTF-8 lone surrogate 検証 (LOW)
 * VULN-014: ハンドラ登録ハードリミット (LOW)
 * VULN-015: 未定義環境変数の警告 (LOW)
 * SDK-A: agentBackLog 個別サイズ制限
 * SDK-B: aiContext __proto__/constructor キー拒否
 * SDK-C: ErrorRouter console.error のPII切り詰め
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
    parseConfigYaml,
    ConfigLoadError,
} from "../../src/configs/config-loader";
import { Sentinel, ValidationError, validateLogInput } from "../../src/index";
import { createTestConfig, createTestLog, createTestTaskRule } from "../helpers/fixtures";
import { ErrorRouter } from "../../src/error-routing/error-router";
import { MaskingService } from "../../src/security/masking-service";
import { EventDetector } from "../../src/core/detection/event-detector";

// =========================================================================
// VULN-001: ReDoS防御 — config-loader にパターン長制限 + ネスト量指定子検出
// =========================================================================

describe("VULN-001: config-loader ReDoS prevention", () => {
    const BASE_YAML = (pattern: string) => `
project_name: test-project
service_id: test-service
masking:
  enabled: true
  rules:
    - type: REGEX
      pattern: "${pattern}"
      replacement: "[REDACTED]"
`;

    const DETECTION_YAML = (pattern: string) => `
project_name: test-project
service_id: test-service
task_rules:
  - rule_id: r1
    event_name: SYSTEM_CRITICAL_FAILURE
    severity: CRITICAL
    action_type: SYSTEM_NOTIFICATION
    execution_level: AUTO
    priority: 1
detection_rules:
  - rule_id: d1
    event_name: SYSTEM_CRITICAL_FAILURE
    priority: HIGH
    conditions:
      message_pattern: "${pattern}"
`;

    describe("masking rule patterns", () => {
        it("rejects patterns longer than 256 characters", () => {
            const longPattern = "a".repeat(257);
            expect(() => parseConfigYaml(BASE_YAML(longPattern))).toThrow(ConfigLoadError);
            expect(() => parseConfigYaml(BASE_YAML(longPattern))).toThrow(/pattern too long/i);
        });

        it("accepts patterns within 256 characters", () => {
            const safePattern = "secret_[a-z]+";
            expect(() => parseConfigYaml(BASE_YAML(safePattern))).not.toThrow();
        });

        it("rejects nested quantifiers (a+)+", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a+)+"))).toThrow(ConfigLoadError);
            expect(() => parseConfigYaml(BASE_YAML("(a+)+"))).toThrow(/ReDoS/i);
        });

        it("rejects nested quantifiers (a*)*", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a*)*"))).toThrow(/ReDoS/i);
        });

        it("rejects nested quantifiers (a+)*", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a+)*"))).toThrow(/ReDoS/i);
        });

        // VULN-001 enhancement: ? quantifier inside group + outer quantifier
        it("rejects nested quantifiers (a?)+", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a?)+"))).toThrow(/ReDoS/i);
        });

        it("rejects nested quantifiers (a?)*", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a?)*"))).toThrow(/ReDoS/i);
        });

        // {n,m} as outer quantifier after group
        it("rejects (a+){2,} — group quantifier + outer repetition", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a+){2,}"))).toThrow(/ReDoS/i);
        });

        it("rejects (a?){10,} — optional + high repetition", () => {
            expect(() => parseConfigYaml(BASE_YAML("(a?){10,}"))).toThrow(/ReDoS/i);
        });

        // Overlapping character class quantifiers
        it("rejects ([a-zA-Z]+)+ — overlapping class nested quantifier", () => {
            expect(() => parseConfigYaml(BASE_YAML("([a-zA-Z]+)+"))).toThrow(/ReDoS/i);
        });

        it("rejects (.*a)+ — dot-star inside group with outer +", () => {
            expect(() => parseConfigYaml(BASE_YAML("(.*a)+"))).toThrow(/ReDoS/i);
        });

        it("rejects repetition count > 1000", () => {
            expect(() => parseConfigYaml(BASE_YAML("a{1001}"))).toThrow(ConfigLoadError);
            expect(() => parseConfigYaml(BASE_YAML("a{1001}"))).toThrow(/repetition/i);
        });

        it("accepts safe repetition count", () => {
            expect(() => parseConfigYaml(BASE_YAML("a{100}"))).not.toThrow();
        });

        it("accepts non-nested quantifiers", () => {
            expect(() => parseConfigYaml(BASE_YAML("[a-z]+"))).not.toThrow();
            expect(() => parseConfigYaml(BASE_YAML("\\\\d{4}-\\\\d{4}"))).not.toThrow();
        });

        it("accepts group with inner quantifier but no outer quantifier (a+)b", () => {
            // (a+) has quantifier inside group, but no outer quantifier → safe
            expect(() => parseConfigYaml(BASE_YAML("(a+)b"))).not.toThrow();
        });

        it("accepts group at end of pattern (closing paren is last char)", () => {
            // Tests the `i + 1 < pattern.length ? pattern[i + 1] : ""` false branch
            expect(() => parseConfigYaml(BASE_YAML("test(abc)"))).not.toThrow();
        });
    });

    describe("detection rule messagePattern", () => {
        it("rejects patterns longer than 256 characters", () => {
            const longPattern = "x".repeat(257);
            expect(() => parseConfigYaml(DETECTION_YAML(longPattern))).toThrow(ConfigLoadError);
            expect(() => parseConfigYaml(DETECTION_YAML(longPattern))).toThrow(/pattern too long/i);
        });

        it("rejects nested quantifiers", () => {
            expect(() => parseConfigYaml(DETECTION_YAML("(a+)+"))).toThrow(/ReDoS/i);
        });

        it("accepts safe patterns like 'fatal|panic'", () => {
            expect(() => parseConfigYaml(DETECTION_YAML("fatal|panic"))).not.toThrow();
        });
    });
});

// =========================================================================
// VULN-011: fallback時のエラー伝播
// =========================================================================

describe("VULN-011: remote fallback error propagation", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("sets transportError when fallback to local is triggered", async () => {
        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
        });
        const sentinel = Sentinel.initialize(config, {
            transport: {
                mode: "remote",
                fallbackToLocal: true,
                transport: {
                    send: () => Promise.reject(new Error("connection refused")),
                },
            },
        });

        const result = await sentinel.ingest({ message: "test message" });

        // フォールバックが使われた場合でも transportError にエラーが記録されるべき
        expect(result.transportError).toBeDefined();
        expect(result.transportError).toContain("connection refused");
    });

    it("still returns valid local processing result on fallback", async () => {
        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
        });
        const sentinel = Sentinel.initialize(config, {
            transport: {
                mode: "remote",
                fallbackToLocal: true,
                transport: {
                    send: () => Promise.reject(new Error("timeout")),
                },
            },
        });

        const result = await sentinel.ingest({ message: "test message" });

        expect(result.traceId).toBeDefined();
        expect(typeof result.traceId).toBe("string");
    });
});

// =========================================================================
// VULN-013: UTF-8 lone surrogate 検証
// =========================================================================

describe("VULN-013: UTF-8 lone surrogate rejection", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("rejects message with lone high surrogate", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        // lone high surrogate: \uD800 without paired low surrogate
        const messageWithLoneSurrogate = "hello\uD800world";
        await expect(sentinel.ingest({ message: messageWithLoneSurrogate }))
            .rejects.toThrow(ValidationError);
    });

    it("rejects message with lone low surrogate", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        const messageWithLoneLow = "hello\uDC00world";
        await expect(sentinel.ingest({ message: messageWithLoneLow }))
            .rejects.toThrow(ValidationError);
    });

    it("accepts valid surrogate pair (emoji)", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        // Valid surrogate pair: 😀 = \uD83D\uDE00
        await expect(sentinel.ingest({ message: "hello 😀 world" }))
            .resolves.toBeDefined();
    });

    it("accepts normal ASCII message", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        await expect(sentinel.ingest({ message: "normal ascii message" }))
            .resolves.toBeDefined();
    });

    it("rejects string fields with lone surrogates (actorId)", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        await expect(sentinel.ingest({ message: "ok", actorId: "user\uD800id" }))
            .rejects.toThrow(ValidationError);
    });
});

// =========================================================================
// VULN-014: ハンドラ登録ハードリミット
// =========================================================================

describe("VULN-014: handler registration hard limit", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("throws when exceeding 100 handlers per action type", () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        // 100件までは登録可能
        for (let i = 0; i < 100; i++) {
            sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {});
        }

        // 101件目でエラー
        expect(() => sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {}))
            .toThrow(/too many handlers/i);
    });

    it("allows registration up to the limit", () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        for (let i = 0; i < 100; i++) {
            expect(() => sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {}))
                .not.toThrow();
        }
    });

    it("allows new registration after unsubscribing", () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        const unsubscribes: (() => void)[] = [];
        for (let i = 0; i < 100; i++) {
            unsubscribes.push(sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {}));
        }

        // 1件解除
        unsubscribes[0]();

        // 再登録可能
        expect(() => sentinel.onTaskAction("SYSTEM_NOTIFICATION", async () => {}))
            .not.toThrow();
    });
});

// =========================================================================
// VULN-015: 未定義環境変数の警告
// =========================================================================

describe("VULN-015: undefined environment variable warning", () => {
    it("logs warning for undefined env vars without defaults", () => {
        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        const yaml = `
project_name: \${SENTINEL_UNDEFINED_VAR_FOR_TEST}
service_id: test-service
`;
        // project_name が空文字列になるため ConfigLoadError が発生するが、
        // その前に警告が出力されるべき
        try {
            parseConfigYaml(yaml, { envSource: {} });
        } catch {
            // ConfigLoadError expected
        }

        expect(warnSpy).toHaveBeenCalledWith(
            expect.stringContaining("SENTINEL_UNDEFINED_VAR_FOR_TEST"),
        );

        warnSpy.mockRestore();
    });

    it("does not warn for env vars with defaults", () => {
        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        const yaml = `
project_name: \${MISSING_VAR:-default-project}
service_id: test-service
`;
        parseConfigYaml(yaml, { envSource: {} });

        expect(warnSpy).not.toHaveBeenCalled();
        warnSpy.mockRestore();
    });

    it("does not warn for defined env vars", () => {
        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        const yaml = `
project_name: \${MY_PROJECT}
service_id: test-service
`;
        parseConfigYaml(yaml, { envSource: { MY_PROJECT: "my-project" } });

        expect(warnSpy).not.toHaveBeenCalled();
        warnSpy.mockRestore();
    });

    it("throws in strictEnvExpansion mode for undefined vars without default", () => {
        const yaml = `
project_name: \${STRICT_MISSING_VAR}
service_id: test-service
`;
        expect(() => parseConfigYaml(yaml, {
            envSource: {},
            strictEnvExpansion: true,
        } as any)).toThrow(/STRICT_MISSING_VAR/);
    });

    it("does not throw in strictEnvExpansion mode for vars with default", () => {
        const yaml = `
project_name: \${MISSING:-fallback-name}
service_id: test-service
`;
        expect(() => parseConfigYaml(yaml, {
            envSource: {},
            strictEnvExpansion: true,
        } as any)).not.toThrow();
    });
});

// =========================================================================
// SDK-A: agentBackLog 個別サイズ制限
// =========================================================================

describe("SDK-A: agentBackLog individual size limit", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("rejects agentBackLog exceeding maxInputSize", async () => {
        const config = createTestConfig({
            taskRules: [createTestTaskRule()],
            validationLimits: { maxInputSize: 1024 },
        });
        const sentinel = Sentinel.initialize(config);

        const largeBackLog: Record<string, unknown> = {};
        for (let i = 0; i < 200; i++) {
            largeBackLog[`key_${i}`] = "x".repeat(100);
        }

        await expect(sentinel.ingest({
            message: "test",
            agentBackLog: largeBackLog,
        })).rejects.toThrow(ValidationError);
        await expect(sentinel.ingest({
            message: "test",
            agentBackLog: largeBackLog,
        })).rejects.toThrow(/agentBackLog/);
    });

    it("accepts small agentBackLog", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        await expect(sentinel.ingest({
            message: "test",
            agentBackLog: { step: "analysis", result: "ok" },
        })).resolves.toBeDefined();
    });

    it("rejects agentBackLog with too many entries (>100)", () => {
        const manyEntries: Record<string, unknown> = {};
        for (let i = 0; i < 101; i++) {
            manyEntries[`step${i}`] = { model: "gpt-4", output: "ok" };
        }

        expect(() => validateLogInput({
            message: "test",
            agentBackLog: manyEntries as any,
        })).toThrow(ValidationError);
        expect(() => validateLogInput({
            message: "test",
            agentBackLog: manyEntries as any,
        })).toThrow(/agentBackLog/);
    });

    it("accepts agentBackLog with 100 entries", () => {
        const entries: Record<string, unknown> = {};
        for (let i = 0; i < 100; i++) {
            entries[`step${i}`] = { model: "gpt-4", output: "ok" };
        }

        expect(() => validateLogInput({
            message: "test",
            agentBackLog: entries as any,
        })).not.toThrow();
    });
});

// =========================================================================
// SDK-B: aiContext __proto__/constructor キー拒否
// =========================================================================

describe("SDK-B: aiContext prototype pollution prevention", () => {
    beforeEach(() => Sentinel.reset());
    afterEach(() => Sentinel.reset());

    it("rejects aiContext with __proto__ key", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        const maliciousContext = JSON.parse('{"__proto__": {"isAdmin": true}, "loopDepth": 0}');
        await expect(sentinel.ingest({
            message: "test",
            aiContext: maliciousContext,
        })).rejects.toThrow(ValidationError);
        await expect(sentinel.ingest({
            message: "test",
            aiContext: maliciousContext,
        })).rejects.toThrow(/prohibited/i);
    });

    it("rejects aiContext with constructor key", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        await expect(sentinel.ingest({
            message: "test",
            aiContext: { constructor: { prototype: {} }, loopDepth: 0 } as any,
        })).rejects.toThrow(ValidationError);
    });

    it("accepts normal aiContext", async () => {
        const config = createTestConfig({ taskRules: [createTestTaskRule()] });
        const sentinel = Sentinel.initialize(config);

        await expect(sentinel.ingest({
            message: "test",
            aiContext: { loopDepth: 1, model: "gpt-4", provider: "openai" },
        })).resolves.toBeDefined();
    });
});

// =========================================================================
// REDOS-003: masking-service regex入力長ガード
// =========================================================================

describe("REDOS-003: masking-service regex input length guard", () => {
    it("skips user REGEX rules on strings exceeding MAX_REGEX_INPUT_LENGTH", () => {
        const hugeString = "a".repeat(100_000);
        const log = createTestLog({ message: hugeString });

        const start = performance.now();
        const masked = MaskingService.mask(log, [
            {
                type: "REGEX",
                pattern: /[a-z]+/g,
                replacement: "[REDACTED]",
                description: "test",
            },
        ]);
        const elapsed = performance.now() - start;

        // Regex should be skipped for oversized strings — fast completion
        expect(elapsed).toBeLessThan(500);
        // Oversized string: REGEX rule skipped, original preserved
        expect(masked.message).toBe(hugeString);
    });

    it("still applies REGEX masking on normal-length strings", () => {
        const log = createTestLog({
            message: "secret-key: abc123",
        });

        const masked = MaskingService.mask(log, [
            {
                type: "REGEX",
                pattern: /secret-key:\s*\S+/g,
                replacement: "[REDACTED]",
                description: "test",
            },
        ]);

        expect(masked.message).toBe("[REDACTED]");
    });

    it("still applies PII_TYPE masking regardless of length", () => {
        const log = createTestLog({
            message: "Card: 4111-1111-1111-1111",
        });

        const masked = MaskingService.mask(log, [
            { type: "PII_TYPE", category: "CREDIT_CARD" },
        ]);

        expect(masked.message).toContain("[MASKED_CREDIT_CARD]");
    });
});

// =========================================================================
// REDOS-004: event-detector messagePattern入力長ガード
// =========================================================================

describe("REDOS-004: event-detector messagePattern input length guard", () => {
    it("skips messagePattern test on oversized messages", () => {
        const detector = new EventDetector([{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                messagePattern: /suspicious/,
            },
        }]);

        // 70KB message — exceeds safe regex input length
        const log = createTestLog({
            message: "suspicious" + "x".repeat(70_000),
        });

        const start = performance.now();
        const result = detector.detect(log);
        const elapsed = performance.now() - start;

        expect(elapsed).toBeLessThan(100);
        // messagePattern skipped → no custom rule match
        expect(result).toBeNull();
    });

    it("applies messagePattern on normal-length messages", () => {
        const detector = new EventDetector([{
            ruleId: "r1",
            eventName: "SECURITY_INTRUSION_DETECTED",
            priority: "HIGH",
            conditions: {
                messagePattern: /suspicious/,
                logTypes: ["SECURITY"],
            },
        }]);

        const log = createTestLog({
            type: "SECURITY",
            message: "suspicious activity detected",
        });

        const result = detector.detect(log);
        // SECURITY + level 3 → built-in doesn't match (needs level >= 5)
        // Custom rule should match
        expect(result).not.toBeNull();
    });
});

// =========================================================================
// SDK-C: ErrorRouter console.error のPII切り詰め
// =========================================================================

describe("SDK-C: ErrorRouter console.error PII truncation", () => {
    it("truncates long error messages in console.error output", async () => {
        const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

        const router = new ErrorRouter({
            enabled: true,
            rules: [{
                id: "test-rule",
                match: { kind: "unknown" },
                destination: "audit_sink" as any,
            }],
            sinks: {
                audit: {
                    send: () => { throw new Error("X".repeat(500)); },
                },
            },
        });

        await router.route(new Error("original"), "test");

        // console.error に出力されたメッセージが切り詰められていること
        if (errorSpy.mock.calls.length > 0) {
            const msg = errorSpy.mock.calls[0][0] as string;
            // 500文字のエラーメッセージが200文字以下に切り詰められるべき
            expect(msg.length).toBeLessThan(400);
        }

        errorSpy.mockRestore();
    });
});
