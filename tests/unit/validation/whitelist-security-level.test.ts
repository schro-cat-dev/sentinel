/**
 * Whitelist Security Level Tests
 *
 * level: strict / standard / permissive / off の挙動テスト。
 * 堅牢性 vs 柔軟性のトレードオフが正しく制御されるか検証。
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig, ValidationError } from "../../../src/index";
import { validateConfigWhitelists } from "../../../src/validation/config-validator";
import { createTestTaskRule } from "../../helpers/fixtures";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== strict: 最も堅牢 =====
describe("Security Level: strict", () => {
    it("rejects invalid values with error", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            taskRules: [createTestTaskRule({ eventName: "TYPO" as never })],
            whitelist: { level: "strict" },
        });
        expect(() => validateConfigWhitelists(config)).toThrow(ValidationError);
    });

    it("ignores extensions — custom values are rejected", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            taskRules: [createTestTaskRule({ eventName: "CUSTOM_EVENT" as never })],
            whitelist: {
                level: "strict",
                extensions: { eventName: ["CUSTOM_EVENT"] },
            },
        });
        // strict ignores extensions → CUSTOM_EVENT is invalid
        expect(() => validateConfigWhitelists(config)).toThrow(ValidationError);
    });

    it("accepts valid built-in values", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule()],
            whitelist: { level: "strict" },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("Sentinel.initialize rejects strict + invalid config", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                taskRules: [createTestTaskRule({ severity: "ULTRA" as never })],
                whitelist: { level: "strict" },
            })),
        ).toThrow(ValidationError);
    });
});

// ===== standard: デフォルト =====
describe("Security Level: standard (default)", () => {
    it("rejects invalid values with error", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            taskRules: [createTestTaskRule({ actionType: "BAD" as never })],
        });
        expect(() => validateConfigWhitelists(config)).toThrow(ValidationError);
    });

    it("allows extensions", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "CUSTOM" as never })],
            whitelist: {
                level: "standard",
                extensions: { eventName: ["CUSTOM"] },
            },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("level defaults to standard when omitted", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            taskRules: [createTestTaskRule({ executionLevel: "INVALID" as never })],
        });
        // Default = standard → throws on invalid
        expect(() => validateConfigWhitelists(config)).toThrow(ValidationError);
    });
});

// ===== permissive: 警告のみ =====
describe("Security Level: permissive", () => {
    it("does not throw on invalid values", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ severity: "ULTRA" as never })],
            whitelist: { level: "permissive" },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("returns warnings for invalid values", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "TYPO_EVENT" as never,
                severity: "ULTRA" as never,
            })],
            whitelist: { level: "permissive" },
        });
        const { warnings } = validateConfigWhitelists(config);
        expect(warnings.length).toBeGreaterThanOrEqual(2);
        expect(warnings.some((w) => w.includes("TYPO_EVENT"))).toBe(true);
        expect(warnings.some((w) => w.includes("ULTRA"))).toBe(true);
    });

    it("calls logger.warn for each invalid value", () => {
        const warnFn = vi.fn();
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            logger: { warn: warnFn, error: vi.fn() },
            taskRules: [createTestTaskRule({ actionType: "BAD" as never })],
            whitelist: { level: "permissive" },
        });
        validateConfigWhitelists(config);
        expect(warnFn).toHaveBeenCalled();
        expect(warnFn.mock.calls[0][1]).toEqual({ source: "whitelist-validation" });
    });

    it("Sentinel.initialize succeeds with permissive + invalid config", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                taskRules: [createTestTaskRule({ severity: "ULTRA" as never })],
                whitelist: { level: "permissive" },
            })),
        ).not.toThrow();
    });

    it("allows extensions in permissive mode", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "CUSTOM" as never })],
            whitelist: {
                level: "permissive",
                extensions: { eventName: ["CUSTOM"] },
            },
        });
        const { warnings } = validateConfigWhitelists(config);
        // CUSTOM is in extensions → no warning
        expect(warnings).toHaveLength(0);
    });
});

// ===== off: 検証なし =====
describe("Security Level: off", () => {
    it("does not validate anything", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({
                eventName: "TOTALLY_INVALID" as never,
                actionType: "DOES_NOT_EXIST" as never,
                severity: "NONSENSE" as never,
                executionLevel: "FAKE" as never,
            })],
            whitelist: { level: "off" },
        });
        expect(() => validateConfigWhitelists(config)).not.toThrow();
    });

    it("returns empty warnings", () => {
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "BAD" as never })],
            whitelist: { level: "off" },
        });
        const { warnings } = validateConfigWhitelists(config);
        expect(warnings).toHaveLength(0);
    });

    it("Sentinel.initialize succeeds with off + any config", () => {
        expect(() =>
            Sentinel.initialize(createDefaultConfig({
                projectName: "p", serviceId: "s",
                security: { enableHashChain: false },
                taskRules: [createTestTaskRule({ actionType: "ANYTHING" as never })],
                whitelist: { level: "off" },
            })),
        ).not.toThrow();
    });

    it("onTaskAction does not validate when level is off", () => {
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            whitelist: { level: "off" },
        }));
        // With level=off, registry has no fields → validate is no-op
        expect(() =>
            sentinel.onTaskAction("TOTALLY_INVALID", async () => ({ status: "completed" })),
        ).not.toThrow();
    });
});

// ===== レベル間の比較テスト =====
describe("Security Level: comparative behavior", () => {
    const makeConfig = (level: "strict" | "standard" | "permissive" | "off") =>
        createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "INVALID" as never })],
            whitelist: { level },
        });

    it("strict throws, standard throws, permissive warns, off ignores", () => {
        expect(() => validateConfigWhitelists(makeConfig("strict"))).toThrow(ValidationError);
        expect(() => validateConfigWhitelists(makeConfig("standard"))).toThrow(ValidationError);

        const { warnings } = validateConfigWhitelists(makeConfig("permissive"));
        expect(warnings.length).toBeGreaterThan(0);

        const { warnings: offWarnings } = validateConfigWhitelists(makeConfig("off"));
        expect(offWarnings).toHaveLength(0);
    });

    it("enabledDomains is respected regardless of level", () => {
        // permissive + security disabled → no warning for invalid eventName
        const config = createDefaultConfig({
            projectName: "p", serviceId: "s",
            security: { enableHashChain: false },
            taskRules: [createTestTaskRule({ eventName: "INVALID" as never })],
            whitelist: { level: "permissive", enabledDomains: ["task"] },
        });
        const { warnings } = validateConfigWhitelists(config);
        // eventName comes from security domain (disabled) → no warning
        expect(warnings.filter((w) => w.includes("eventName"))).toHaveLength(0);
    });
});
