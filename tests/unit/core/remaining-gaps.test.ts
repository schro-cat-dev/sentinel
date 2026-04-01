/**
 * Remaining Gaps Tests (TDD)
 *
 * #1: projectName をパイプラインで使用
 * #3: MaskingService REGEX フラグ保持
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Sentinel, createDefaultConfig } from "../../../src/index";
import { MaskingService } from "../../../src/security/masking-service";
import type { MaskingRule } from "../../../src/configs/masking-rule";

beforeEach(() => Sentinel.reset());
afterEach(() => Sentinel.reset());

// ===== #1: projectName reflected in pipeline =====
describe("#1: projectName used in pipeline", () => {
    it("projectName is included in normalized log", async () => {
        let captured: unknown = null;
        const sentinel = Sentinel.initialize(createDefaultConfig({
            projectName: "my-fintech-app",
            serviceId: "payment-svc",
            security: { enableHashChain: false },
            onLogProcessed: (log) => { captured = log; },
        }));

        await sentinel.ingest({ message: "test", level: 3 });

        expect(captured).toHaveProperty("projectName", "my-fintech-app");
    });
});

// ===== #3: MaskingService REGEX preserves original flags =====
describe("#3: MaskingService REGEX flag preservation", () => {
    it("case-insensitive flag (i) is preserved in REGEX rule", () => {
        const rules: MaskingRule[] = [{
            type: "REGEX",
            pattern: /secret_token/i,
            replacement: "[REDACTED]",
            description: "case-insensitive token masking",
        }];

        const input = { message: "Found SECRET_TOKEN in logs" };
        const result = MaskingService.mask(input, rules, []) as { message: string };

        // With /i flag preserved, SECRET_TOKEN should be masked
        expect(result.message).not.toContain("SECRET_TOKEN");
        expect(result.message).toContain("[REDACTED]");
    });

    it("case-insensitive flag (i) works on mixed case", () => {
        const rules: MaskingRule[] = [{
            type: "REGEX",
            pattern: /password/i,
            replacement: "[MASKED]",
            description: "password masking",
        }];

        const input = { message: "PASSWORD=abc123 and Password=xyz" };
        const result = MaskingService.mask(input, rules, []) as { message: string };

        expect(result.message).not.toContain("PASSWORD");
        expect(result.message).not.toContain("Password");
    });

    it("multiline flag (m) is preserved", () => {
        const rules: MaskingRule[] = [{
            type: "REGEX",
            pattern: /^secret:.*/m,
            replacement: "[REDACTED_LINE]",
            description: "multiline masking",
        }];

        const input = { message: "normal line\nsecret: value\nanother line" };
        const result = MaskingService.mask(input, rules, []) as { message: string };

        expect(result.message).toContain("[REDACTED_LINE]");
        expect(result.message).toContain("normal line");
    });

    it("no flag regex still works", () => {
        const rules: MaskingRule[] = [{
            type: "REGEX",
            pattern: /api_key_\d+/,
            replacement: "[KEY]",
            description: "api key masking",
        }];

        const input = { message: "using api_key_12345 for access" };
        const result = MaskingService.mask(input, rules, []) as { message: string };

        expect(result.message).toContain("[KEY]");
        expect(result.message).not.toContain("api_key_12345");
    });
});
