import { WhitelistRegistry } from "./whitelist-registry";
import { SECURITY_WHITELIST } from "./whitelists/security-whitelist";
import { TASK_WHITELIST } from "./whitelists/task-whitelist";
import { PRIVACY_WHITELIST } from "./whitelists/privacy-whitelist";
import type { SentinelConfig, SentinelLogger } from "../configs/sentinel-config";
import type { WhitelistDefinition } from "./whitelist-types";

/** ドメイン名 → WhitelistDefinition のマッピング */
const ALL_WHITELISTS: Record<string, WhitelistDefinition> = {
    security: SECURITY_WHITELIST,
    task: TASK_WHITELIST,
    privacy: PRIVACY_WHITELIST,
};

export type WhitelistDomain = "security" | "task" | "privacy";
export type WhitelistLevel = "strict" | "standard" | "permissive" | "off";

/** 検証結果。permissive モード時に警告リストを返す。 */
export interface WhitelistValidationResult {
    registry: WhitelistRegistry;
    warnings: string[];
}

/**
 * SentinelConfig のホワイトリスト検証を実行する。
 *
 * level に応じた挙動:
 * - "strict":    全ドメイン検証、extensions 無視、不正値は ValidationError
 * - "standard":  全ドメイン検証、extensions 適用、不正値は ValidationError
 * - "permissive": 全ドメイン検証、不正値は警告のみ（logger.warn）
 * - "off":       検証スキップ（空レジストリを返す）
 */
export function validateConfigWhitelists(
    config: SentinelConfig,
): WhitelistValidationResult {
    const level: WhitelistLevel = config.whitelist?.level ?? "standard";
    const warnings: string[] = [];

    // "off" → 検証なし
    if (level === "off") {
        return { registry: new WhitelistRegistry([]), warnings };
    }

    const enabledDomains: WhitelistDomain[] =
        config.whitelist?.enabledDomains ?? ["security", "task", "privacy"];

    const definitions = enabledDomains
        .filter((d) => Object.prototype.hasOwnProperty.call(ALL_WHITELISTS, d))
        .map((d) => ALL_WHITELISTS[d]);

    // "strict" → extensions を無視
    const extensions = level === "strict" ? undefined : config.whitelist?.extensions;
    const registry = new WhitelistRegistry(definitions, extensions);

    // "permissive" → エラーではなく警告に変換
    const validate = (field: string, value: string) => {
        try {
            registry.validate(field, value);
        } catch (err) {
            if (level === "permissive") {
                warnings.push((err as Error).message);
                logWarning(config.logger, (err as Error).message);
            } else {
                throw err;
            }
        }
    };

    // --- detectionRules ---
    if (config.detectionRules) {
        for (const rule of config.detectionRules) {
            validate("eventName", rule.eventName);
            validate("detectionPriority", rule.priority);
        }
    }

    // --- taskRules ---
    for (const rule of config.taskRules) {
        validate("eventName", rule.eventName);
        validate("severity", rule.severity);
        validate("actionType", rule.actionType);
        validate("executionLevel", rule.executionLevel);
    }

    // --- masking rules (PII categories — 無効時も検証して潜在的な設定ミスを検出) ---
    for (const rule of config.masking.rules) {
        if (rule.type === "PII_TYPE") {
            validate("piiCategory", rule.category);
        }
    }

    return { registry, warnings };
}

/** loggerがあれば警告出力、なければ環境に応じてconsole.warn */
function logWarning(logger: SentinelLogger | undefined, message: string): void {
    if (logger) {
        logger.warn(message, { source: "whitelist-validation" });
    }
}
