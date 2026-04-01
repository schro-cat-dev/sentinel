/**
 * YAML / ファイルベースコンフィグローダー
 *
 * YAMLファイルからSentinelConfigを生成する。
 * 環境変数展開・バリデーション・デフォルトマージを含む。
 *
 * `yaml` パッケージは optional peer dependency。
 * 利用者は `npm install yaml` でインストールする必要がある。
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createDefaultConfig, type SentinelConfig } from "./sentinel-config";
import type { MaskingRule } from "./masking-rule";
import type { TaskRule } from "../types/task";
import type { DetectionRule, DetectionRuleConditions } from "../types/event";

// =========================================================================
// YAML raw types (snake_case、ファイル構造に対応)
// =========================================================================

/** YAMLファイルのトップレベル構造 */
export interface RawYamlConfig {
    project_name?: string;
    service_id?: string;
    environment?: string;
    masking?: {
        enabled?: boolean;
        rules?: RawMaskingRule[];
        preserve_fields?: string[];
    };
    security?: {
        enable_hash_chain?: boolean;
        signing_key_id?: string;
    };
    task_rules?: RawTaskRule[];
    detection_rules?: RawDetectionRule[];
    whitelist?: {
        level?: string;
        enabled_domains?: string[];
        extensions?: Record<string, string[]>;
    };
}

interface RawMaskingRule {
    type: string;
    category?: string;
    pattern?: string;
    replacement?: string;
    description?: string;
    sensitive_keys?: string[];
}

interface RawTaskRule {
    rule_id: string;
    event_name: string;
    severity: string;
    action_type: string;
    execution_level: string;
    priority: number;
    description?: string;
    execution_params?: Record<string, string>;
    guardrails?: {
        require_human_approval?: boolean;
        timeout_ms?: number;
        max_retries?: number;
    };
}

interface RawDetectionRule {
    rule_id: string;
    event_name: string;
    priority: string;
    conditions?: {
        log_types?: string[];
        min_level?: number;
        max_level?: number;
        message_pattern?: string;
        tag_match?: { key: string; value?: string };
        origin?: string;
        is_critical?: boolean;
    };
}

// =========================================================================
// Config Loader Options
// =========================================================================

export interface ConfigLoaderOptions {
    /** 環境変数を展開するか（デフォルト: true） */
    expandEnv?: boolean;
    /** 環境変数のソース（テスト用にオーバーライド可能） */
    envSource?: Record<string, string | undefined>;
    /**
     * YAMLパーサー関数（テスト用にインジェクション可能。省略時は `yaml` パッケージを使用）。
     * `false` を渡すと「yamlパッケージ未インストール」をシミュレートする（テスト専用）。
     */
    yamlParser?: ((content: string) => RawYamlConfig) | false;
}

// =========================================================================
// Validation errors
// =========================================================================

export class ConfigLoadError extends Error {
    constructor(
        public readonly field: string,
        message: string,
    ) {
        super(`Config error [${field}]: ${message}`);
        this.name = "ConfigLoadError";
    }
}

// =========================================================================
// Public API
// =========================================================================

/**
 * YAMLファイルからSentinelConfigをロードする。
 *
 * @param filePath YAMLファイルパス（絶対 or 相対）
 * @param options ローダーオプション
 * @returns 完全なSentinelConfig（デフォルトマージ済み）
 * @throws ConfigLoadError バリデーションエラー
 * @throws Error ファイル読み込みエラー、YAMLパースエラー
 */
export function loadConfigFromYaml(
    filePath: string,
    options: ConfigLoaderOptions = {},
): SentinelConfig {
    const absolutePath = resolve(filePath);
    const content = readFileSync(absolutePath, "utf-8");
    return parseConfigYaml(content, options);
}

/**
 * YAML文字列からSentinelConfigをパースする。
 * ファイルI/Oなしでテスト可能。
 */
export function parseConfigYaml(
    yamlContent: string,
    options: ConfigLoaderOptions = {},
): SentinelConfig {
    const expandEnv = options.expandEnv ?? true;
    const envSource = options.envSource ?? process.env;

    // 1. 環境変数展開
    const expanded = expandEnv
        ? expandEnvVars(yamlContent, envSource)
        : yamlContent;

    // 2. YAMLパース
    const raw = parseYaml(expanded, options.yamlParser);

    // 3. バリデーション
    validateRawConfig(raw);

    // 4. snake_case → camelCase 変換 + デフォルトマージ
    return convertToSentinelConfig(raw);
}

// =========================================================================
// Internal: 環境変数展開
// =========================================================================

/**
 * ${VAR_NAME} および ${VAR_NAME:-default} パターンを展開する。
 * セキュリティ: コマンド実行（$()）やネスト展開は禁止。
 */
function expandEnvVars(
    content: string,
    env: Record<string, string | undefined>,
): string {
    return content.replace(
        /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}/g,
        (_match, varName: string, defaultValue: string | undefined) => {
            const value = env[varName];
            if (value !== undefined) return value;
            if (defaultValue !== undefined) return defaultValue;
            return "";
        },
    );
}

// =========================================================================
// Internal: YAMLパース
// =========================================================================

function parseYaml(
    content: string,
    customParser?: ((content: string) => RawYamlConfig) | false,
): RawYamlConfig {
    if (typeof customParser === "function") return customParser(content);

    // customParser === false はテスト専用: yaml未インストールをシミュレート
    if (customParser === false) {
        throw new Error(
            'YAML parsing requires the "yaml" package. Install it with: npm install yaml',
        );
    }

    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const yamlModule = require("yaml") as { parse: (s: string) => RawYamlConfig };
        return yamlModule.parse(content);
    } catch (e) {
        if (e instanceof Error && e.message.includes("Cannot find module")) {
            throw new Error(
                'YAML parsing requires the "yaml" package. Install it with: npm install yaml',
            );
        }
        throw e;
    }
}

// =========================================================================
// Internal: バリデーション
// =========================================================================

const VALID_ENVIRONMENTS = new Set(["production", "staging", "development", "local", "test"]);
const VALID_MASKING_TYPES = new Set(["PII_TYPE", "REGEX", "KEY_MATCH"]);
const VALID_PII_CATEGORIES = new Set([
    "CREDIT_CARD", "PHONE", "EMAIL", "GOVERNMENT_ID",
    "JAPAN_ACCOUNT", "POSTAL_CODE", "DRIVER_LICENSE", "HEALTH_INSURANCE",
]);
const VALID_WHITELIST_LEVELS = new Set(["strict", "standard", "permissive", "off"]);

function validateRawConfig(raw: RawYamlConfig): void {
    if (!raw.project_name || typeof raw.project_name !== "string") {
        throw new ConfigLoadError("project_name", "is required and must be a string");
    }
    if (!raw.service_id || typeof raw.service_id !== "string") {
        throw new ConfigLoadError("service_id", "is required and must be a string");
    }
    if (raw.environment && !VALID_ENVIRONMENTS.has(raw.environment)) {
        throw new ConfigLoadError("environment", `must be one of: ${[...VALID_ENVIRONMENTS].join(", ")}`);
    }

    // masking rules — type固有フィールドの検証は convertMaskingRule で実施
    if (raw.masking?.rules) {
        for (let i = 0; i < raw.masking.rules.length; i++) {
            const rule = raw.masking.rules[i];
            if (rule.type === "PII_TYPE" && (!rule.category || !VALID_PII_CATEGORIES.has(rule.category))) {
                throw new ConfigLoadError(`masking.rules[${i}].category`, `invalid category "${rule.category}"`);
            }
            if (rule.type === "REGEX" && !rule.pattern) {
                throw new ConfigLoadError(`masking.rules[${i}].pattern`, "is required for REGEX type");
            }
            if (rule.type === "KEY_MATCH" && (!rule.sensitive_keys || rule.sensitive_keys.length === 0)) {
                throw new ConfigLoadError(`masking.rules[${i}].sensitive_keys`, "is required for KEY_MATCH type");
            }
        }
    }

    // whitelist level
    if (raw.whitelist?.level && !VALID_WHITELIST_LEVELS.has(raw.whitelist.level)) {
        throw new ConfigLoadError("whitelist.level", `must be one of: ${[...VALID_WHITELIST_LEVELS].join(", ")}`);
    }

    // task rules
    if (raw.task_rules) {
        for (let i = 0; i < raw.task_rules.length; i++) {
            const rule = raw.task_rules[i];
            if (!rule.rule_id) throw new ConfigLoadError(`task_rules[${i}].rule_id`, "is required");
            if (!rule.event_name) throw new ConfigLoadError(`task_rules[${i}].event_name`, "is required");
            if (!rule.action_type) throw new ConfigLoadError(`task_rules[${i}].action_type`, "is required");
        }
    }
}

// =========================================================================
// Internal: snake_case → SentinelConfig 変換
// =========================================================================

function convertToSentinelConfig(raw: RawYamlConfig): SentinelConfig {
    const maskingRules: MaskingRule[] = (raw.masking?.rules ?? []).map((r, i) => convertMaskingRule(r, i));
    const taskRules: TaskRule[] = (raw.task_rules ?? []).map(convertTaskRule);
    const detectionRules: DetectionRule[] | undefined = raw.detection_rules?.map(convertDetectionRule);

    return createDefaultConfig({
        projectName: raw.project_name!,
        serviceId: raw.service_id!,
        environment: (raw.environment ?? "development") as SentinelConfig["environment"],
        masking: {
            enabled: raw.masking?.enabled ?? false,
            rules: maskingRules,
            preserveFields: raw.masking?.preserve_fields ?? ["traceId", "spanId"],
        },
        security: {
            enableHashChain: raw.security?.enable_hash_chain ?? true,
            signingKeyId: raw.security?.signing_key_id,
        },
        taskRules,
        detectionRules,
        whitelist: raw.whitelist ? {
            level: raw.whitelist.level as SentinelConfig["whitelist"] extends { level?: infer L } ? L : never,
            enabledDomains: raw.whitelist.enabled_domains as ("security" | "task" | "privacy")[],
            extensions: raw.whitelist.extensions,
        } : undefined,
    });
}

function convertMaskingRule(raw: RawMaskingRule, index: number): MaskingRule {
    if (raw.type === "PII_TYPE") {
        return { type: "PII_TYPE", category: raw.category as MaskingRule extends { category: infer C } ? C : never };
    }
    if (raw.type === "REGEX") {
        return {
            type: "REGEX",
            pattern: new RegExp(raw.pattern!, raw.description?.includes("global") ? "g" : ""),
            replacement: raw.replacement ?? "[REDACTED]",
            description: raw.description ?? "",
        };
    }
    if (raw.type === "KEY_MATCH") {
        return {
            type: "KEY_MATCH",
            sensitiveKeys: raw.sensitive_keys ?? [],
            replacement: raw.replacement,
        };
    }
    throw new ConfigLoadError(`masking.rules[${index}].type`, `invalid type "${raw.type}"`);
}

function convertTaskRule(raw: RawTaskRule): TaskRule {
    return {
        ruleId: raw.rule_id,
        eventName: raw.event_name,
        severity: raw.severity as TaskRule["severity"],
        actionType: raw.action_type as TaskRule["actionType"],
        executionLevel: raw.execution_level as TaskRule["executionLevel"],
        priority: raw.priority as TaskRule["priority"],
        description: raw.description ?? "",
        executionParams: {
            notificationChannel: raw.execution_params?.notificationChannel,
            targetEndpoint: raw.execution_params?.targetEndpoint,
            scriptIdentifier: raw.execution_params?.scriptIdentifier,
            promptTemplate: raw.execution_params?.promptTemplate,
        },
        guardrails: {
            requireHumanApproval: raw.guardrails?.require_human_approval ?? false,
            timeoutMs: raw.guardrails?.timeout_ms ?? 30000,
            maxRetries: raw.guardrails?.max_retries ?? 3,
        },
    };
}

function convertDetectionRule(raw: RawDetectionRule): DetectionRule {
    const conditions: DetectionRuleConditions = {};
    if (raw.conditions) {
        if (raw.conditions.log_types) conditions.logTypes = raw.conditions.log_types;
        if (raw.conditions.min_level !== undefined) conditions.minLevel = raw.conditions.min_level;
        if (raw.conditions.max_level !== undefined) conditions.maxLevel = raw.conditions.max_level;
        if (raw.conditions.message_pattern) conditions.messagePattern = new RegExp(raw.conditions.message_pattern);
        if (raw.conditions.tag_match) conditions.tagMatch = raw.conditions.tag_match;
        if (raw.conditions.origin) conditions.origin = raw.conditions.origin;
        if (raw.conditions.is_critical !== undefined) conditions.isCritical = raw.conditions.is_critical;
    }
    return {
        ruleId: raw.rule_id,
        eventName: raw.event_name as DetectionRule["eventName"],
        priority: raw.priority as DetectionRule["priority"],
        conditions,
    };
}
