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
import { createDefaultConfig, type SentinelConfig, type TaskTransportConfig, TASK_TRANSPORT_TYPES } from "./sentinel-config";
import { PII_CATEGORIES, type MaskingRule } from "./masking-rule";
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
    task_transports?: RawTaskTransport[];
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

interface RawTaskTransport {
    name?: string;
    type?: string;
    enabled?: boolean;
    endpoint?: string;
    headers?: Record<string, string>;
    [key: string]: unknown;
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
     * 未定義環境変数（デフォルト値なし）をエラーにする（デフォルト: false）。
     * true の場合、${VAR} が未定義で :-default もない場合に ConfigLoadError をスローする。
     * 本番環境でAPIキー等の必須変数の設定漏れを防ぐために使用。
     */
    strictEnvExpansion?: boolean;
    /** YAMLパーサー関数（省略時は `yaml` パッケージを使用） */
    yamlParser?: (content: string) => RawYamlConfig;
    /**
     * requireの差し替え（依存注入）。
     * yaml パッケージ未インストール時のエラーハンドリングテスト等で使用。
     * 省略時はNode.jsの require を使用。
     */
    requireFn?: (moduleName: string) => { parse: (s: string) => RawYamlConfig };
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
    const strictEnv = options.strictEnvExpansion ?? false;

    // 1. 環境変数展開
    const expanded = expandEnv
        ? expandEnvVars(yamlContent, envSource, strictEnv)
        : yamlContent;

    // 2. YAMLパース
    const raw = parseYaml(expanded, { yamlParser: options.yamlParser, requireFn: options.requireFn });

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
    strict = false,
): string {
    const missingVars: string[] = [];
    const result = content.replace(
        /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}/g,
        (_match, varName: string, defaultValue: string | undefined) => {
            const value = env[varName];
            if (value !== undefined) return value;
            if (defaultValue !== undefined) return defaultValue;
            missingVars.push(varName);
            return "";
        },
    );
    if (missingVars.length > 0) {
        if (strict) {
            throw new ConfigLoadError(
                "environment",
                `Undefined environment variables without defaults: ${missingVars.join(", ")}`,
            );
        }
        console.warn(
            `[Sentinel] Undefined environment variables (resolved to ""): ${missingVars.join(", ")}`,
        );
    }
    return result;
}

// =========================================================================
// Internal: YAMLパース
// =========================================================================

function parseYaml(
    content: string,
    options: Pick<ConfigLoaderOptions, "yamlParser" | "requireFn">,
): RawYamlConfig {
    if (options.yamlParser) return options.yamlParser(content);

    const loadYaml = options.requireFn ?? defaultRequireYaml;
    try {
        const yamlModule = loadYaml("yaml");
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

function defaultRequireYaml(_moduleName: string): { parse: (s: string) => RawYamlConfig } {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("yaml") as { parse: (s: string) => RawYamlConfig };
}

// =========================================================================
// Internal: バリデーション
// =========================================================================

const VALID_ENVIRONMENTS = new Set(["production", "staging", "development", "local", "test"]);
const VALID_MASKING_TYPES = new Set(["PII_TYPE", "REGEX", "KEY_MATCH"]);
const VALID_PII_CATEGORIES = new Set<string>(PII_CATEGORIES);
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

    // task transports
    if (raw.task_transports) {
        const validTypes = new Set<string>(TASK_TRANSPORT_TYPES);
        for (let i = 0; i < raw.task_transports.length; i++) {
            const t = raw.task_transports[i];
            if (!t.name || typeof t.name !== "string") {
                throw new ConfigLoadError(`task_transports[${i}].name`, "is required and must be a string");
            }
            if (t.type !== undefined && !validTypes.has(t.type)) {
                throw new ConfigLoadError(
                    `task_transports[${i}].type`,
                    `must be one of: ${TASK_TRANSPORT_TYPES.join(", ")} (got "${t.type}")`,
                );
            }
            if (t.type === "http_webhook" && (!t.endpoint || typeof t.endpoint !== "string")) {
                throw new ConfigLoadError(
                    `task_transports[${i}].endpoint`,
                    `is required for type "http_webhook"`,
                );
            }
            if (t.method !== undefined && t.method !== "POST" && t.method !== "PUT") {
                throw new ConfigLoadError(
                    `task_transports[${i}].method`,
                    `must be "POST" or "PUT" (got "${String(t.method)}")`,
                );
            }
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
    const taskTransportConfigs: TaskTransportConfig[] | undefined = raw.task_transports?.map(convertTaskTransport);

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
        taskTransportConfigs,
        whitelist: raw.whitelist ? {
            level: raw.whitelist.level as SentinelConfig["whitelist"] extends { level?: infer L } ? L : never,
            enabledDomains: raw.whitelist.enabled_domains as ("security" | "task" | "privacy")[],
            extensions: raw.whitelist.extensions,
        } : undefined,
    });
}

function convertTaskTransport(raw: RawTaskTransport): TaskTransportConfig {
    const { name, type, enabled, endpoint, headers, ...rest } = raw;
    return {
        name: name!,
        type: (type as TaskTransportConfig["type"]) ?? "custom",
        enabled: enabled ?? true,
        endpoint,
        headers,
        ...rest,
    };
}

const MAX_REGEX_PATTERN_LENGTH = 256;

/**
 * ReDoSリスクのあるパターンを検出するヒューリスティック。
 * ネスト量指定子 (a+)+ や過度な繰り返し {1001,} を拒否する。
 */
function detectReDoSRisk(pattern: string): string | null {
    // パターン長制限
    if (pattern.length > MAX_REGEX_PATTERN_LENGTH) {
        return `pattern too long (${pattern.length} > ${MAX_REGEX_PATTERN_LENGTH})`;
    }
    // ネスト量指定子の検出: グループ内に量指定子があり、グループ自体にも量指定子がある
    let depth = 0;
    let quantifierAtDepth = false;
    for (let i = 0; i < pattern.length; i++) {
        const ch = pattern[i];
        if (ch === "\\") { i++; continue; } // エスケープをスキップ
        if (ch === "(") {
            depth++;
            quantifierAtDepth = false;
        } else if (ch === ")") {
            // 外部量指定子の検出: +, *, ?, {n,m}
            const next = i + 1 < pattern.length ? pattern[i + 1] : "";
            const hasOuterQuantifier = next === "+" || next === "*" || next === "?" || next === "{";
            if (quantifierAtDepth && hasOuterQuantifier) {
                return "nested quantifiers detected (ReDoS risk)";
            }
            depth--;
            quantifierAtDepth = false;
        } else if ((ch === "+" || ch === "*" || ch === "?") && depth > 0) {
            quantifierAtDepth = true;
        }
    }
    // 過度な繰り返しの検出
    const repetitionMatch = pattern.match(/\{(\d+)/g);
    if (repetitionMatch) {
        for (const m of repetitionMatch) {
            const n = parseInt(m.slice(1), 10);
            if (n > 1000) {
                return `repetition count too high (${n} > 1000)`;
            }
        }
    }
    return null;
}

function validateRegexPattern(pattern: string, field: string): void {
    const risk = detectReDoSRisk(pattern);
    if (risk) {
        throw new ConfigLoadError(field, risk);
    }
}

function convertMaskingRule(raw: RawMaskingRule, index: number): MaskingRule {
    if (raw.type === "PII_TYPE") {
        return { type: "PII_TYPE", category: raw.category as MaskingRule extends { category: infer C } ? C : never };
    }
    if (raw.type === "REGEX") {
        validateRegexPattern(raw.pattern!, `masking.rules[${index}].pattern`);
        return {
            type: "REGEX",
            pattern: new RegExp(raw.pattern!, raw.description?.includes("global") ? "g" : ""),
            replacement: raw.replacement ?? "[REDACTED]",
            description: raw.description ?? "",
        };
    }
    if (raw.type === "KEY_MATCH") {
        // sensitive_keys は validateRawConfig で必須・非空が検証済み
        return {
            type: "KEY_MATCH",
            sensitiveKeys: raw.sensitive_keys!,
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
            maxRetries: Math.min(10, Math.max(0, raw.guardrails?.max_retries ?? 3)),
        },
    };
}

function convertDetectionRule(raw: RawDetectionRule): DetectionRule {
    const conditions: DetectionRuleConditions = {};
    if (raw.conditions) {
        if (raw.conditions.log_types) conditions.logTypes = raw.conditions.log_types;
        if (raw.conditions.min_level !== undefined) conditions.minLevel = raw.conditions.min_level;
        if (raw.conditions.max_level !== undefined) conditions.maxLevel = raw.conditions.max_level;
        if (raw.conditions.message_pattern) {
            validateRegexPattern(raw.conditions.message_pattern, `detection_rules[${raw.rule_id}].conditions.message_pattern`);
            conditions.messagePattern = new RegExp(raw.conditions.message_pattern);
        }
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
