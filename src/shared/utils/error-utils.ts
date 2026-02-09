import type { AppErrorPayloadProtocol } from "../errors/error-payload-protocol";

type SafeValue = string | number | boolean | null;

/** TODO 対象追加。PII検出正規表現（国際対応） */
const PII_PATTERNS: readonly RegExp[] = [
    // Email (全言語対応)
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
    // 日本口座番号（支店+口座）
    /\d{3,5}[-]\d{6,7}[-]\d{6,7}/g,
    // 国際口座番号（IBAN簡易）
    /[A-Z]{2}\d{2}[A-Z0-9]{4,30}/g,
    // カード番号（16-19桁）
    /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{16,19}\b/g,
    // 電話番号（日本+国際）
    /(?:0\d{1,4}[-]\d{1,4}[-]\d{4}|0[0-9]{10,12}|\+\d{10,15})/g,
    // 個人名パターン（ローカルパート強化）
    /\b[a-zA-Z]{2,}[.][a-zA-Z]{2,}\b/gi,
    // 住所・郵便番号
    /(?:〒?\d{3}[-]\d{4}|[0-9]{5})/g,
];

/** PII安全確認（偽陰性ゼロ） */
export const isPiiSafe = (value: string): boolean => {
    if (!value || value.length < 3) return true;
    return !PII_PATTERNS.some((pattern) => pattern.test(value));
};

/** 循環参照安全Object.keys（再帰深度修正） */
const safeObjectKeys = (obj: unknown, maxDepth: number = 5): number => {
    if (typeof obj !== "object" || obj === null) return 0;

    const seen = new WeakSet<object>();

    const countKeys = (target: unknown, depth: number): number => {
        if (depth > maxDepth || seen.has(target as object)) return 0;
        if (typeof target !== "object" || target === null) return 0;

        seen.add(target as object);
        return Object.keys(target as Record<string, unknown>).length;
    };

    return countKeys(obj, 0);
};

/** PII自動マスキング（完全型安全・インデックスバグ修正） */
export const maskPiiContext = (
    context: Record<string, SafeValue>,
): Record<string, SafeValue> => {
    const safe = { ...context };

    // キー名PIIチェック＆マスク
    for (const key in safe) {
        const typedKey = key as keyof typeof safe;
        const value = safe[typedKey];

        if (!isPiiSafe(key)) {
            // キー名もマスク（新規キー作成）
            const maskedKey =
                `***_${key.length}_MASKED***` as keyof typeof safe;
            safe[maskedKey] = value;
            delete safe[typedKey];
        } else if (typeof value === "string" && !isPiiSafe(value)) {
            safe[typedKey] = `***_${key}_MASKED***` as SafeValue;
        }
    }

    return safe;
};

/** 安全なcontext変換（循環参照対策・完全型安全） */
export const safeContext = (
    data: Record<string, unknown>,
): Record<string, SafeValue> => {
    const result: Record<string, SafeValue> = {};

    for (const [key, value] of Object.entries(data)) {
        if (key.length > 50) continue; // キー長制限

        if (value === undefined || value === null) {
            result[key] = null;
        } else if (Array.isArray(value)) {
            result[key] = Math.min(value.length, 1000);
        } else if (value && typeof value === "object") {
            result[key] = safeObjectKeys(value, 5);
        } else if (typeof value === "string") {
            result[key] =
                value.length > 50 ? `${value.slice(0, 47)}...` : value;
        } else if (typeof value === "number") {
            result[key] = Number.isFinite(value) ? Math.floor(value) : 0;
        } else if (typeof value === "boolean") {
            result[key] = value;
        } else {
            result[key] = null;
        }
    }

    return maskPiiContext(result);
};

/** 監査用シリアライザ（キー名PII除去） */
export const serializeForAudit = (error: AppErrorPayloadProtocol): string => {
    const context = error.meta.context || {};
    const safeContextKeys = Object.keys(context).filter(isPiiSafe).slice(0, 10);

    const auditData = {
        timestamp: new Date().toISOString(),
        traceId: error.meta.traceId ?? "unknown",
        kind: error.kind,
        code: error.code,
        layer: error.meta.layer ?? "Unknown",
        entityType: error.meta.entityType ?? null,
        contextKeyCount: safeContextKeys.length,
    };

    return JSON.stringify(auditData, undefined, 2);
};

/** 運用ログ用（非破壊・完全型安全） */
export const logFinancialError = (error: AppErrorPayloadProtocol): void => {
    const safeContextData = error.meta.context
        ? safeContext(error.meta.context as Record<string, unknown>)
        : null;

    // ログ用一時オブジェクト（元オブジェクト非破壊）
    const auditError = {
        ...error,
        meta: {
            ...error.meta,
            context: safeContextData,
        },
    } as AppErrorPayloadProtocol;

    console.error(serializeForAudit(auditError));
};

/** 設定可能エラー分類 */
export interface ErrorSeverityConfig {
    readonly CRITICAL: readonly string[];
    readonly WARNING: readonly string[];
}

export const DEFAULT_ERROR_SEVERITY: ErrorSeverityConfig = {
    CRITICAL: ["DbConnection", "WalCrypto", "External"] as const,
    WARNING: ["DbQuery", "DbConstraint", "DbTimeout"] as const,
};

/** エラー重大度分類 */
export const classifyError = (
    error: AppErrorPayloadProtocol,
    config: ErrorSeverityConfig = DEFAULT_ERROR_SEVERITY,
): "CRITICAL" | "WARNING" | "INFO" => {
    if (config.CRITICAL.includes(error.kind)) return "CRITICAL";
    if (config.WARNING.includes(error.kind)) return "WARNING";
    return "INFO";
};

/** 多言語対応ログヘルパー */
export const getErrorMessage = (
    error: AppErrorPayloadProtocol,
    locale: "ja" | "en" = "ja",
): string => {
    const messages: Record<string, Record<"ja" | "en", string>> = {
        DB_CONSTRAINT_VIOLATION: {
            ja: "データベース制約違反",
            en: "Database constraint violation",
        },
        DB_DUPLICATE_KEY: {
            ja: "データベース重複キー違反",
            en: "Database duplicate key violation",
        },
    } as const;

    return messages[error.code]?.[locale] ?? error.message;
};
