import type { ErrorPayloadProtocol } from "../errors/error-payload-protocol";
import { isPiiSafe, maskPiiContext } from "../../security/pii-context-masker";

// 後方互換: security/pii-context-masker.ts に移動した関数を再export
export { isPiiSafe, maskPiiContext };

type SafeValue = string | number | boolean | null;

/** 安全なcontext変換（完全型安全） */
export const safeContext = (
    data: Record<string, SafeValue | object | undefined>,
): Record<string, SafeValue> => {
    const result: Record<string, SafeValue> = {};

    for (const [key, value] of Object.entries(data)) {
        if (key.length > 50) continue; // キー長制限

        if (value === undefined || value === null) {
            result[key] = null;
        } else if (Array.isArray(value)) {
            result[key] = Math.min(value.length, 1000);
        } else if (value && typeof value === "object") {
            result[key] = Object.keys(value).length;
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
export const serializeForAudit = (error: ErrorPayloadProtocol): string => {
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
export const logFinancialError = (error: ErrorPayloadProtocol): void => {
    const safeContextData = error.meta.context
        ? safeContext(error.meta.context)
        : null;

    // ログ用一時オブジェクト（元オブジェクト非破壊）
    const auditError = {
        ...error,
        meta: {
            ...error.meta,
            context: safeContextData,
        },
    } as ErrorPayloadProtocol;

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
    error: ErrorPayloadProtocol,
    config: ErrorSeverityConfig = DEFAULT_ERROR_SEVERITY,
): "CRITICAL" | "WARNING" | "INFO" => {
    if (config.CRITICAL.includes(error.kind)) return "CRITICAL";
    if (config.WARNING.includes(error.kind)) return "WARNING";
    return "INFO";
};

/** 多言語対応ログヘルパー */
export const getErrorMessage = (
    error: ErrorPayloadProtocol,
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
