import { ERROR_HTTP_STATUS, ERROR_LAYERS, ErrorLayer } from "../../constants";
import { ERROR_KIND } from "../../constants/error-protocol-kind";
import { DB_ERROR_KINDS } from "../../constants/kinds/persistence/db-error-kind";
import { ErrorMeta, ErrorPayloadProtocol } from "../error-payload-protocol";

// NOTE: ここで各種エラー型は個別の回復処理またはエラー情報特定のための個別コンテキスト情報をDI
export interface DbConnectionError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.CONNECTION;
    readonly host: string;
    readonly port: number;
    readonly database: string;
}

export interface DbQueryError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.QUERY;
    readonly sql: string;
    readonly params?: Record<string, unknown>;
    readonly rowCount?: number;
}

export interface DbTransactionError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.TRANSACTION;
    readonly operation: "begin" | "commit" | "rollback";
    readonly transactionId: string;
}

export interface DbConstraintError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.CONSTRAINT;
    readonly constraint: string;
    readonly table: string;
    readonly column?: string;
}

export interface DbTimeoutError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.QUERY_TIMEOUT;
    readonly query: string;
    readonly timeoutMs: number;
}

export interface DbDeadlockError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.DEADLOCK;
    readonly query: string;
    readonly deadlockId: string;
}

export interface DbDuplicateKeyError extends ErrorPayloadProtocol {
    readonly kind: typeof ERROR_KIND.EXTERNAL;
    readonly detailKind: typeof DB_ERROR_KINDS.DUPLICATE_KEY;
    readonly table: string;
    readonly keyFields: string[];
    readonly keyValues: unknown[];
}

// 共通ベースメタ（ErrorLayer構造体対応）
const DEFAULT_DB_META_BASE: Partial<ErrorMeta> = {
    layer: {
        module: "Database",
        component: ERROR_LAYERS.REPOSITORY,
    },
    entityType: "Database",
};

// 安全なコンテキスト変換
const safeContext = (
    data: Record<string, unknown>,
): Record<string, string | number | boolean> => {
    const result: Record<string, string | number | boolean> = {};
    for (const [key, value] of Object.entries(data)) {
        if (value === null || value === undefined) {
            result[key] = false;
        } else if (Array.isArray(value)) {
            result[key] = value.length.toString();
        } else if (typeof value === "object") {
            result[key] = Object.keys(value).length.toString();
        } else {
            result[key] = String(value);
        }
    }
    return result;
};

// --- ファクトリ関数群（完全版）---
export const dbConnectionError = (
    host: string,
    port: number,
    database: string,
    meta: Partial<ErrorMeta> = {},
): DbConnectionError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.CONNECTION,
    code: "DB_CONNECTION_FAILED",
    message: `Database connection failed: ${host}:${port}/${database}`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
        context: safeContext({ host, port, database }),
        ...meta,
    },
    host,
    port,
    database,
});

export const dbQueryError = (
    sql: string,
    params?: Record<string, unknown>,
    rowCount?: number,
    meta: Partial<ErrorMeta> = {},
): DbQueryError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.QUERY,
    code: "DB_QUERY_FAILED",
    message: `Database query failed`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.INTERNAL_SERVER_ERROR,
        operation: "query",
        context: safeContext({
            sql: sql.length > 100 ? sql.slice(0, 100) + "..." : sql,
            paramsCount: params ? Object.keys(params).length : 0,
            rowCount: rowCount || 0,
        }),
        ...meta,
    },
    sql,
    params,
    rowCount,
});

export const dbTransactionError = (
    operation: "begin" | "commit" | "rollback",
    transactionId: string,
    meta: Partial<ErrorMeta> = {},
): DbTransactionError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.TRANSACTION,
    code: "DB_TRANSACTION_FAILED",
    message: `Database transaction ${operation} failed: ${transactionId}`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.INTERNAL_SERVER_ERROR,
        operation: `transaction_${operation}`,
        context: safeContext({ transactionId, operation }),
        ...meta,
    },
    operation,
    transactionId,
});

export const dbConstraintError = (
    constraint: string,
    table: string,
    column?: string,
    meta: Partial<ErrorMeta> = {},
): DbConstraintError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.CONSTRAINT,
    code: "DB_CONSTRAINT_VIOLATION",
    message: `Constraint violation: ${constraint} on ${table}`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.BAD_REQUEST,
        context: safeContext({
            constraint,
            table,
            column: column || null,
        }),
        ...meta,
    },
    constraint,
    table,
    column,
});

export const dbTimeoutError = (
    query: string,
    timeoutMs: number,
    meta: Partial<ErrorMeta> = {},
): DbTimeoutError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.QUERY_TIMEOUT,
    code: "DB_TIMEOUT",
    message: `Database query timeout after ${timeoutMs}ms`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
        operation: "timeout",
        context: safeContext({
            timeoutMs,
            query: query.length > 100 ? query.slice(0, 100) + "..." : query,
        }),
        ...meta,
    },
    query,
    timeoutMs,
});

export const dbDeadlockError = (
    query: string,
    deadlockId: string,
    meta: Partial<ErrorMeta> = {},
): DbDeadlockError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.DEADLOCK,
    code: "DB_DEADLOCK",
    message: `Database deadlock detected: ${deadlockId}`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
        operation: "deadlock",
        context: safeContext({
            deadlockId,
            query: query.length > 100 ? query.slice(0, 100) + "..." : query,
        }),
        ...meta,
    },
    query,
    deadlockId,
});

export const dbDuplicateKeyError = (
    table: string,
    keyFields: string[],
    keyValues: unknown[],
    meta: Partial<ErrorMeta> = {},
): DbDuplicateKeyError => ({
    kind: ERROR_KIND.EXTERNAL,
    detailKind: DB_ERROR_KINDS.DUPLICATE_KEY,
    code: "DB_DUPLICATE_KEY",
    message: `Duplicate key violation on ${table}`,
    meta: {
        ...DEFAULT_DB_META_BASE,
        layer: {
            module: (meta.layer as Partial<ErrorLayer>)?.module || "Database",
            component:
                (meta.layer as Partial<ErrorLayer>)?.component ||
                ERROR_LAYERS.REPOSITORY,
        },
        httpStatus: ERROR_HTTP_STATUS.CONFLICT,
        context: safeContext({
            table,
            keyFields: keyFields.join(","),
            keyValuesCount: keyValues.length,
            firstKeyValueType: keyValues[0] ? typeof keyValues[0] : "unknown",
        }),
        ...meta,
    },
    table,
    keyFields,
    keyValues,
});

export type DbError =
    | DbConnectionError
    | DbQueryError
    | DbTransactionError
    | DbConstraintError
    | DbTimeoutError
    | DbDeadlockError
    | DbDuplicateKeyError;
