import { ERROR_HTTP_STATUS, ERROR_LAYERS } from "../../constants";
import { ERROR_KIND } from "../../constants/error-protocol-kind";
import { DB_ERROR_KINDS } from "../../constants/kinds/persistence/db-error-kind";
import { ErrorMeta, ErrorPayloadProtocol } from "../error-payload-protocol";

// NOTE: ここで各種エラー型は個別の回復処理またはエラー情報特定のための個別コンテキスト情報をDI。プロトコルとしては内部的には守れるので標準的なフローを遵守しつつ、拡張性と柔軟性・堅牢性を担保。
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

// --- ファクトリ関数群 ---
const DEFAULT_DB_META: ErrorMeta = {
    layer: ERROR_LAYERS.REPOSITORY,
    httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
};

export const dbConnectionError = (
    host: string,
    port: number,
    database: string,
    meta: Partial<ErrorMeta> = {},
): DbConnectionError => ({
    kind: "External",
    detailKind: "DbConnection",
    code: "DB_CONNECTION_FAILED",
    message: `Database connection failed: ${host}:${port}/${database}`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
        entityType: "Database",
        context: { host, port, database },
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
    kind: "External",
    detailKind: "DbQuery",
    code: "DB_QUERY_FAILED",
    message: `Database query failed`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.INTERNAL_SERVER_ERROR,
        operation: "query",
        context: { sql: sql.slice(0, 100) + "..." },
        ...meta,
    },
    sql,
    params,
    rowCount,
});

// 3. 不足ファクトリ（この4つを追加）
export const dbTransactionError = (
    operation: "begin" | "commit" | "rollback",
    transactionId: string,
    meta: Partial<ErrorMeta> = {},
): DbTransactionError => ({
    kind: "External",
    detailKind: "DbTransaction",
    code: "DB_TRANSACTION_FAILED",
    message: `Database transaction ${operation} failed: ${transactionId}`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.INTERNAL_SERVER_ERROR,
        operation: `transaction_${operation}`,
        context: { transactionId, operation },
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
    kind: "External",
    detailKind: "DbConstraint",
    code: "DB_CONSTRAINT_VIOLATION",
    message: `Constraint violation: ${constraint} on ${table}`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.BAD_REQUEST,
        entityType: table,
        context: safeContext({
            constraint,
            table,
            column: column || null, // note: undefined → null変換
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
    kind: "External",
    detailKind: "DbTimeout",
    code: "DB_TIMEOUT",
    message: `Database query timeout after ${timeoutMs}ms`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
        operation: "timeout",
        context: { timeoutMs, query: query.slice(0, 100) + "..." },
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
    kind: "External",
    detailKind: "DbDeadlock",
    code: "DB_DEADLOCK",
    message: `Database deadlock detected: ${deadlockId}`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.SERVICE_UNAVAILABLE,
        operation: "deadlock",
        context: { deadlockId, query: query.slice(0, 100) + "..." },
        ...meta,
    },
    query,
    deadlockId,
});

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
            result[key] = value as string | number | boolean;
        }
    }
    return result;
};

export const dbDuplicateKeyError = (
    table: string,
    keyFields: string[],
    keyValues: unknown[],
    meta: Partial<ErrorMeta> = {},
): DbDuplicateKeyError => ({
    kind: "External",
    detailKind: "DbDuplicateKey",
    code: "DB_DUPLICATE_KEY",
    message: `Duplicate key violation on ${table}`,
    meta: {
        ...DEFAULT_DB_META,
        httpStatus: ERROR_HTTP_STATUS.CONFLICT,
        entityType: table,
        context: safeContext({
            keyFields: keyFields.join(","),
            keyValuesCount: keyValues.length,
            firstKeyValueType: typeof keyValues[0],
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
