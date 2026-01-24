import type { AppErrorBase, AppErrorMeta } from "../app-error";

// DB特化判別子
export type DbErrorKind =
    | "DbConnection"
    | "DbQuery"
    | "DbTransaction"
    | "DbConstraint"
    | "DbTimeout"
    | "DbDeadlock"
    | "DbDuplicateKey";

// DBエラーインターフェース群
export interface DbConnectionError extends AppErrorBase {
    readonly kind: "DbConnection";
    readonly host: string;
    readonly port: number;
    readonly database: string;
}

export interface DbQueryError extends AppErrorBase {
    readonly kind: "DbQuery";
    readonly sql: string;
    readonly params?: Record<string, unknown>;
    readonly rowCount?: number;
}

export interface DbTransactionError extends AppErrorBase {
    readonly kind: "DbTransaction";
    readonly operation: "begin" | "commit" | "rollback";
    readonly transactionId: string;
}

export interface DbConstraintError extends AppErrorBase {
    readonly kind: "DbConstraint";
    readonly constraint: string;
    readonly table: string;
    readonly column?: string;
}

export interface DbTimeoutError extends AppErrorBase {
    readonly kind: "DbTimeout";
    readonly query: string;
    readonly timeoutMs: number;
}

export interface DbDeadlockError extends AppErrorBase {
    readonly kind: "DbDeadlock";
    readonly query: string;
    readonly deadlockId: string;
}

export interface DbDuplicateKeyError extends AppErrorBase {
    readonly kind: "DbDuplicateKey";
    readonly table: string;
    readonly keyFields: string[];
    readonly keyValues: unknown[];
}

// ファクトリ関数群（完全型安全）
export const dbConnectionError = (
    host: string,
    port: number,
    database: string,
    meta: AppErrorMeta = {
        layer: "Repository",
        httpStatus: 503,
    },
): DbConnectionError => ({
    kind: "DbConnection",
    code: "DB_CONNECTION_FAILED",
    message: `Database connection failed: ${host}:${port}/${database}`,
    meta: {
        ...meta,
        entityType: "Database",
        context: { host, port, database },
    },
    host,
    port,
    database,
});

export const dbQueryError = (
    sql: string,
    params?: Record<string, unknown>,
    rowCount?: number,
    meta: AppErrorMeta = {
        layer: "Repository",
        httpStatus: 500,
    },
): DbQueryError => ({
    kind: "DbQuery",
    code: "DB_QUERY_FAILED",
    message: `Database query failed`,
    meta: {
        ...meta,
        operation: "query",
        context: { sql: sql.slice(0, 100) + "..." },
    },
    sql,
    params,
    rowCount,
});

export const dbTransactionError = (
    operation: "begin" | "commit" | "rollback",
    transactionId: string,
    meta: AppErrorMeta = {
        layer: "Repository",
        httpStatus: 500,
    },
): DbTransactionError => ({
    kind: "DbTransaction",
    code: "DB_TRANSACTION_FAILED",
    message: `Transaction ${operation} failed`,
    meta: {
        ...meta,
        operation,
        entityId: transactionId,
    },
    operation,
    transactionId,
});

export const dbConstraintError = (
    constraint: string,
    table: string,
    column?: string, // 現実では半分くらいundefined
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 409 },
): DbConstraintError => ({
    kind: "DbConstraint",
    code: "DB_CONSTRAINT_VIOLATION",
    message: `Constraint violation on ${table}.${constraint}`,
    meta: {
        ...meta,
        entityType: table,
        context: {
            constraint,
            table,
            column: column ?? null,
            isColumnIdentified: !!column, // boolean（運用確認用）
        },
    },
    constraint,
    table,
    column,
});

export const dbTimeoutError = (
    query: string,
    timeoutMs: number,
    meta: AppErrorMeta = {
        layer: "Repository",
        httpStatus: 408,
    },
): DbTimeoutError => ({
    kind: "DbTimeout",
    code: "DB_QUERY_TIMEOUT",
    message: `Query timeout after ${timeoutMs}ms`,
    meta: {
        ...meta,
        operation: "query",
        context: { timeoutMs },
    },
    query: query.slice(0, 100),
    timeoutMs,
});

export const dbDeadlockError = (
    query: string,
    deadlockId: string,
    meta: AppErrorMeta = {
        layer: "Repository",
        httpStatus: 503,
    },
): DbDeadlockError => ({
    kind: "DbDeadlock",
    code: "DB_DEADLOCK_DETECTED",
    message: `Database deadlock detected`,
    meta: {
        ...meta,
        operation: "query",
        context: { deadlockId },
    },
    query: query.slice(0, 100),
    deadlockId,
});

const safeContext = (
    data: Record<string, unknown>,
): Record<string, string | number | boolean> => {
    const result: Record<string, string | number | boolean> = {};
    for (const [key, value] of Object.entries(data)) {
        if (value === null || value === undefined) {
            result[key] = false; // null→false変換（金融系ではnull許容しない）
        } else if (Array.isArray(value)) {
            result[key] = value.length.toString(); // 配列→length string
        } else if (typeof value === "object") {
            result[key] = Object.keys(value).length.toString(); // オブジェクト→key数
        } else {
            result[key] = value as string | number | boolean;
        }
    }
    return result;
};

const createDbMeta = (
    baseMeta: AppErrorMeta,
    table: string,
    details: Record<string, unknown>,
): AppErrorMeta => ({
    ...baseMeta,
    entityType: table,
    context: safeContext(details),
});

export const dbDuplicateKeyError = (
    table: string,
    keyFields: string[],
    keyValues: unknown[],
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 409 },
): DbDuplicateKeyError => ({
    kind: "DbDuplicateKey",
    code: "DB_DUPLICATE_KEY",
    message: `Duplicate key violation on ${table}`,
    meta: createDbMeta(meta, table, {
        keyFields: keyFields.join(","),
        keyValuesCount: keyValues.length,
        firstKeyValueType: typeof keyValues[0],
    }),
    table,
    keyFields,
    keyValues,
});

// 型ガード
export const isDbError = (
    error: AppErrorBase,
): error is
    | DbConnectionError
    | DbQueryError
    | DbTransactionError
    | DbConstraintError
    | DbTimeoutError
    | DbDeadlockError
    | DbDuplicateKeyError =>
    [
        "DbConnection",
        "DbQuery",
        "DbTransaction",
        "DbConstraint",
        "DbTimeout",
        "DbDeadlock",
        "DbDuplicateKey",
    ].includes(error.kind);
