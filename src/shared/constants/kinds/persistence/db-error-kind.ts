/**
 * RDBMS（PostgreSQL, MySQL等）エラー種別（キー名＝意味）
 */
export const DB_ERROR_KINDS = {
    // 接続系
    CONNECTION: "DbConnection" as const, // 汎用系；下3つをはじめとする具体化した他のエラーケースに該当しないのを扱う用
    CONNECTION_TIMEOUT: "DbConnectionTimeout" as const,
    CONNECTION_REFUSED: "DbConnectionRefused" as const,
    CONNECTION_POOL_EXHAUSTED: "DbConnectionPoolExhausted" as const,

    // クエリ実行系
    QUERY: "DbQuery" as const,
    QUERY_TIMEOUT: "DbQueryTimeout" as const,
    QUERY_SYNTAX: "DbQuerySyntax" as const,

    // トランザクション系
    TRANSACTION: "DbTransaction" as const,
    TRANSACTION_BEGIN: "DbTransactionBegin" as const,
    TRANSACTION_COMMIT: "DbTransactionCommit" as const,
    TRANSACTION_ROLLBACK: "DbTransactionRollback" as const,
    TRANSACTION_TIMEOUT: "DbTransactionTimeout" as const,

    // 制約違反系
    CONSTRAINT: "DbConstraint" as const,
    FOREIGN_KEY_CONSTRAINT: "DbForeignKeyConstraint" as const,
    UNIQUE_CONSTRAINT: "DbUniqueConstraint" as const,
    CHECK_CONSTRAINT: "DbCheckConstraint" as const,
    NOT_NULL_CONSTRAINT: "DbNotNullConstraint" as const,

    // 同時実行系
    DEADLOCK: "DbDeadlock" as const,
    LOCK_TIMEOUT: "DbLockTimeout" as const,
    SERIALIZATION_FAILURE: "DbSerializationFailure" as const,

    // 重複系
    DUPLICATE_KEY: "DbDuplicateKey" as const,

    // リソース系
    OUT_OF_MEMORY: "DbOutOfMemory" as const,
    DISK_FULL: "DbDiskFull" as const,
} as const;

/**
 * RDBMS（PostgreSQL, MySQL等）エラー種別
 * @remarks ACIDトランザクション・制約違反・デッドロック特化
 */
export type DbErrorKind = (typeof DB_ERROR_KINDS)[keyof typeof DB_ERROR_KINDS];
