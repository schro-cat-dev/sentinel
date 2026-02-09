/**
 * NoSQL/ドキュメントDBエラー種別シード値（キー名＝意味）
 */
export const DATASTORE_ERROR_KINDS = {
    // 接続・ネットワーク系
    CONNECTION: "DatastoreConnection" as const,
    NETWORK_TIMEOUT: "DatastoreNetworkTimeout" as const,

    // 容量制限系
    PROVISIONED_THROUGHPUT_EXCEEDED:
        "DatastoreProvisionedThroughputExceeded" as const,
    THROTTLED: "DatastoreThrottled" as const,
    WRITE_THROTTLE: "DatastoreWriteThrottle" as const,
    READ_THROTTLE: "DatastoreReadThrottle" as const,

    // 条件チェック系
    CONDITIONAL_CHECK_FAILED: "DatastoreConditionalCheckFailed" as const,

    // トランザクション系
    TRANSACTION_CANCELED: "DatastoreTransactionCanceled" as const,
    TRANSACTION_CONFLICT: "DatastoreTransactionConflict" as const,

    // インデックス系
    INDEX_NOT_FOUND: "DatastoreIndexNotFound" as const,
    INVALID_INDEX: "DatastoreInvalidIndex" as const,

    // ドキュメント系
    DOCUMENT_SIZE_EXCEEDED: "DatastoreDocumentSizeExceeded" as const,
    DOCUMENT_NOT_FOUND: "DatastoreDocumentNotFound" as const,

    // 一貫性系
    EVENTUAL_CONSISTENCY_CONFLICT:
        "DatastoreEventualConsistencyConflict" as const,

    // リソース系
    TABLE_NOT_FOUND: "DatastoreTableNotFound" as const,
    LIMIT_EXCEEDED: "DatastoreLimitExceeded" as const,
} as const;

/**
 * NoSQL/ドキュメントDBエラー種別（最終一貫性モデル）
 * @remarks DynamoDB, Firestore, MongoDB対応
 */
export type DatastoreErrorKind =
    (typeof DATASTORE_ERROR_KINDS)[keyof typeof DATASTORE_ERROR_KINDS];
