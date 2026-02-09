/**
 * キャッシュストアエラー種別シード値（キー名＝意味）
 */
export const CACHE_ERROR_KINDS = {
    // 接続系
    CONNECTION: "CacheConnection" as const,
    CONNECTION_TIMEOUT: "CacheConnectionTimeout" as const,
    CONNECTION_REFUSED: "CacheConnectionRefused" as const,

    // キー操作系
    KEY_NOT_FOUND: "CacheKeyNotFound" as const,
    KEY_TOO_LARGE: "CacheKeyTooLarge" as const,

    // 操作タイムアウト系
    TIMEOUT: "CacheTimeout" as const,
    OPERATION_TIMEOUT: "CacheOperationTimeout" as const,

    // メモリ系
    OUT_OF_MEMORY: "CacheOutOfMemory" as const,
    MAX_MEMORY_EXCEEDED: "CacheMaxMemoryExceeded" as const,
    EVICTION: "CacheEviction" as const, // max-memory-policy超過（LRU追放等）

    // シリアライズ系
    SERIALIZATION_FAILED: "CacheSerializationFailed" as const,
    DESERIALIZATION_FAILED: "CacheDeserializationFailed" as const,

    // クラスタ系
    CLUSTER_REDIRECT: "CacheClusterRedirect" as const,
    SLOT_NOT_FOUND: "CacheSlotNotFound" as const,

    // Luaスクリプト系
    SCRIPT_ERROR: "CacheScriptError" as const,
    SCRIPT_TIMEOUT: "CacheScriptTimeout" as const,

    // パイプライン系
    PIPELINE_ERROR: "CachePipelineError" as const,
} as const;

/**
 * キャッシュストアエラー種別（揮発性・最終一貫性）
 * @remarks Redis, Memcached対応。フォールバック前提
 */
export type CacheErrorKind =
    (typeof CACHE_ERROR_KINDS)[keyof typeof CACHE_ERROR_KINDS];
