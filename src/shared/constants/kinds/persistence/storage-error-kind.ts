/**
 * ストレージ/WALエラー種別シード値（技術非依存・抽象層・キー名＝意味）
 */
export const STORAGE_ERROR_KINDS = {
    // WAL特化（Sentinelの中核）
    WAL_INIT: "WalInit" as const,
    WAL_WRITE: "WalWrite" as const,
    WAL_READ: "WalRead" as const,
    WAL_CRYPTO: "WalCrypto" as const,
    WAL_DISK_FULL: "WalDiskFull" as const,
    WAL_LOCK: "WalLock" as const,
    WAL_TRUNCATE: "WalTruncate" as const,
    WAL_CORRUPTED: "WalCorrupted" as const,
    WAL_FSYNC: "WalFsync" as const,
    WAL_SEGMENT_FULL: "WalSegmentFull" as const,
    WAL_ARCHIVE_FAILED: "WalArchiveFailed" as const,
    WAL_CHECKPOINT_FAILED: "WalCheckpointFailed" as const,
    WAL_REPLAY_CONFLICT: "WalReplayConflict" as const,

    // ローカルファイルシステム（技術非依存）
    FILE_PERMISSION_DENIED: "FilePermissionDenied" as const,
    FILE_NOT_FOUND: "FileNotFound" as const,
    FILE_EXISTS: "FileExists" as const,
    FILE_READ_ONLY: "FileReadOnly" as const,
    FILE_TOO_LARGE: "FileTooLarge" as const,
    DIRECTORY_NOT_FOUND: "DirectoryNotFound" as const,
    INVALID_PATH: "InvalidPath" as const,
    PATH_TRAVERSAL_DETECTED: "PathTraversalDetected" as const,
    FILE_LOCK_CONTENTION: "FileLockContention" as const,

    // I/O性能系（耐久性の観点より）
    // storage = 「順序保証＋耐久性」
    // ↓
    // 性能問題も耐久性直撃
    // - IoRateLimitExceeded → WAL fsync 15秒超 → クラスタ停止
    // - IoLatencyHigh → ディスク99th 500ms超 → ユーザー影響
    IO_RATE_LIMIT_EXCEEDED: "IoRateLimitExceeded" as const,
    IO_BANDWIDTH_EXCEEDED: "IoBandwidthExceeded" as const,
    IO_LATENCY_HIGH: "IoLatencyHigh" as const,

    // オブジェクトストレージ（S3/GCS/Azure非依存）
    OBJECT_STORAGE_BUCKET_NOT_FOUND: "ObjectStorageBucketNotFound" as const,
    OBJECT_STORAGE_OBJECT_NOT_FOUND: "ObjectStorageObjectNotFound" as const,
    OBJECT_STORAGE_UPLOAD_FAILED: "ObjectStorageUploadFailed" as const,
    OBJECT_STORAGE_CHECKSUM_MISMATCH: "ObjectStorageChecksumMismatch" as const,
    OBJECT_STORAGE_ACCESS_DENIED: "ObjectStorageAccessDenied" as const,
    OBJECT_STORAGE_POLICY_DENIED: "ObjectStoragePolicyDenied" as const,
    OBJECT_STORAGE_MULTIPART_UPLOAD_ABORTED:
        "ObjectStorageMultipartUploadAborted" as const,
    OBJECT_STORAGE_INCOMPLETE_MULTIPART_UPLOAD:
        "ObjectStorageIncompleteMultipartUpload" as const,
    OBJECT_STORAGE_REQUEST_TIMEOUT: "ObjectStorageRequestTimeout" as const,
    OBJECT_STORAGE_TOO_MANY_REQUESTS: "ObjectStorageTooManyRequests" as const,

    // ディスク・ハードウェア系
    DISK_READ_ERROR: "DiskReadError" as const,
    DISK_WRITE_ERROR: "DiskWriteError" as const,
    DISK_HARDWARE_FAILURE: "DiskHardwareFailure" as const,
    DISK_SEEK_ERROR: "DiskSeekError" as const,
    DISK_ECC_ERROR: "DiskEccError" as const,
    DISK_SECTOR_CORRUPTION: "DiskSectorCorruption" as const,
} as const;

/**
 * ストレージ/WALエラー種別（順序保証・耐久性重視）
 * @remarks WAL, S3, ローカルファイルシステム対応
 */
export type StorageErrorKind =
    (typeof STORAGE_ERROR_KINDS)[keyof typeof STORAGE_ERROR_KINDS];
