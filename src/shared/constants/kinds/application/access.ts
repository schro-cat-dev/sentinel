/**
 * アクセス先・リソース状態関連エラー
 * @remarks NotFound(404)/Conflict(409)/テナント不一致等
 */
export const ACCESS_ERROR_KINDS = {
    // 404系（リソース存在しない）
    /** リクエストされたリソース（エンティティ）がデータベースに存在しない */
    RESOURCE_NOT_FOUND: "ResourceNotFound" as const,
    /** リクエストされたパスまたはエンドポイントが存在しない */
    PATH_NOT_ALLOWED: "PathNotAllowed" as const,

    // 409系（リソース状態競合）
    /** リソースが既に存在する（一意制約違反等） */
    ALREADY_EXISTS: "AlreadyExists" as const,
    /** 同時編集等によるリソース状態の競合 */
    CONFLICT: "Conflict" as const,
    /** ETag/バージョン番号不一致（楽観的ロック失敗） */
    VERSION_MISMATCH: "VersionMismatch" as const,

    // 403系（テナント/アクセス制御）
    /** リクエストとリソースのテナント（Tenant）が不一致 */
    TENANT_MISMATCH: "TenantMismatch" as const,
    /** アクセスしようとしたリソースへのアクセス権限がない */
    ACCESS_DENIED: "AccessDenied" as const,
} as const;

export type AccessErrorKind =
    (typeof ACCESS_ERROR_KINDS)[keyof typeof ACCESS_ERROR_KINDS];
