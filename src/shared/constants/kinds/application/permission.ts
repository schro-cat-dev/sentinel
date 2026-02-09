/**
 * 純粋な認可ポリシー違反（403 Forbidden）
 * @remarks テナント不一致はaccess.tsで管理。RBAC/ABACポリシー違反のみ
 */
export const PERMISSION_ERROR_KINDS = {
    /** ユーザーに必要な権限（Permission）が付与されていない */
    INSUFFICIENT_PERMISSION: "InsufficientPermission" as const,
    /** リソースに対するアクセス権限が明示的に禁止されている */
    FORBIDDEN_RESOURCE: "ForbiddenResource" as const,
    /** 操作実行に必要なロール（Role）がユーザーに付与されていない */
    ROLE_REQUIRED: "RoleRequired" as const,
    /** OAuthスコープまたはAPIスコープが不足している */
    SCOPE_MISSING: "ScopeMissing" as const,
} as const;

export type PermissionErrorKind =
    (typeof PERMISSION_ERROR_KINDS)[keyof typeof PERMISSION_ERROR_KINDS];
