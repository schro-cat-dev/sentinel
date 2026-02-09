import { ACCESS_ERROR_KINDS, AccessErrorKind } from "./access";
import { AUTH_ERROR_KINDS, AuthErrorKind } from "./auth";
import { LIMIT_OVER_ERROR_KINDS, LimitOverKind } from "./limit-over";
import { PERMISSION_ERROR_KINDS, PermissionErrorKind } from "./permission";
import { SECURITY_ERROR_KINDS, SecurityErrorKind } from "./security";
import { VALIDATION_ERROR_KINDS, ValidationErrorKind } from "./validation";

export * from "./auth";
export * from "./validation";
export * from "./limit-over";
export * from "./permission";
export * from "./access";
export * from "./security";

/**
 * 全アプリケーションエラー種別の完全なunion型（運用・監視用）
 * @remarks 400-429系HTTPステータス対応
 */
export type ApplicationErrorDetailKind =
    | AuthErrorKind
    | ValidationErrorKind
    | LimitOverKind
    | PermissionErrorKind
    | AccessErrorKind
    | SecurityErrorKind;

/**
 * アプリケーションエラー詳細種別の全リスト（運用・ログ用）
 * API等の互換性の観点から、lowercaseに変換
 */
export const APPLICATION_ERROR_DETAIL_TYPES = [
    // 各KINDsからキー名を自動取得→kebab-case
    ...Object.keys(AUTH_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(VALIDATION_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(LIMIT_OVER_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(PERMISSION_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(ACCESS_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(SECURITY_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
] as const;

/**
 * アプリケーションエラーのカテゴリ分類（運用ダッシュボード用）
 */
export type ApplicationErrorCategory =
    | "auth"
    | "validation"
    | "limit-over"
    | "permission"
    | "access"
    | "security";

/**
 * 型ガード群（完全網羅・型安全・ApplicationErrorDetailKind直受け）
 */
export const isAuthErrorKind = (
    kind: ApplicationErrorDetailKind,
): kind is AuthErrorKind =>
    Object.values(AUTH_ERROR_KINDS).includes(kind as AuthErrorKind);

export const isValidationErrorKind = (
    kind: ApplicationErrorDetailKind,
): kind is ValidationErrorKind =>
    Object.values(VALIDATION_ERROR_KINDS).includes(kind as ValidationErrorKind);

export const isLimitOverErrorKind = (
    kind: ApplicationErrorDetailKind,
): kind is LimitOverKind =>
    Object.values(LIMIT_OVER_ERROR_KINDS).includes(kind as LimitOverKind);

export const isPermissionErrorKind = (
    kind: ApplicationErrorDetailKind,
): kind is PermissionErrorKind =>
    Object.values(PERMISSION_ERROR_KINDS).includes(kind as PermissionErrorKind);

export const isAccessErrorKind = (
    kind: ApplicationErrorDetailKind,
): kind is AccessErrorKind =>
    Object.values(ACCESS_ERROR_KINDS).includes(kind as AccessErrorKind);

export const isSecurityErrorKind = (
    kind: ApplicationErrorDetailKind,
): kind is SecurityErrorKind =>
    Object.values(SECURITY_ERROR_KINDS).includes(kind as SecurityErrorKind);

/**
 * シード値からカテゴリを判定（型安全・型ガード統一）
 */
export const getApplicationErrorCategory = (
    kind: ApplicationErrorDetailKind,
): ApplicationErrorCategory => {
    if (isAuthErrorKind(kind)) return "auth";
    if (isValidationErrorKind(kind)) return "validation";
    if (isLimitOverErrorKind(kind)) return "limit-over";
    if (isPermissionErrorKind(kind)) return "permission";
    if (isAccessErrorKind(kind)) return "access";
    if (isSecurityErrorKind(kind)) return "security";
    throw new Error(`Unknown ApplicationErrorDetailKind: ${kind}`);
};

/**
 * 全アプリケーションエラーKINDsのエクスポート（外部利用用）
 */
export {
    AUTH_ERROR_KINDS,
    VALIDATION_ERROR_KINDS,
    LIMIT_OVER_ERROR_KINDS,
    PERMISSION_ERROR_KINDS,
    ACCESS_ERROR_KINDS,
    SECURITY_ERROR_KINDS,
};
