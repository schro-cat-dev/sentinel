import {
    ACCESS_ERROR_KINDS,
    ApplicationErrorDetailKind,
    AUTH_ERROR_KINDS,
    getApplicationErrorCategory,
    LIMIT_OVER_ERROR_KINDS,
    PERMISSION_ERROR_KINDS,
    SECURITY_ERROR_KINDS,
    VALIDATION_ERROR_KINDS,
} from "./application";
import {
    CACHE_ERROR_KINDS,
    DATASTORE_ERROR_KINDS,
    DB_ERROR_KINDS,
    getInfraErrorCategory,
    PersistenceErrorDetailKind,
    STORAGE_ERROR_KINDS,
} from "./persistence";

// 全エラー種類情報エクスポート（メインバレル）
export * from "./application";
export * from "./persistence";

/**
 * 全エラー種別の完全なunion型（運用・監視用）
 * @remarks Application(400-429系) + Persistence(Infrastructure全般)
 */
export type DetailErrorKind =
    | ApplicationErrorDetailKind
    | PersistenceErrorDetailKind;

/**
 * 全エラー種類の大枠カテゴリ分類（運用ダッシュボード用）
 */
export type ErrorCategoryScope = "application" | "persistence";

/**
 * エラーカテゴリスコープ判定型ガード
 */
export const isApplicationErrorDetailKind = (
    kind: DetailErrorKind,
): kind is ApplicationErrorDetailKind => {
    try {
        getApplicationErrorCategory(kind as ApplicationErrorDetailKind);
        return true;
    } catch {
        return false;
    }
};

export const isPersistenceErrorDetailKind = (
    kind: DetailErrorKind,
): kind is PersistenceErrorDetailKind => {
    try {
        getInfraErrorCategory(kind as PersistenceErrorDetailKind);
        return true;
    } catch {
        return false;
    }
};

/**
 * detailKindからカテゴリスコープ（application/persistence）を判定
 * @remarks 型安全な最終分類関数
 */
export const getErrorCategoryScope = (
    kind: DetailErrorKind,
): ErrorCategoryScope => {
    if (isApplicationErrorDetailKind(kind)) return "application";
    if (isPersistenceErrorDetailKind(kind)) return "persistence";
    throw new Error(`Unknown DetailErrorKind: ${kind}`);
};

/**
 * 全KINDs確認用（デバッグ・テスト）
 * @remarks キー名一覧（運用確認用）
 */
export const ALL_ERROR_KINDS = {
    application: [
        ...Object.keys(AUTH_ERROR_KINDS),
        ...Object.keys(VALIDATION_ERROR_KINDS),
        ...Object.keys(LIMIT_OVER_ERROR_KINDS),
        ...Object.keys(PERMISSION_ERROR_KINDS),
        ...Object.keys(ACCESS_ERROR_KINDS),
        ...Object.keys(SECURITY_ERROR_KINDS),
    ],
    persistence: [
        ...Object.keys(DB_ERROR_KINDS),
        ...Object.keys(CACHE_ERROR_KINDS),
        ...Object.keys(DATASTORE_ERROR_KINDS),
        ...Object.keys(STORAGE_ERROR_KINDS),
    ],
} as const;
