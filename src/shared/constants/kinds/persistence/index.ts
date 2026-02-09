import { CACHE_ERROR_KINDS, CacheErrorKind } from "./cache-error-kind";
import {
    DATASTORE_ERROR_KINDS,
    DatastoreErrorKind,
} from "./datastore-error-kind";
import { DB_ERROR_KINDS, DbErrorKind } from "./db-error-kind";
import { STORAGE_ERROR_KINDS, StorageErrorKind } from "./storage-error-kind";

export * from "./cache-error-kind";
export * from "./datastore-error-kind";
export * from "./db-error-kind";
export * from "./storage-error-kind";

/**
 * 全Infraエラー種別の完全なunion型（運用・監視用）
 * @remarks Sentinelの障害自動分類基盤
 */
export type PersistenceErrorDetailKind =
    | DbErrorKind
    | DatastoreErrorKind
    | CacheErrorKind
    | StorageErrorKind;

/**
 * 永続化層エラー詳細種別の全リスト（運用・ログ用）
 */
export const PERSISTENCE_ERROR_DETAIL_TYPES = [
    // 各ファイルのキー名から自動生成（kebab-case）
    ...Object.keys(DB_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(CACHE_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(DATASTORE_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
    ...Object.keys(STORAGE_ERROR_KINDS).map((k) =>
        k.toLowerCase().replace(/_/g, "-"),
    ),
] as const;

/**
 * Infraエラーのカテゴリ分類（運用ダッシュボード用）
 */
export type InfraErrorCategory = "db" | "datastore" | "cache" | "storage";

/**
 * 型ガード群（完全網羅・型安全・PersistenceErrorDetailKind直受け）
 */
export const isDbErrorKind = (
    kind: PersistenceErrorDetailKind,
): kind is DbErrorKind =>
    Object.values(DB_ERROR_KINDS).includes(kind as DbErrorKind);

export const isDatastoreErrorKind = (
    kind: PersistenceErrorDetailKind,
): kind is DatastoreErrorKind =>
    Object.values(DATASTORE_ERROR_KINDS).includes(kind as DatastoreErrorKind);

export const isCacheErrorKind = (
    kind: PersistenceErrorDetailKind,
): kind is CacheErrorKind =>
    Object.values(CACHE_ERROR_KINDS).includes(kind as CacheErrorKind);

export const isStorageErrorKind = (
    kind: PersistenceErrorDetailKind,
): kind is StorageErrorKind =>
    Object.values(STORAGE_ERROR_KINDS).includes(kind as StorageErrorKind);

/**
 * シード値からカテゴリを判定（型安全・型ガード統一）
 */
export const getInfraErrorCategory = (
    kind: PersistenceErrorDetailKind,
): InfraErrorCategory => {
    if (isDbErrorKind(kind)) return "db";
    if (isDatastoreErrorKind(kind)) return "datastore";
    if (isCacheErrorKind(kind)) return "cache";
    if (isStorageErrorKind(kind)) return "storage";
    throw new Error(`Unknown PersistenceErrorDetailKind: ${kind}`);
};
