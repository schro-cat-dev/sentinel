// データ型等一元化、汎用化の場合は、本ファイル最下部のコメントアウトの実装方針確認。（他PJ検索面倒なので）
export const SUCCESS_HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202, // 非同期処理受付
    NO_CONTENT: 204, // DELETE成功
} as const;

export const ERROR_HTTP_STATUS = {
    BAD_REQUEST: 400, // バリデーションエラー i.e. リクエスト自体の破損・不整合（JSON破損、必須ヘッダーなし、等））
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    REQUEST_TIMEOUT: 408,
    CONFLICT: 409, // リソース競合（重複、ロック）
    UNPROCESSABLE_ENTITY: 422, // 意味論的エラー（残高不足、期限切れ、等）
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500, // 予期しないエラー
    SERVICE_UNAVAILABLE: 503,
    GATEWAY_TIMEOUT: 504, // DB/外部APIタイムアウト
} as const;

export const REDIRECT_HTTP_STATUS = {
    MOVED_PERMANENTLY: 301,
    FOUND: 302,
    SEE_OTHER: 303,
    TEMPORARY_REDIRECT: 307,
    PERMANENT_REDIRECT: 308, // 現代API必須らしい
} as const;

export const HTTP_STATUS = {
    ...ERROR_HTTP_STATUS,
    ...SUCCESS_HTTP_STATUS,
    ...REDIRECT_HTTP_STATUS,
} as const;

export type HttpStatusCode = (typeof HTTP_STATUS)[keyof typeof HTTP_STATUS];

// よく使うやつ。NOTE: 他のデータハンドリングタイプはまたメイン個人PJ内検索。
// import { z } from "zod";

// /**
//  * HASH_TYPES represents the supported hash algorithms for PBKDF2.
//  */
// export const HASH_TYPES = {
//     SHA1: "SHA-1",
//     SHA256: "SHA-256",
//     SHA384: "SHA-384",
//     SHA512: "SHA-512",
// } as const;

// /**
//  * HashTypeEnum defines the Zod enum for hash algorithms.
//  */
// export const HashTypeEnum = z.enum(
//     Object.values(HASH_TYPES) as unknown as [
//         (typeof HASH_TYPES)[keyof typeof HASH_TYPES],
//     ],
// );

// export type HashType = z.infer<typeof HashTypeEnum>;
