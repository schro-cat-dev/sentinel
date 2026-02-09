/**
 * 入力検証関連エラー種別（400 Bad Request系）
 * @remarks スキーマ違反、型不正、範囲外、ビジネスルール違反など
 */
export const VALIDATION_ERROR_KINDS = {
    /** JSONスキーマ検証失敗 */
    SCHEMA_VIOLATION: "Validation" as const,
    /** 必須フィールド欠落 */
    REQUIRED_FIELD_MISSING: "Validation" as const,
    /** データ型不正 */
    INVALID_TYPE: "Validation" as const,
    /** 値が範囲外 */
    OUT_OF_RANGE: "Validation" as const,
    /** 文字列形式不正（email, uuid, date等） */
    INVALID_FORMAT: "Validation" as const,
    /** 長さ制限超過/不足 */
    LENGTH_VIOLATION: "Validation" as const,
    /** 配列要素数制限超過 */
    ARRAY_SIZE_VIOLATION: "Validation" as const,
    /** 数値精度超過 */
    PRECISION_VIOLATION: "Validation" as const,
    /** ビジネスルール違反 */
    BUSINESS_RULE_VIOLATION: "Validation" as const,
    /** 循環参照検出 */
    CIRCULAR_REFERENCE: "Validation" as const,
    /** 空値許可外 */
    EMPTY_VALUE_NOT_ALLOWED: "Validation" as const,
} as const;

/**
 * 入力検証エラー種別（全て "Validation" で統一し、コンテキストで区別）
 */
export type ValidationErrorKind =
    (typeof VALIDATION_ERROR_KINDS)[keyof typeof VALIDATION_ERROR_KINDS];

/**
 * 入力検証エラー詳細種別の列挙（運用・ログ用）
 */
export const VALIDATION_ERROR_DETAIL_TYPES = [
    "schema_violation",
    "required_field_missing",
    "invalid_type",
    "out_of_range",
    "invalid_format",
    "length_violation",
    "array_size_violation",
    "precision_violation",
    "business_rule_violation",
    "circular_reference",
    "empty_value_not_allowed",
] as const;

export type ValidationErrorDetailType =
    (typeof VALIDATION_ERROR_DETAIL_TYPES)[number];
