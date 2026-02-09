/**
 * 認証関連エラー種別（401 Unauthorized系）
 * @remarks 認証情報不正、トークン期限切れ、認証方式不正など
 */
export const AUTH_ERROR_KINDS = {
    /** 認証情報が存在しない、または無効（ID/PW不一致等） */
    CREDENTIALS_INVALID: "CredentialsInvalid" as const,
    /** Bearerトークン形式不正（Bearer欠落、Base64デコード失敗等） */
    TOKEN_FORMAT_INVALID: "TokenFormatInvalid" as const,
    /** トークン署名検証失敗（改ざん検出、秘密鍵不一致等） */
    TOKEN_SIGNATURE_INVALID: "TokenSignatureInvalid" as const,
    /** トークン期限切れ（expクレーム検証失敗） */
    TOKEN_EXPIRED: "TokenExpired" as const,
    /** トークン発行者不一致（issクレーム検証失敗） */
    TOKEN_ISSUER_INVALID: "TokenIssuerInvalid" as const,
    /** 認証方式未サポート（BasicAuth禁止等） */
    AUTH_METHOD_UNSUPPORTED: "AuthMethodUnsupported" as const,
    /** 多要素認証（MFA/2FA）が必要 */
    MFA_REQUIRED: "MfaRequired" as const,
    /** 認証プロバイダ（OAuth, SAML等）接続エラー */
    PROVIDER_CONNECTION_FAILED: "ProviderConnectionFailed" as const,
} as const;

export type AuthErrorKind =
    (typeof AUTH_ERROR_KINDS)[keyof typeof AUTH_ERROR_KINDS];
