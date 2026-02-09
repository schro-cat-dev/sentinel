/**
 * セキュリティ関連エラー種別
 * @remarks 攻撃検知、不正アクセス、入力サニタイズ失敗等
 */
export const SECURITY_ERROR_KINDS = {
    // サニタイズ関連
    /** 不正な文字エンコーディングまたは制御文字検出 */
    UNSAFE_INPUT: "UnsafeInput" as const,
    /** `<script>`等のXSS攻撃パターン検出 */
    XSS_DETECTED: "XssDetected" as const,
    /** SQLインジェクション攻撃パターンマッチ */
    SQL_INJECTION_RISK: "SqlInjectionRisk" as const,
    /** HTMLパーシング失敗または不正構造 */
    HTML_MALFORMED: "HtmlMalformed" as const,

    // 不正アクセス検知
    /** 異常なアクセス頻度・パターン検出（例：同一IP短時間大量リクエスト） */
    ABNORMAL_ACCESS_PATTERN: "AbnormalAccessPattern" as const,
    /** 同一アカウント連続認証失敗（ブルートフォース攻撃） */
    BRUTE_FORCE_DETECTED: "BruteForceDetected" as const,
    /** CSRFトークン欠落または不一致 */
    CSRF_TOKEN_INVALID: "CsrfTokenInvalid" as const,
    /** IPアドレスがブラックリストに登録済み */
    IP_BLACKLISTED: "IpBlacklisted" as const,

    // その他セキュリティ
    /** 既知のマルウェア署名または不正ペイロード検出 */
    MALICIOUS_PAYLOAD: "MaliciousPayload" as const,
    /** リクエストレートが統計的異常値超過 */
    RATE_ANOMALY: "RateAnomaly" as const,
} as const;

export type SecurityErrorKind =
    (typeof SECURITY_ERROR_KINDS)[keyof typeof SECURITY_ERROR_KINDS];
