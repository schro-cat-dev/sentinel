// NOTE: エラー発生時の回復処理などのパイプラインに繋ぐそうでのイベントの緊急度など、条件分岐する際の評価指標。
// これを導入することにより、カスタマイズの柔軟性を担保。
// 集合論的に見て重複より全てをカバーできているか。
// 1. 粒度的にwalとかdbとかはexternalに分類。
// 2. ServiceUnavailableは障害などをカバー。
// Internal: システム内部、External: 外部システム内部、BusinessConflict: ビジネス要件が原因による失敗・エラー、ServiceUnavailable: 前提条件が崩れている・存在していない
export const ERROR_KIND = {
    INTERNAL: "Internal",
    EXTERNAL: "External",
    BUSINESS_CONFLICT: "BusinessConflict",
    SERVICE_UNAVAILABLE: "ServiceUnavailable",
} as const;

export type ErrorKind = (typeof ERROR_KIND)[keyof typeof ERROR_KIND];
