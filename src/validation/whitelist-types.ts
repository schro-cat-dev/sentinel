/**
 * 1つのホワイトリスト定義。ドメインごとに1つ。
 * フィールド名 → 許可値セットのマッピング。
 */
export interface WhitelistDefinition {
    /** ドメイン識別子（ログ・エラーメッセージ用） */
    readonly domain: string;
    /** フィールド名 → 有効値の読み取り専用配列 */
    readonly fields: Readonly<Record<string, readonly string[]>>;
}

/**
 * ユーザーが config で追加するカスタム有効値。
 * キーはフィールド名（例: "actionType"）、値は追加する文字列配列。
 */
export type WhitelistExtensions = Partial<Record<string, readonly string[]>>;
