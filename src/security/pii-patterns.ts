/**
 * PII 正規表現パターンの単一ソース定義
 *
 * masking-service.ts（マスキング実行）と error-utils.ts（PII検出）の
 * 両方がこのモジュールからパターンを参照する。
 *
 * パターンはフラグなしで定義し、利用側で用途に応じたフラグを付与する:
 * - マスキング: global (/g) フラグ付きで replace() に使用
 * - 検出: フラグなしで test() に使用
 */

import type { PiiCategory } from "../configs/masking-rule";

/** PIIカテゴリごとのパターン定義（フラグなし source 文字列） */
export const PII_PATTERN_SOURCES: Record<PiiCategory, string> = {
    CREDIT_CARD: String.raw`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b`,
    PHONE: String.raw`(\+81|0)[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{4}`,
    EMAIL: String.raw`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
    GOVERNMENT_ID: String.raw`\b\d{12}\b`,
    JAPAN_ACCOUNT: String.raw`\d{3}[-]\d{7}|\d{4}[-]\d{7}`,
    POSTAL_CODE: String.raw`(?:〒?\s?)?\d{3}[-]?\d{4}`,
    DRIVER_LICENSE: String.raw`\b[1-9]\d{5,7}[0-9\\*]\d{2,4}\b`,
    HEALTH_INSURANCE: String.raw`\b\d{2}\s?\d{2}\s?\d{6}\b`,
} as const;

/**
 * マスキング用: global フラグ付き RegExp を生成
 * MaskingService が使用する
 */
export function getPiiPatternForMasking(category: PiiCategory): RegExp {
    const source = PII_PATTERN_SOURCES[category];
    return new RegExp(source, "g");
}

/**
 * PII検出用: フラグなし RegExp 配列を生成
 * error-utils の isPiiSafe() が使用する
 *
 * マスキング用パターン + 追加の汎用PII検出パターン（口座番号、IBAN等）
 */
export function getPiiDetectionPatterns(): readonly RegExp[] {
    const patterns: RegExp[] = Object.values(PII_PATTERN_SOURCES).map(
        (source) => new RegExp(source, "i"),
    );
    // 追加の汎用パターン（error-utils由来、カテゴリに属さないもの）
    patterns.push(
        /[A-Z]{2}\d{2}[A-Z0-9]{4,30}/, // IBAN簡易
        /\b[a-zA-Z]{2,}[.][a-zA-Z]{2,}\b/i, // 個人名パターン
    );
    return patterns;
}
