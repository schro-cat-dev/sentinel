/**
 * PII コンテキストマスキング
 *
 * エラーログ等のcontext情報からPIIを検出・マスキングする。
 * security/ 層に配置し、PII検出パターンは pii-patterns.ts から取得する。
 *
 * 旧配置: shared/utils/error-utils.ts（後方互換のため再exportあり）
 */

import { getPiiDetectionPatterns } from "./pii-patterns";

type SafeValue = string | number | boolean | null;

const PII_PATTERNS: readonly RegExp[] = getPiiDetectionPatterns();

/**
 * PII安全確認（偽陰性ゼロ）
 *
 * 長さ3未満の文字列はパターンマッチをスキップして true を返す。
 * 根拠: PII_PATTERNS 内の全正規表現は最短でも3文字以上の入力を要求する
 * （メール: "a@b" 以上、電話: "0X-..." 以上、カード: 4桁以上、等）。
 * したがって2文字以下の入力がいずれかのパターンに一致することは不可能であり、
 * このガード節は偽陰性を生まない安全な最適化である。
 *
 * 不変条件: pii-patterns.ts にパターンを追加する際は、
 *   最短マッチ長が3以上であることを確認すること。
 *   3文字未満でマッチするパターンを追加する場合はこのガードを更新する。
 *
 * @see tests/unit/shared/error-utils.test.ts — "length < 3 閾値の設計根拠テスト"
 */
export const isPiiSafe = (value: string): boolean => {
    if (!value || value.length < 3) return true;
    return !PII_PATTERNS.some((pattern) => pattern.test(value));
};

/** PII自動マスキング（完全型安全・prototype pollution防御） */
export const maskPiiContext = (
    context: Record<string, SafeValue>,
): Record<string, SafeValue> => {
    const safe = { ...context };

    for (const key in safe) {
        if (!Object.prototype.hasOwnProperty.call(safe, key)) continue;
        const typedKey = key as keyof typeof safe;
        const value = safe[typedKey];

        if (!isPiiSafe(key)) {
            const maskedKey =
                `***_${key.length}_MASKED***` as keyof typeof safe;
            safe[maskedKey] = value;
            delete safe[typedKey];
        } else if (typeof value === "string" && !isPiiSafe(value)) {
            safe[typedKey] = `***_${key}_MASKED***` as SafeValue;
        }
    }

    return safe;
};
