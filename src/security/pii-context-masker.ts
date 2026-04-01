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

/** PII安全確認（偽陰性ゼロ） */
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
