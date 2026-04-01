/**
 * マスキングルール定義
 */

/** PIIカテゴリの単一ソース定義。validation/whitelists, config-loader等はここからimportする */
export const PII_CATEGORIES = [
    "CREDIT_CARD",
    "PHONE",
    "EMAIL",
    "GOVERNMENT_ID",
    "JAPAN_ACCOUNT",
    "POSTAL_CODE",
    "DRIVER_LICENSE",
    "HEALTH_INSURANCE",
] as const;

export type PiiCategory = (typeof PII_CATEGORIES)[number];

export type MaskingRule =
    | {
          type: "REGEX";
          pattern: RegExp;
          replacement: string;
          description: string;
      }
    | {
          type: "KEY_MATCH";
          sensitiveKeys: string[];
          replacement?: string;
      }
    | {
          type: "PII_TYPE";
          category: PiiCategory;
      };
