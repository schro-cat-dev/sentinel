import type { WhitelistDefinition } from "../whitelist-types";

export const VALID_PII_CATEGORIES: readonly string[] = [
    "CREDIT_CARD",
    "PHONE",
    "EMAIL",
    "GOVERNMENT_ID",
    "JAPAN_ACCOUNT",
    "POSTAL_CODE",
    "DRIVER_LICENSE",
    "HEALTH_INSURANCE",
];

export const PRIVACY_WHITELIST: WhitelistDefinition = {
    domain: "privacy",
    fields: {
        piiCategory: VALID_PII_CATEGORIES,
    },
};
