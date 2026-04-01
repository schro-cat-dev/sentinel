import type { WhitelistDefinition } from "../whitelist-types";
import { PII_CATEGORIES } from "../../configs/masking-rule";

export const VALID_PII_CATEGORIES: readonly string[] = PII_CATEGORIES;

export const PRIVACY_WHITELIST: WhitelistDefinition = {
    domain: "privacy",
    fields: {
        piiCategory: VALID_PII_CATEGORIES,
    },
};
