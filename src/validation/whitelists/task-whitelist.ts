import { TASK_ACTION_TYPES, TASK_SEVERITIES } from "../../types/task";
import type { WhitelistDefinition } from "../whitelist-types";

const VALID_EXECUTION_LEVELS: readonly string[] = ["AUTO", "SEMI_AUTO", "MANUAL", "MONITOR"];

export const TASK_WHITELIST: WhitelistDefinition = {
    domain: "task",
    fields: {
        actionType: TASK_ACTION_TYPES,
        severity: TASK_SEVERITIES,
        executionLevel: VALID_EXECUTION_LEVELS,
    },
};
