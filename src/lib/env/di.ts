import type { CleanEnvSchema } from "./types";
import type { EnvValidator } from "./validator";

export interface EnvProvider {
    [key: string]: string | number | boolean;
}

export interface EnvDI {
    createEnv<TClean extends CleanEnvSchema>(
        validator: EnvValidator<TClean>,
    ): TClean;
}
