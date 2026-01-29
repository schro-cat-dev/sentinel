export type EnvValue = string | number | boolean;

export interface EnvRawSchema {
    readonly [key: string]: string | undefined;
}

export interface CleanEnvSchema {
    readonly [key: string]: EnvValue;
}
