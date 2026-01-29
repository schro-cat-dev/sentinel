import type { EnvRawSchema, CleanEnvSchema } from './types';

export interface EnvValidator<
  TClean extends CleanEnvSchema,
  TRaw extends EnvRawSchema = EnvRawSchema,
> {
  validate(cleanEnv: TClean): TClean;
  parse(rawEnv: TRaw): TClean;
}
