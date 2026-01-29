import type { CleanEnvSchema } from './types';
import type { EnvValidator } from './validator';
import type { EnvDI } from './di';

export const EnvFactory: EnvDI = {
  createEnv: <TClean extends CleanEnvSchema>(
    validator: EnvValidator<TClean>
  ): TClean => {
    const parsed = validator.parse(process.env);
    return validator.validate(parsed);
  },
};
