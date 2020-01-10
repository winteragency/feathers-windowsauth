import { Application } from '@feathersjs/feathers';

export interface LdapSetupSettings {
  authService?: string;
}

export const getDefaultSettings = (_app: Application, other?: Partial<LdapSetupSettings>) => {
  const defaults: LdapSetupSettings = {
    ...other
  };

  return defaults;
};