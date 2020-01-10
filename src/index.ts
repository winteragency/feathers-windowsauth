import Debug from 'debug';
import { Application } from '@feathersjs/feathers';
import { LdapStrategy, LdapUser } from './strategy';
import { default as setupExpress } from './express';
import { LdapSetupSettings, getDefaultSettings } from './utils';

const debug = Debug('feathers-windowsauth');

export { LdapSetupSettings, LdapStrategy, LdapUser };

export const setup = (options: LdapSetupSettings) => (app: Application) => {
  const service = app.defaultAuthentication ? app.defaultAuthentication(options.authService) : null;

  if (!service) {
    throw new Error('An authentication service must exist before registering feathers-windowsauth');
  }

  const { windowsauth } = service.configuration;

  if (!windowsauth) {
    debug(`No windowsauth configuration object found in authentication configuration. Skipping LDAP setup.`);
    return;
  }

  debug(`Setting app global windowsauth object`);
  app.set('windowsauth', {
    ...windowsauth,
    path: windowsauth.path ? windowsauth.path : '/ldap'
  });
};

export const express = (settings: Partial<LdapSetupSettings> = {}) => (app: Application) => {
  const options = getDefaultSettings(app, settings);

  app.configure(setup(options));
  app.configure(setupExpress(options));
};

export const expressLdap = express;