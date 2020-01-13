// @ts-ignore
import Debug from 'debug';
import { Application } from '@feathersjs/feathers';
import { AuthenticationResult } from '@feathersjs/authentication';
import { Application as ExpressApplication } from '@feathersjs/express';
import { NotAuthenticated } from '@feathersjs/errors';
import { LdapSetupSettings } from './utils';
import { LdapStrategy } from './strategy';

import { default as passport } from 'passport';
import { default as WindowsStrategy } from 'passport-windowsauth';
 
const debug = Debug('feathers-windowsauth/express');

export default (options: LdapSetupSettings) => {
  return (feathersApp: Application) => {
    const { authService } = options;
    const app = feathersApp as ExpressApplication;
    const config = app.get('windowsauth');

    if (!config) {
      debug('No LDAP configuration found, skipping Express LDAP setup');
      return;
    }

    const { path, errorMessage } = config;

    passport.use(new WindowsStrategy(config, async (profile: any, done: Function) => {
      done(null, profile);
    }));

    app.post(path, async (req, res, next) => {
      passport.authenticate('WindowsAuthentication', async (err, ldapResponse, info) => {
        const service = app.defaultAuthentication(authService);
        const [ strategy ] = service.getStrategies('ldap') as LdapStrategy[];
        const params = {
            authStrategies: [ strategy.name ]
        };
        const sendResponse = async (data: AuthenticationResult|Error) => {
          try {
            const redirect = await strategy.getRedirect(data, params);
  
            if (redirect !== null) {
              res.redirect(redirect);
            } else if (data instanceof Error) {
              throw data;
            } else {
              res.json(data);
            }
          } catch (error) {
            debug('LDAP error', error);
            next(error);
          }
        };

        try {
          if (err) {
            throw err;
          }
    
          if(!ldapResponse) {
            throw new NotAuthenticated(errorMessage);
          }
          
          const authentication = {
            strategy: strategy.name,
            ...ldapResponse
          };

          debug(`Calling ${authService}.create authentication with LDAP strategy`);

          const authResult = await service.create(authentication, params);

          debug('Successful LDAP authentication, sending response');

          await sendResponse(authResult);
        } catch (error) {
          debug('Received LDAP authentication error', error.stack);
          await sendResponse(error);
        }
      })(req, res, next);
    });
  };
};