// @ts-ignore
import querystring from 'querystring';
import Debug from 'debug';
import {
  AuthenticationRequest, AuthenticationBaseStrategy, AuthenticationResult
} from '@feathersjs/authentication';
import { Params } from '@feathersjs/feathers';

const debug = Debug('feathers-windowsauth/strategy');

export interface LdapUser {
  [key: string]: any;
}

export class LdapStrategy extends AuthenticationBaseStrategy {
    get configuration () {
        const authConfig = this.authentication.configuration;
        const config = super.configuration || {};
    
        return {
            service: authConfig.service,
            entity: authConfig.entity,
            entityId: authConfig.entityId,
            ...config
          };
    }

  get entityId (): string {
    const { entityService } = this;

    return this.configuration.entityId || (entityService && entityService.id);
  }

  async getEntityQuery (ldapUser: LdapUser, _params: Params) {
    return {
      [`ldapId`]: ldapUser.id
    };
  }

  async getEntityData (ldapUser: LdapUser, _existingEntity: any, _params: Params) {
    return {
      [`email`]: ldapUser.emails[0].value,
      [`displayName`]: ldapUser.displayName
    };
  }

  /* istanbul ignore next */
  async getLdapUser (data: AuthenticationRequest, _params: Params) {
    return data;
  }

  async getCurrentEntity (params: Params) {
    const { authentication } = params;
    const { entity } = this.configuration;

    if (authentication && authentication.strategy) {
      debug('getCurrentEntity with authentication', authentication);

      const { strategy } = authentication;
      const authResult = await this.authentication.authenticate(authentication, params, strategy);

      return authResult[entity];
    }

    return null;
  }

  async getRedirect (data: AuthenticationResult|Error, params?: Params) {
    const { redirect } = this.authentication.configuration.windowsauth;

    if (!redirect) {
      return null;
    }

    const separator = redirect.endsWith('?') ? '' :
      (redirect.indexOf('#') !== -1 ? '?' : '#');
    const authResult: AuthenticationResult = data;
    const query = authResult.accessToken ? {
      access_token: authResult.accessToken
    } : {
      error: data.message || 'SAML Authentication not successful'
    };

    return redirect + separator + querystring.stringify(query);
  }

  async findEntity (ldapUser: LdapUser, params: Params) {
    const query = await this.getEntityQuery(ldapUser, params);

    debug('findEntity with query', query);

    const result = await this.entityService.find({
      ...params,
      query
    });
    const [ entity = null ] = result.data ? result.data : result;

    debug('findEntity returning', entity);

    return entity;
  }

  async createEntity (ldapUser: LdapUser, params: Params) {
    const data = await this.getEntityData(ldapUser, null, params);

    debug('createEntity with data', data);

    return this.entityService.create(data, params);
  }

  async updateEntity (entity: any, ldapUser: LdapUser, params: Params) {
    const id = entity[this.entityId];
    const data = await this.getEntityData(ldapUser, entity, params);

    debug(`updateEntity with id ${id} and data`, data);

    return this.entityService.patch(id, data, params);
  }

  async authenticate (authentication: AuthenticationRequest, params: Params) {
    const entity: string = this.configuration.entity;
    const ldapUser: LdapUser = await this.getLdapUser(authentication, params);
    const existingEntity = await this.findEntity(ldapUser, params) || await this.getCurrentEntity(params);

    debug(`authenticate with (existing) entity`, existingEntity);

    const authEntity = !existingEntity ? await this.createEntity(ldapUser, params) : await this.updateEntity(existingEntity, ldapUser, params);

    return {
      authentication: { strategy: this.name },
      [entity]: authEntity
    };
  }
}