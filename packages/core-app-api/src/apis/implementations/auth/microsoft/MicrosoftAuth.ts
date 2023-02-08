/*
 * Copyright 2020 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  microsoftAuthApiRef,
  AuthRequestOptions,
  AuthProviderInfo,
  DiscoveryApi,
  OAuthRequestApi,
} from '@backstage/core-plugin-api';
import { OAuth2 } from '../oauth2';
import { OAuthApiCreateOptions } from '../types';

const DEFAULT_PROVIDER = {
  id: 'microsoft',
  title: 'Microsoft',
  icon: () => null,
};

/**
 * Implements the OAuth flow to Microsoft products.
 *
 * @public
 */
export default class MicrosoftAuth {
  private oauth2: { [audience: string]: OAuth2 };
  private environment: string;
  private provider: AuthProviderInfo;
  private oauthRequestApi: OAuthRequestApi;
  private discoveryApi: DiscoveryApi;

  static create(options: OAuthApiCreateOptions): typeof microsoftAuthApiRef.T {
    return new MicrosoftAuth(options);
  }
  private constructor(options: OAuthApiCreateOptions) {
    const {
      environment = 'development',
      provider = DEFAULT_PROVIDER,
      oauthRequestApi,
      discoveryApi,
      defaultScopes = [
        'openid',
        'offline_access',
        'profile',
        'email',
        'User.Read',
      ],
    } = options;

    this.environment = environment;
    this.provider = provider;
    this.oauthRequestApi = oauthRequestApi;
    this.discoveryApi = discoveryApi;

    this.oauth2 = {
      'https://graph.microsoft.com': OAuth2.create({
        discoveryApi: this.discoveryApi,
        oauthRequestApi: this.oauthRequestApi,
        provider: this.provider,
        environment: this.environment,
        defaultScopes,
      }),
    };
  }

  private microsoftGraph(): OAuth2 {
    return this.oauth2['https://graph.microsoft.com'];
  }

  getAccessToken(scope?: string | string[], options?: AuthRequestOptions) {
    const scopes = typeof scope === 'string' ? scope.split(' ') : scope;

    return this.getAudience(scopes).getAccessToken(scopes, options);
  }

  getAudience(scopes?: string[]): OAuth2 {
    const audience = scopes
      ?.map(MicrosoftAuth.scopeAudience)
      ?.find(aud => aud !== 'openid');
    if (!audience) return this.microsoftGraph();
    if (!(audience in this.oauth2)) {
      this.oauth2[audience] = OAuth2.create({
        discoveryApi: this.discoveryApi,
        oauthRequestApi: this.oauthRequestApi,
        provider: this.provider,
        environment: this.environment,
        defaultScopes: scopes,
      });
    }
    return this.oauth2[audience];
  }

  private static scopeAudience(scope: string): string {
    if (scope.includes('/')) {
      const aud = scope.split('/')[0];
      return aud === '00000003-0000-0000-c000-000000000000'
        ? 'https://graph.microsoft.com'
        : aud;
    }
    switch (scope) {
      case 'email':
      case 'openid':
      case 'offline_access':
      case 'profile': {
        return 'openid';
      }
      default:
        return 'https://graph.microsoft.com';
    }
  }

  getIdToken(options?: AuthRequestOptions) {
    return this.microsoftGraph().getIdToken(options);
  }

  getProfile(options?: AuthRequestOptions) {
    return this.microsoftGraph().getProfile(options);
  }

  getBackstageIdentity(options?: AuthRequestOptions) {
    return this.microsoftGraph().getBackstageIdentity(options);
  }

  signIn() {
    return this.microsoftGraph().signIn();
  }

  signOut() {
    return this.microsoftGraph().signOut();
  }

  sessionState$() {
    return this.microsoftGraph().sessionState$();
  }
}
