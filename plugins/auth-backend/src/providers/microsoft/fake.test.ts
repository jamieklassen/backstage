/*
 * Copyright 2023 The Backstage Authors
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
import { FakeMicrosoftAPI } from './fake';
import { setupServer } from 'msw/node';
import { setupRequestMockHandlers } from '@backstage/backend-test-utils';
import fetch from 'node-fetch';

describe('FakeMicrosoftAPI', () => {
  const api = new FakeMicrosoftAPI();

  describe('#token', () => {
    it('exchanges auth codes', () => {
      const { access_token } = api.token(
        new URLSearchParams({
          grant_type: 'authorization_code',
          code: api.generateAuthCode('User.Read'),
        }),
      );

      expect(api.hasScope(access_token, 'User.Read')).toBe(true);
    });

    it('supports scopes for the first requested audience only', () => {
      const { access_token } = api.token(
        new URLSearchParams({
          grant_type: 'authorization_code',
          code: api.generateAuthCode('someaudience/somescope User.Read'),
        }),
      );

      expect(api.hasScope(access_token, 'User.Read')).toBe(false);
    });

    it('refreshes tokens', () => {
      const { access_token } = api.token(
        new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: api.generateRefreshToken(
            'email openid profile User.Read',
          ),
        }),
      );

      expect(api.hasScope(access_token, 'email openid profile User.Read')).toBe(
        true,
      );
    });
  });

  describe('#handlers', () => {
    const server = setupServer();
    setupRequestMockHandlers(server);

    beforeEach(() => {
      server.use(...api.handlers());
    });

    describe('profile endpoint', () => {
      const url = 'https://graph.microsoft.com/v1.0/me/';

      it('returns user profile', () => {
        const profile = fetch(url, {
          headers: {
            authorization: `Bearer ${api.tokenWithScope('User.Read')}`,
          },
        }).then(r => r.json());

        return expect(profile).resolves.toMatchObject({
          mail: 'conrad@example.com',
        });
      });

      it('forbids access when microsoft graph scope is missing', () => {
        const res = fetch(url, {
          headers: { authorization: `Bearer ${api.tokenWithScope('other')}` },
        });

        return expect(res).resolves.toMatchObject({ status: 403 });
      });
    });

    describe('photos endpoint', () => {
      const url = 'https://graph.microsoft.com/v1.0/me/photos/48x48/$value';

      it('forbids access when microsoft graph scope is missing', () => {
        const res = fetch(url, {
          headers: { authorization: `Bearer ${api.tokenWithScope('other')}` },
        });

        return expect(res).resolves.toMatchObject({ status: 403 });
      });
    });
  });
});
