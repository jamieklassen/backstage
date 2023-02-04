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

import { MicrosoftAuthProvider, microsoft } from './provider';
import { getVoidLogger } from '@backstage/backend-common';
import { setupRequestMockHandlers } from '@backstage/backend-test-utils';
import { ConfigReader } from '@backstage/config';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import { AuthResolverContext } from '../types';
import express from 'express';
import { OAuthRefreshRequest } from '../../lib/oauth';
import crypto from 'crypto';

describe('microsoft.create', () => {
  const server = setupServer();
  setupRequestMockHandlers(server);
  const providerFactory = microsoft.create();

  describe('#start', () => {
    it('redirects to authorize URL', async () => {
      jest.spyOn(crypto, 'randomBytes').mockReturnValue(
        // as base64 this is 'AQIDBAUGBwgJCgsMDQ4PEA=='
        Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
      );
      const provider = providerFactory({
        providerId: 'microsoft',
        globalConfig: {
          baseUrl: 'http://backstage.test/api/auth',
          appUrl: 'http://backstage.test',
          isOriginAllowed: _ => true,
        },
        config: new ConfigReader({
          development: {
            tenantId: 'tenantId',
            clientId: 'clientId',
            clientSecret: 'clientSecret',
          },
        }),
        logger: getVoidLogger(),
        resolverContext: {} as AuthResolverContext,
      });
      const res = {
        cookie: jest.fn(),
        setHeader: jest.fn(),
        end: jest.fn(),
      };

      await provider.start(
        {
          query: {
            env: 'development',
            scope: 'email openid profile User.Read',
          },
        } as unknown as express.Request,
        res as unknown as express.Response,
      );

      expect(res.setHeader).toHaveBeenCalledWith(
        'Location',
        'https://login.microsoftonline.com/tenantId/oauth2/v2.0/authorize' +
          '?response_type=code' +
          '&redirect_uri=http%3A%2F%2Fbackstage.test%2Fapi%2Fauth%2Fmicrosoft%2Fhandler%2Fframe&scope=email%20openid%20profile%20User.Read' +
          // this is 'nonce=AQIDBAUGBwgJCgsMDQ4PEA==&env=development', hex-encoded:
          '&state=6e6f6e63653d41514944424155474277674a4367734d44513450454125334425334426656e763d646576656c6f706d656e74' +
          '&client_id=clientId',
      );
    });
  });

  describe('acquiring access tokens', () => {
    beforeEach(() => {
      server.use(
        rest.post(
          'https://login.microsoftonline.com/common/oauth2/v2.0/token',
          (_, res, ctx) =>
            res(
              ctx.json({
                token_type: 'Bearer',
                scope: 'email openid profile User.Read',
                expires_in: 123,
                ext_expires_in: 123,
                access_token: 'accessToken',
                refresh_token: 'refreshToken',
                id_token: 'idToken',
              }),
            ),
        ),
        rest.get('https://graph.microsoft.com/v1.0/me/', (_, res, ctx) =>
          res(
            ctx.json({
              id: 'conrad',
              displayName: 'Conrad',
              surname: 'Ribas',
              givenName: 'Francisco',
              mail: 'conrad@example.com',
            }),
          ),
        ),
        rest.get(
          'https://graph.microsoft.com/v1.0/me/photos/*',
          async (_, res, ctx) => {
            const imageBuffer = new Uint8Array([104, 111, 119, 100, 121])
              .buffer;
            return res(
              ctx.set('Content-Length', imageBuffer.byteLength.toString()),
              ctx.set('Content-Type', 'image/jpeg'),
              ctx.body(imageBuffer),
            );
          },
        ),
      );
    });

    describe('#handle', () => {
      let provider: MicrosoftAuthProvider;

      beforeEach(() => {
        server.use(
          rest.post(
            'https://login.microsoftonline.com/tenantId/oauth2/v2.0/token',
            (_, res, ctx) =>
              res(
                ctx.json({
                  token_type: 'Bearer',
                  scope: 'email openid profile User.Read',
                  expires_in: 123,
                  ext_expires_in: 123,
                  access_token: 'accessToken',
                  refresh_token: 'refreshToken',
                  id_token: 'header.e30K.signature',
                }),
              ),
          ),
        );
        provider = providerFactory({
          providerId: 'microsoft',
          globalConfig: {
            baseUrl: 'http://backstage.test/api/auth',
            appUrl: 'http://backstage.test',
            isOriginAllowed: _ => true,
          },
          config: new ConfigReader({
            development: {
              tenantId: 'tenantId',
              clientId: 'clientId',
              clientSecret: 'clientSecret',
            },
          }),
          logger: getVoidLogger(),
          resolverContext: {} as AuthResolverContext,
        });
      });

      it('returns provider info and profile with photo data', async () => {
        const res = {
          json: jest.fn(),
          setHeader: jest.fn(),
          cookie: jest.fn(),
          end: jest.fn(),
        };

        await provider.frameHandler(
          {
            query: {
              env: 'development',
              code: 'authorizationcode',
              state:
                // this is 'nonce=AQIDBAUGBwgJCgsMDQ4PEA==&env=development', hex-encoded:
                '6e6f6e63653d41514944424155474277674a4367734d44513450454125334425334426656e763d646576656c6f706d656e74',
            },
            cookies: {
              'microsoft-nonce': 'AQIDBAUGBwgJCgsMDQ4PEA==',
            },
          } as unknown as express.Request,
          res as unknown as express.Response,
        );

        expect(res.end.mock.calls[0][0]).toContain(
          encodeURIComponent(
            JSON.stringify({
              type: 'authorization_response',
              response: {
                providerInfo: {
                  idToken: 'header.e30K.signature',
                  accessToken: 'accessToken',
                  scope: 'email openid profile User.Read',
                  expiresInSeconds: 123,
                },
                profile: {
                  email: 'conrad@example.com',
                  picture: 'data:image/jpeg;base64,aG93ZHk=',
                  displayName: 'Conrad',
                },
              },
            }),
          ),
        );
      });

      it('sets refresh token', async () => {
        const res = {
          json: jest.fn(),
          setHeader: jest.fn(),
          cookie: jest.fn(),
          end: jest.fn(),
        };

        await provider.frameHandler(
          {
            query: {
              env: 'development',
              code: 'authorizationcode',
              state:
                // this is 'nonce=AQIDBAUGBwgJCgsMDQ4PEA==&env=development', hex-encoded:
                '6e6f6e63653d41514944424155474277674a4367734d44513450454125334425334426656e763d646576656c6f706d656e74',
            },
            cookies: {
              'microsoft-nonce': 'AQIDBAUGBwgJCgsMDQ4PEA==',
            },
          } as unknown as express.Request,
          res as unknown as express.Response,
        );

        expect(res.cookie).toHaveBeenCalledWith(
          'microsoft-refresh-token',
          'refreshToken',
          {
            domain: 'backstage.test',
            httpOnly: true,
            maxAge: 86400000000,
            path: '/api/auth/microsoft',
            sameSite: 'lax',
            secure: false,
          },
        );
      });

      it('omits photo data when fetching it fails', async () => {
        server.use(
          rest.get(
            'https://graph.microsoft.com/v1.0/me/photos/*',
            async (_, res) => res.networkError('remote hung up'),
          ),
        );
        const res = {
          json: jest.fn(),
          setHeader: jest.fn(),
          cookie: jest.fn(),
          end: jest.fn(),
        };

        await provider.frameHandler(
          {
            query: {
              env: 'development',
              code: 'authorizationcode',
              state:
                // this is 'nonce=AQIDBAUGBwgJCgsMDQ4PEA==&env=development', hex-encoded:
                '6e6f6e63653d41514944424155474277674a4367734d44513450454125334425334426656e763d646576656c6f706d656e74',
            },
            cookies: {
              'microsoft-nonce': 'AQIDBAUGBwgJCgsMDQ4PEA==',
            },
          } as unknown as express.Request,
          res as unknown as express.Response,
        );

        expect(res.end.mock.calls[0][0]).toContain(
          encodeURIComponent(
            JSON.stringify({
              type: 'authorization_response',
              response: {
                providerInfo: {
                  idToken: 'header.e30K.signature',
                  accessToken: 'accessToken',
                  scope: 'email openid profile User.Read',
                  expiresInSeconds: 123,
                },
                profile: {
                  email: 'conrad@example.com',
                  // picture: 'data:image/jpeg;base64,aG93ZHk=',
                  displayName: 'Conrad',
                },
              },
            }),
          ),
        );
      });
    });

    describe('#refresh', () => {
      it('returns provider info, profile and refresh token', async () => {
        const provider = new MicrosoftAuthProvider({
          logger: getVoidLogger(),
          resolverContext: {} as AuthResolverContext,
          authHandler: async ({ fullProfile }) => ({
            profile: {
              email: fullProfile.emails![0]!.value,
              displayName: fullProfile.displayName,
              picture: 'http://microsoft.com/lols',
            },
          }),
          clientId: 'mock',
          clientSecret: 'mock',
          callbackUrl: 'http://backstage.test/api/auth/microsoft/handler/frame',
        });

        const result = await provider.refresh({
          scope: 'email openid profile User.Read',
          refreshToken: 'refreshToken',
        } as unknown as OAuthRefreshRequest);

        expect(result).toEqual({
          refreshToken: 'refreshToken',
          response: {
            providerInfo: {
              accessToken: 'accessToken',
              expiresInSeconds: 123,
              idToken: 'idToken',
              scope: 'email openid profile User.Read',
            },
            profile: {
              email: 'conrad@example.com',
              displayName: 'Conrad',
              picture: 'http://microsoft.com/lols',
            },
          },
        });
      });
    });
  });
});
