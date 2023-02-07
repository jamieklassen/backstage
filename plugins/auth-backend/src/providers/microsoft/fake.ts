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
import { rest } from 'msw';
import { decodeJwt } from 'jose';

export class FakeMicrosoftAPI {
  generateAuthCode(scopeClaim: string): string {
    const audience = (scope: string) => {
      if (scope.includes('/')) {
        return scope.split('/')[0];
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
    };
    const scopes = scopeClaim.split(' ');
    const firstAudience = scopes.map(audience).find(aud => aud !== 'openid');
    return scopes
      .filter(s => [firstAudience, 'openid'].includes(audience(s)))
      .join(' ');
  }
  generateRefreshToken(scopeClaim: string): string {
    return this.generateAuthCode(scopeClaim);
  }
  tokenWithScope(scope: string): string {
    return `header.${Buffer.from(JSON.stringify({ scp: scope })).toString(
      'base64',
    )}.signature`;
  }
  private exchangeCode(authCode: string) {
    return this.tokenWithScope(authCode);
  }
  hasScope(token: string | undefined, scope: string): boolean {
    if (token === undefined) return false;
    return (decodeJwt(token).scp as string).includes(scope);
  }
  token(formData: URLSearchParams) {
    const refresh = formData.get('grant_type') === 'refresh_token';
    const scope =
      formData.get('scope') ?? refresh
        ? formData.get('refresh_token')!
        : formData.get('code')!;
    return {
      access_token: refresh
        ? this.tokenWithScope(scope)
        : this.exchangeCode(scope),
      scope,
      ...(scope?.includes('offline_access') && {
        refresh_token: this.generateRefreshToken(scope),
      }),
      ...(scope?.includes('openid') && { id_token: 'header.e30K.microsoft' }),
    };
  }
  handlers() {
    return [
      rest.post(
        'https://login.microsoftonline.com/tenantId/oauth2/v2.0/token',
        async (req, res, ctx) => {
          return res(
            ctx.json({
              ...this.token(new URLSearchParams(await req.text())),
              token_type: 'Bearer',
              expires_in: 123,
              ext_expires_in: 123,
            }),
          );
        },
      ),
      rest.get('https://graph.microsoft.com/v1.0/me/', (req, res, ctx) => {
        if (
          !this.hasScope(
            req.headers.get('authorization')?.replace(/^Bearer /, ''),
            'User.Read',
          )
        ) {
          return res(ctx.status(403));
        }
        return res(
          ctx.json({
            id: 'conrad',
            displayName: 'Conrad',
            surname: 'Ribas',
            givenName: 'Francisco',
            mail: 'conrad@example.com',
          }),
        );
      }),
      rest.get(
        'https://graph.microsoft.com/v1.0/me/photos/*',
        async (req, res, ctx) => {
          if (
            !this.hasScope(
              req.headers.get('authorization')?.replace(/^Bearer /, ''),
              'User.Read',
            )
          ) {
            return res(ctx.status(403));
          }
          const imageBuffer = new Uint8Array([104, 111, 119, 100, 121]).buffer;
          return res(
            ctx.set('Content-Length', imageBuffer.byteLength.toString()),
            ctx.set('Content-Type', 'image/jpeg'),
            ctx.body(imageBuffer),
          );
        },
      ),
    ];
  }
}
