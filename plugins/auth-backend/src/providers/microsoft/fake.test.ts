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

describe('FakeMicrosoftAPI', () => {
  it('exchanges auth codes', () => {
    const scope = 'useless placeholder, for now';
    const api = new FakeMicrosoftAPI();

    const { access_token } = api.token(
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: api.generateAuthCode(scope),
      }),
    );

    expect(api.hasScope(access_token, scope)).toBe(true);
  });
});
