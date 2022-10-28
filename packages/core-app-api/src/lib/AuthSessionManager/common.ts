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

import { SessionScopesFunc } from './types';

export function hasScopes(
  searched: Set<string>,
  searchFor: Set<string>,
): boolean {
  for (const scope of searchFor) {
    if (!searched.has(scope)) {
      return false;
    }
  }
  return true;
}

type ScopeHelperOptions<T> = {
  sessionScopes: SessionScopesFunc<T> | undefined;
  defaultScopes?: Set<string>;
};

export class SessionScopeHelper<T> {
  constructor(private readonly options: ScopeHelperOptions<T>) {}

  sessionExistsAndHasScope(
    session: T | undefined,
    scopes?: Set<string>,
  ): boolean {
    if (!session) {
      return false;
    }
    if (!scopes) {
      return true;
    }
    if (this.options.sessionScopes === undefined) {
      return true;
    }
    const sessionScopes = this.options.sessionScopes(session);
    return hasScopes(sessionScopes, scopes);
  }

  getExtendedScope(session: T | undefined, scopes?: Set<string>) {
    const newScope = new Set(this.options.defaultScopes);
    debugger; // ... which is notable because it merges any requested scopes
              // (of which there are none for a simple sign-in) with any
              // default scopes from the provider. Microsoft has a number of
              // default scopes, one of which is Azure-specific. Next let's
              // look at the implementation of `createSession` on the session
              // manager's associated AuthConnector ...
    if (session && this.options.sessionScopes !== undefined) {
      const sessionScopes = this.options.sessionScopes(session);
      for (const scope of sessionScopes) {
        newScope.add(scope);
      }
    }
    if (scopes) {
      for (const scope of scopes) {
        newScope.add(scope);
      }
    }
    return newScope;
  }
}
