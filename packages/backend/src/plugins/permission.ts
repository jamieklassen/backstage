/*
 * Copyright 2021 The Backstage Authors
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

import { BackstageIdentityResponse } from '@backstage/plugin-auth-node';
import { PluginEndpointDiscovery } from '@backstage/backend-common';
import { createRouter } from '@backstage/plugin-permission-backend';
import {
  AuthorizeResult,
  PolicyDecision,
  isResourcePermission,
} from '@backstage/plugin-permission-common';
import {
  PermissionPolicy,
  PolicyQuery,
} from '@backstage/plugin-permission-node';
import {
  DefaultPlaylistPermissionPolicy,
  isPlaylistPermission,
} from '@backstage/plugin-playlist-backend';
import { CatalogApi, CatalogClient } from '@backstage/catalog-client';
import {
  RELATION_PARENT_OF,
  RELATION_CHILD_OF,
  RELATION_MEMBER_OF,
  RELATION_HAS_MEMBER,
} from '@backstage/catalog-model';
import {
  catalogConditions,
  createCatalogConditionalDecision,
} from '@backstage/plugin-catalog-backend/alpha';
import { RESOURCE_TYPE_CATALOG_ENTITY } from '@backstage/plugin-catalog-common/alpha';
import { Router } from 'express';
import { PluginEnvironment } from '../types';

class ExamplePermissionPolicy implements PermissionPolicy {
  private playlistPermissionPolicy = new DefaultPlaylistPermissionPolicy();
  private catalogApi: CatalogApi;

  constructor(discoveryApi: PluginEndpointDiscovery) {
    this.catalogApi = new CatalogClient({ discoveryApi });
  }

  async handle(
    request: PolicyQuery,
    user?: BackstageIdentityResponse,
  ): Promise<PolicyDecision> {
    if (isPlaylistPermission(request.permission)) {
      return this.playlistPermissionPolicy.handle(request, user);
    }
    if (
      isResourcePermission(request.permission, RESOURCE_TYPE_CATALOG_ENTITY)
    ) {
      return createCatalogConditionalDecision(request.permission, {
        anyOf: [
          {
            not: catalogConditions.isEntityKind({
              kinds: ['Component'],
            }),
          },
          catalogConditions.isEntityOwner({
            claims: user
              ? await this.traverseOrg(user.identity.userEntityRef)
              : [],
          }),
        ],
      });
    }

    return {
      result: AuthorizeResult.ALLOW,
    };
  }

  private async traverseOrg(
    entityRef: string,
    exploredRefs: Set<string> = new Set(),
  ): Promise<string[]> {
    exploredRefs.add(entityRef);
    const entity = await this.catalogApi.getEntityByRef(entityRef);
    const result = await Promise.all(
      entity?.relations
        ?.filter(r =>
          [RELATION_PARENT_OF, RELATION_HAS_MEMBER]
            .concat(
              entity?.metadata.annotations?.['tanzu.vmware.com/space'] ===
                'false' || entity.kind === 'User'
                ? [RELATION_CHILD_OF, RELATION_MEMBER_OF]
                : [],
            )
            .includes(r.type),
        )
        .map(r => r.targetRef)
        .filter(r => r.startsWith('group:') || r.startsWith('user:'))
        .filter(r => !exploredRefs.has(r))
        .map(async parentEntityRef => {
          return [
            parentEntityRef,
            ...(await this.traverseOrg(parentEntityRef, exploredRefs)),
          ];
        }) ?? [],
    );
    return Array.from(new Set([entityRef, ...result.flat()]));
  }
}

export default async function createPlugin(
  env: PluginEnvironment,
): Promise<Router> {
  return await createRouter({
    config: env.config,
    logger: env.logger,
    discovery: env.discovery,
    policy: new ExamplePermissionPolicy(env.discovery),
    identity: env.identity,
  });
}
