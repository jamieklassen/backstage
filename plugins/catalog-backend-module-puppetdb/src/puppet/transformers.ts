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

import { ResourceTransformer } from './types';
import { DEFAULT_NAMESPACE, ResourceEntity } from '@backstage/catalog-model';
import { DEFAULT_OWNER } from '../providers';
import { ANNOTATION_PUPPET_CERTNAME } from './constants';

/**
 * A default implementation of the {@link ResourceTransformer}.
 *
 * @param node - The found PuppetDB node entry in its source format. This is the entry that you want to transform.
 * @param _config - The configuration for the entity provider.
 *
 * @returns A `ResourceEntity`.
 *
 * @public
 */
export const defaultResourceTransformer: ResourceTransformer = async (
  node,
  _config,
) => {
  const certName = node.certname.toLowerCase();
  const type = node.facts?.data?.find(e => e.name === 'is_virtual')?.value
    ? 'virtual-machine'
    : 'physical-server';
  const kernel = node.facts?.data?.find(e => e.name === 'kernel')?.value;

  const entity: ResourceEntity = {
    apiVersion: 'backstage.io/v1beta1',
    kind: 'Resource',
    metadata: {
      name: certName,
      annotations: {
        [ANNOTATION_PUPPET_CERTNAME]: certName,
      },
      namespace: DEFAULT_NAMESPACE,
      description: node.facts?.data
        ?.find(e => e.name === 'ipaddress')
        ?.value?.toString(),
      tags: kernel ? [kernel.toString().toLowerCase()] : [],
    },
    spec: {
      type: type,
      owner: DEFAULT_OWNER,
      dependsOn: [],
      dependencyOf: [],
    },
  };

  return entity;
};
