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

/**
 * A Backstage backend plugin that integrates towards Kubernetes
 *
 * @packageDocumentation
 */

export * from './kubernetes-auth-translator/AwsIamKubernetesAuthTranslator';
export * from './kubernetes-auth-translator/AzureIdentityKubernetesAuthTranslator';
export * from './kubernetes-auth-translator/GoogleKubernetesAuthTranslator';
export * from './kubernetes-auth-translator/GoogleServiceAccountAuthProvider';
export * from './kubernetes-auth-translator/KubernetesAuthTranslatorGenerator';
export * from './kubernetes-auth-translator/NoopKubernetesAuthTranslator';
export * from './kubernetes-auth-translator/OidcKubernetesAuthTranslator';
export * from './kubernetes-auth-translator/types';

export * from './service/router';
export * from './service/KubernetesBuilder';
export * from './service/KubernetesClientProvider';
export * from './service/KubernetesProxy';

export * from './types/types';

export { DEFAULT_OBJECTS } from './service/KubernetesFanOutHandler';
