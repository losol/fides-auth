// What a protocol operation runs against: an OIDC client's config, its
// discovery cache and its logger. Each operation is written once, over this.

import type * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import type { OidcClientConfig } from './config.js';

export interface ProtocolContext {
  readonly config: OidcClientConfig;
  /** The provider's openid-client Configuration, from the context's discovery cache. */
  configuration(): Promise<openid.Configuration>;
  /** Logs under `fides-auth:oauth`. */
  readonly logger: FidesLogger;
}

