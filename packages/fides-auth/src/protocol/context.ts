// What a protocol operation runs against. Each operation is written once, over
// a context: an OIDC client passes its own discovery cache and logger, and the
// free functions in /oauth pass the module-level cache and their module logger.

import type * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import type { OAuthConfig, OidcClientConfig } from './config.js';
import { discoverConfiguration } from './discovery.js';

export interface ProtocolContext {
  readonly config: OidcClientConfig;
  /** The provider's openid-client Configuration, from the context's discovery cache. */
  configuration(): Promise<openid.Configuration>;
  /** Logs under `fides-auth:oauth`. */
  readonly logger: FidesLogger;
}

/** The context of a free function: the module-level discovery cache and the caller's logger. */
export function moduleContext(config: OAuthConfig, logger: FidesLogger): ProtocolContext {
  return { config, configuration: () => discoverConfiguration(config), logger };
}
