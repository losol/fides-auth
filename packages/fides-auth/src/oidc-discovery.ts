// oidc-discovery.ts
//
// One place where fides-auth turns an OAuthConfig into an openid-client
// Configuration, and one cache in front of it.
//
// Discovery was previously performed inline at every call site, which meant an
// HTTP GET to the provider's /.well-known/openid-configuration before *every*
// token operation. On the heartbeat path that is one extra round-trip per user
// every few minutes: it doubles the latency of a refresh, doubles the load on
// the provider, and doubles the surface on which a refresh can fail — a
// discovery blip is indistinguishable from a token-endpoint blip to the caller.
//
// Reusing a Configuration is openid-client's intended usage; its own examples
// build one at startup and keep it.

import * as openid from 'openid-client';

import { createLogger } from './logger';
import type { OAuthConfig } from './oauth';

const logger = createLogger({ namespace: 'fides-auth:oidc-discovery' });

/**
 * Default lifetime of a cached configuration.
 *
 * Discovery documents change rarely — a new endpoint, a signing-key rollover —
 * and openid-client refetches JWKS on its own schedule, so this only bounds how
 * long a *metadata* change takes to be noticed. Five minutes keeps that window
 * short while removing essentially every discovery request from the hot path.
 */
const DEFAULT_TTL_MS = 5 * 60_000;

interface CacheEntry {
  /**
   * Held as the promise, not the resolved value, so concurrent callers share one
   * round-trip. Caching only the result would let a burst of requests each start
   * their own discovery before the first finished — precisely what a fleet of
   * heartbeats produces.
   */
  configuration: Promise<openid.Configuration>;
  expiresAt: number;
  /**
   * The secret this entry was built with, compared on lookup so a rotated client
   * secret invalidates the entry without the secret going into the cache key.
   */
  clientSecret: string;
}

const cache = new Map<string, CacheEntry>();
let ttlMs = DEFAULT_TTL_MS;

/** Options for {@link configureDiscoveryCache}. */
export interface DiscoveryCacheOptions {
  /**
   * How long a discovered configuration stays reusable, in milliseconds.
   * Pass `0` to disable caching and discover on every call. Must be finite and
   * non-negative; anything else throws rather than quietly disabling the cache.
   * @default 300_000 (5 minutes)
   */
  ttlMs?: number;
}

/**
 * Adjusts the discovery cache. Existing entries are dropped so the new setting
 * takes effect immediately.
 *
 * @throws TypeError if `ttlMs` is not a finite, non-negative number. Rejecting
 * loudly matters here because the alternative is silent: `NaN` — what
 * `Number(process.env.DISCOVERY_TTL)` yields when the variable is unset — would
 * otherwise turn the cache off and restore a discovery round-trip on every
 * token operation, with nothing to show for it in the logs.
 */
export function configureDiscoveryCache(options: DiscoveryCacheOptions): void {
  if (options.ttlMs !== undefined) {
    if (!Number.isFinite(options.ttlMs) || options.ttlMs < 0) {
      throw new TypeError(
        `configureDiscoveryCache: ttlMs must be a finite number >= 0, got ${options.ttlMs}`,
      );
    }
    ttlMs = options.ttlMs;
  }
  cache.clear();
}

/**
 * Drops every cached configuration.
 *
 * Call this after changing provider configuration that discovery would not
 * otherwise pick up until the TTL expires. Tests should call it between cases,
 * since the cache is module state.
 */
export function clearDiscoveryCache(): void {
  cache.clear();
}

/**
 * Issuer and client identify a configuration; the secret is checked separately.
 * JSON-encoded rather than concatenated so no separator can be forged by a
 * value that happens to contain it.
 */
function cacheKey(config: OAuthConfig): string {
  return JSON.stringify([config.issuer, config.clientId]);
}

/**
 * Discovers the provider's OpenID configuration, reusing a recent result.
 *
 * Every fides-auth flow goes through here, so this is also the single place
 * where the client authentication method is decided.
 *
 * @param config - OAuth configuration identifying the provider and client.
 * @returns The openid-client `Configuration` for this provider and client.
 */
export async function discoverConfiguration(
  config: OAuthConfig,
): Promise<openid.Configuration> {
  const key = cacheKey(config);
  const now = Date.now();
  const cached = cache.get(key);

  if (cached && cached.expiresAt > now && cached.clientSecret === config.clientSecret) {
    return cached.configuration;
  }

  logger.debug({ issuer: config.issuer }, 'Discovering OpenID configuration');

  const configuration = openid.discovery(
    new URL(config.issuer),
    config.clientId,
    config.clientSecret,
    // openid-client's own default is client_secret_post; stating it keeps the
    // method visible at the one place that would grow a `clientAuth` option.
    openid.ClientSecretPost(config.clientSecret),
  );

  if (ttlMs > 0) {
    cache.set(key, { configuration, expiresAt: now + ttlMs, clientSecret: config.clientSecret });

    // Never cache a failure: a provider that was briefly unreachable must be
    // retried on the next call, not remembered as broken for the whole TTL.
    // Guarded so a slow failure cannot evict a newer entry that replaced it.
    configuration.catch(() => {
      if (cache.get(key)?.configuration === configuration) cache.delete(key);
    });
  }

  return configuration;
}
