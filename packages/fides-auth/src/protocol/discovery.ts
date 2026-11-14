// discovery.ts
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

import { createLogger, type FidesLogger } from '../shared/logger.js';
import type { ClientAuthConfig, OAuthConfig, OidcClientConfig } from './config.js';

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
   * The server metadata and secret or private key this entry was built with,
   * compared on lookup so a change invalidates the entry without the credential
   * going into the cache key.
   */
  inputs: readonly unknown[];
}

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
    moduleCache.ttlMs = checkTtl(options.ttlMs, 'configureDiscoveryCache: ttlMs');
  }
  moduleCache.clear();
}

/**
 * Drops every cached configuration.
 *
 * Call this after changing provider configuration that discovery would not
 * otherwise pick up until the TTL expires. Tests should call it between cases,
 * since the cache is module state.
 */
export function clearDiscoveryCache(): void {
  moduleCache.clear();
}

/**
 * Maps `clientAuth` to openid-client's client authentication. Every
 * `Configuration` fides-auth builds gets its client authentication from here.
 *
 * @throws TypeError for an unknown `clientAuth`, rather than falling back to another method.
 */
export function resolveClientAuth(config: ClientAuthConfig): {
  /** Client metadata shorthand; set only for the secret methods. */
  clientSecret: string | undefined;
  clientAuthentication: openid.ClientAuth;
} {
  switch (config.clientAuth) {
    case undefined:
    case 'client_secret_post':
      return {
        clientSecret: config.clientSecret,
        clientAuthentication: openid.ClientSecretPost(config.clientSecret),
      };
    case 'client_secret_basic':
      return {
        clientSecret: config.clientSecret,
        clientAuthentication: openid.ClientSecretBasic(config.clientSecret),
      };
    case 'none':
      return { clientSecret: undefined, clientAuthentication: openid.None() };
    case 'private_key_jwt':
      return {
        clientSecret: undefined,
        clientAuthentication: openid.PrivateKeyJwt(config.privateKey),
      };
    default:
      throw new TypeError(
        `Unsupported clientAuth: ${String((config as { clientAuth: unknown }).clientAuth)}`,
      );
  }
}

/**
 * Issuer, client and auth method identify a configuration; the credential is
 * checked separately. JSON-encoded rather than concatenated so no separator can
 * be forged by a value that happens to contain it.
 */
function cacheKey(config: OidcClientConfig): string {
  const method = config.clientAuth ?? 'client_secret_post';
  return JSON.stringify([config.issuer, config.clientId, method]);
}

/** The values an entry must have been built from, compared by identity. */
function cacheInputs(config: OidcClientConfig): readonly unknown[] {
  const metadata = config.serverMetadata;
  switch (config.clientAuth) {
    case 'none':
      return [metadata];
    case 'private_key_jwt': {
      // A `{ key, kid }` wrapper may be rebuilt per call; compare what it holds.
      const pk = config.privateKey;
      return 'key' in pk ? [metadata, pk.key, pk.kid] : [metadata, pk, undefined];
    }
    default:
      return [metadata, config.clientSecret];
  }
}

function sameInputs(a: readonly unknown[], b: readonly unknown[]): boolean {
  return a.length === b.length && a.every((value, i) => Object.is(value, b[i]));
}

/** Unset scope means `defaultScope`, which includes `openid`. */
function requestsOpenId(scope: string | string[] | undefined): boolean {
  if (scope === undefined) return true;
  const joined = Array.isArray(scope) ? scope.join(' ') : scope;
  return joined.split(/\s+/).includes('openid');
}

/** Async so a bad config rejects like a failed discovery and is never cached. */
async function buildConfiguration(config: OidcClientConfig): Promise<openid.Configuration> {
  const { clientSecret, clientAuthentication } = resolveClientAuth(config);
  const metadata = config.serverMetadata;

  if (!metadata) {
    return openid.discovery(
      new URL(config.issuer),
      config.clientId,
      clientSecret,
      clientAuthentication,
    );
  }

  // Don't fall back to `config.issuer`: the ID token's `iss` must match the server's own.
  if (!metadata.issuer && requestsOpenId(config.scope)) {
    throw new TypeError(
      'serverMetadata.issuer is required when scope includes "openid", to check the ID token',
    );
  }

  return new openid.Configuration(metadata, config.clientId, clientSecret, clientAuthentication);
}

/** A discovery cache: the module keeps one for the free functions, and each OIDC client has its own. */
export interface DiscoveryCache {
  /** How long an entry stays reusable, in milliseconds. `0` disables caching. */
  ttlMs: number;
  /** The configuration for `config`, from the cache or a new discovery. */
  discover(config: OidcClientConfig): Promise<openid.Configuration>;
  /** Drops every entry. */
  clear(): void;
}

/**
 * Checks a TTL before it is used, so a bad value fails loudly.
 *
 * @throws TypeError naming `label` if `ttlMs` is not a finite, non-negative number.
 */
export function checkTtl(ttlMs: number, label: string): number {
  if (!Number.isFinite(ttlMs) || ttlMs < 0) {
    throw new TypeError(`${label} must be a finite number >= 0, got ${ttlMs}`);
  }
  return ttlMs;
}

/** Creates an empty discovery cache that logs through `logger`. */
export function createDiscoveryCache(logger: FidesLogger, ttlMs = DEFAULT_TTL_MS): DiscoveryCache {
  const cache = new Map<string, CacheEntry>();
  let ttl = ttlMs;

  return {
    get ttlMs() {
      return ttl;
    },
    set ttlMs(value) {
      ttl = value;
    },

    discover(config) {
      const key = cacheKey(config);
      const inputs = cacheInputs(config);
      const now = Date.now();
      const cached = cache.get(key);

      if (cached && cached.expiresAt > now && sameInputs(cached.inputs, inputs)) {
        return cached.configuration;
      }

      logger.debug(
        { issuer: config.issuer },
        config.serverMetadata
          ? 'Building configuration from server metadata'
          : 'Discovering OpenID configuration',
      );

      const configuration = buildConfiguration(config);

      if (ttl > 0) {
        cache.set(key, { configuration, expiresAt: now + ttl, inputs });

        // Never cache a failure: a provider that was briefly unreachable must be
        // retried on the next call, not remembered as broken for the whole TTL.
        // Guarded so a slow failure cannot evict a newer entry that replaced it.
        configuration.catch(() => {
          if (cache.get(key)?.configuration === configuration) cache.delete(key);
        });
      }

      return configuration;
    },

    clear() {
      cache.clear();
    },
  };
}

const moduleCache = createDiscoveryCache(createLogger({ namespace: 'fides-auth:oidc-discovery' }));

/**
 * Discovers the provider's OpenID configuration, or builds it from
 * `config.serverMetadata`, reusing a recent result.
 *
 * @param config - OAuth configuration identifying the provider and client.
 * @returns The openid-client `Configuration` for this provider and client.
 */
export async function discoverConfiguration(
  config: OAuthConfig,
): Promise<openid.Configuration> {
  return moduleCache.discover(config);
}
