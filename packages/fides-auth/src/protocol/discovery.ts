// discovery.ts
//
// One place where fides-auth turns an OidcClientConfig into an openid-client
// Configuration, and a cache in front of it.
//
// Without the cache, every token operation would start with an HTTP GET to the
// provider's /.well-known/openid-configuration. On the heartbeat path that is
// one extra round-trip per user every few minutes: it doubles the latency of a
// refresh, doubles the load on the provider, and doubles the surface on which a
// refresh can fail — a discovery blip is indistinguishable from a token-endpoint
// blip to the caller.
//
// Reusing a Configuration is openid-client's intended usage; its own examples
// build one at startup and keep it.

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import type { ClientAuthConfig, OidcClientConfig } from './config.js';

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

/** `localhost`, a `*.localhost` name, `127.0.0.0/8` or `[::1]`. */
export function isLoopback(url: URL): boolean {
  const host = url.hostname;
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '[::1]' ||
    /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

/** The metadata URLs fides-auth or openid-client may send a request or the browser to. */
const ENDPOINTS = [
  'authorization_endpoint',
  'token_endpoint',
  'userinfo_endpoint',
  'jwks_uri',
  'end_session_endpoint',
  'revocation_endpoint',
  'introspection_endpoint',
  'pushed_authorization_request_endpoint',
] as const;

/**
 * Refuses an http URL, or with `allowInsecureRequests` one that isn't
 * loopback, with an error that names it. openid-client would refuse it later,
 * at the request, with only the code `OAUTH_HTTP_REQUEST_FORBIDDEN`.
 */
function checkTransport(label: string, value: unknown, allowInsecure: boolean): void {
  if (typeof value !== 'string') return;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return; // Not a URL: openid-client reports that itself.
  }
  if (url.protocol !== 'http:') return;
  if (!allowInsecure) {
    throw new TypeError(
      `${label} ${value} uses http, and fides-auth reaches the provider only over https. ` +
        'For a provider on a loopback address in development or CI, set allowInsecureRequests: true.',
    );
  }
  if (!isLoopback(url)) {
    throw new TypeError(
      `${label} ${value} uses http, and allowInsecureRequests allows http only to a loopback address ` +
        '(localhost, *.localhost, 127.0.0.0/8 or [::1]).',
    );
  }
}

function checkMetadata(metadata: openid.ServerMetadata, allowInsecure: boolean): void {
  for (const name of ENDPOINTS) checkTransport(name, metadata[name], allowInsecure);
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
  const allowInsecure = config.allowInsecureRequests === true;

  if (!metadata) {
    checkTransport('The issuer', config.issuer, allowInsecure);
    const discovered = await openid.discovery(
      new URL(config.issuer),
      config.clientId,
      clientSecret,
      clientAuthentication,
      ...(allowInsecure ? [{ execute: [openid.allowInsecureRequests] }] : []),
    );
    checkMetadata(discovered.serverMetadata(), allowInsecure);
    return discovered;
  }

  // Don't fall back to `config.issuer`: the ID token's `iss` must match the server's own.
  if (!metadata.issuer && requestsOpenId(config.scope)) {
    throw new TypeError(
      'serverMetadata.issuer is required when scope includes "openid", to check the ID token',
    );
  }

  checkMetadata(metadata, allowInsecure);
  const configuration = new openid.Configuration(
    metadata,
    config.clientId,
    clientSecret,
    clientAuthentication,
  );
  if (allowInsecure) openid.allowInsecureRequests(configuration);
  return configuration;
}

/** A discovery cache. Each OIDC client has its own. */
export interface DiscoveryCache {
  /** How long an entry stays reusable, in milliseconds. `0` disables caching. */
  readonly ttlMs: number;
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

  return {
    ttlMs,

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

      if (ttlMs > 0) {
        cache.set(key, { configuration, expiresAt: now + ttlMs, inputs });

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
