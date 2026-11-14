/**
 * Tests for the discovery cache.
 *
 * The behaviours that matter operationally: one round-trip serves a burst of
 * concurrent refreshes, a failed provider is retried rather than remembered as
 * broken, and a rotated secret or key is not served from a stale entry.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  Configuration: vi.fn(function (this: Record<string, unknown>, server: unknown) {
    this.server = server;
  }),
  refreshTokenGrant: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
  ClientSecretBasic: vi.fn(() => () => undefined),
  None: vi.fn(() => () => undefined),
  PrivateKeyJwt: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient } from './client.js';
import type { OidcClientConfig } from './config.js';
import { checkTtl, createDiscoveryCache, type DiscoveryCache } from './discovery.js';

const quietLogger: FidesLogger = { debug() {}, info() {}, warn() {}, error() {} };
const quiet = { create: () => quietLogger };

const config: OidcClientConfig = {
  issuer: 'https://auth.example.test',
  clientId: 'client-a',
  clientSecret: 'secret-a',
  redirectUri: 'https://app.example.test/callback',
  scope: 'openid',
};

/** Stand-in keys: PrivateKeyJwt is mocked, so only their identity matters. */
const keyA = { type: 'private' } as unknown as CryptoKey;
const keyB = { type: 'private' } as unknown as CryptoKey;

function keyConfig(privateKey: CryptoKey | openid.PrivateKey): OidcClientConfig {
  return {
    issuer: config.issuer,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scope: config.scope,
    clientAuth: 'private_key_jwt',
    privateKey,
  };
}

/** A distinct object per call, so tests can tell one discovery from another. */
function discovered(tag: string) {
  return { tag } as unknown as openid.Configuration;
}

let cache: DiscoveryCache;

beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  cache = createDiscoveryCache(quietLogger);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('createDiscoveryCache — caching', () => {
  it('discovers once and reuses the result', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('first'));

    const a = await cache.discover(config);
    const b = await cache.discover(config);

    expect(openid.discovery).toHaveBeenCalledTimes(1);
    expect(b).toBe(a);
  });

  it('serves a burst of concurrent callers from one round-trip', async () => {
    // The heartbeat case: many requests arrive before the first discovery
    // resolves. Caching the promise rather than the value is what makes this
    // one request instead of ten.
    let resolve!: (value: openid.Configuration) => void;
    vi.mocked(openid.discovery).mockReturnValue(
      new Promise<openid.Configuration>((r) => {
        resolve = r;
      }),
    );

    const pending = Promise.all(
      Array.from({ length: 10 }, () => cache.discover(config)),
    );
    resolve(discovered('shared'));
    const results = await pending;

    expect(openid.discovery).toHaveBeenCalledTimes(1);
    expect(new Set(results).size).toBe(1);
  });

  it('rediscovers once the entry has expired', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('first'))
      .mockResolvedValueOnce(discovered('second'));
    cache = createDiscoveryCache(quietLogger, 1_000);

    const first = await cache.discover(config);

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 1_001);
    const second = await cache.discover(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
    expect(second).not.toBe(first);
  });

  it('keeps providers apart', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('a'))
      .mockResolvedValueOnce(discovered('b'));

    await cache.discover(config);
    await cache.discover({ ...config, issuer: 'https://other.example.test' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('keeps clients on one provider apart', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('a'))
      .mockResolvedValueOnce(discovered('b'));

    await cache.discover(config);
    await cache.discover({ ...config, clientId: 'client-b' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('does not serve a stale entry after the client secret rotates', async () => {
    // The cached Configuration carries the old secret, so reusing it would
    // authenticate with a credential the provider has already retired.
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('old'))
      .mockResolvedValueOnce(discovered('new'));

    await cache.discover(config);
    const after = await cache.discover({ ...config, clientSecret: 'secret-b' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
    expect(after).toEqual(discovered('new'));
  });

  it('treats a change of auth method as a new entry', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('post'))
      .mockResolvedValueOnce(discovered('basic'));

    await cache.discover(config);
    const basic = await cache.discover({ ...config, clientAuth: 'client_secret_basic' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
    expect(basic).toEqual(discovered('basic'));
  });

  it('reuses an entry for the same private key', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('key'));

    await cache.discover(keyConfig(keyA));
    await cache.discover(keyConfig(keyA));

    expect(openid.discovery).toHaveBeenCalledTimes(1);
  });

  it('does not serve a stale entry after the private key rotates', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('old'))
      .mockResolvedValueOnce(discovered('new'));

    await cache.discover(keyConfig(keyA));
    const after = await cache.discover(keyConfig(keyB));

    expect(openid.discovery).toHaveBeenCalledTimes(2);
    expect(after).toEqual(discovered('new'));
  });

  it('compares a { key, kid } wrapper by what it holds', async () => {
    // A wrapper rebuilt per call must not defeat the cache; a new kid must.
    vi.mocked(openid.discovery).mockResolvedValue(discovered('key'));

    await cache.discover(keyConfig({ key: keyA, kid: '1' }));
    await cache.discover(keyConfig({ key: keyA, kid: '1' }));
    await cache.discover(keyConfig({ key: keyA, kid: '2' }));

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });
});

describe('createDiscoveryCache — serverMetadata', () => {
  const metadata = {
    issuer: config.issuer,
    token_endpoint: `${config.issuer}/token`,
  } as openid.ServerMetadata;
  const withMetadata: OidcClientConfig = { ...config, serverMetadata: metadata };

  it('builds the configuration without discovering', async () => {
    await cache.discover(withMetadata);

    expect(openid.discovery).not.toHaveBeenCalled();
    expect(openid.Configuration).toHaveBeenCalledWith(
      metadata,
      config.clientId,
      'secret-a',
      expect.any(Function),
    );
  });

  it('caches it like a discovered configuration', async () => {
    const a = await cache.discover(withMetadata);
    const b = await cache.discover(withMetadata);

    expect(openid.Configuration).toHaveBeenCalledTimes(1);
    expect(b).toBe(a);
  });

  it('does not serve a discovered entry once serverMetadata is set', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('discovered'));

    await cache.discover(config);
    const built = await cache.discover(withMetadata);

    expect(openid.Configuration).toHaveBeenCalledTimes(1);
    expect(built).not.toEqual(discovered('discovered'));
  });

  it('treats new metadata as a new entry', async () => {
    await cache.discover(withMetadata);
    await cache.discover({ ...config, serverMetadata: { ...metadata } });

    expect(openid.Configuration).toHaveBeenCalledTimes(2);
  });

  it('requires issuer when the scope includes openid', async () => {
    // Without it the ID token's `iss` cannot be checked.
    const noIssuer = { token_endpoint: metadata.token_endpoint } as openid.ServerMetadata;

    await expect(
      cache.discover({ ...config, scope: 'profile openid', serverMetadata: noIssuer }),
    ).rejects.toThrow(/serverMetadata\.issuer is required/);
    expect(openid.Configuration).not.toHaveBeenCalled();
  });

  it('allows a missing issuer when openid is not requested', async () => {
    const noIssuer = { token_endpoint: metadata.token_endpoint } as openid.ServerMetadata;

    await cache.discover({ ...config, scope: 'api:read', serverMetadata: noIssuer });

    expect(openid.Configuration).toHaveBeenCalledTimes(1);
  });

  it('reads an array scope the same way', async () => {
    const noIssuer = { token_endpoint: metadata.token_endpoint } as openid.ServerMetadata;

    await expect(
      cache.discover({ ...config, scope: ['profile', 'openid'], serverMetadata: noIssuer }),
    ).rejects.toThrow(/serverMetadata\.issuer is required/);
    await cache.discover({ ...config, scope: ['api:read'], serverMetadata: noIssuer });

    expect(openid.Configuration).toHaveBeenCalledTimes(1);
  });
});

describe('createDiscoveryCache — failures', () => {
  it('retries instead of remembering a provider as broken', async () => {
    vi.mocked(openid.discovery)
      .mockRejectedValueOnce(new Error('unreachable'))
      .mockResolvedValueOnce(discovered('recovered'));

    await expect(cache.discover(config)).rejects.toThrow('unreachable');
    // A cached rejection would keep every later call failing for the whole TTL,
    // turning one blip into five minutes of downtime.
    await expect(cache.discover(config)).resolves.toEqual(discovered('recovered'));
    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('propagates the original error unchanged', async () => {
    // classifyRefreshFailure reads the error to decide 401 vs 503, so the cache
    // must not wrap or replace it.
    const cause = Object.assign(new TypeError('fetch failed'), { code: 'ECONNREFUSED' });
    vi.mocked(openid.discovery).mockRejectedValue(cause);

    await expect(cache.discover(config)).rejects.toBe(cause);
  });
});

describe('createDiscoveryCache — TTL', () => {
  it('caches for five minutes by default', () => {
    expect(cache.ttlMs).toBe(300_000);
  });

  it('disables caching at ttlMs 0', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('always'));
    cache = createDiscoveryCache(quietLogger, 0);

    await cache.discover(config);
    await cache.discover(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it.each([[NaN], [Infinity], [-Infinity], [-1]])(
    'checkTtl rejects %p rather than quietly disabling the cache',
    (ttlMs) => {
      // NaN is what Number(process.env.DISCOVERY_TTL) yields when the variable
      // is unset, and it would otherwise restore a discovery round-trip on every
      // token operation with nothing in the logs to say so.
      expect(() => checkTtl(ttlMs, 'ttlMs')).toThrow(TypeError);
    },
  );

  it('clear forces the next call to rediscover', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('x'));

    await cache.discover(config);
    cache.clear();
    await cache.discover(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });
});

describe('the refresh hot path', () => {
  it('stops re-discovering on every heartbeat', async () => {
    // This is the reason the cache exists. Without it, every heartbeat's
    // refresh would start with a full discovery round-trip before the token
    // request — doubling latency, provider load, and the surface on which a
    // refresh can fail.
    vi.mocked(openid.discovery).mockResolvedValue(discovered('idp'));
    vi.mocked(openid.refreshTokenGrant).mockResolvedValue({
      access_token: 'access',
      token_type: 'bearer',
    } as unknown as openid.TokenEndpointResponse);

    const client = createOidcClient(config, { logger: quiet });
    for (let beat = 0; beat < 5; beat++) {
      await client.refresh('refresh-token');
    }

    expect(openid.refreshTokenGrant).toHaveBeenCalledTimes(5);
    expect(openid.discovery).toHaveBeenCalledTimes(1);
  });

  it('still reaches the provider when discovery is disabled from cache', async () => {
    const client = createOidcClient(config, { logger: quiet, discoveryTtlMs: 0 });
    vi.mocked(openid.discovery).mockResolvedValue(discovered('idp'));
    vi.mocked(openid.refreshTokenGrant).mockResolvedValue({
      access_token: 'access',
      token_type: 'bearer',
    } as unknown as openid.TokenEndpointResponse);

    await client.refresh('refresh-token');
    await client.refresh('refresh-token');

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });
});
