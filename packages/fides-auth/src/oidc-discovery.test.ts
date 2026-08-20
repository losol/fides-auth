/**
 * Tests for the discovery cache.
 *
 * The behaviours that matter operationally: one round-trip serves a burst of
 * concurrent refreshes, a failed provider is retried rather than remembered as
 * broken, and a rotated secret is not served from a stale entry.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  refreshTokenGrant: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import {
  clearDiscoveryCache,
  configureDiscoveryCache,
  discoverConfiguration,
} from './oidc-discovery';
import { refreshAccessToken, type OAuthConfig } from './oauth';

const config: OAuthConfig = {
  issuer: 'https://auth.example.test',
  clientId: 'client-a',
  clientSecret: 'secret-a',
  redirect_uri: 'https://app.example.test/callback',
  scope: 'openid',
};

/** A distinct object per call, so tests can tell one discovery from another. */
function discovered(tag: string) {
  return { tag } as unknown as openid.Configuration;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  configureDiscoveryCache({ ttlMs: 300_000 });
});

afterEach(() => {
  vi.useRealTimers();
  clearDiscoveryCache();
});

describe('discoverConfiguration — caching', () => {
  it('discovers once and reuses the result', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('first'));

    const a = await discoverConfiguration(config);
    const b = await discoverConfiguration(config);

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
      Array.from({ length: 10 }, () => discoverConfiguration(config)),
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
    configureDiscoveryCache({ ttlMs: 1_000 });

    const first = await discoverConfiguration(config);

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 1_001);
    const second = await discoverConfiguration(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
    expect(second).not.toBe(first);
  });

  it('keeps providers apart', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('a'))
      .mockResolvedValueOnce(discovered('b'));

    await discoverConfiguration(config);
    await discoverConfiguration({ ...config, issuer: 'https://other.example.test' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('keeps clients on one provider apart', async () => {
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('a'))
      .mockResolvedValueOnce(discovered('b'));

    await discoverConfiguration(config);
    await discoverConfiguration({ ...config, clientId: 'client-b' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('does not serve a stale entry after the client secret rotates', async () => {
    // The cached Configuration carries the old secret, so reusing it would
    // authenticate with a credential the provider has already retired.
    vi.mocked(openid.discovery)
      .mockResolvedValueOnce(discovered('old'))
      .mockResolvedValueOnce(discovered('new'));

    await discoverConfiguration(config);
    const after = await discoverConfiguration({ ...config, clientSecret: 'secret-b' });

    expect(openid.discovery).toHaveBeenCalledTimes(2);
    expect(after).toEqual(discovered('new'));
  });
});

describe('discoverConfiguration — failures', () => {
  it('retries instead of remembering a provider as broken', async () => {
    vi.mocked(openid.discovery)
      .mockRejectedValueOnce(new Error('unreachable'))
      .mockResolvedValueOnce(discovered('recovered'));

    await expect(discoverConfiguration(config)).rejects.toThrow('unreachable');
    // A cached rejection would keep every later call failing for the whole TTL,
    // turning one blip into five minutes of downtime.
    await expect(discoverConfiguration(config)).resolves.toEqual(discovered('recovered'));
    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('propagates the original error unchanged', async () => {
    // classifyRefreshFailure reads the error to decide 401 vs 503, so the cache
    // must not wrap or replace it.
    const cause = Object.assign(new TypeError('fetch failed'), { code: 'ECONNREFUSED' });
    vi.mocked(openid.discovery).mockRejectedValue(cause);

    await expect(discoverConfiguration(config)).rejects.toBe(cause);
  });
});

describe('configureDiscoveryCache', () => {
  it('disables caching at ttlMs 0', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('always'));
    configureDiscoveryCache({ ttlMs: 0 });

    await discoverConfiguration(config);
    await discoverConfiguration(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('drops existing entries so a new setting takes effect at once', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('x'));

    await discoverConfiguration(config);
    configureDiscoveryCache({ ttlMs: 60_000 });
    await discoverConfiguration(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it.each([[NaN], [Infinity], [-Infinity], [-1]])(
    'rejects ttlMs %p rather than quietly disabling the cache',
    (ttlMs) => {
      // NaN is what Number(process.env.DISCOVERY_TTL) yields when the variable
      // is unset, and it would otherwise restore a discovery round-trip on every
      // token operation with nothing in the logs to say so.
      expect(() => configureDiscoveryCache({ ttlMs })).toThrow(TypeError);
    },
  );

  it('leaves the existing setting intact when it rejects a value', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('x'));
    configureDiscoveryCache({ ttlMs: 60_000 });

    expect(() => configureDiscoveryCache({ ttlMs: NaN })).toThrow();

    // Still caching on the previous setting, not half-applied.
    await discoverConfiguration(config);
    await discoverConfiguration(config);
    expect(openid.discovery).toHaveBeenCalledTimes(1);
  });

  it('clearDiscoveryCache forces the next call to rediscover', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered('x'));

    await discoverConfiguration(config);
    clearDiscoveryCache();
    await discoverConfiguration(config);

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });
});

describe('the refresh hot path', () => {
  it('stops re-discovering on every heartbeat', async () => {
    // This is the reason the cache exists. Every heartbeat calls
    // refreshAccessToken, which used to perform a full discovery round-trip
    // before the token request — doubling latency, provider load, and the
    // surface on which a refresh can fail.
    vi.mocked(openid.discovery).mockResolvedValue(discovered('idp'));
    vi.mocked(openid.refreshTokenGrant).mockResolvedValue({
      access_token: 'access',
      token_type: 'bearer',
    } as unknown as openid.TokenEndpointResponse);

    for (let beat = 0; beat < 5; beat++) {
      await refreshAccessToken(config, 'refresh-token');
    }

    expect(openid.refreshTokenGrant).toHaveBeenCalledTimes(5);
    expect(openid.discovery).toHaveBeenCalledTimes(1);
  });

  it('still reaches the provider when discovery is disabled from cache', async () => {
    configureDiscoveryCache({ ttlMs: 0 });
    vi.mocked(openid.discovery).mockResolvedValue(discovered('idp'));
    vi.mocked(openid.refreshTokenGrant).mockResolvedValue({
      access_token: 'access',
      token_type: 'bearer',
    } as unknown as openid.TokenEndpointResponse);

    await refreshAccessToken(config, 'refresh-token');
    await refreshAccessToken(config, 'refresh-token');

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });
});
