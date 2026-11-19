/**
 * Tests for Pushed Authorization Requests (RFC 9126) support in authorization-url.ts:
 * routing between PAR and the standard flow, from `usePar` and the provider's
 * metadata.
 *
 * If these tests fail, run from the repo root:
 *   pnpm --filter @eventuras/fides-auth test
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('openid-client', () => ({
  buildAuthorizationUrl: vi.fn(),
  buildAuthorizationUrlWithPAR: vi.fn(),
}));

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import { createAuthorizationRequest } from './authorization-parameters.js';
import { authorizationUrl } from './authorization-url.js';
import type { OidcClientConfig } from './config.js';
import type { ProtocolContext } from './context.js';

type LogEntry = { level: string; msg?: string; data?: Record<string, unknown> };

const logs: LogEntry[] = [];
const record = (level: string) => (data?: Record<string, unknown> | string, msg?: string) => {
  logs.push(typeof data === 'string' ? { level, msg: data } : { level, msg, data });
};
const logger: FidesLogger = {
  debug: record('debug'),
  info: record('info'),
  warn: record('warn'),
  error: record('error'),
};

function makeConfig(overrides: Partial<OidcClientConfig> = {}): OidcClientConfig {
  return {
    issuer: 'https://auth.example.com',
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUri: 'https://app.example.com/callback',
    scope: 'openid profile email',
    ...overrides,
  } as OidcClientConfig;
}

const parameters = {
  redirect_uri: 'https://app.example.com/callback',
  scope: 'openid profile email',
  code_challenge: 'challenge-abc',
  code_challenge_method: 'S256',
  state: 'state-xyz',
};

function makeDiscoveredConfig(parEndpoint?: string): openid.Configuration {
  return {
    serverMetadata: () => ({
      pushed_authorization_request_endpoint: parEndpoint,
    }),
  } as unknown as openid.Configuration;
}

/** A context whose provider is `discovered`. */
function ctx(config: OidcClientConfig, discovered: openid.Configuration): ProtocolContext {
  return { config, configuration: async () => discovered, logger };
}

beforeEach(() => {
  vi.clearAllMocks();
  logs.length = 0;
});

const advisory = () =>
  logs.find((e) => e.level === 'info' && e.msg?.includes('Provider advertises PAR'));

describe('authorizationUrl — PAR routing', () => {
  it('uses PAR when usePar=true and the provider advertises it', async () => {
    const discovered = makeDiscoveredConfig('https://auth.example.com/par');
    const parUrl = new URL('https://auth.example.com/authorize?client_id=x&request_uri=urn:1');
    vi.mocked(openid.buildAuthorizationUrlWithPAR).mockResolvedValue(parUrl);

    const result = await authorizationUrl(ctx(makeConfig({ usePar: true }), discovered), parameters);

    expect(openid.buildAuthorizationUrlWithPAR).toHaveBeenCalledWith(discovered, parameters);
    expect(openid.buildAuthorizationUrl).not.toHaveBeenCalled();
    expect(result).toBe(parUrl);
  });

  it('propagates errors from openid-client', async () => {
    vi.mocked(openid.buildAuthorizationUrlWithPAR).mockRejectedValue(new Error('par failed'));
    const discovered = makeDiscoveredConfig('https://auth.example.com/par');

    await expect(
      authorizationUrl(ctx(makeConfig({ usePar: true }), discovered), parameters),
    ).rejects.toThrow('par failed');
  });

  it('throws when usePar=true but the provider does not advertise PAR', async () => {
    await expect(
      authorizationUrl(ctx(makeConfig({ usePar: true }), makeDiscoveredConfig()), parameters),
    ).rejects.toThrow(/does not advertise pushed_authorization_request_endpoint/);

    expect(openid.buildAuthorizationUrlWithPAR).not.toHaveBeenCalled();
    expect(openid.buildAuthorizationUrl).not.toHaveBeenCalled();
  });

  it('uses the standard flow when usePar is unset and logs an advisory if PAR is advertised', async () => {
    const authUrl = new URL('https://auth.example.com/authorize?client_id=x');
    vi.mocked(openid.buildAuthorizationUrl).mockReturnValue(authUrl);
    const discovered = makeDiscoveredConfig('https://auth.example.com/par');

    const result = await authorizationUrl(ctx(makeConfig(), discovered), parameters);

    expect(openid.buildAuthorizationUrl).toHaveBeenCalledWith(discovered, parameters);
    expect(openid.buildAuthorizationUrlWithPAR).not.toHaveBeenCalled();
    expect(result).toBe(authUrl);
    expect(advisory()?.msg).toContain('set usePar: true in the config to use it');
  });

  it('uses the standard flow without advisory when the provider does not advertise PAR', async () => {
    vi.mocked(openid.buildAuthorizationUrl).mockReturnValue(new URL('https://auth.example.com/authorize'));

    await authorizationUrl(ctx(makeConfig(), makeDiscoveredConfig()), parameters);

    expect(openid.buildAuthorizationUrl).toHaveBeenCalledTimes(1);
    expect(openid.buildAuthorizationUrlWithPAR).not.toHaveBeenCalled();
    expect(advisory()).toBeUndefined();
  });

  it('uses the standard flow when usePar=false even if PAR is advertised', async () => {
    const authUrl = new URL('https://auth.example.com/authorize?client_id=x');
    vi.mocked(openid.buildAuthorizationUrl).mockReturnValue(authUrl);
    const discovered = makeDiscoveredConfig('https://auth.example.com/par');

    const result = await authorizationUrl(ctx(makeConfig({ usePar: false }), discovered), parameters);

    expect(openid.buildAuthorizationUrl).toHaveBeenCalledTimes(1);
    expect(openid.buildAuthorizationUrlWithPAR).not.toHaveBeenCalled();
    expect(result).toBe(authUrl);
  });
});

describe('authorizationUrl — extra parameters over PAR', () => {
  it('pushes extra parameters and the joined scope to the PAR endpoint', async () => {
    const discovered = makeDiscoveredConfig('https://auth.example.com/par');
    vi.mocked(openid.buildAuthorizationUrlWithPAR).mockResolvedValue(
      new URL('https://auth.example.com/authorize?client_id=x&request_uri=urn:1'),
    );
    const context = ctx(
      makeConfig({
        usePar: true,
        scope: ['openid', 'profile'],
        authorizationParameters: { resource: 'https://api.example.com' },
      }),
      discovered,
    );

    const request = await createAuthorizationRequest(context, {
      parameters: { login_hint: 'user@example.com' },
    });
    await authorizationUrl(context, request.parameters);

    expect(openid.buildAuthorizationUrlWithPAR).toHaveBeenCalledWith(discovered, {
      redirect_uri: 'https://app.example.com/callback',
      scope: 'openid profile',
      resource: 'https://api.example.com',
      login_hint: 'user@example.com',
      code_challenge: request.codeChallenge,
      code_challenge_method: 'S256',
      state: request.state,
      nonce: request.nonce,
    });
  });
});
