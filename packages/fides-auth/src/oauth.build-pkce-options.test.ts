/**
 * Tests for buildPKCEOptions: the PKCE values, the assembled authorization
 * parameters, and the log line.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { configureLogger } from './logger';
import { buildPKCEOptions, defaultScope, type OAuthConfig } from './oauth';

// RFC 7636 Appendix B octets and the verifier/challenge they produce.
const RFC_7636_OCTETS = [
  116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77,
  105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
];
const RFC_7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const logs: { level: string; msg?: string }[] = [];
const record = (level: string) => (data?: Record<string, unknown> | string, msg?: string) => {
  logs.push({ level, msg: typeof data === 'string' ? data : msg });
};
configureLogger({
  create: () => ({
    debug: record('debug'),
    info: record('info'),
    warn: record('warn'),
    error: record('error'),
  }),
});

const oauthConfig: OAuthConfig = {
  issuer: 'https://auth.example.com',
  clientId: 'test-client',
  clientSecret: 'test-secret',
  redirect_uri: 'https://app.example.com/callback',
  scope: 'openid profile',
};

beforeEach(() => {
  logs.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('buildPKCEOptions', () => {
  it('derives the S256 challenge from the verifier', async () => {
    // First draw is the verifier; the state draw stays random.
    vi.spyOn(crypto, 'getRandomValues').mockImplementationOnce(
      <T extends ArrayBufferView | null>(array: T) => {
        (array as unknown as Uint8Array).set(RFC_7636_OCTETS);
        return array;
      },
    );

    const pkce = await buildPKCEOptions(oauthConfig);

    expect(pkce.code_verifier).toBe(RFC_7636_VERIFIER);
    expect(pkce.code_challenge).toBe(RFC_7636_CHALLENGE);
    expect(pkce.state).not.toBe(RFC_7636_VERIFIER);
  });

  it('assembles the authorization parameters', async () => {
    const pkce = await buildPKCEOptions(oauthConfig);

    expect(pkce.parameters).toEqual({
      redirect_uri: 'https://app.example.com/callback',
      scope: 'openid profile',
      code_challenge: pkce.code_challenge,
      code_challenge_method: 'S256',
      state: pkce.state,
    });
  });

  it('creates a fresh state each call', async () => {
    const [a, b] = await Promise.all([buildPKCEOptions(oauthConfig), buildPKCEOptions(oauthConfig)]);

    expect(a.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.state).not.toBe(b.state);
  });

  it('falls back to defaultScope when scope is missing', async () => {
    const { scope: _scope, ...withoutScope } = oauthConfig;
    const pkce = await buildPKCEOptions(withoutScope as OAuthConfig);

    expect(pkce.parameters.scope).toBe(defaultScope);
  });

  it('logs at debug, not info', async () => {
    await buildPKCEOptions(oauthConfig);

    expect(logs).toEqual([{ level: 'debug', msg: 'PKCE parameters generated' }]);
  });
});
