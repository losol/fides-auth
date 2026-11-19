/**
 * Regression test for `OidcClient.exchangeCode` callback URL normalization.
 *
 * If these tests fail, run from the repo root:
 *   pnpm --filter @eventuras/fides-auth test
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  authorizationCodeGrant: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient } from './client.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };

/** Exchanges the code on `callbackUrl` with a new client. */
function exchange(callbackUrl: URL, codeVerifier: string, state: string, nonce?: string) {
  const client = createOidcClient(
    {
      issuer: 'https://auth.example.com',
      clientId: 'test-client',
      clientSecret: 'test-secret',
      redirectUri: 'https://app.example.com/callback',
      scope: 'openid profile email',
    },
    { logger: quiet },
  );
  return client.exchangeCode(callbackUrl, { codeVerifier, state, nonce });
}

const discoveredConfig = { serverMetadata: () => ({}) } as unknown as openid.Configuration;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(openid.discovery).mockResolvedValue(discoveredConfig);
  vi.mocked(openid.authorizationCodeGrant).mockResolvedValue({
    access_token: 'access',
    token_type: 'Bearer',
    expires_in: 3600,
  } as openid.TokenEndpointResponse);
});

describe('exchangeCode — callback URL normalization', () => {
  it('rewrites the callback URL origin to the configured redirectUri before exchange', async () => {
    // Reverse proxy without trust-proxy hands the pod an http:// request,
    // even though the public origin is https://.
    const proxyStrippedCallback = new URL(
      'http://pod.internal:3000/callback?code=auth-code-123&state=state-xyz',
    );

    await exchange(proxyStrippedCallback, 'verifier-123', 'state-xyz');

    const [, passedCallbackUrl] = vi.mocked(openid.authorizationCodeGrant).mock.calls[0];
    expect(passedCallbackUrl).toBeInstanceOf(URL);
    expect((passedCallbackUrl as URL).origin).toBe('https://app.example.com');
    expect((passedCallbackUrl as URL).pathname).toBe('/callback');
    expect((passedCallbackUrl as URL).searchParams.get('code')).toBe('auth-code-123');
    expect((passedCallbackUrl as URL).searchParams.get('state')).toBe('state-xyz');
  });

  it('keeps the configured host when the callback pathname starts with //', async () => {
    // A protocol-relative-looking pathname (e.g. forwarded via a misbehaving
    // proxy or attacker-crafted request) must not swap the host of the
    // normalized callback URL.
    const maliciousCallback = new URL(
      'http://pod.internal//evil.com/callback?code=auth-code-789&state=state-pwn',
    );
    expect(maliciousCallback.pathname).toBe('//evil.com/callback');

    await exchange(maliciousCallback, 'verifier-789', 'state-pwn');

    const [, passedCallbackUrl] = vi.mocked(openid.authorizationCodeGrant).mock.calls[0];
    expect((passedCallbackUrl as URL).host).toBe('app.example.com');
    expect((passedCallbackUrl as URL).origin).toBe('https://app.example.com');
  });

  it('passes through unchanged when callback already uses the configured origin', async () => {
    const matchingCallback = new URL(
      'https://app.example.com/callback?code=auth-code-456&state=state-abc',
    );

    await exchange(matchingCallback, 'verifier-456', 'state-abc');

    const [, passedCallbackUrl] = vi.mocked(openid.authorizationCodeGrant).mock.calls[0];
    expect((passedCallbackUrl as URL).toString()).toBe(matchingCallback.toString());
  });
});

describe('exchangeCode — nonce', () => {
  const callback = new URL('https://app.example.com/callback?code=auth-code&state=state-1');

  it('hands the nonce of the login to openid-client, with the state and the verifier', async () => {
    await exchange(callback, 'verifier-1', 'state-1', 'nonce-1');

    const [, , checks] = vi.mocked(openid.authorizationCodeGrant).mock.calls[0];
    expect(checks).toEqual({
      pkceCodeVerifier: 'verifier-1',
      expectedState: 'state-1',
      expectedNonce: 'nonce-1',
    });
  });

  it('expects no nonce for a login that sent none', async () => {
    await exchange(callback, 'verifier-1', 'state-1');

    const [, , checks] = vi.mocked(openid.authorizationCodeGrant).mock.calls[0];
    expect(checks).toEqual({ pkceCodeVerifier: 'verifier-1', expectedState: 'state-1' });
    // Not even as undefined: openid-client reads the key.
    expect(checks && 'expectedNonce' in checks).toBe(false);
  });
});
