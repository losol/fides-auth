/**
 * The `iss` of the authorization response (RFC 9207), end to end: the handlers
 * run the real openid-client against a stubbed provider, so what is tested is
 * that a callback from another provider, or one without the `iss` this
 * provider says it sends, ends the login before the code is sent anywhere.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLoggerFactory } from '../shared/logger.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type FidesAuth, type LoginError } from './fides-auth.js';

const APP = 'https://app.test';
const ISSUER = 'https://idp.test';
const secret = 'a'.repeat(64);

const quiet: FidesLoggerFactory = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

const fetchMock = vi.fn(async (input: string | URL | Request) => {
  const url = String(input instanceof Request ? input.url : input);
  if (url !== `${ISSUER}/token`) throw new Error(`Unexpected request to ${url}`);
  return Response.json({ access_token: 'access-1', token_type: 'bearer', expires_in: 300 });
});

beforeEach(() => {
  fetchMock.mockClear();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function browser(): { cookies: CookieStore; jar: Map<string, string> } {
  const jar = new Map<string, string>();
  return {
    jar,
    cookies: {
      get: (name) => jar.get(name) ?? null,
      set: (name, value, options) => {
        if (options?.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
      },
    },
  };
}

/** An instance for a provider whose metadata has `metadata` next to its endpoints. */
function instance(metadata: Record<string, unknown> = {}) {
  const failures: LoginError[] = [];
  const auth = createFidesAuth({
    oauthConfig: {
      issuer: ISSUER,
      clientId: 'web',
      clientSecret: 'shh',
      redirectUri: `${APP}/api/auth/callback`,
      // No openid, so the token response needs no ID token.
      scope: 'api:read',
      serverMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        ...metadata,
      },
    },
    secret,
    logger: quiet,
    onLoginError: (failure) => void failures.push(failure),
  });
  return { auth, failures };
}

/** Starts a login and answers it with a callback, with `iss` when given. */
async function login(auth: FidesAuth, cookies: CookieStore, iss?: string): Promise<Response> {
  const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
  const state = new URL(started.headers.get('location') ?? '').searchParams.get('state') ?? '';
  const query = new URLSearchParams({ code: 'c', state, ...(iss === undefined ? {} : { iss }) });
  return auth.handleOidcCallback(new Request(`${APP}/api/auth/callback?${query}`), cookies);
}

const sendsIss = { authorization_response_iss_parameter_supported: true };

describe('the iss of the authorization response', () => {
  it.each([
    ['a callback without iss, from a provider that says it sends one', sendsIss, undefined],
    ['a callback from another provider, when this one says it sends iss', sendsIss, 'https://evil.test'],
    ['a callback from another provider, when this one says nothing of iss', {}, 'https://evil.test'],
  ])('refuses %s', async (_, metadata, iss) => {
    const { auth, failures } = instance(metadata);
    const { cookies, jar } = browser();

    const done = await login(auth, cookies, iss);

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toMatchObject({ code: 'login_failed', stage: 'callback' });
    // The code never left for the token endpoint.
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await auth.readSession(cookies)).toBeNull();
    expect(jar.has('__Host-session')).toBe(false);
  });

  it.each([
    ['with the iss of a provider that says it sends one', sendsIss, ISSUER],
    ['with the iss of a provider that says nothing of it', {}, ISSUER],
    ['without iss, from a provider that says nothing of it', {}, undefined],
  ])('logs in on a callback %s', async (_, metadata, iss) => {
    const { auth, failures } = instance(metadata);
    const { cookies, jar } = browser();

    const done = await login(auth, cookies, iss);

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect((await auth.getTokens(cookies))?.accessToken).toBe('access-1');
    expect(jar.has('__Host-session')).toBe(true);
  });
});
