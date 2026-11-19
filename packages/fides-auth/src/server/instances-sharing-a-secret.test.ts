/**
 * Two instances on one origin with one secret, each for its own provider:
 * "log in with A" and "log in with B". A session is sealed for its provider
 * and client, and so is a login on its way to one. Otherwise provider B could
 * send the browser to A's callback with a code of its choosing, and A would
 * finish the login B's transaction started: the user would be signed in as
 * whoever that code is for.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLoggerFactory } from '../shared/logger.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type LoginError } from './fides-auth.js';

const APP = 'https://app.test';
const secret = 'a'.repeat(64);
const quiet: FidesLoggerFactory = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

/** The token endpoints that were asked for tokens. */
let asked: string[];

beforeEach(() => {
  asked = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input instanceof Request ? input.url : input);
      asked.push(url);
      // Whoever is asked answers with a session for an attacker's account.
      return Response.json({ access_token: 'access-of-the-attacker', token_type: 'bearer', expires_in: 300 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function instance(name: string, clientId = 'web') {
  const failures: LoginError[] = [];
  const issuer = `https://${name}.test`;
  const auth = createFidesAuth({
    oauthConfig: {
      issuer,
      clientId,
      clientSecret: 'shh',
      redirectUri: `${APP}/auth/${name}/callback`,
      scope: 'api:read',
      serverMetadata: {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
      },
    },
    secret,
    logger: quiet,
    onLoginError: (failure) => void failures.push(failure),
  });
  return { auth, failures, issuer };
}

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

describe('instances that share a secret and an origin', () => {
  it("doesn't finish at one provider's callback a login that was started for the other", async () => {
    const a = instance('idp-a');
    const b = instance('idp-b');
    const { cookies } = browser();

    // The user clicks "log in with B". B sees the request, state and all.
    const started = await b.auth.handleOidcLogin(new Request(`${APP}/auth/idp-b/login`), cookies);
    const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');

    // B sends the browser to A's callback instead, with a code from A for the attacker's account.
    const done = await a.auth.handleOidcCallback(
      new Request(`${APP}/auth/idp-a/callback?code=code-of-the-attacker&state=${state}&iss=${a.issuer}`),
      cookies,
    );

    // A has no login under way with that state: the code goes nowhere.
    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_expired`);
    expect(a.failures).toEqual([{ code: 'login_expired', stage: 'callback', cause: undefined }]);
    expect(asked).toEqual([]);
    expect(await a.auth.readSession(cookies)).toBeNull();
    expect(await b.auth.readSession(cookies)).toBeNull();
  });

  it('still finishes the login at the provider it was started for', async () => {
    const a = instance('idp-a');
    const b = instance('idp-b');
    const { cookies } = browser();
    const started = await b.auth.handleOidcLogin(new Request(`${APP}/auth/idp-b/login`), cookies);
    const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');

    // A's refusal above must not have spent B's login either.
    await a.auth.handleOidcCallback(new Request(`${APP}/auth/idp-a/callback?code=x&state=${state}`), cookies);
    const done = await b.auth.handleOidcCallback(
      new Request(`${APP}/auth/idp-b/callback?code=code-from-b&state=${state}`),
      cookies,
    );

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(asked).toEqual([`${b.issuer}/token`]);
    // And the session it made is B's alone.
    expect(await b.auth.readSession(cookies)).not.toBeNull();
    expect(await a.auth.readSession(cookies)).toBeNull();
  });

  it('keeps two clients of one provider apart too', async () => {
    const one = instance('idp-a', 'client-one');
    const two = instance('idp-a', 'client-two');
    const { cookies } = browser();
    const started = await one.auth.handleOidcLogin(new Request(`${APP}/auth/idp-a/login`), cookies);
    const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');

    const done = await two.auth.handleOidcCallback(
      new Request(`${APP}/auth/idp-a/callback?code=c&state=${state}`),
      cookies,
    );

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_expired`);
    expect(asked).toEqual([]);
  });
});
