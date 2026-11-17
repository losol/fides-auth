/**
 * A response from the provider that arrives with a 2xx status and then fails
 * validation is attached whole to the error oauth4webapi throws. These tests
 * run the real openid-client against a stubbed provider, and look for the
 * response's tokens and claims in everything that leaves the library: the
 * error that is thrown, what the loggers get, and what `onLoginError` gets.
 */
import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createOidcClient } from '../protocol/client.js';
import { classifyRefreshFailure } from '../protocol/logging.js';
import type { FidesLoggerFactory } from '../shared/logger.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type LoginError } from './fides-auth.js';

const APP = 'https://app.test';
const ISSUER = 'https://idp.test';
const ACCESS = 'access-token-do-not-leak';
const REFRESH = 'refresh-token-do-not-leak';
const EMAIL = 'ada-do-not-leak@example.test';

const oauthConfig = {
  issuer: ISSUER,
  clientId: 'web',
  clientSecret: 'shh',
  redirectUri: `${APP}/api/auth/callback`,
  scope: 'openid',
  serverMetadata: {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
  },
};

/** As deep as a logger or a `console.error` would ever print it. */
const dump = (value: unknown): string => inspect(value, { depth: null, showHidden: true, getters: true });

/**
 * Everything a part of the library handed to a logger, printed when it was
 * handed over, as a logger that writes at once would see it.
 */
function recordingLoggers(): { factory: FidesLoggerFactory; logged: string[] } {
  const logged: string[] = [];
  const log = (...args: unknown[]) => void logged.push(dump(args));
  return { logged, factory: { create: () => ({ debug: log, info: log, warn: log, error: log }) } };
}

let answer: () => Response;

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `${ISSUER}/token` || url === `${ISSUER}/userinfo`) return answer();
      throw new Error(`Unexpected request to ${url}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Token responses with a 200 that openid-client refuses, tokens and all. */
const refused: Array<[string, Record<string, unknown>]> = [
  ['no token_type', { access_token: ACCESS, refresh_token: REFRESH, expires_in: 300 }],
  ['a token_type it doesn\'t support', { access_token: ACCESS, refresh_token: REFRESH, token_type: 'mac' }],
  ['a scope that isn\'t a string', { access_token: ACCESS, refresh_token: REFRESH, token_type: 'bearer', scope: 7 }],
  ['an expires_in that isn\'t a number', { access_token: ACCESS, refresh_token: REFRESH, token_type: 'bearer', expires_in: 'soon' }],
];

describe('the OIDC client', () => {
  it.each(refused)('throws a refresh error without the token response, for %s', async (_, body) => {
    answer = () => Response.json(body);
    const { factory, logged } = recordingLoggers();
    const oidc = createOidcClient(oauthConfig, { logger: factory });

    const error = await oidc.refresh('old-refresh-token').catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(Error);
    for (const leaked of [ACCESS, REFRESH]) {
      expect(dump(error)).not.toContain(leaked);
      expect(logged.join('\n')).not.toContain(leaked);
    }
    // What was wrong is still there to read, on the cause.
    expect(dump(error)).toMatch(/token_type|scope|expires_in/);
  });

  it.each(refused)('throws a code exchange error without the token response, for %s', async (_, body) => {
    answer = () => Response.json(body);
    const { factory, logged } = recordingLoggers();
    const oidc = createOidcClient(oauthConfig, { logger: factory });
    const request = await oidc.createAuthorizationRequest();

    const error = await oidc
      .exchangeCode(new URL(`${APP}/api/auth/callback?code=c&state=${request.state}&iss=${ISSUER}`), request)
      .catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(Error);
    for (const leaked of [ACCESS, REFRESH]) {
      expect(dump(error)).not.toContain(leaked);
      expect(logged.join('\n')).not.toContain(leaked);
    }
  });

  it('throws a UserInfo error without the claims, when the response has no sub', async () => {
    answer = () => Response.json({ email: EMAIL, name: 'Ada' });
    const { factory, logged } = recordingLoggers();
    const oidc = createOidcClient(oauthConfig, { logger: factory });

    const error = await oidc.userInfo(ACCESS, { expectedSubject: 'user-1' }).catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(Error);
    expect(dump(error)).not.toContain(EMAIL);
    expect(logged.join('\n')).not.toContain(EMAIL);
  });

  it('still tells a refused refresh token from the rest', async () => {
    answer = () => Response.json({ error: 'invalid_grant', error_description: 'expired' }, { status: 400 });
    const oidc = createOidcClient(oauthConfig, { logger: recordingLoggers().factory });

    const error = await oidc.refresh('old-refresh-token').catch((thrown: unknown) => thrown);

    expect(classifyRefreshFailure(error)).toBe('invalid_grant');
    expect(error).toMatchObject({ error: 'invalid_grant', error_description: 'expired' });
  });
});

describe('a login whose token response is refused', () => {
  it('hands onLoginError and the loggers no tokens', async () => {
    answer = () => Response.json({ access_token: ACCESS, refresh_token: REFRESH, expires_in: 300 });
    const { factory, logged } = recordingLoggers();
    const failures: LoginError[] = [];
    const auth = createFidesAuth({
      oauthConfig,
      secret: 'a'.repeat(64),
      logger: factory,
      onLoginError: (failure) => void failures.push(failure),
    });
    const jar = new Map<string, string>();
    const cookies: CookieStore = {
      get: (name) => jar.get(name) ?? null,
      set: (name, value, options) => {
        if (options?.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
      },
    };

    const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
    const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');
    const response = await auth.handleOidcCallback(
      new Request(`${APP}/api/auth/callback?code=c&state=${state}`),
      cookies,
    );

    expect(response.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(failures[0]?.cause).toBeInstanceOf(Error);
    for (const leaked of [ACCESS, REFRESH]) {
      expect(dump(failures)).not.toContain(leaked);
      expect(logged.join('\n')).not.toContain(leaked);
    }
    expect(jar.has('__Host-session')).toBe(false);
  });
});
