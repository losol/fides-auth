/**
 * Tests for logout token verification (OpenID Connect Back-Channel Logout 1.0
 * §2.6), with real keys and a local JWKS.
 */
import { createLocalJWKSet, exportJWK, generateKeyPair, type JWK, SignJWT, UnsecuredJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import type { RemoteJwks } from './id-token.js';
import {
  BACK_CHANNEL_LOGOUT_EVENT,
  LogoutTokenError,
  type LogoutTokenErrorReason,
  verifyLogoutTokenWith,
} from './logout-token.js';

const issuer = 'https://auth.example.test';
const audience = 'client-a';

let key: CryptoKey;
let otherKey: CryptoKey;
let jwks: RemoteJwks;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  key = pair.privateKey;
  otherKey = (await generateKeyPair('RS256')).privateKey;
  const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: 'key-1', alg: 'RS256', use: 'sig' };
  jwks = createLocalJWKSet({ keys: [jwk] }) as unknown as RemoteJwks;
});

const logoutEvent = { [BACK_CHANNEL_LOGOUT_EVENT]: {} };

interface TokenOptions {
  /** Claims over the defaults. `undefined` takes a default out. */
  claims?: Record<string, unknown>;
  key?: CryptoKey;
  typ?: string;
  iss?: string;
  aud?: string;
  exp?: string | number | null;
  iat?: boolean;
}

function sign({ claims = {}, typ, iss, aud, exp, iat = true, key: signingKey }: TokenOptions = {}): Promise<string> {
  const payload: Record<string, unknown> = { sub: 'user-1', jti: 'jti-1', events: logoutEvent, ...claims };
  for (const name of Object.keys(payload)) if (payload[name] === undefined) delete payload[name];
  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'key-1', ...(typ ? { typ } : {}) })
    .setIssuer(iss ?? issuer)
    .setAudience(aud ?? audience);
  if (iat) jwt.setIssuedAt();
  if (exp !== null) jwt.setExpirationTime(exp ?? '2m');
  return jwt.sign(signingKey ?? key);
}

const verify = (token: string) => verifyLogoutTokenWith(jwks, token, { issuer, audience });

/** The reason a token is refused for. */
async function refusal(token: string | Promise<string>): Promise<LogoutTokenErrorReason | 'accepted'> {
  try {
    await verify(await token);
    return 'accepted';
  } catch (error) {
    expect(error).toBeInstanceOf(LogoutTokenError);
    return (error as LogoutTokenError).reason;
  }
}

describe('verifyLogoutTokenWith: what it accepts', () => {
  it('a token that names a user', async () => {
    const verified = await verify(await sign());

    expect(verified).toMatchObject({ iss: issuer, sub: 'user-1', jti: 'jti-1' });
    expect('sid' in verified).toBe(false);
    expect(verified.claims.events).toEqual(logoutEvent);
  });

  it('a token that names only a session', async () => {
    const verified = await verify(await sign({ claims: { sub: undefined, sid: 'idp-session-1' } }));

    expect(verified).toMatchObject({ iss: issuer, sid: 'idp-session-1' });
    expect('sub' in verified).toBe(false);
  });

  it('a token that names both', async () => {
    const verified = await verify(await sign({ claims: { sid: 'idp-session-1' } }));

    expect(verified).toMatchObject({ sub: 'user-1', sid: 'idp-session-1' });
  });

  it.each(['logout+jwt', 'application/logout+jwt', 'Logout+JWT', 'JWT'])('the type %s', async (typ) => {
    expect(await refusal(sign({ typ }))).toBe('accepted');
  });

  it('other events next to the logout event, and members in it', async () => {
    const events = { [BACK_CHANNEL_LOGOUT_EVENT]: { reason: 'admin' }, 'https://example.test/other': {} };

    expect(await refusal(sign({ claims: { events } }))).toBe('accepted');
  });
});

describe('verifyLogoutTokenWith: what it refuses', () => {
  it.each<[string, TokenOptions]>([
    ['another issuer', { iss: 'https://evil.example.test' }],
    ['another audience', { aud: 'client-b' }],
    ['an expired token', { exp: Math.floor(Date.now() / 1000) - 60 }],
    ['no exp', { exp: null }],
    ['no iat', { iat: false }],
    ['no jti', { claims: { jti: undefined } }],
    ['a jti that is not a string', { claims: { jti: 7 } }],
    ['an empty jti', { claims: { jti: '' } }],
  ])('%s, as an invalid token', async (_, options) => {
    expect(await refusal(sign(options))).toBe('invalid_token');
  });

  it('a token issued more than five minutes ago, though it has not expired: a copy sent again', async () => {
    const now = Math.floor(Date.now() / 1000);
    const old = sign({ claims: { iat: now - 6 * 60 }, iat: false, exp: now + 3600 });
    const recent = sign({ claims: { iat: now - 4 * 60 }, iat: false, exp: now + 3600 });

    expect(await refusal(old)).toBe('invalid_token');
    expect(await refusal(recent)).toBe('accepted');
  });

  it('a token from the future, beyond what two clocks differ by', async () => {
    const now = Math.floor(Date.now() / 1000);

    expect(await refusal(sign({ claims: { iat: now + 20 }, iat: false }))).toBe('accepted');
    expect(await refusal(sign({ claims: { iat: now + 120 }, iat: false }))).toBe('invalid_token');
  });

  it('a signature by a key the provider does not have', async () => {
    const forged = sign({ key: otherKey });

    expect(await refusal(forged)).toBe('invalid_token');
  });

  it('an unsigned token', async () => {
    const unsigned = new UnsecuredJWT({ sub: 'user-1', jti: 'j', events: logoutEvent })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('2m')
      .encode();

    expect(await refusal(unsigned)).toBe('invalid_token');
  });

  it('a token signed with the client secret, as HS256', async () => {
    const symmetric = await new SignJWT({ sub: 'user-1', jti: 'j', events: logoutEvent })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(new TextEncoder().encode('the-client-secret-the-client-secret'));

    expect(await refusal(symmetric)).toBe('invalid_token');
  });

  it('what is not a JWT at all', async () => {
    expect(await refusal('not-a-token')).toBe('invalid_token');
    expect(await refusal('')).toBe('invalid_token');
  });

  it("an ID token: signed by the provider for this client, but no logout event", async () => {
    const idToken = sign({ claims: { events: undefined, sid: 'idp-session-1' } });

    expect(await refusal(idToken)).toBe('no_logout_event');
  });

  it.each<[string, unknown]>([
    ['is a string', BACK_CHANNEL_LOGOUT_EVENT],
    ['is a list', [BACK_CHANNEL_LOGOUT_EVENT]],
    ['is null', null],
    ['has only another event', { 'https://example.test/other': {} }],
    ['has the logout event as true', { [BACK_CHANNEL_LOGOUT_EVENT]: true }],
    ['has the logout event as null', { [BACK_CHANNEL_LOGOUT_EVENT]: null }],
    ['has the logout event as a list', { [BACK_CHANNEL_LOGOUT_EVENT]: [] }],
  ])('a token whose events claim %s', async (_, events) => {
    expect(await refusal(sign({ claims: { events } }))).toBe('no_logout_event');
  });

  it.each<[string, unknown]>([
    ['a nonce', 'n-1'],
    ['an empty nonce', ''],
    ['a null nonce', null],
  ])('a token with %s, which only an ID token has', async (_, nonce) => {
    expect(await refusal(sign({ claims: { nonce } }))).toBe('has_nonce');
  });

  it.each<[string, Record<string, unknown>]>([
    ['neither a sub nor a sid', { sub: undefined }],
    ['an empty sub', { sub: '' }],
    ['a sub that is not a string', { sub: 7 }],
    ['an empty sid next to a sub', { sid: '' }],
    ['a sid that is not a string', { sub: undefined, sid: ['a'] }],
  ])('a token with %s', async (_, claims) => {
    expect(await refusal(sign({ claims }))).toBe('no_subject');
  });

  it.each(['at+jwt', 'application/at+jwt', 'id_token+jwt', 'secevent+jwt'])(
    'the type %s, which is another kind of JWT',
    async (typ) => {
      expect(await refusal(sign({ typ }))).toBe('wrong_type');
    },
  );

  it("keeps the token out of the error", async () => {
    const token = await sign({ aud: 'client-b' });

    const error = await verify(token).catch((thrown: unknown) => thrown);

    expect(String((error as Error).message)).not.toContain(token);
    expect(String(((error as Error).cause as Error | undefined)?.message)).not.toContain(token);
  });
});
