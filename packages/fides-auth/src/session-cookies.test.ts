import { describe, it, expect } from 'vitest';

import { encodeSessionCookies, decodeSessionCookies } from './session-cookies';
import { createEncryptedJWT } from './utils';
import { Session } from './types';

// 32-byte (64 hex char) key for A256GCM.
const SECRET = 'a'.repeat(64);

/** Builds an unsigned JWT carrying only an `exp` claim (decoded, never verified). */
function jwtWithExp(secondsFromNow: number): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ exp })}.sig`;
}

const session = (accessToken?: string): Session => ({
  tokens: {
    accessToken,
    refreshToken: 'refresh-token',
    accessTokenExpiresAt: '2099-01-01T00:00:00.000Z',
  },
  user: { name: 'Ada', email: 'ada@example.test', roles: ['admin'] },
  scopes: ['openid', 'profile'],
});

describe('encodeSessionCookies', () => {
  it('splits the access token into its own value, kept out of the main value', async () => {
    const accessToken = jwtWithExp(3600);
    const encoded = await encodeSessionCookies(session(accessToken), SECRET);

    expect(encoded.session).toBeTruthy();
    expect(encoded.accessToken).toBeTruthy();
    expect(encoded.session).not.toContain(accessToken.split('.')[1]);
  });

  it('omits the access-token value when the session has none', async () => {
    const encoded = await encodeSessionCookies(session(undefined), SECRET);
    expect(encoded.accessToken).toBeUndefined();
  });
});

describe('decodeSessionCookies', () => {
  it('round-trips a split session', async () => {
    const accessToken = jwtWithExp(3600);
    const encoded = await encodeSessionCookies(session(accessToken), SECRET);

    const decoded = await decodeSessionCookies(
      { session: encoded.session, accessToken: encoded.accessToken ?? null },
      SECRET,
    );

    expect(decoded?.tokens?.accessToken).toBe(accessToken);
    expect(decoded?.tokens?.refreshToken).toBe('refresh-token');
    expect(decoded?.user?.email).toBe('ada@example.test');
    expect(decoded?.scopes).toEqual(['openid', 'profile']);
  });

  it('returns null when there is no session value', async () => {
    expect(await decodeSessionCookies({ session: null, accessToken: null }, SECRET)).toBeNull();
  });

  it('returns null when the split access token has expired', async () => {
    const encoded = await encodeSessionCookies(session(jwtWithExp(-60)), SECRET);
    const decoded = await decodeSessionCookies(
      { session: encoded.session, accessToken: encoded.accessToken ?? null },
      SECRET,
    );
    expect(decoded).toBeNull();
  });

  it('keeps the session for an opaque (non-JWT) access token instead of treating it as expired', async () => {
    const accessToken = 'opaque-reference-token-not-a-jwt';
    const encoded = await encodeSessionCookies(session(accessToken), SECRET);

    const decoded = await decodeSessionCookies(
      { session: encoded.session, accessToken: encoded.accessToken ?? null },
      SECRET,
    );

    expect(decoded).not.toBeNull();
    expect(decoded?.tokens?.accessToken).toBe(accessToken);
  });

  it('tolerates a corrupt access-token value, returning the session without it', async () => {
    const encoded = await encodeSessionCookies(session(jwtWithExp(3600)), SECRET);
    const decoded = await decodeSessionCookies(
      { session: encoded.session, accessToken: 'not-a-valid-jwe' },
      SECRET,
    );
    expect(decoded).not.toBeNull();
    expect(decoded?.tokens?.accessToken).toBeUndefined();
    expect(decoded?.tokens?.refreshToken).toBe('refresh-token');
  });

  it('reads a legacy session that holds the access token in the main value', async () => {
    const accessToken = jwtWithExp(3600);
    const legacy = await createEncryptedJWT(session(accessToken), SECRET);

    const decoded = await decodeSessionCookies({ session: legacy, accessToken: null }, SECRET);
    expect(decoded?.tokens?.accessToken).toBe(accessToken);
  });
});
