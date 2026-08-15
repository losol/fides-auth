import { describe, it, expect } from 'vitest';

import {
  encodeSessionCookies,
  decodeSessionCookies,
  decodeIdTokenCookie,
} from './session-cookies';
import { createEncryptedJWT, decryptJWT } from './utils';
import { Session, Tokens } from './types';

// 32-byte (64 hex char) key for A256GCM.
const SECRET = 'a'.repeat(64);

/** Builds an unsigned JWT carrying only an `exp` claim (decoded, never verified). */
function jwtWithExp(secondsFromNow: number): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ exp })}.sig`;
}

const session = (accessToken?: string, idToken?: string): Session => ({
  tokens: {
    accessToken,
    idToken,
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

  it('gives the ID token its own value, kept out of the other two', async () => {
    const idToken = jwtWithExp(3600);
    const encoded = await encodeSessionCookies(session(jwtWithExp(3600), idToken), SECRET);

    expect(encoded.idToken).toBeTruthy();

    // Decrypt rather than search the ciphertext: the point is that the payloads
    // carry no idToken, not that a base64 fragment happens to be absent.
    const main = await decryptJWT(encoded.session, SECRET);
    const accessTokenValue = await decryptJWT(encoded.accessToken!, SECRET);

    expect((main.tokens as Tokens | undefined)?.idToken).toBeUndefined();
    expect(accessTokenValue.idToken).toBeUndefined();
  });

  it('omits the ID-token value when the session has none', async () => {
    const encoded = await encodeSessionCookies(session(jwtWithExp(3600)), SECRET);
    expect(encoded.idToken).toBeUndefined();
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

  it('round-trips the ID token', async () => {
    const idToken = jwtWithExp(3600);
    const encoded = await encodeSessionCookies(session(jwtWithExp(3600), idToken), SECRET);

    const decoded = await decodeSessionCookies(
      {
        session: encoded.session,
        accessToken: encoded.accessToken ?? null,
        idToken: encoded.idToken ?? null,
      },
      SECRET,
    );

    expect(decoded?.tokens?.idToken).toBe(idToken);
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

describe('decodeIdTokenCookie', () => {
  it('returns the ID token after the access token has expired', async () => {
    const idToken = jwtWithExp(3600);
    const encoded = await encodeSessionCookies(session(jwtWithExp(-60), idToken), SECRET);

    // The session itself is gone once the access token expires...
    expect(
      await decodeSessionCookies(
        {
          session: encoded.session,
          accessToken: encoded.accessToken ?? null,
          idToken: encoded.idToken ?? null,
        },
        SECRET,
      ),
    ).toBeNull();

    // ...but the logout hint must survive it.
    expect(await decodeIdTokenCookie(encoded.idToken!, SECRET)).toBe(idToken);
  });

  it('returns undefined for a corrupt value instead of throwing', async () => {
    expect(await decodeIdTokenCookie('not-a-jwe', SECRET)).toBeUndefined();
  });
});
