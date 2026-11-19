/**
 * The session format, pinned.
 *
 * The values below were written by 1.0.0-beta.8 with the secret, the provider
 * and the client in this file, except the login under way, which 1.0.0-beta.11
 * wrote: see there. Every 1.x must keep reading them: a cookie in a
 * browser, a record in a store and a lookup hash in an index all outlive the
 * deploy that wrote them.
 *
 * If a change makes one of these tests fail, that change logs every user out,
 * or leaves `endUserSessions` blind to the sessions already stored. Don't
 * replace a value to make the test pass. Make the old one keep working beside
 * the new, or take the change to the next major with a new record version.
 * The format is described in docs/session-format.md.
 */
import { describe, expect, it, vi } from 'vitest';

vi.mock('../protocol/client.js', () => ({ createOidcClient: vi.fn(() => ({ revoke: vi.fn(async () => true) })) }));

import { fetchCookieStore } from './fetch-cookie-store.js';
import { createFidesAuth } from './fides-auth.js';
import { readTransaction } from './login-transaction.js';
import { sessionKeyInfo } from './session-lifecycle.js';
import { deriveKey } from './session-secret.js';
import { createMemorySessionStore } from './session-store.js';
import { sha256 } from '../session/utils.js';

const SECRET = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const ISSUER = 'https://idp.example';
const CLIENT = 'web';
/** The handle a browser holds under store storage: 32 bytes as hex. */
const HANDLE = 'abababababababababababababababababababababababababababababababab';

const quiet = { debug() {}, info() {}, warn() {}, error() {} };
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** What the sealed values below hold. */
const session = {
  correlationId: '0123456789abcdef',
  createdAt: '2026-01-01T00:00:00.000Z',
  expiresAt: '2999-01-01T00:00:00.000Z',
  user: { sub: 'user-1', name: 'Ada', email: 'ada@example.test', roles: ['admin'] },
  scopes: ['openid', 'profile'],
  idp: { iss: ISSUER, sub: 'user-1', sid: 'idp-session-1' },
  data: { theme: 'dark' },
};
const tokens = {
  accessToken: 'access-token',
  accessTokenExpiresAt: '2999-01-01T00:00:00.000Z',
  accessTokenIssuedAt: '2026-01-01T00:00:00.000Z',
  refreshToken: 'refresh-token',
  idToken: 'id-token',
};

/** The record, sealed for cookie storage. */
const SEALED_FOR_COOKIE =
  'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..aYK_ptYR1sNHJ1AE.TY9qv01jmU7yz5JnvZwFLA725vMZOmogBpYBUM' +
  'hT9fsT9rVF4IMfKerI7f1Xj1swEzxUSuNAheYvwtWQMFhIfz-YNTkqdz7AlYACe34R928aDHMMv7szCzMFc41p8NvjIpeFZB' +
  '8ZWuj1_Hm0zCZvSo14uL_bsI-CKYWlHqPPAxOuBJktj2EZnS8iKSeIca7GPdJF94IzlqPFgfmr-qrZ8H0LeQmlNbZqDq0kZp' +
  '3wcNaI7KaDKpQxL1fDVxRpPkYw4U5P9XnJkHciB5P0e8Jym7Ug0Bh-88tvAexl6fexrxV8XjVKom0xdt7j7Zjfenn55IGz6q' +
  'OVhR1KIfpcPly0HNZy29zT77Qm2hDfKZVYqgUUzLdA3-PcKxv3oMGSANTckR0lOP0xFThIWoOP7tejMw_RqhuVuhiDnx_y9d' +
  '9Dfp7PAb-py0nuPNpb3B9xvvvkVgyow8h-vC5jX8uTQn6XHev_r_Db11spJebAnukh9BnsO1eMtSAxPNA-gfBk-tKKSgjvp7' +
  'IGEgF6vZP1nYQqhHwSlcBQBS9rxZfsUEoSMArKAzYTqmgJRWk9CGQZQtnNUmFwS1ze_JlPvKRr5NZouo3a2YC7RhlCqB2EpG' +
  'P0AxzYulRBORZsJnRkrqPMTm-uqY6Bq6P3pAk77OnZGzKPSs2citNKC6x9lSYaa8Mm_7Fg-qV7pp-kpskkiRhHnDpzsCLxl4' +
  'XuydQIe0avQWcjMFc7tyQB.4v_ic03TP__vGVmyOmU18Q';

/** The same record, sealed for the store key of `HANDLE`. */
const SEALED_FOR_STORE =
  'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..cdY4gJeBWVpzjKVf.6VX8x-2rPalYdfSj9HwGBUnShF7cYVZSprepmM' +
  'HC0cMCjVjGUC5vp6rBXo2jF6PDuppdsHUPZl9Q2MLkZlQr5NBG_AhGGHLgsnUBD-gqh_1crn6X1sm6LcBs3aSOMumOnyi0_R' +
  'uV4P78srP9vJMERVGSKZPBOFHRWnb0zxMszTqo0COjR7PABcrxD0R3e5sbr8d_3Uo7o32yiWWMpS9vdlA7hvezSp2aZygPcH' +
  'FyIFHH_yzAZU_etKLKl24rXJ4C67htaPCsJQVG6rDmiXOajtczBvmxqA3S_5iVBFy8oB04WsVA1UwgIxXV-mLC848JQlczZ5' +
  'DdgJo5nWL2YyUb7iDlzZi5o6vL1qaRBxnMTLbWOGCAL-LFO0uWTjOyN0Ly6sa6GFFNL9NuH8SO5WaAt5eK0I8T2mQFxwDWwF' +
  'MEw_KcbPYlbi9txWszi4bBvN49vfu_emF9KrrzDdzy-LZ9-0Hme4zsPQaN0iMqManJxw-RZO_HZ63CAWfbqiGOOK7AH4VGlh' +
  'VYcaR7XfAkZ6CCQ53tm3Ix_3ZkoFsEowHE5LesZ9_aDUNPVdS3TrNjOEghjMmuAGXlAgIUP_IqKk_hN48EINZ_QIax7qC4CZ' +
  '1rxRb8VdXrG-f66UGOj3Y3hMSeDf29uSZrd7mbwVVuNMznwCM6p8EMxc_j7hZzA4JfJ8cSQ-d7ErnQJYvY9Bz39FndB3xmSZ' +
  'ngHrcbESWMpPmEdtnlgjc1.d_LVTQZJ-QCYTFKp2WCavQ';

/**
 * A login under way: state `state-1`, verifier `verifier-1`, return path
 * `/after`, scope `openid`. Written by 1.0.0-beta.11, the first to seal a
 * login for its provider and client.
 */
const TRANSACTION_COOKIE =
  'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..y85MQ49Wt0ElX68H.qqRXlE49LHU2nyjG5qTgV6GSNva_EDfeQPCllX' +
  'mINA5V4ofahtCFjKg7NsHM8iyosKqkNwJXXB-LiyBqZlwWZHurGqXgCcmUWo_5SUTqM0oNycXukCKL2nXNqHSJfEVOUn3Zbu' +
  '9v_dmuocTxjUzuM8jT6evkt-mu9psWj6fYXw.iURoY8eqC8jGNq6Q-wKp4w';

/**
 * The same login as the betas up to 1.0.0-beta.10 sealed it: under a key
 * without the provider and the client in it, which any instance with the
 * secret could open. It is kept here to show that it no longer does.
 */
const TRANSACTION_COOKIE_WITHOUT_AUDIENCE =
  'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..qzQdCbVWjZe0RlL6.nrXy_oS33fP3oCZosPLCNBvRjXwfnXctf-Xjqi' +
  'utYU9eGZj2xIOgduclg180fottmmt_TsOD16CgJ6HxYV7OFDu8Pi82VmDOluX7BD0DrzG4VcBdIjehciCna2IpFDFNIonNnh' +
  'C9M4zDbmhxaOsJCh2hHyMCF_BUHya4ND85DQ.xOWjrUXH5KK4FHo7XyeZ4g';

const STORE_KEY = '271a413bd339c5709fdceaec41f14f11e9fbfb5042d72d331c65f32b284cd09a';
const SUB_HASH = 'e76303af4b609bb3b3bca2c766132dafb2e908e9a37c79c4ba74722c101cb6ed';
const IDP_SID_HASH = '7eb494827cdf5af498f2754df2f7988a1e21480196d8de5adab430aad9be50e9';

function auth(sessionStore?: ReturnType<typeof createMemorySessionStore>) {
  return createFidesAuth<{ theme: string }>({
    oauthConfig: {
      issuer: ISSUER,
      clientId: CLIENT,
      clientSecret: 'shh',
      redirectUri: 'https://app.example/api/auth/callback',
      scope: 'openid',
    },
    secret: SECRET,
    sessionStore,
    logger: { create: () => quiet },
  });
}

const withCookie = (cookie: string) =>
  fetchCookieStore(new Request('https://app.example/', { headers: { cookie } }));

describe('the keys', () => {
  const audience = '["https://idp.example","web"]';

  it('are HKDF-SHA-256 of the secret, with an info that names the purpose', async () => {
    expect(sessionKeyInfo(audience, 'cookie')).toBe('["fides-auth session","[\\"https://idp.example\\",\\"web\\"]","cookie"]');
    expect(hex(await deriveKey(SECRET, sessionKeyInfo(audience, 'cookie')))).toBe(
      '0539a20a2ca1a59de11040f25ff9f3f1649c0a7eec7a62a93f05c2220d871f7a',
    );
    expect(hex(await deriveKey(SECRET, sessionKeyInfo(audience, `store ${STORE_KEY}`)))).toBe(
      'a3c2b5a5bb61fd2c126e51d9027b09a51216e11f04ee70e13cf701fb6bd2c818',
    );
    expect(hex(await deriveKey(SECRET, 'fides-auth login-tx'))).toBe(
      '8d5b904b03ae5fdb54b5394309e11624263df3b1e23635f3e5b6df09721a0965',
    );
  });

  it('file a stored session under the SHA-256 of its handle', async () => {
    expect(await sha256(HANDLE)).toBe(STORE_KEY);
  });
});

describe('a session a 1.x wrote', () => {
  it('reads from its cookie', async () => {
    const cookies = withCookie(`__Host-session=${SEALED_FOR_COOKIE}`);

    expect(await auth().readSessionWithTokens(cookies)).toEqual({ session, tokens, tokenStatus: 'active' });
  });

  it('reads from its cookie when that was cut into chunks', async () => {
    const [a, b, c] = [SEALED_FOR_COOKIE.slice(0, 300), SEALED_FOR_COOKIE.slice(300, 600), SEALED_FOR_COOKIE.slice(600)];
    const cookies = withCookie(`__Host-session=${a}; __Host-session.1=${b}; __Host-session.2=${c}`);

    expect((await auth().readSession(cookies))?.user).toEqual(session.user);
  });

  it('reads from a store, by its handle', async () => {
    const store = createMemorySessionStore();
    await store.set(
      STORE_KEY,
      {
        data: SEALED_FOR_STORE,
        expiresAt: session.expiresAt,
        correlationId: session.correlationId,
        iss: ISSUER,
        subHash: SUB_HASH,
        idpSidHash: IDP_SID_HASH,
      },
      { continuation: false, reason: 'login' },
    );

    const instance = auth(store);
    expect(await instance.readSessionWithTokens(withCookie(`__Host-session=${HANDLE}`))).toEqual({
      session,
      tokens,
      tokenStatus: 'active',
    });
    // And is found by its user, through the lookup hash that was stored with it.
    expect(await instance.endUserSessions({ sub: 'user-1' })).toBe(1);
    expect(await store.get(STORE_KEY)).toBeNull();
  });

  it('is saved under the same key, with the same lookup hashes', async () => {
    const store = createMemorySessionStore();
    const set = vi.spyOn(store, 'set');
    const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const idToken = `${b64({ alg: 'none' })}.${b64({ iss: ISSUER, sub: 'user-1', sid: 'idp-session-1' })}.`;
    const cookies = withCookie('');

    await auth(store).createSession(cookies, { access_token: 'a', token_type: 'bearer', id_token: idToken });

    const [key, record] = set.mock.calls[0] ?? [];
    const handle = /__Host-session=([0-9a-f]{64})/.exec(cookies.headers().getSetCookie().join('\n'))?.[1] ?? '';
    expect(key).toBe(await sha256(handle));
    expect(record).toMatchObject({ iss: ISSUER, subHash: SUB_HASH, idpSidHash: IDP_SID_HASH });
    expect(Object.keys(record ?? {}).sort()).toEqual(['correlationId', 'data', 'expiresAt', 'idpSidHash', 'iss', 'subHash']);
  });

  it('doesn\'t open for another provider, another client or the other storage', async () => {
    const other = createFidesAuth({
      oauthConfig: { issuer: ISSUER, clientId: 'another', clientSecret: 'shh', redirectUri: 'https://app.example/cb', scope: 'openid' },
      secret: SECRET,
      logger: { create: () => quiet },
    });
    expect(await other.readSession(withCookie(`__Host-session=${SEALED_FOR_COOKIE}`))).toBeNull();
    expect(await auth().readSession(withCookie(`__Host-session=${SEALED_FOR_STORE}`))).toBeNull();
  });
});

describe('a session a later 1.x wrote', () => {
  it('keeps the fields this one doesn\'t know, through an update', async () => {
    const audience = JSON.stringify([ISSUER, CLIENT]);
    const key = await deriveKey(SECRET, sessionKeyInfo(audience, 'cookie'));
    const { createEncryptedJWT } = await import('../session/utils.js');
    const sealed = await createEncryptedJWT(
      { v: 1, session: { ...session, added: 'in 1.9' }, tokens: { ...tokens, addedToken: 'in 1.9' } },
      key,
    );
    const instance = auth();
    const cookies = withCookie(`__Host-session=${sealed}`);

    await instance.updateSession(cookies, (current) => ({ ...current, data: { theme: 'light' } }));
    const cookie = cookies.headers().getSetCookie().map((line) => line.split(';')[0]).join('; ');

    const after = await instance.readSessionWithTokens(withCookie(cookie));
    expect(after.session).toMatchObject({ added: 'in 1.9', data: { theme: 'light' } });
    expect(after.tokens).toMatchObject({ addedToken: 'in 1.9', refreshToken: 'refresh-token' });
  });
});

describe('a login a 1.x started', () => {
  it('is read back from its cookie', async () => {
    const cookies = withCookie(`__Host-oauth_tx_0=${TRANSACTION_COOKIE}`);

    const audience = JSON.stringify([ISSUER, CLIENT]);

    expect(await readTransaction(cookies, 'state-1', SECRET, { audience, logger: quiet })).toEqual({
      state: 'state-1',
      codeVerifier: 'verifier-1',
      returnTo: '/after',
      scope: 'openid',
      createdAt: 1767225600000,
    });
    // For its own provider and client only.
    const other = JSON.stringify(['https://another-idp.example', CLIENT]);
    expect(await readTransaction(cookies, 'state-1', SECRET, { audience: other, logger: quiet })).toBeNull();
  });

  it('is not read when a beta before 1.0.0-beta.11 sealed it, for no provider in particular', async () => {
    // A deliberate break, before 1.0: such a login could be finished by an
    // instance for another provider. It costs a login that was under way
    // during the upgrade, which the user starts again.
    const cookies = withCookie(`__Host-oauth_tx_0=${TRANSACTION_COOKIE_WITHOUT_AUDIENCE}`);
    const audience = JSON.stringify([ISSUER, CLIENT]);

    expect(await readTransaction(cookies, 'state-1', SECRET, { audience, logger: quiet })).toBeNull();
    expect(await readTransaction(cookies, 'state-1', SECRET, { logger: quiet })).toBeNull();
  });
});

describe('a test of the app\'s own', () => {
  it('starts a session and reads it the way docs/session-format.md shows', async () => {
    const instance = auth();
    const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsignedIdToken = (claims: object) => `${b64({ alg: 'none' })}.${b64(claims)}.`;

    const cookies = fetchCookieStore(new Request('https://app.example/'));
    await instance.createSession(cookies, {
      access_token: 'access-token',
      token_type: 'bearer',
      expires_in: 300,
      id_token: unsignedIdToken({ iss: ISSUER, sub: 'user-1' }),
    });
    const cookie = cookies
      .headers()
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');

    const request = new Request('https://app.example/account', { headers: { cookie } });
    expect((await instance.readSession(fetchCookieStore(request)))?.user?.sub).toBe('user-1');

    // And with a store: a handle in the cookie, the session in the store.
    const store = createMemorySessionStore();
    const stored = fetchCookieStore(new Request('https://app.example/'));
    await auth(store).createSession(stored, { access_token: 'a', token_type: 'bearer', id_token: unsignedIdToken({ iss: ISSUER, sub: 'user-2' }) });
    const handle = stored.headers().getSetCookie().map((line) => line.split(';')[0]).join('; ');
    expect(handle).toMatch(/^__Host-session=[0-9a-f]{64}$/);
    const again = new Request('https://app.example/account', { headers: { cookie: handle } });
    expect((await auth(store).readSession(fetchCookieStore(again)))?.user?.sub).toBe('user-2');
  });
});

