/**
 * fides-auth against a real OpenID provider. The unit tests use stubs written
 * with the library, which share its reading of the specifications; here the
 * other side is oidc-provider, which checks every request by its own code:
 * the client assertion, PAR, PKCE, the DPoP proofs and their nonces, the
 * binding of the code to `dpop_jkt`, and the tokens it then accepts.
 */
import { createFidesAuth, createMemorySessionStore, type FidesAuth, type LoginError } from '@eventuras/fides-auth/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  appCookies,
  CLIENT_ID,
  CLIENT_SECRET,
  type Harness,
  type HarnessOptions,
  ProviderBrowser,
  startHarness,
} from './harness.js';

const secret = 'a'.repeat(64);
const quiet = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

interface Setup {
  dpop?: boolean;
  usePar?: boolean;
  profile?: 'fapi2';
  clientAuth?: 'private_key_jwt' | 'client_secret_basic';
}

function instance(harness: Harness, { dpop = false, usePar = false, profile, clientAuth = 'private_key_jwt' }: Setup = {}) {
  const failures: LoginError[] = [];
  const auth = createFidesAuth({
    oauthConfig: {
      issuer: harness.issuer,
      clientId: CLIENT_ID,
      redirectUri: `${harness.appUrl}/callback`,
      scope: 'openid profile offline_access',
      // The provider gives a refresh token for offline_access only with consent.
      authorizationParameters: { prompt: 'consent' },
      dpop,
      usePar,
      ...(profile ? { profile } : {}),
      ...(clientAuth === 'private_key_jwt'
        ? { clientAuth: 'private_key_jwt' as const, privateKey: { key: harness.clientKey, kid: 'client-1' } }
        : { clientAuth: 'client_secret_basic' as const, clientSecret: CLIENT_SECRET }),
    },
    secret,
    sessionStore: createMemorySessionStore(),
    logger: quiet,
    onLoginError: (failure) => void failures.push(failure),
  });
  return { auth, failures };
}

/** A whole login: the app's redirect, the user at the provider, and the app's callback. */
async function login(harness: Harness, auth: FidesAuth, user = 'ada') {
  const browser = appCookies();
  const started = await auth.handleOidcLogin(new Request(`${harness.appUrl}/login`), browser.cookies);
  const authorize = new URL(started.headers.get('location') ?? '');
  const atProvider = new ProviderBrowser(harness.appUrl);
  const back = await atProvider.signIn(authorize, user);
  const done = await auth.handleOidcCallback(new Request(back), browser.cookies);
  return { ...browser, atProvider, authorize, back, done };
}

/** What the failed login was refused for, down the chain of causes. */
function why(failures: LoginError[]): string {
  const parts: string[] = [];
  let cause: unknown = failures[0]?.cause;
  for (let depth = 0; depth < 4 && cause; depth += 1) {
    const error = cause as { message?: string; error?: string; error_description?: string; cause?: unknown };
    parts.push([error.message, error.error, error.error_description].filter(Boolean).join(' / '));
    cause = error.cause;
  }
  return parts.join(' <- ');
}

function scenarios(name: string, harnessOptions: HarnessOptions, setup: Setup) {
  describe(name, () => {
    let harness: Harness;
    beforeAll(async () => {
      harness = await startHarness(harnessOptions);
    });
    afterAll(async () => {
      await harness.close();
    });

    it('logs in, and the session has the user the provider signed in', async () => {
      const { auth, failures } = instance(harness, setup);

      const { cookies, done, back } = await login(harness, auth);

      expect(why(failures)).toBe('');
      expect(done.headers.get('location')).toBe(`${harness.appUrl}/?login=success`);
      // The provider names itself on the callback (RFC 9207).
      expect(back.searchParams.get('iss')).toBe(harness.issuer);
      const session = await auth.readSession(cookies);
      // This provider keeps the profile claims for UserInfo; the ID token names the user.
      expect(session?.user).toMatchObject({ sub: 'ada' });
      expect(session?.idp).toMatchObject({ iss: harness.issuer, sub: 'ada' });
      expect(session?.idp?.sid).toEqual(expect.any(String));
      const tokens = await auth.getTokens(cookies);
      expect(tokens?.refreshToken).toEqual(expect.any(String));
      expect(tokens?.tokenType).toBe(setup.dpop ? 'dpop' : undefined);
    });

    it("has an ID token that verifies against the provider's keys", async () => {
      const { auth } = instance(harness, setup);
      const { cookies } = await login(harness, auth);

      const claims = await auth.oidc.verifyIdToken((await auth.getTokens(cookies))?.idToken ?? '');

      expect(claims.sub).toBe('ada');
      // The nonce of the login came back in it.
      expect(claims.nonce).toEqual(expect.any(String));
    });

    it('calls an endpoint that checks the token, and gets the user', async () => {
      const { auth } = instance(harness, setup);
      const { cookies } = await login(harness, auth);

      const { data } = await auth.authorizedFetch(cookies, 'me', {
        allowedBase: `${harness.issuer}/`,
        parse: (response) => response.json() as Promise<{ sub: string }>,
      });

      expect(data.sub).toBe('ada');
    });

    it('refreshes, and the new token works where the old one was issued', async () => {
      const { auth } = instance(harness, setup);
      const { cookies } = await login(harness, auth);
      const before = await auth.getTokens(cookies);

      const refreshed = await auth.refreshSession(cookies);

      expect(refreshed).toMatchObject({ ok: true, refreshed: true, rotatedRefreshToken: true });
      const after = await auth.getTokens(cookies);
      expect(after?.accessToken).not.toBe(before?.accessToken);
      expect(after?.dpopKey).toEqual(before?.dpopKey);
      const { data } = await auth.authorizedFetch(cookies, 'me', {
        allowedBase: `${harness.issuer}/`,
        parse: (response) => response.json() as Promise<{ sub: string }>,
      });
      expect(data.sub).toBe('ada');
      // And twice more, so a rotated refresh token is used too.
      expect((await auth.refreshSession(cookies)).ok).toBe(true);
      expect((await auth.refreshSession(cookies)).ok).toBe(true);
    });

    it('gets the claims from UserInfo with the session key', async () => {
      const { auth } = instance(harness, setup);
      const { cookies } = await login(harness, auth);
      const tokens = await auth.getTokens(cookies);

      const claims = await auth.oidc.userInfo(tokens?.accessToken ?? '', {
        expectedSubject: 'ada',
        dpopKey: tokens?.dpopKey,
      });

      expect(claims).toMatchObject({ sub: 'ada', name: 'Name of ada' });
    });

    it('logs out: the refresh token is revoked at the provider', async () => {
      const { auth } = instance(harness, setup);
      const { cookies } = await login(harness, auth);
      const spent = (await auth.getTokens(cookies))?.refreshToken ?? '';
      const key = (await auth.getTokens(cookies))?.dpopKey;

      await auth.clearSession(cookies);

      expect(await auth.readSession(cookies)).toBeNull();
      // The provider no longer takes it.
      await expect(auth.oidc.refresh(spent, key ? { dpopKey: key } : undefined)).rejects.toMatchObject({
        error: 'invalid_grant',
      });
    });

    it("ends the session when the provider says the user logged out there", async () => {
      const { auth } = instance(harness, setup);
      harness.onBackChannelLogout((request) => auth.handleBackChannelLogout(request));
      const ada = await login(harness, auth);
      const grace = await login(harness, auth, 'grace');
      const before = harness.backChannelLogouts.length;

      // The user logs out at the provider: an RP-initiated logout from this app, confirmed in its form.
      const idToken = (await auth.getTokens(ada.cookies))?.idToken ?? '';
      const logoutUrl = await auth.oidc.logoutUrl({ idTokenHint: idToken, postLogoutRedirectUri: harness.appUrl });
      expect(logoutUrl).not.toBeNull();
      await ada.atProvider.signOut(logoutUrl as URL);

      await expect.poll(() => harness.backChannelLogouts.length, { timeout: 5000 }).toBeGreaterThan(before);
      // The provider's own logout token was taken: signature, issuer, audience, event and all.
      expect(harness.backChannelLogouts.at(-1)).toEqual({ status: 200 });
      expect(await auth.readSession(ada.cookies)).toBeNull();
      expect((await auth.readSession(grace.cookies))?.user?.sub).toBe('grace');
    });
  });
}

scenarios('a confidential client with a secret, bearer tokens', { clientAuth: 'client_secret_basic' }, { clientAuth: 'client_secret_basic' });
scenarios('private_key_jwt, PAR and DPoP', {}, { dpop: true, usePar: true });
scenarios('DPoP where the provider insists on a nonce', { requireDpopNonce: true }, { dpop: true, usePar: true });
scenarios('the FAPI 2.0 profile on both sides', { fapi2: true, requireDpopNonce: true }, { dpop: true, usePar: true, profile: 'fapi2' });
