// The client under test: one login with fides-auth against one test module of
// the conformance suite, which plays the OpenID provider.
//
// It does what an app does and nothing else: starts a login, lets the browser
// follow the provider's redirect, finishes the login at the callback, and calls
// an API with the session's token. When the suite answers with something a
// client must refuse (a wrong `iss`, a bad signature, a missing `state`), the
// library is left to refuse it; this script only reports where it stopped.
//
// One process per module, started by run.ts: the suite serves new keys and
// metadata under the same issuer for each module, and a fresh process has
// nothing cached from the last one. The suite's certificate comes in through
// NODE_EXTRA_CA_CERTS. The last line it prints is its outcome as JSON.

import {
  type CookieStore,
  createFidesAuth,
  createMemorySessionStore,
  type LoginError,
} from '@eventuras/fides-auth/server';
import { importJWK, type JWK } from 'jose';

/** The suite's stand-in for an API: the accounts endpoint of its resource server. */
const ACCOUNTS_PATH = 'open-banking/v1.1/accounts';

/** Where the client got to. `done` is a whole login and an answer from the API. */
export type Stage = 'login' | 'authorize' | 'callback' | 'userinfo' | 'resource' | 'done';

export interface Outcome {
  /** `done`, or the step that failed. */
  stage: Stage;
  /** Why it stopped there, down the chain of causes. Empty for `done`. */
  reason: string;
}

export interface Input {
  /** The issuer of this test: `<suite>/test/a/<alias>/`. */
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  /** The client's private key, as a JWK with `kid` and `alg`. */
  clientJwk: JWK;
}

function input(): Input {
  const raw = process.env.CONFORMANCE_CLIENT;
  if (!raw) throw new Error('CONFORMANCE_CLIENT is not set: this script is started by run.ts');
  return JSON.parse(raw) as Input;
}

/** What something was refused for, down the chain of causes. */
function why(thrown: unknown): string {
  const parts: string[] = [];
  let cause: unknown = thrown;
  // The chain ends at a cause that is no error: openid-client hangs the response it refused there.
  for (let depth = 0; depth < 5 && (cause instanceof Error || typeof cause === 'string'); depth += 1) {
    if (typeof cause === 'string') {
      parts.push(cause);
      break;
    }
    const error = cause as {
      name?: string;
      message?: string;
      code?: string;
      reason?: string;
      status?: number;
      error?: string;
      error_description?: string;
      cause?: unknown;
    };
    const part = [error.message, error.code, error.reason, error.status, error.error, error.error_description]
      .filter((value) => value !== undefined && value !== '')
      .join(' / ');
    parts.push(part || String(cause));
    cause = error.cause;
  }
  return parts.join(' <- ');
}

/** The browser's cookies for the app. */
function cookieJar(): CookieStore {
  const jar = new Map<string, string>();
  return {
    get: (name) => jar.get(name) ?? null,
    set: (name, value, options) => {
      if (options?.maxAge === 0) jar.delete(name);
      else jar.set(name, value);
    },
  };
}

async function run({ issuer, clientId, redirectUri, scope, clientJwk }: Input): Promise<Outcome> {
  const appUrl = new URL(redirectUri).origin;
  const failures: LoginError[] = [];
  const quiet = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

  const auth = createFidesAuth({
    oauthConfig: {
      issuer,
      clientId,
      redirectUri,
      scope,
      // The FAPI 2.0 Security Profile: private_key_jwt, PAR, PKCE and DPoP,
      // and the library's own checks for it.
      profile: 'fapi2',
      clientAuth: 'private_key_jwt',
      privateKey: { key: (await importJWK(clientJwk, clientJwk.alg)) as CryptoKey, kid: clientJwk.kid },
      usePar: true,
      dpop: true,
    },
    secret: 'c'.repeat(64),
    sessionStore: createMemorySessionStore(),
    logger: quiet,
    onLoginError: (failure) => void failures.push(failure),
  });
  const cookies = cookieJar();

  // The app sends the browser to the provider: discovery and PAR happen here.
  const started = await auth.handleOidcLogin(new Request(`${appUrl}/login`), cookies);
  const authorize = started.headers.get('location');
  if (failures.length > 0 || !authorize?.startsWith(issuer)) {
    return { stage: 'login', reason: why(failures[0]?.cause ?? `redirected to ${authorize}`) };
  }

  // The browser at the provider. The suite signs nobody in: it redirects straight back.
  const atProvider = await fetch(authorize, { redirect: 'manual' });
  const back = atProvider.headers.get('location');
  if (!back?.startsWith(redirectUri)) {
    const body = (await atProvider.text()).slice(0, 300);
    return { stage: 'authorize', reason: `the suite answered ${atProvider.status}: ${back ?? body}` };
  }
  await atProvider.body?.cancel();

  // The callback: the response is checked, the code exchanged, the ID token verified.
  const finished = await auth.handleOidcCallback(new Request(back), cookies);
  const session = await auth.readSession(cookies);
  if (failures.length > 0 || !session) {
    return {
      stage: 'callback',
      reason: why(failures[0]?.cause ?? `no session; redirected to ${finished.headers.get('location')}`),
    };
  }

  // With an ID token there is a user to ask UserInfo about, with the session's key.
  if (session.idp?.sub) {
    try {
      const tokens = await auth.getTokens(cookies);
      await auth.oidc.userInfo(tokens?.accessToken ?? '', {
        expectedSubject: session.idp.sub,
        dpopKey: tokens?.dpopKey,
      });
    } catch (thrown) {
      return { stage: 'userinfo', reason: why(thrown) };
    }
  }

  // The API call, with the DPoP-bound token. This is what ends a test that is meant to pass.
  try {
    await auth.authorizedFetch(cookies, ACCOUNTS_PATH, {
      allowedBase: issuer,
      parse: (response) => response.json(),
    });
  } catch (thrown) {
    return { stage: 'resource', reason: why(thrown) };
  }
  return { stage: 'done', reason: '' };
}

// run.ts imports only the types of this file, so this runs only as a script.
let outcome: Outcome;
try {
  outcome = await run(input());
} catch (thrown) {
  // Nothing above is meant to throw: the library answers a failed login with a redirect.
  outcome = { stage: 'login', reason: `threw: ${why(thrown)}` };
}
console.log(JSON.stringify(outcome));
