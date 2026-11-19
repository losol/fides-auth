// The client under test: one login with fides-auth against one test module of
// the conformance suite, which plays the OpenID provider.
//
// It does what an app does and nothing else: starts a login, lets the browser
// follow the provider's redirect, finishes the login at the callback, and calls
// UserInfo and an API with the session's token. When the suite answers with
// something a client must refuse (a wrong `iss`, a bad signature, a missing
// `state`), the library is left to refuse it; this script only reports where
// it stopped.
//
// It is one of three clients, by `kind`: the FAPI 2.0 one (`private_key_jwt`,
// PAR, DPoP), the plain OpenID Connect one (a client secret and bearer tokens),
// and that one with a back-channel logout route, which the suite posts a logout
// token to while the browser is at its end-session endpoint.
//
// One process per module, started by run.ts: the suite serves new keys and
// metadata under the same issuer for each module, and a fresh process has
// nothing cached from the last one. The suite's certificate comes in through
// NODE_EXTRA_CA_CERTS. The last line it prints is its outcome as JSON.

import { createServer, type IncomingMessage, type Server } from 'node:http';

import {
  type CookieStore,
  createFidesAuth,
  createMemorySessionStore,
  type LoginError,
} from '@eventuras/fides-auth/server';
import { importJWK, type JWK } from 'jose';

/** The suite's stand-in for an API: the accounts endpoint of its resource server. */
const ACCOUNTS_PATH = 'open-banking/v1.1/accounts';

/**
 * Where the client got to. `done` is a whole login and an answer from UserInfo
 * or the API. Two are how a back-channel logout ended: `logged-out` when the
 * route answered 200 and the session is gone, `logout-refused` when it
 * answered 400 and the session is still there. Any other mix of answer and
 * session is `backchannel`, and `logout` is the browser's trip to the
 * end-session endpoint going wrong.
 */
export type Stage =
  | 'login'
  | 'authorize'
  | 'callback'
  | 'userinfo'
  | 'resource'
  | 'logout'
  | 'backchannel'
  | 'logged-out'
  | 'logout-refused'
  | 'done';

/** Which client this is: see the top of the file. */
export type Kind = 'fapi2' | 'basic' | 'logout';

export interface Outcome {
  /** `done`, how the logout ended, or the step that failed. */
  stage: Stage;
  /** Why it stopped there, down the chain of causes. Empty for `done`. */
  reason: string;
}

export interface Input {
  kind: Kind;
  /** The issuer of this test: `<suite>/test/a/<alias>/`. */
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  /** `fapi2`: the client's private key, as a JWK with `kid` and `alg`. */
  clientJwk?: JWK;
  /** `basic` and `logout`: the client's secret, for `client_secret_basic`. */
  clientSecret?: string;
  /** `logout`: where the app's back-channel logout route listens, and where the provider sends the browser after. */
  logout?: LogoutInput;
}

export interface LogoutInput {
  /** The address and port to listen on. The suite's container must reach them. */
  host: string;
  port: number;
  /** The path of the route: the path of the client's `backchannel_logout_uri`. */
  path: string;
  postLogoutRedirectUri: string;
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

/** Reads a Node request into a fetch Request, for the library's handler. */
async function toRequest(url: string, incoming: IncomingMessage): Promise<Request> {
  const chunks: Buffer[] = [];
  for await (const chunk of incoming) chunks.push(chunk as Buffer);
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (typeof value === 'string') headers.set(name, value);
  }
  return new Request(url, {
    method: incoming.method,
    headers,
    body: incoming.method === 'GET' || incoming.method === 'HEAD' ? undefined : Buffer.concat(chunks),
  });
}

/** The app's one route, as a server: a request to `path` goes to `handler`, anything else is a 404. */
function listen({ host, port, path }: LogoutInput, handler: (request: Request) => Promise<Response>): Promise<Server> {
  const server = createServer((incoming, outgoing) => {
    void (async () => {
      const url = new URL(incoming.url ?? '/', `http://${incoming.headers.host ?? host}`);
      const response =
        url.pathname === path ? await handler(await toRequest(url.href, incoming)) : new Response(null, { status: 404 });
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    })().catch((thrown: unknown) => {
      // The library's handler threw: the provider gets a 500, which no module takes for an answer.
      outgoing.writeHead(500).end(String(thrown));
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

type OAuthConfig = Parameters<typeof createFidesAuth>[0]['oauthConfig'];

async function oauthConfig({ kind, issuer, clientId, redirectUri, scope, clientJwk, clientSecret }: Input): Promise<OAuthConfig> {
  if (kind === 'fapi2') {
    if (!clientJwk) throw new Error('The fapi2 client needs clientJwk');
    return {
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
    };
  }
  if (!clientSecret) throw new Error(`The ${kind} client needs clientSecret`);
  // What most apps are: the code flow with a client secret and bearer tokens.
  // Nothing else is set, so the rest is the library's defaults.
  return { issuer, clientId, redirectUri, scope, clientAuth: 'client_secret_basic', clientSecret };
}

async function run(given: Input): Promise<Outcome> {
  const { kind, issuer, redirectUri, logout } = given;
  const appUrl = new URL(redirectUri).origin;
  const failures: LoginError[] = [];
  // What the library logged as a warning or an error: why it refused a logout token is only there.
  const logged: string[] = [];
  const note = (context: unknown, message?: unknown) => {
    logged.push(typeof context === 'string' ? context : `${String(message)} ${JSON.stringify(context)}`);
  };
  const logger = { create: () => ({ debug() {}, info() {}, warn: note, error: note }) };

  const auth = createFidesAuth({
    oauthConfig: await oauthConfig(given),
    secret: 'c'.repeat(64),
    // In memory, and able to search: back-channel logout has to find the session.
    sessionStore: createMemorySessionStore(),
    logger,
    onLoginError: (failure) => void failures.push(failure),
    ...(logout ? { postLogoutRedirectUri: logout.postLogoutRedirectUri } : {}),
  });
  const cookies = cookieJar();

  // The app's back-channel logout route, up before the login as an app's is.
  const backChannel: number[] = [];
  const server = logout
    ? await listen(logout, async (request) => {
        const response = await auth.handleBackChannelLogout(request);
        backChannel.push(response.status);
        return response;
      })
    : undefined;

  try {
    // The app sends the browser to the provider: discovery (and PAR) happen here.
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

    // With an ID token there is a user to ask UserInfo about, with the session's
    // key when the token is bound to one. In the OpenID Connect plans this is
    // what ends a test that is meant to pass.
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

    if (kind === 'fapi2') {
      // The API call, with the DPoP-bound token. This is what ends a FAPI test that is meant to pass.
      try {
        await auth.authorizedFetch(cookies, ACCOUNTS_PATH, {
          allowedBase: issuer,
          parse: (response) => response.json(),
        });
      } catch (thrown) {
        return { stage: 'resource', reason: why(thrown) };
      }
    }
    if (!logout) return { stage: 'done', reason: '' };

    // The user logs out at the provider, and not through this app's logout
    // route: the session here is left as it is, so that only the logout token
    // the provider then posts can end it. (`handleOidcLogout` ends the session
    // before the browser leaves, and the token would find nothing to end.)
    const state = 'conformance-logout';
    const tokens = await auth.getTokens(cookies);
    const endSession = await auth.oidc.logoutUrl({
      postLogoutRedirectUri: logout.postLogoutRedirectUri,
      idTokenHint: tokens?.idToken,
      state,
    });
    if (!endSession) return { stage: 'logout', reason: 'the provider has no end_session_endpoint' };
    // The suite posts the logout token to the route above before it answers this.
    const atEndSession = await fetch(endSession, { redirect: 'manual' });
    const after = atEndSession.headers.get('location');
    await atEndSession.body?.cancel();
    if (after !== `${logout.postLogoutRedirectUri}?state=${state}`) {
      return { stage: 'logout', reason: `the suite answered ${atEndSession.status}, and sent the browser to ${after}` };
    }

    const stillThere = (await auth.readSession(cookies)) !== null;
    const said = `the route answered ${backChannel.join(', ') || 'no request'}; the session is ${stillThere ? 'still there' : 'gone'}`;
    const reason = [said, ...logged].join(' | ');
    if (backChannel.length === 1 && backChannel[0] === 200 && !stillThere) return { stage: 'logged-out', reason: said };
    if (backChannel.length === 1 && backChannel[0] === 400 && stillThere) return { stage: 'logout-refused', reason };
    return { stage: 'backchannel', reason };
  } finally {
    server?.closeAllConnections();
    server?.close();
  }
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
