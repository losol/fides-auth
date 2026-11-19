// A real OpenID provider for the tests: oidc-provider, over https on a
// loopback port, with a certificate made for the run. fides-auth is the client
// and talks to it through fetch like to any provider; nothing is stubbed.
//
// The provider's own UserInfo endpoint stands in for an API: it takes a
// DPoP-bound access token only with a proof it has checked itself.

import { createServer as createHttpsServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { getCACertificates, setDefaultCACertificates } from 'node:tls';

import type { CookieStore } from '@eventuras/fides-auth/server';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import Provider, { type Configuration } from 'oidc-provider';
import { generate } from 'selfsigned';

export const CLIENT_ID = 'interop-client';

export interface Harness {
  issuer: string;
  /** Where the app listens: the redirect URI and the back-channel logout URI are on it. */
  appUrl: string;
  /** The client's key, for `private_key_jwt`. */
  clientKey: CryptoKey;
  /** Requests the provider's server got, as `METHOD path`. */
  requests: string[];
  /** Sets what answers the app's back-channel logout route. */
  onBackChannelLogout(handler: (request: Request) => Promise<Response>): void;
  /** The back-channel logout requests the app got, with the status it answered. */
  backChannelLogouts: Array<{ status: number }>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  /** Runs the provider under its FAPI 2.0 profile. */
  fapi2?: boolean;
  /** Whether the provider insists on a DPoP nonce at the token endpoint and UserInfo. */
  requireDpopNonce?: boolean;
  /** `private_key_jwt` or `client_secret_basic`. */
  clientAuth?: 'private_key_jwt' | 'client_secret_basic';
}

export const CLIENT_SECRET = 'interop-secret-interop-secret-interop-secret';

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

/** Reads a Node request into a fetch Request, for the handlers under test. */
async function toRequest(url: string, incoming: import('node:http').IncomingMessage): Promise<Request> {
  const chunks: Buffer[] = [];
  for await (const chunk of incoming) chunks.push(chunk as Buffer);
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (typeof value === 'string') headers.set(name, value);
  }
  const body = Buffer.concat(chunks);
  return new Request(url, {
    method: incoming.method,
    headers,
    body: incoming.method === 'GET' || incoming.method === 'HEAD' ? undefined : body,
  });
}

let certificatePromise: ReturnType<typeof generate> | undefined;

/**
 * One certificate for the run, for every server the tests start, and trusted
 * by this process alone. Set once: Node reads its default authorities when the
 * first connection is made.
 */
function trustedCertificate(): ReturnType<typeof generate> {
  certificatePromise ??= generate([{ name: 'commonName', value: 'localhost' }], {
    keySize: 2048,
    extensions: [
      { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] },
    ],
  }).then((certificate) => {
    setDefaultCACertificates([...getCACertificates('default'), certificate.cert]);
    return certificate;
  });
  return certificatePromise;
}

export async function startHarness(options: HarnessOptions = {}): Promise<Harness> {
  const { fapi2 = false, requireDpopNonce = false, clientAuth = 'private_key_jwt' } = options;

  const certificate = await trustedCertificate();
  const tls = { key: certificate.private, cert: certificate.cert };

  // The app: only the back-channel logout route is reached over the network.
  let backChannel: (request: Request) => Promise<Response> = async () => new Response(null, { status: 404 });
  const backChannelLogouts: Array<{ status: number }> = [];
  const appServer = createHttpsServer(tls);
  const appPort = await listen(appServer);
  const appUrl = `https://localhost:${appPort}`;
  appServer.on('request', (incoming, outgoing) => {
    void (async () => {
      const request = await toRequest(`${appUrl}${incoming.url}`, incoming);
      const response =
        new URL(request.url).pathname === '/backchannel-logout'
          ? await backChannel(request)
          : new Response(null, { status: 404 });
      backChannelLogouts.push({ status: response.status });
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    })();
  });

  const providerKeys = await generateKeyPair('ES256', { extractable: true });
  const clientKeys = await generateKeyPair('ES256', { extractable: true });
  const clientJwk: JWK = { ...(await exportJWK(clientKeys.publicKey)), alg: 'ES256', use: 'sig', kid: 'client-1' };

  const providerServer = createHttpsServer(tls);
  const providerPort = await listen(providerServer);
  const issuer = `https://localhost:${providerPort}`;

  const configuration: Configuration = {
    clients: [
      {
        client_id: CLIENT_ID,
        redirect_uris: [`${appUrl}/callback`],
        post_logout_redirect_uris: [appUrl],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        id_token_signed_response_alg: 'ES256',
        backchannel_logout_uri: `${appUrl}/backchannel-logout`,
        backchannel_logout_session_required: true,
        ...(clientAuth === 'private_key_jwt'
          ? { token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [clientJwk] } }
          : { token_endpoint_auth_method: 'client_secret_basic', client_secret: CLIENT_SECRET }),
      },
    ],
    jwks: { keys: [{ ...(await exportJWK(providerKeys.privateKey)), alg: 'ES256', use: 'sig', kid: 'provider-1' }] },
    cookies: { keys: ['interop-cookie-key'] },
    claims: { openid: ['sub', 'sid'], profile: ['name'] },
    findAccount: (_ctx: unknown, sub: string) => ({
      accountId: sub,
      claims: () => ({ sub, name: `Name of ${sub}` }),
    }),
    features: {
      devInteractions: { enabled: true },
      pushedAuthorizationRequests: { enabled: true },
      dPoP: {
        enabled: true,
        ...(requireDpopNonce
          ? { nonceSecret: Buffer.alloc(32, 7), requireNonce: () => true }
          : {}),
      },
      backchannelLogout: { enabled: true },
      revocation: { enabled: true },
      rpInitiatedLogout: { enabled: true },
      ...(fapi2 ? { fapi: { enabled: true, profile: '2.0' as const } } : {}),
    },
    rotateRefreshToken: true,
    // The provider refuses to call a loopback address, which is where the
    // app of these tests listens. Its own requests go out without that guard.
    fetch: (url: URL, init: RequestInit) => fetch(url, { ...init, dispatcher: undefined } as RequestInit),
  };

  const provider = new Provider(issuer, configuration);
  // Quiet: the provider reports refused requests on stderr, and the tests refuse on purpose.
  provider.on('server_error', () => undefined);
  const requests: string[] = [];
  const callback = provider.callback();
  providerServer.on('request', (incoming, outgoing) => {
    requests.push(`${incoming.method} ${new URL(incoming.url ?? '/', issuer).pathname}`);
    void callback(incoming, outgoing);
  });

  return {
    issuer,
    appUrl,
    clientKey: clientKeys.privateKey,
    requests,
    backChannelLogouts,
    onBackChannelLogout(handler) {
      backChannel = handler;
    },
    async close() {
      await Promise.all([close(appServer), close(providerServer)]);
    },
  };
}

/** A browser's cookie jar for the app, as a CookieStore. */
export function appCookies(): { cookies: CookieStore; jar: Map<string, string> } {
  const jar = new Map<string, string>();
  return {
    jar,
    cookies: {
      get: (name) => jar.get(name) ?? null,
      set: (name, value, cookieOptions) => {
        if (cookieOptions?.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
      },
    },
  };
}

/** The user's browser at the provider: its cookies there, kept between a login and a logout. */
export class ProviderBrowser {
  private readonly jar = new Map<string, string>();

  constructor(private readonly appUrl: string) {}

  private async request(url: URL, init: RequestInit = {}): Promise<Response> {
    const cookie = [...this.jar].map(([name, value]) => `${name}=${value}`).join('; ');
    const response = await fetch(url, { ...init, redirect: 'manual', headers: { ...init.headers, cookie } });
    for (const set of response.headers.getSetCookie()) {
      const [pair = ''] = set.split(';');
      const at = pair.indexOf('=');
      const value = pair.slice(at + 1);
      if (value === '' || /expires=Thu, 01 Jan 1970/i.test(set)) this.jar.delete(pair.slice(0, at));
      else this.jar.set(pair.slice(0, at), value);
    }
    return response;
  }

  /**
   * Follows redirects from `start`, filling in each form the provider shows
   * with `fill`, until the provider sends the browser back to the app.
   * Returns that URL.
   */
  private async follow(start: URL, fill: (html: string, url: URL) => { action: URL; fields: Record<string, string> }): Promise<URL> {
    let url = start;
    let init: RequestInit = {};
    for (let step = 0; step < 15; step += 1) {
      const response = await this.request(url, init);
      init = {};
      const location = response.headers.get('location');
      if (location) {
        const next = new URL(location, url);
        await response.body?.cancel();
        if (next.origin === new URL(this.appUrl).origin) return next;
        url = next;
        continue;
      }
      const html = await response.text();
      if (response.status !== 200) {
        throw new Error(`The provider answered ${response.status} at ${url.pathname}: ${html.slice(0, 300)}`);
      }
      const form = fill(html, url);
      url = form.action;
      init = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(form.fields).toString(),
      };
    }
    throw new Error('The provider kept redirecting');
  }

  /**
   * Signs `user` in from the app's authorization URL: the provider's login
   * form, then its consent form. Returns the URL it sends the browser back to
   * the app with.
   */
  signIn(authorizeUrl: URL, user = 'ada'): Promise<URL> {
    return this.follow(authorizeUrl, (html, url) => {
      const prompt = /name="prompt" value="(\w+)"/.exec(html)?.[1];
      if (!prompt) throw new Error(`No form at ${url.pathname}: ${html.slice(0, 300)}`);
      return {
        action: url,
        fields: (prompt === 'login' ? { prompt, login: user, password: 'any' } : { prompt }) as Record<string, string>,
      };
    });
  }

  /** Logs the user out at the provider, confirming in its form. Returns where it sends the browser after. */
  signOut(logoutUrl: URL): Promise<URL> {
    return this.follow(logoutUrl, (html, url) => {
      const action = /<form[^>]*action="([^"]+)"/.exec(html)?.[1];
      const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1];
      if (!action || !xsrf) throw new Error(`No logout form at ${url.pathname}: ${html.slice(0, 300)}`);
      return { action: new URL(action, url), fields: { xsrf, logout: 'yes' } };
    });
  }
}
