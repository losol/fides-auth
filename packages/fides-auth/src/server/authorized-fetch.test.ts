/**
 * Tests for authorizedFetch against two real local servers: the API, and
 * another origin that must never see a request. Real sockets, so redirects and
 * timeouts behave as they do in production.
 */
import { getEventListeners } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock only the OAuth exchange, so the tryRefreshSessionInStore test runs for real.
vi.mock('./session-refresh.js', () => ({ refreshSession: vi.fn() }));

import { configureLogger } from '../shared/logger.js';
import { refreshSession } from './session-refresh.js';
import type { Session } from '../shared/types.js';
import { AuthorizedFetchError, authorizedFetch } from './authorized-fetch.js';
import type { CookieStore } from './cookie-store.js';
import { persistSession, readSession, tryRefreshSessionInStore } from './session.js';

interface Seen {
  path: string;
  authorization?: string;
}

const apiSeen: Seen[] = [];
const otherSeen: Seen[] = [];
const logs: unknown[] = [];

let api: { server: Server; url: string };
let other: { server: Server; url: string };
let base: string;

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));
}

function apiHandler(req: IncomingMessage, res: ServerResponse): void {
  apiSeen.push({ path: req.url ?? '', authorization: req.headers.authorization });
  switch (new URL(req.url ?? '/', 'http://x').pathname) {
    case '/v1/redirect-out':
      res.writeHead(302, { Location: `${other.url}/steal` }).end();
      return;
    case '/v1/redirect-in':
      res.writeHead(302, { Location: '/v1/ok' }).end();
      return;
    case '/v1/slow':
      return; // never answers
    case '/v1/stall-body':
      res.writeHead(200, { 'Content-Type': 'application/json' }).write('{"a":');
      return;
    case '/v1/empty':
      res.writeHead(204).end();
      return;
    case '/v1/missing':
      json(res, 404, { error: 'not_found' });
      return;
    case '/v1/protected':
      if (req.headers.authorization === 'Bearer new-token') json(res, 200, { hello: 'again' });
      else json(res, 401, { error: 'invalid_token' });
      return;
    case '/v1/always-401':
      json(res, 401, { error: 'invalid_token' });
      return;
    default:
      json(res, 200, { hello: 'world' });
  }
}

async function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ server: Server; url: string }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${port}` };
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

const session = (accessToken = 'old-token'): Session => ({
  sid: 'sid-1',
  tokens: {
    accessToken,
    refreshToken: 'refresh-token',
    accessTokenExpiresAt: '2099-01-01T00:00:00.000Z',
  },
  user: { name: 'Ada', email: 'ada@example.test' },
});

const refreshed = () => ({ ok: true as const, session: session('new-token'), rotatedRefreshToken: false });

/** Awaits a rejection and returns it as an AuthorizedFetchError. */
async function failure(promise: Promise<unknown>): Promise<AuthorizedFetchError> {
  const error = await promise.then(
    () => { throw new Error('expected a rejection'); },
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(AuthorizedFetchError);
  return error as AuthorizedFetchError;
}

let fetchSpy: ReturnType<typeof vi.spyOn<typeof globalThis, 'fetch'>>;

beforeAll(async () => {
  api = await listen(apiHandler);
  other = await listen((req, res) => {
    otherSeen.push({ path: req.url ?? '', authorization: req.headers.authorization });
    json(res, 200, { stolen: true });
  });
  base = `${api.url}/v1`;

  const record = (level: string) => (data?: unknown, msg?: string) => {
    logs.push({ level, data, msg });
  };
  configureLogger({
    create: () => ({
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    }),
  });
});

afterAll(async () => {
  await Promise.all([close(api.server), close(other.server)]);
});

beforeEach(() => {
  apiSeen.length = 0;
  otherSeen.length = 0;
  logs.length = 0;
  vi.clearAllMocks();
  fetchSpy = vi.spyOn(globalThis, 'fetch');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('authorizedFetch — allowedBase', () => {
  it('sends the token to a URL under allowedBase', async () => {
    const result = await authorizedFetch(session(), `${base}/ok`, {
      allowedBase: base,
      parse: (r) => r.json(),
    });

    expect(result.data).toEqual({ hello: 'world' });
    expect(result.refreshed).toBe(false);
    expect(apiSeen).toEqual([{ path: '/v1/ok', authorization: 'Bearer old-token' }]);
  });

  it('resolves a relative path under the base path, with or without a trailing slash', async () => {
    await authorizedFetch(session(), 'users/42?page=2', { allowedBase: base });
    await authorizedFetch(session(), 'users/43', { allowedBase: `${base}/` });

    expect(apiSeen.map((s) => s.path)).toEqual(['/v1/users/42?page=2', '/v1/users/43']);
  });

  it('allows the base path itself', async () => {
    await authorizedFetch(session(), base, { allowedBase: `${base}/` });

    expect(apiSeen.map((s) => s.path)).toEqual(['/v1']);
  });

  it('allows the whole origin when allowedBase has no path', async () => {
    await authorizedFetch(session(), '/anything', { allowedBase: api.url });

    expect(apiSeen.map((s) => s.path)).toEqual(['/anything']);
  });

  it.each<[string, () => string]>([
    ['a sibling path sharing the prefix', () => `${api.url}/v1-evil/x`],
    ['an absolute path sharing the prefix', () => '/v1-evil'],
    ['an absolute path outside the base', () => '/admin'],
    ['.. out of the base', () => '../admin'],
    ['.. inside an absolute URL', () => `${api.url}/v1/../admin`],
    ['an encoded ..', () => '%2e%2e/admin'],
    ['another origin', () => `${other.url}/v1/ok`],
    ['a protocol-relative URL', () => `//${new URL(other.url).host}/v1/ok`],
    ['a backslash host', () => `\\\\${new URL(other.url).host}/v1/ok`],
    ['another scheme', () => `https://${new URL(api.url).host}/v1/ok`],
    ['another port', () => `http://127.0.0.1:1/v1/ok`],
    ['credentials in the URL', () => `http://user:pass@${new URL(api.url).host}/v1/ok`],
    ['an unparseable URL', () => 'http://[::1'],
  ])('refuses %s and sends nothing', async (_, url) => {
    const error = await failure(authorizedFetch(session(), url(), { allowedBase: base }));

    expect(error.reason).toBe('url_not_allowed');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(apiSeen).toEqual([]);
    expect(otherSeen).toEqual([]);
  });

  it('throws a TypeError for an allowedBase that is relative, not http(s), or has credentials', async () => {
    for (const allowedBase of ['/v1', 'file:///etc/', `http://u:p@${new URL(api.url).host}/v1`]) {
      await expect(authorizedFetch(session(), 'ok', { allowedBase })).rejects.toThrow(TypeError);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('authorizedFetch — redirects', () => {
  it('refuses a redirect to another origin, so the token never reaches it', async () => {
    const error = await failure(authorizedFetch(session(), 'redirect-out', { allowedBase: base }));

    expect(error.reason).toBe('network_error');
    expect(fetchSpy.mock.calls[0]?.[1]?.redirect).toBe('error');
    expect(apiSeen).toHaveLength(1);
    expect(otherSeen).toEqual([]);
  });

  it('refuses a redirect inside allowedBase too', async () => {
    const error = await failure(authorizedFetch(session(), 'redirect-in', { allowedBase: base }));

    expect(error.reason).toBe('network_error');
    expect(apiSeen.map((s) => s.path)).toEqual(['/v1/redirect-in']);
  });
});

describe('authorizedFetch — timeout', () => {
  it('times out a request that gets no response', async () => {
    const error = await failure(
      authorizedFetch(session(), 'slow', { allowedBase: base, timeoutMs: 50 }),
    );

    expect(error.reason).toBe('timeout');
    expect(error.url).toBe(`${base}/slow`);
  });

  it('times out a body that stalls while parse reads it', async () => {
    const error = await failure(
      authorizedFetch(session(), 'stall-body', {
        allowedBase: base,
        timeoutMs: 100,
        parse: (r) => r.json(),
      }),
    );

    expect(error.reason).toBe('timeout');
  });

  it('defaults to 10 seconds', async () => {
    const timeout = vi.spyOn(AbortSignal, 'timeout');

    await authorizedFetch(session(), 'ok', { allowedBase: base });

    expect(timeout).toHaveBeenCalledWith(10_000);
  });

  it("passes the caller's own abort through untouched", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 20);

    const error = await authorizedFetch(session(), 'slow', {
      allowedBase: base,
      signal: controller.signal,
    }).catch((e: unknown) => e);

    expect(error).not.toBeInstanceOf(AuthorizedFetchError);
    expect((error as Error).name).toBe('AbortError');
  });
});

describe('authorizedFetch — caller signal without AbortSignal.any', () => {
  // Node before 18.17 has no AbortSignal.any.
  const abortSignal = AbortSignal as { any?: typeof AbortSignal.any };
  const nativeAny = abortSignal.any;
  const listeners = (signal: AbortSignal) => getEventListeners(signal, 'abort');

  beforeEach(() => {
    abortSignal.any = undefined;
  });

  afterEach(() => {
    abortSignal.any = nativeAny;
  });

  it('sends the request', async () => {
    const result = await authorizedFetch(session(), 'ok', {
      allowedBase: base,
      signal: new AbortController().signal,
      parse: (r) => r.json(),
    });

    expect(AbortSignal.any).toBeUndefined();
    expect(result.data).toEqual({ hello: 'world' });
  });

  it("rejects with the caller's reason", async () => {
    const controller = new AbortController();
    const reason = new Error('navigated away');
    setTimeout(() => controller.abort(reason), 20);

    const error = await authorizedFetch(session(), 'slow', {
      allowedBase: base,
      signal: controller.signal,
    }).catch((e: unknown) => e);

    expect(error).toBe(reason);
    expect(listeners(controller.signal)).toHaveLength(0);
  });

  it('sends nothing when the signal is already aborted', async () => {
    const reason = new Error('too late');
    const signal = AbortSignal.abort(reason);

    const error = await authorizedFetch(session(), 'ok', { allowedBase: base, signal }).catch(
      (e: unknown) => e,
    );

    expect(error).toBe(reason);
    expect(apiSeen).toEqual([]);
    expect(listeners(signal)).toHaveLength(0);
  });

  it("times out with the timeout's reason", async () => {
    const { signal } = new AbortController();

    const error = await failure(
      authorizedFetch(session(), 'slow', { allowedBase: base, signal, timeoutMs: 50 }),
    );

    expect(error.reason).toBe('timeout');
    expect((error.cause as Error).name).toBe('TimeoutError');
    expect(listeners(signal)).toHaveLength(0);
  });

  it('stops listening to the signal when the request settles', async () => {
    const { signal } = new AbortController();
    const options = { allowedBase: base, signal, parse: (r: Response) => r.json() };

    await authorizedFetch(session(), 'ok', options);
    expect(listeners(signal)).toHaveLength(0);

    // Two requests: the 401 and the retry.
    await authorizedFetch(session(), 'protected', { ...options, refresh: async () => refreshed() });
    expect(listeners(signal)).toHaveLength(0);

    await failure(authorizedFetch(session(), 'redirect-in', options));
    expect(listeners(signal)).toHaveLength(0);

    const invalid = () => { throw new Error('invalid body'); };
    await failure(authorizedFetch(session(), 'ok', { ...options, parse: invalid }));
    expect(listeners(signal)).toHaveLength(0);

    // No body, so nothing is left to read.
    await authorizedFetch(session(), 'empty', { allowedBase: base, signal });
    expect(listeners(signal)).toHaveLength(0);
  });

  it('times out a body that parse hands back unread', async () => {
    const { signal } = new AbortController();

    const { data } = await authorizedFetch(session(), 'stall-body', {
      allowedBase: base,
      signal,
      timeoutMs: 100,
      parse: (r) => r.body,
    });

    await expect(new Response(data).text()).rejects.toMatchObject({ name: 'TimeoutError' });
    expect(listeners(signal)).toHaveLength(0);
  });

  it('times out a body the caller reads after the call', async () => {
    const { signal } = new AbortController();

    const { response } = await authorizedFetch(session(), 'stall-body', {
      allowedBase: base,
      signal,
      timeoutMs: 100,
    });

    await expect(response.text()).rejects.toMatchObject({ name: 'TimeoutError' });
    expect(listeners(signal)).toHaveLength(0);
  });

  it("aborts a body the caller reads after the call, with the caller's reason", async () => {
    const controller = new AbortController();
    const reason = new Error('navigated away');

    const { response } = await authorizedFetch(session(), 'stall-body', {
      allowedBase: base,
      signal: controller.signal,
    });
    const body = response.text();
    controller.abort(reason);

    await expect(body).rejects.toBe(reason);
    expect(listeners(controller.signal)).toHaveLength(0);
  });
});

describe('authorizedFetch — errors and parse', () => {
  it('turns a non-2xx into an http_error without the query or the token', async () => {
    const error = await failure(
      authorizedFetch(session(), 'missing?email=ada%40example.test', {
        allowedBase: base,
        method: 'post',
        body: '{}',
      }),
    );

    expect(error.reason).toBe('http_error');
    expect(error.status).toBe(404);
    expect(error.method).toBe('POST');
    expect(error.url).toBe(`${base}/missing`);
    expect(error.message).toBe(`authorizedFetch http_error (404) for POST ${base}/missing`);
    for (const shown of [inspect(error, { depth: 5 }), JSON.stringify(error)]) {
      expect(shown).not.toContain('old-token');
      expect(shown).not.toContain('email');
    }
    // The body stays readable for the caller.
    expect(await error.response?.json()).toEqual({ error: 'not_found' });
  });

  it('returns what parse returns', async () => {
    const result = await authorizedFetch(session(), 'ok', {
      allowedBase: base,
      parse: async (r) => {
        const body = (await r.json()) as { hello?: unknown };
        if (typeof body.hello !== 'string') throw new Error('no hello');
        return body.hello;
      },
    });

    expect(result.data).toBe('world');
  });

  it('leaves data undefined without parse', async () => {
    const result = await authorizedFetch(session(), 'ok', { allowedBase: base });

    expect(result.data).toBeUndefined();
    expect(result.response.status).toBe(200);
  });

  it('wraps a parse failure as parse_failed', async () => {
    const invalid = new Error('invalid body');
    const error = await failure(
      authorizedFetch(session(), 'ok', {
        allowedBase: base,
        parse: () => { throw invalid; },
      }),
    );

    expect(error.reason).toBe('parse_failed');
    expect(error.status).toBe(200);
    expect(error.cause).toBe(invalid);
  });

  it('reports an unreachable server as network_error', async () => {
    const gone = await listen(() => undefined);
    await close(gone.server);

    const error = await failure(authorizedFetch(session(), `${gone.url}/x`, { allowedBase: gone.url }));

    expect(error.reason).toBe('network_error');
  });

  it('sends nothing for a session without an access token', async () => {
    const error = await failure(authorizedFetch({ sid: 'sid-1' }, 'ok', { allowedBase: base }));

    expect(error.reason).toBe('no_access_token');
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('authorizedFetch — refresh on 401', () => {
  it('refreshes once and retries with the new token', async () => {
    const refresh = vi.fn(async () => refreshed());

    const result = await authorizedFetch(session(), 'protected', {
      allowedBase: base,
      refresh,
      parse: (r) => r.json(),
    });

    expect(result.data).toEqual({ hello: 'again' });
    expect(result.refreshed).toBe(true);
    expect(result.session.tokens?.accessToken).toBe('new-token');
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(apiSeen.map((s) => s.authorization)).toEqual(['Bearer old-token', 'Bearer new-token']);
  });

  it('accepts a session from refreshSessionInStore', async () => {
    const result = await authorizedFetch(session(), 'protected', {
      allowedBase: base,
      refresh: async () => session('new-token'),
    });

    expect(result.refreshed).toBe(true);
    expect(apiSeen).toHaveLength(2);
  });

  it('does not retry when the refresh fails, and says why', async () => {
    const error = await failure(
      authorizedFetch(session(), 'protected', {
        allowedBase: base,
        refresh: async () => ({
          ok: false,
          reason: 'refresh_failed',
          cause: 'invalid_grant',
          sid: 'sid-1',
        }),
      }),
    );

    expect(error.reason).toBe('refresh_failed');
    expect(error.status).toBe(401);
    expect(error.refreshFailure).toEqual({ reason: 'refresh_failed', cause: 'invalid_grant' });
    expect(apiSeen).toHaveLength(1);
  });

  it('does not retry when refreshSessionInStore returns null or the refresh throws', async () => {
    const boom = new Error('store down');
    for (const refresh of [async () => null, async () => { throw boom; }]) {
      const error = await failure(
        authorizedFetch(session(), 'protected', { allowedBase: base, refresh }),
      );
      expect(error.reason).toBe('refresh_failed');
    }

    expect(apiSeen).toHaveLength(2); // one per call, no retries
  });

  it('refreshes only once: a second 401 is an http_error', async () => {
    const refresh = vi.fn(async () => refreshed());

    const error = await failure(
      authorizedFetch(session(), 'always-401', { allowedBase: base, refresh }),
    );

    expect(error.reason).toBe('http_error');
    expect(error.status).toBe(401);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(apiSeen).toHaveLength(2);
  });

  it('treats a 401 as an http_error without refresh', async () => {
    const error = await failure(authorizedFetch(session(), 'protected', { allowedBase: base }));

    expect(error.reason).toBe('http_error');
    expect(apiSeen).toHaveLength(1);
  });

  it('works with tryRefreshSessionInStore, which persists the new session', async () => {
    const secret = 'a'.repeat(64);
    const jar = new Map<string, string>();
    const store: CookieStore = {
      get: (name) => jar.get(name) ?? null,
      set: (name, value) => { jar.set(name, value); },
      delete: (name) => { jar.delete(name); },
    };
    const oauthConfig = {
      issuer: 'https://idp.test',
      clientId: 'c',
      clientSecret: 's',
      redirect_uri: 'https://app.test/cb',
      scope: 'openid',
    };
    await persistSession(store, session(), secret);
    vi.mocked(refreshSession).mockResolvedValue(session('new-token'));

    const result = await authorizedFetch(session(), 'protected', {
      allowedBase: base,
      refresh: () => tryRefreshSessionInStore(store, oauthConfig, secret),
    });

    expect(result.session.tokens?.accessToken).toBe('new-token');
    expect((await readSession(store, secret))?.tokens?.accessToken).toBe('new-token');
  });
});

describe('authorizedFetch — logging', () => {
  it('never logs a token', async () => {
    await authorizedFetch(session(), `${other.url}/v1/ok?x=1`, { allowedBase: base }).catch(() => undefined);
    await authorizedFetch(session(), 'protected', { allowedBase: base, refresh: async () => refreshed() });
    await authorizedFetch(session(), 'always-401', { allowedBase: base, refresh: async () => null }).catch(() => undefined);

    const logged = inspect(logs, { depth: 10 });
    expect(logs.length).toBeGreaterThan(0);
    expect(logged).toContain('Refused to send the access token');
    expect(logged).not.toContain('old-token');
    expect(logged).not.toContain('new-token');
    expect(logged).not.toContain('refresh-token');
    expect(logged).not.toContain('x=1');
  });
});
