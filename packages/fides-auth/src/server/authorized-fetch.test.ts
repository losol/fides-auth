/**
 * Tests for authorizedFetch against two real local servers: the API, and
 * another origin that must never see a request. Real sockets, so redirects and
 * timeouts behave as they do in production.
 */
import { getEventListeners } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import type { Tokens } from '../shared/types.js';
import {
  AuthorizedFetchError,
  type AuthorizedFetchOptions,
  authorizedFetch as fetchWithTokens,
} from './authorized-fetch.js';

interface Seen {
  path: string;
  authorization?: string;
}

const apiSeen: Seen[] = [];
const otherSeen: Seen[] = [];
const logs: unknown[] = [];

const record = (level: string) => (data?: unknown, msg?: string) => {
  logs.push({ level, data, msg });
};
const recorder: FidesLogger = {
  debug: record('debug'),
  info: record('info'),
  warn: record('warn'),
  error: record('error'),
};

/** `authorizedFetch`, logging to `logs`. */
function authorizedFetch<T = undefined>(
  tokens: Tokens | null | undefined,
  url: string | URL,
  options: AuthorizedFetchOptions<T>,
) {
  return fetchWithTokens(tokens, url, options, recorder);
}

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
    case '/v1/challenge-expired':
      res
        .writeHead(401, {
          'WWW-Authenticate':
            'Bearer realm="api", error="invalid_token", error_description="The access token expired"',
        })
        .end();
      return;
    case '/v1/challenge-scope':
      res.writeHead(403, { 'WWW-Authenticate': 'Bearer error=insufficient_scope, scope="admin"' }).end();
      return;
    case '/v1/challenge-odd':
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer error="<b>invalid token</b>"' }).end();
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

const tokens = (accessToken = 'old-token'): Tokens => ({
  accessToken,
  refreshToken: 'refresh-token',
  accessTokenExpiresAt: '2099-01-01T00:00:00.000Z',
});


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
    const result = await authorizedFetch(tokens(), `${base}/ok`, {
      allowedBase: base,
      parse: (r) => r.json(),
    });

    expect(result.data).toEqual({ hello: 'world' });
    expect(apiSeen).toEqual([{ path: '/v1/ok', authorization: 'Bearer old-token' }]);
  });

  it('resolves a relative path under the base path, with or without a trailing slash', async () => {
    await authorizedFetch(tokens(), 'users/42?page=2', { allowedBase: base });
    await authorizedFetch(tokens(), 'users/43', { allowedBase: `${base}/` });

    expect(apiSeen.map((s) => s.path)).toEqual(['/v1/users/42?page=2', '/v1/users/43']);
  });

  it('allows the base path itself', async () => {
    await authorizedFetch(tokens(), base, { allowedBase: `${base}/` });

    expect(apiSeen.map((s) => s.path)).toEqual(['/v1']);
  });

  it('allows the whole origin when allowedBase has no path', async () => {
    await authorizedFetch(tokens(), '/anything', { allowedBase: api.url });

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
    const error = await failure(authorizedFetch(tokens(), url(), { allowedBase: base }));

    expect(error.reason).toBe('url_not_allowed');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(apiSeen).toEqual([]);
    expect(otherSeen).toEqual([]);
  });

  it.each([
    '/v1/..%2f..%2fadmin',
    '/v1/..%5cadmin',
    '/v1/..;/admin',
    '/v1/%252e%252e/admin',
    '/v1/a/%2e%2e%2f%2e%2e%2fadmin',
    '/v1/%2E%2E%5Cadmin',
    // A malformed escape elsewhere doesn't hide the rest.
    '/v1/..%2f..%2fadmin%zz',
    '/v1/%zz/..%5cadmin',
    '/v1/%E0%A4%A/..%2fadmin',
    '/v1/.%3b/admin',
  ])('refuses the encoded dot segments in %s and sends nothing', async (path) => {
    const error = await failure(authorizedFetch(tokens(), `${api.url}${path}`, { allowedBase: base }));

    expect(error.reason).toBe('url_not_allowed');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(apiSeen).toEqual([]);
  });

  it.each([
    '/v1/projects/group%2Fproject',
    '/v1/files/a%20b',
    '/v1/users/..hidden',
    '/v1/a..b/c',
    '/v1/%zz',
    '/v1/a%3Bb/caf%C3%A9',
    '/v1/100%25/done',
  ])('still sends %s, path unchanged', async (path) => {
    await authorizedFetch(tokens(), `${api.url}${path}`, { allowedBase: base });

    expect(apiSeen.map((s) => s.path)).toEqual([path]);
  });

  it('throws a TypeError for an allowedBase that is relative, not http(s), or has credentials', async () => {
    for (const allowedBase of ['/v1', 'file:///etc/', `http://u:p@${new URL(api.url).host}/v1`]) {
      await expect(authorizedFetch(tokens(), 'ok', { allowedBase })).rejects.toThrow(TypeError);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('authorizedFetch — redirects', () => {
  it('refuses a redirect to another origin, so the token never reaches it', async () => {
    const error = await failure(authorizedFetch(tokens(), 'redirect-out', { allowedBase: base }));

    expect(error.reason).toBe('network_error');
    expect(fetchSpy.mock.calls[0]?.[1]?.redirect).toBe('error');
    expect(apiSeen).toHaveLength(1);
    expect(otherSeen).toEqual([]);
  });

  it('refuses a redirect inside allowedBase too', async () => {
    const error = await failure(authorizedFetch(tokens(), 'redirect-in', { allowedBase: base }));

    expect(error.reason).toBe('network_error');
    expect(apiSeen.map((s) => s.path)).toEqual(['/v1/redirect-in']);
  });
});

describe('authorizedFetch — timeout', () => {
  it('times out a request that gets no response', async () => {
    const error = await failure(
      authorizedFetch(tokens(), 'slow', { allowedBase: base, timeoutMs: 50 }),
    );

    expect(error.reason).toBe('timeout');
    expect(error.url).toBe(`${base}/slow`);
  });

  it('times out a body that stalls while parse reads it', async () => {
    const error = await failure(
      authorizedFetch(tokens(), 'stall-body', {
        allowedBase: base,
        timeoutMs: 100,
        parse: (r) => r.json(),
      }),
    );

    expect(error.reason).toBe('timeout');
  });

  it('times out a body that stalls after the garbage collector has run', async () => {
    // What a long-running server meets sooner or later: once Node's fetch has
    // lost its request object to the collector, the signal no longer reaches
    // the body. Without a timeout of its own, this read hangs every time.
    setFlagsFromString('--expose-gc');
    const collect = runInNewContext('gc') as () => void;

    const error = await failure(
      authorizedFetch(tokens(), 'stall-body', {
        allowedBase: base,
        timeoutMs: 100,
        parse: async (r) => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          collect();
          return r.json();
        },
      }),
    );

    expect(error.reason).toBe('timeout');
  });

  describe('when fetch no longer passes the abort on to the body', () => {
    // Node's fetch follows the signal through an object that can be garbage
    // collected once the response is back, and then nothing stops a body that
    // stalls. A response whose body ignores the signal stands in for that.
    const deaf = () => new Response(new ReadableStream({ start() {} }), { status: 200 });

    it('times the body read out all the same', async () => {
      fetchSpy.mockResolvedValueOnce(deaf());
      const started = Date.now();

      const error = await failure(
        authorizedFetch(tokens(), 'ok', { allowedBase: base, timeoutMs: 50, parse: (r) => r.json() }),
      );

      expect(error.reason).toBe('timeout');
      expect(Date.now() - started).toBeLessThan(1000);
    });

    it("stops for the caller's own abort, with the caller's reason", async () => {
      fetchSpy.mockResolvedValueOnce(deaf());
      const controller = new AbortController();
      const reason = new Error('navigated away');
      setTimeout(() => controller.abort(reason), 20);

      const error = await authorizedFetch(tokens(), 'ok', {
        allowedBase: base,
        signal: controller.signal,
        parse: (r) => r.text(),
      }).catch((e: unknown) => e);

      expect(error).toBe(reason);
    });

    it('leaves a parse that finishes in time alone, and stops listening', async () => {
      const controller = new AbortController();
      const result = await authorizedFetch(tokens(), 'ok', {
        allowedBase: base,
        signal: controller.signal,
        parse: (r) => r.json(),
      });

      expect(result.data).toEqual({ hello: 'world' });
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
    });
  });

  it('defaults to 10 seconds', async () => {
    const timeout = vi.spyOn(AbortSignal, 'timeout');

    await authorizedFetch(tokens(), 'ok', { allowedBase: base });

    expect(timeout).toHaveBeenCalledWith(10_000);
  });

  it("passes the caller's own abort through untouched", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 20);

    const error = await authorizedFetch(tokens(), 'slow', {
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
    const result = await authorizedFetch(tokens(), 'ok', {
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

    const error = await authorizedFetch(tokens(), 'slow', {
      allowedBase: base,
      signal: controller.signal,
    }).catch((e: unknown) => e);

    expect(error).toBe(reason);
    expect(listeners(controller.signal)).toHaveLength(0);
  });

  it('sends nothing when the signal is already aborted', async () => {
    const reason = new Error('too late');
    const signal = AbortSignal.abort(reason);

    const error = await authorizedFetch(tokens(), 'ok', { allowedBase: base, signal }).catch(
      (e: unknown) => e,
    );

    expect(error).toBe(reason);
    expect(apiSeen).toEqual([]);
    expect(listeners(signal)).toHaveLength(0);
  });

  it("times out with the timeout's reason", async () => {
    const { signal } = new AbortController();

    const error = await failure(
      authorizedFetch(tokens(), 'slow', { allowedBase: base, signal, timeoutMs: 50 }),
    );

    expect(error.reason).toBe('timeout');
    expect((error.cause as Error).name).toBe('TimeoutError');
    expect(listeners(signal)).toHaveLength(0);
  });

  it('stops listening to the signal when the request settles', async () => {
    const { signal } = new AbortController();
    const options = { allowedBase: base, signal, parse: (r: Response) => r.json() };

    await authorizedFetch(tokens(), 'ok', options);
    expect(listeners(signal)).toHaveLength(0);

    await failure(authorizedFetch(tokens(), 'redirect-in', options));
    expect(listeners(signal)).toHaveLength(0);

    const invalid = () => { throw new Error('invalid body'); };
    await failure(authorizedFetch(tokens(), 'ok', { ...options, parse: invalid }));
    expect(listeners(signal)).toHaveLength(0);

    // No body, so nothing is left to read.
    await authorizedFetch(tokens(), 'empty', { allowedBase: base, signal });
    expect(listeners(signal)).toHaveLength(0);
  });

  it('times out a body that parse hands back unread', async () => {
    const { signal } = new AbortController();

    const { data } = await authorizedFetch(tokens(), 'stall-body', {
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

    const { response } = await authorizedFetch(tokens(), 'stall-body', {
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

    const { response } = await authorizedFetch(tokens(), 'stall-body', {
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
      authorizedFetch(tokens(), 'missing?email=ada%40example.test', {
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
    const result = await authorizedFetch(tokens(), 'ok', {
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
    const result = await authorizedFetch(tokens(), 'ok', { allowedBase: base });

    expect(result.data).toBeUndefined();
    expect(result.response.status).toBe(200);
  });

  it('wraps a parse failure as parse_failed', async () => {
    const invalid = new Error('invalid body');
    const error = await failure(
      authorizedFetch(tokens(), 'ok', {
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

    const error = await failure(authorizedFetch(tokens(), `${gone.url}/x`, { allowedBase: gone.url }));

    expect(error.reason).toBe('network_error');
  });

  it('sends nothing without an access token', async () => {
    const error = await failure(authorizedFetch({}, 'ok', { allowedBase: base }));

    expect(error.reason).toBe('no_access_token');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each(['abc\r\ndef', 'abc\u0000def'])(
    'does not put an unusable token in the error: %j',
    async (accessToken) => {
      const error = await failure(authorizedFetch(tokens(accessToken), 'ok', { allowedBase: base }));

      expect(error.reason).toBe('no_access_token');
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(error.message).not.toContain('abc');
      expect(String(error.cause)).not.toContain('abc');
    },
  );
});

describe('authorizedFetch — 401', () => {
  it('is an http_error, sent once: authorizedFetch never refreshes', async () => {
    const error = await failure(authorizedFetch(tokens(), 'protected', { allowedBase: base }));

    expect(error.reason).toBe('http_error');
    expect(error.status).toBe(401);
    expect(apiSeen).toHaveLength(1);
  });
});

describe('authorizedFetch — why a request was refused', () => {
  it("passes on the API's Bearer error from WWW-Authenticate", async () => {
    const expired = await failure(authorizedFetch(tokens(), 'challenge-expired', { allowedBase: base }));
    expect(expired).toMatchObject({ status: 401, bearerError: 'invalid_token' });

    const scope = await failure(authorizedFetch(tokens(), 'challenge-scope', { allowedBase: base }));
    expect(scope).toMatchObject({ status: 403, bearerError: 'insufficient_scope' });
  });

  it('keeps only a snake_case code, and nothing without a challenge', async () => {
    const odd = await failure(authorizedFetch(tokens(), 'challenge-odd', { allowedBase: base }));
    expect(odd.bearerError).toBeUndefined();

    const plain = await failure(authorizedFetch(tokens(), 'protected', { allowedBase: base }));
    expect(plain.bearerError).toBeUndefined();
  });

  it('says whether the access token had expired by this clock', async () => {
    const at = (accessTokenExpiresAt?: string): Tokens => ({ accessToken: 'old-token', accessTokenExpiresAt });

    const expired = await failure(
      authorizedFetch(at('2000-01-01T00:00:00.000Z'), 'protected', { allowedBase: base }),
    );
    expect(expired.accessTokenExpired).toBe(true);

    const live = await failure(authorizedFetch(at('2099-01-01T00:00:00.000Z'), 'protected', { allowedBase: base }));
    expect(live.accessTokenExpired).toBe(false);

    const unknown = await failure(authorizedFetch(at(undefined), 'protected', { allowedBase: base }));
    expect(unknown.accessTokenExpired).toBeUndefined();
  });
});

describe('authorizedFetch — logging', () => {
  it('never logs a token', async () => {
    await authorizedFetch(tokens(), `${other.url}/v1/ok?x=1`, { allowedBase: base }).catch(() => undefined);
    await authorizedFetch(tokens(), 'protected', { allowedBase: base }).catch(() => undefined);
    await authorizedFetch(tokens('new-token'), 'protected', { allowedBase: base });

    const logged = inspect(logs, { depth: 10 });
    expect(logs.length).toBeGreaterThan(0);
    expect(logged).toContain('Refused to send the access token');
    expect(logged).not.toContain('old-token');
    expect(logged).not.toContain('new-token');
    expect(logged).not.toContain('refresh-token');
    expect(logged).not.toContain('x=1');
  });
});
