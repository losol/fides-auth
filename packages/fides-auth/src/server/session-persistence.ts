// server/session-persistence.ts
//
// Where a session lives between requests. Cookie persistence — the default —
// encrypts it into the three split cookies. Server persistence keeps it in a
// SessionStore and gives the browser only an opaque handle: for providers whose
// tokens don't fit a cookie, and for the revocation and refresh serialization
// a cookie cannot offer. `session.ts` is written against this contract and owns
// the lifecycle events and the refresh flow.

import {
  ACCESS_TOKEN_COOKIE_NAME,
  COOKIE_INFO_BYTES,
  ID_TOKEN_COOKIE_NAME,
  SESSION_COOKIE_NAME,
  SESSION_REF_COOKIE_NAME,
  assertCookieWithinLimit,
  defaultSessionCookieOptions,
} from '../cookies';
import { createLogger } from '../logger';
import {
  decodeIdTokenCookie,
  encodeSessionCookies,
  tryDecodeSessionCookies,
} from '../session-cookies';
import type { SessionPersistenceMode, SessionRejectedReason } from '../session-events';
import { isSession } from '../session-validation';
import type { Session } from '../types';
import { createEncryptedJWT, decryptJWT, generateToken, sha256 } from '../utils';
import type { CookieStore } from './cookie-store';
import type { SessionStore } from './session-store';

const logger = createLogger({ namespace: 'fides-auth:server:session-persistence' });

/** A session encryption key: 32 bytes for A256GCM, as hex or raw bytes. */
export type SessionSecret = string | Uint8Array;

/** Outcome of reading the session: a session, or why there isn't one. */
export type ReadSessionResult =
  | { session: Session; reason?: undefined }
  | { session: null; reason: SessionRejectedReason };

export interface WriteSessionOptions {
  /**
   * True when the write continues the session the request arrived with (a
   * refresh). Otherwise the write starts a new session — under server
   * persistence that mints a new handle, which is what defeats session
   * fixation on login.
   */
  continuation?: boolean;
}

export interface WriteSessionResult {
  /** The value now in the main session cookie: the encrypted session, or the handle. */
  cookieValue: string;
  /** Bytes written across the session cookies. Absent when the session is not in cookies. */
  cookieBytes?: number;
}

/**
 * The persistence contract `session.ts` works against. Get one from
 * {@link cookiePersistence} or {@link serverPersistence}; the methods are the
 * library's own seam, not an extension point.
 */
export interface SessionPersistence {
  readonly mode: SessionPersistenceMode;
  write(
    cookies: CookieStore,
    session: Session,
    options?: WriteSessionOptions,
  ): Promise<WriteSessionResult>;
  read(cookies: CookieStore): Promise<ReadSessionResult>;
  /** The raw ID token whether or not the session is usable — logout needs it most when it isn't. */
  readIdToken(cookies: CookieStore): Promise<string | undefined>;
  clear(cookies: CookieStore): Promise<void>;
  /**
   * Runs `fn` with other refreshes of the same session held off. Concurrent
   * callers in this process share one result; across instances the store's
   * `withLock` serializes them. Present only where requests share state
   * server-side — in cookie mode every request holds its own copy and there
   * is nothing to coordinate.
   */
  exclusive?<T>(cookies: CookieStore, fn: () => Promise<T>): Promise<T>;
}

/** Accepts the pre-0.15 bare secret wherever a persistence is expected. */
export function resolvePersistence(value: SessionSecret | SessionPersistence): SessionPersistence {
  return typeof value === 'string' || value instanceof Uint8Array
    ? cookiePersistence(value)
    : value;
}

const SPLIT_COOKIE_NAMES = [SESSION_COOKIE_NAME, ACCESS_TOKEN_COOKIE_NAME, ID_TOKEN_COOKIE_NAME];

/** Deletes the `session`, `session_at` and `session_it` cookies. */
export async function clearSessionCookies(cookies: CookieStore): Promise<void> {
  for (const name of SPLIT_COOKIE_NAMES) {
    await cookies.delete(name);
  }
}

/** Applies the browser size guard to one cookie value; logs as it nears the limit. */
function checkSize(name: string, value: string): number {
  // Fail loudly above the browser per-cookie limit (the browser would otherwise
  // drop the cookie silently, producing a broken login).
  const size = assertCookieWithinLimit(name, value);
  if (size >= COOKIE_INFO_BYTES) {
    logger.info({ cookieName: name, size }, 'Cookie approaching browser size limit');
  }
  return size;
}

/**
 * The default: the session encrypted into the `session`, `session_at` and
 * `session_it` cookies.
 */
export function cookiePersistence(secret: SessionSecret): SessionPersistence {
  return {
    mode: 'cookie',

    async write(cookies, session) {
      const encoded = await encodeSessionCookies(session, secret);
      const values: Array<[string, string | undefined]> = [
        [SESSION_COOKIE_NAME, encoded.session],
        [ACCESS_TOKEN_COOKIE_NAME, encoded.accessToken],
        [ID_TOKEN_COOKIE_NAME, encoded.idToken],
      ];

      // Size-check everything before touching the store. Throwing part-way
      // through would leave one user's session cookie next to another user's
      // tokens — the caller sees an error while the browser holds a working,
      // mixed-up session.
      let cookieBytes = 0;
      for (const [name, value] of values) {
        if (value) cookieBytes += checkSize(name, value);
      }

      for (const [name, value] of values) {
        if (value) {
          await cookies.set(name, value, defaultSessionCookieOptions);
        } else {
          await cookies.delete(name);
        }
      }

      return { cookieValue: encoded.session, cookieBytes };
    },

    async read(cookies) {
      return tryDecodeSessionCookies(
        {
          session: (await cookies.get(SESSION_COOKIE_NAME)) ?? null,
          accessToken: (await cookies.get(ACCESS_TOKEN_COOKIE_NAME)) ?? null,
          idToken: (await cookies.get(ID_TOKEN_COOKIE_NAME)) ?? null,
        },
        secret,
      );
    },

    async readIdToken(cookies) {
      const raw = await cookies.get(ID_TOKEN_COOKIE_NAME);
      return raw ? decodeIdTokenCookie(raw, secret) : undefined;
    },

    clear: clearSessionCookies,
  };
}

export interface ServerPersistenceOptions {
  /** Where sessions live. See {@link SessionStore}. */
  store: SessionStore;
  /** Encrypts each record at rest, so a store dump alone yields no tokens. */
  secret: SessionSecret;
  /**
   * Name of the cookie carrying the handle.
   * @default 'session_ref'
   */
  cookieName?: string;
  /**
   * Absolute session lifetime: the record and the handle cookie expire this
   * long after login, refreshes notwithstanding.
   * @default 30
   */
  sessionDurationDays?: number;
}

/**
 * The session in a {@link SessionStore}; the browser holds only a random
 * 256-bit handle. The store is keyed by `SHA-256(handle)`, so neither a store
 * dump nor a logged key can be replayed as a cookie, and the record is
 * encrypted under `secret`, so a dump alone yields no tokens.
 */
export function serverPersistence(options: ServerPersistenceOptions): SessionPersistence {
  const {
    store,
    secret,
    cookieName = SESSION_REF_COOKIE_NAME,
    sessionDurationDays = 30,
  } = options;
  const maxAge = sessionDurationDays * 24 * 60 * 60;
  const inflight = new Map<string, Promise<unknown>>();

  /** The handle the request carries and the store key it maps to. */
  async function locate(cookies: CookieStore): Promise<{ handle: string; key: string } | null> {
    const handle = await cookies.get(cookieName);
    return handle ? { handle, key: await sha256(handle) } : null;
  }

  /** Drops split cookies left behind by cookie persistence, when there are any. */
  async function clearSplitCookies(cookies: CookieStore): Promise<void> {
    for (const name of SPLIT_COOKIE_NAMES) {
      if (await cookies.get(name)) await cookies.delete(name);
    }
  }

  async function readRecord(key: string): Promise<ReadSessionResult> {
    const record = await store.get(key);
    if (!record) {
      return { session: null, reason: 'session_not_found' };
    }
    // The adapter's TTL is a convenience; the expiry is enforced here.
    if (!(Date.parse(record.expiresAt) > Date.now())) {
      await store.delete(key);
      return { session: null, reason: 'session_not_found' };
    }

    let payload: unknown;
    try {
      payload = await decryptJWT(record.data, secret);
    } catch (error) {
      logger.warn({ error, sid: record.sid }, 'Stored session would not decrypt');
      return { session: null, reason: 'unreadable_session' };
    }
    if (!isSession(payload)) {
      logger.warn({ sid: record.sid }, 'Stored session has the wrong shape');
      return { session: null, reason: 'unreadable_session' };
    }
    return { session: payload };
  }

  return {
    mode: 'server',

    async write(cookies, session, { continuation = false } = {}) {
      const current = await locate(cookies);
      await clearSplitCookies(cookies);
      const data = await createEncryptedJWT(session, secret);

      if (continuation && current) {
        const existing = await store.get(current.key);
        if (existing) {
          // Same handle, same absolute expiry: a refresh extends nothing.
          await store.set(current.key, { data, expiresAt: existing.expiresAt, sid: session.sid });
        } else {
          // Cleared while the refresh was in flight. The logout wins.
          logger.info({ sid: session.sid }, 'Session ended during refresh; not persisted');
        }
        return { cookieValue: current.handle };
      }

      // A new session gets a new handle, so a handle planted before login
      // (session fixation) never becomes a logged-in one.
      if (current) {
        await store.delete(current.key);
      }
      const handle = generateToken(32);
      const key = await sha256(handle);
      const expiresAt = new Date(Date.now() + maxAge * 1000).toISOString();
      await store.set(key, { data, expiresAt, sid: session.sid });
      await cookies.set(cookieName, handle, { ...defaultSessionCookieOptions, maxAge });
      return { cookieValue: handle };
    },

    async read(cookies) {
      const current = await locate(cookies);
      if (!current) {
        // Split cookies but no handle: a consumer that just switched modes.
        // One re-login, not corruption.
        const legacy = await cookies.get(SESSION_COOKIE_NAME);
        return { session: null, reason: legacy ? 'stale_legacy_session' : 'no_session_cookie' };
      }
      return readRecord(current.key);
    },

    async readIdToken(cookies) {
      const current = await locate(cookies);
      if (!current) return undefined;
      return (await readRecord(current.key)).session?.tokens?.idToken;
    },

    async clear(cookies) {
      // Record first: once it is gone a copied cookie is dead, whatever
      // happens to the cookie itself.
      const current = await locate(cookies);
      if (current) {
        await store.delete(current.key);
        await cookies.delete(cookieName);
      }
      await clearSplitCookies(cookies);
    },

    async exclusive<T>(cookies: CookieStore, fn: () => Promise<T>): Promise<T> {
      const current = await locate(cookies);
      if (!current) return fn();

      const running = inflight.get(current.key);
      if (running) return running as Promise<T>;

      const run = (store.withLock ? store.withLock(current.key, fn) : fn()).finally(() => {
        inflight.delete(current.key);
      });
      inflight.set(current.key, run);
      return run;
    },
  };
}
