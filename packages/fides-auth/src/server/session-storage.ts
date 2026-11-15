// Where a sealed session is kept between requests. A storage moves the sealed
// string and the few plain fields a store needs. It never sees a session, so
// it can't apply a rule differently from the other storage: the rules are in
// session-lifecycle.ts.
//
// Both storages use one cookie name: `__Host-session` when Secure, `session`
// otherwise. Cookie storage cuts the sealed string into up to three chunks;
// store storage keeps it in a SessionStore and puts a random handle in the
// cookie. Every write also deletes the cookies of the older session format
// (LEGACY_COOKIE_NAMES): a browser carrying both could send a Cookie header
// larger than proxies accept.

import {
  COOKIE_MAX_BYTES,
  type CookieOptions,
  CookieTooLargeError,
  cookieByteSize,
} from '../shared/cookies.js';
import type { SessionPersistenceMode } from '../shared/session-events.js';
import { generateToken, sha256 } from '../session/utils.js';
import type { CookieStore } from './cookie-store.js';
import type { SessionMatch, SessionStore, StoredSession, StoreFields } from './session-store.js';

/** Cookie storage cuts a sealed record into at most this many cookies. */
export const MAX_CHUNKS = 3;

/**
 * The cookies of the older session format, which split a session by meaning.
 * Nothing reads them, and every write deletes them. They were always set
 * Secure with `Path=/`, and a deletion must match both to take effect.
 */
export const LEGACY_COOKIE_NAMES = ['session', 'session_at', 'session_it', 'session_ref'] as const;

const LEGACY_DELETE: CookieOptions = {
  path: '/',
  httpOnly: true,
  sameSite: 'lax',
  secure: true,
  maxAge: 0,
};

/** The session cookie's name: `__Host-session` when Secure, `session` otherwise. */
export function sessionCookieName(secure: boolean): string {
  return secure ? '__Host-session' : 'session';
}

/** Cookie names for chunk 0, 1 and 2. */
function chunkNames(secure: boolean): [string, ...string[]] {
  const base = sessionCookieName(secure);
  return [base, ...Array.from({ length: MAX_CHUNKS - 1 }, (_, i) => `${base}.${i + 1}`)];
}

/** Why a storage has no session to hand back. The lifecycle adds the reasons a record gives. */
export type StorageRejectedReason = 'no_session_cookie' | 'session_not_found' | 'unreadable_session';

export type LoadResult =
  | { sealed: string; reason?: undefined }
  | { sealed: null; reason: StorageRejectedReason };

/** The lookup fields a store keeps for back-channel logout. Hashes, never `sub` itself. */
export interface LookupFields {
  iss?: string;
  subHash?: string;
  idpSidHash?: string;
}

export interface SaveRequest {
  sealed: string;
  /** ISO 8601. Cookies get the time left as `Max-Age`; a store keeps it on the record. */
  expiresAt: string;
  correlationId: string;
  lookup?: LookupFields;
  /** What the app's `storeFields` returned, kept in the clear next to the record. Store storage only. */
  fields?: StoreFields;
  /**
   * True for a refresh or an update, which keep the session's identity. False
   * starts a new session: store storage mints a new handle.
   */
  continuation: boolean;
}

/** A session found by its lookup fields, without its cookie. */
export interface FoundSession {
  /** The sealed record as the search saw it. */
  sealed: string;
  correlationId?: string;
  /**
   * Deletes the record, under the store's lock when it has one, and returns
   * the sealed record as it was just before: a refresh on any instance either
   * saved first or finds the record gone. Null when it was already gone.
   */
  remove(): Promise<string | null>;
}

export interface SaveResult {
  /** False when a continuation found the session already ended. Nothing was written. */
  saved: boolean;
  /** Bytes written across the session cookies, under cookie storage. */
  cookieBytes?: number;
}

/** The seam between the lifecycle and where a session is kept. Internal. */
export interface SessionStorage {
  readonly mode: SessionPersistenceMode;
  load(cookies: CookieStore): Promise<LoadResult>;
  save(cookies: CookieStore, request: SaveRequest): Promise<SaveResult>;
  remove(cookies: CookieStore): Promise<void>;
  /** Runs `fn` holding the store's lock on this session. Only store storage has one. */
  lock?<T>(cookies: CookieStore, fn: () => Promise<T>): Promise<T>;
  /**
   * True when `lock` keeps every instance out, so what is read under it is the
   * last word. Only store storage over a store with `withLock`.
   */
  readonly exclusive?: boolean;
  /**
   * Deletes the record and leaves the cookie, which then finds no session.
   * For where cookies can't be written. Only store storage.
   */
  discard?(cookies: CookieStore): Promise<void>;
  /** The sessions that match. Only store storage, and only over a store that can search. */
  findMatching?(match: SessionMatch): Promise<FoundSession[]>;
}

/** The longest value a cookie called `name` can hold: `name=value` must stay below the limit. */
function roomFor(name: string): number {
  return COOKIE_MAX_BYTES - 2 - name.length;
}

function cookieOptions(secure: boolean, maxAge: number): CookieOptions {
  return { path: '/', httpOnly: true, sameSite: 'lax', secure, maxAge };
}

/** Seconds from now until `expiresAt`, never negative. */
function secondsLeft(expiresAt: string): number {
  return Math.max(0, Math.floor((Date.parse(expiresAt) - Date.now()) / 1000));
}

/** Deletes each of `names` the request carries, setting it empty with `maxAge: 0`. */
async function deletePresent(
  cookies: CookieStore,
  names: readonly string[],
  options: CookieOptions,
): Promise<void> {
  for (const name of names) {
    if (await cookies.get(name)) await cookies.set(name, '', { ...options, maxAge: 0 });
  }
}

/**
 * Deletes the legacy cookies the request carries. Under plain http the session
 * cookie is called `session` too, so that one is left for the new value to
 * overwrite.
 */
function deleteLegacy(cookies: CookieStore, secure: boolean): Promise<void> {
  const names = secure ? LEGACY_COOKIE_NAMES : LEGACY_COOKIE_NAMES.filter((n) => n !== 'session');
  return deletePresent(cookies, names, LEGACY_DELETE);
}

/** Options for {@link cookieStorage} and {@link storeStorage}. */
export interface StorageOptions {
  /** Secure cookies with the `__Host-` prefix. False only when the redirect URI is plain http. */
  secure: boolean;
}

/** Keeps the sealed record in the browser, cut into at most {@link MAX_CHUNKS} cookies. */
export function cookieStorage({ secure }: StorageOptions): SessionStorage {
  const names = chunkNames(secure);

  return {
    mode: 'cookie',

    async load(cookies) {
      const first = await cookies.get(names[0]);
      if (!first) return { sealed: null, reason: 'no_session_cookie' };
      let sealed = first;
      for (const name of names.slice(1)) {
        const next = await cookies.get(name);
        if (!next) break;
        sealed += next;
      }
      return { sealed };
    },

    async save(cookies, { sealed, expiresAt }) {
      // Cut and measure everything before writing anything, so a session that
      // doesn't fit leaves the browser's cookies as they were.
      const chunks: string[] = [];
      let rest = sealed;
      for (const name of names) {
        if (rest.length === 0) break;
        chunks.push(rest.slice(0, roomFor(name)));
        rest = rest.slice(roomFor(name));
      }
      if (rest.length > 0) {
        const capacity = names.reduce((sum, name) => sum + roomFor(name), 0);
        throw new CookieTooLargeError(names[0], sealed.length, capacity);
      }

      const options = cookieOptions(secure, secondsLeft(expiresAt));
      let cookieBytes = 0;
      for (const [i, name] of names.entries()) {
        const chunk = chunks[i];
        if (chunk === undefined) break;
        cookieBytes += cookieByteSize(name, chunk);
        await cookies.set(name, chunk, options);
      }
      await deletePresent(cookies, names.slice(chunks.length), options);
      await deleteLegacy(cookies, secure);
      return { saved: true, cookieBytes };
    },

    async remove(cookies) {
      await deletePresent(cookies, names, cookieOptions(secure, 0));
      await deleteLegacy(cookies, secure);
    },
  };
}

/** A handle is 32 random bytes in hex. Anything else is another storage's cookie. */
const HANDLE = /^[0-9a-f]{64}$/;

/**
 * Keeps the sealed record in a {@link SessionStore}, keyed by the SHA-256 of a
 * random handle that only the browser holds. A store dump or a logged key
 * can't be replayed as a cookie.
 */
export function storeStorage({ store, secure }: StorageOptions & { store: SessionStore }): SessionStorage {
  const name = sessionCookieName(secure);
  // Chunks left by cookie storage, when an app moves to a store.
  const otherChunks = chunkNames(secure).slice(1);

  /** The handle and its store key, null without a cookie, or 'invalid' for another storage's value. */
  async function locate(cookies: CookieStore): Promise<{ handle: string; key: string } | null | 'invalid'> {
    const handle = await cookies.get(name);
    if (!handle) return null;
    if (!HANDLE.test(handle)) return 'invalid';
    return { handle, key: await sha256(handle) };
  }

  function record({ sealed, expiresAt, correlationId, lookup, fields }: SaveRequest): StoredSession {
    return { data: sealed, expiresAt, correlationId, ...lookup, ...(fields && { fields }) };
  }

  const storage: SessionStorage = {
    mode: 'server',
    exclusive: !!store.withLock,

    async load(cookies) {
      const current = await locate(cookies);
      if (current === null) return { sealed: null, reason: 'no_session_cookie' };
      if (current === 'invalid') return { sealed: null, reason: 'unreadable_session' };
      const stored = await store.get(current.key);
      return stored ? { sealed: stored.data } : { sealed: null, reason: 'session_not_found' };
    },

    async save(cookies, request) {
      const current = await locate(cookies);

      if (request.continuation) {
        // A refresh or an update keeps the handle. If the record is gone, the
        // session ended while this ran, and the end wins.
        if (current === null || current === 'invalid' || !(await store.get(current.key))) {
          return { saved: false };
        }
        await store.set(current.key, record(request), { continuation: true });
        await deleteLegacy(cookies, secure);
        return { saved: true };
      }

      // A new session gets a new handle, so a handle planted before login
      // (session fixation) never becomes a logged-in one.
      if (current && current !== 'invalid') await store.delete(current.key);
      const handle = generateToken(32);
      await store.set(await sha256(handle), record(request), { continuation: false });
      const options = cookieOptions(secure, secondsLeft(request.expiresAt));
      await cookies.set(name, handle, options);
      await deletePresent(cookies, otherChunks, options);
      await deleteLegacy(cookies, secure);
      return { saved: true };
    },

    async remove(cookies) {
      // The record first: once it is gone, a copied cookie is dead.
      const current = await locate(cookies);
      if (current && current !== 'invalid') await store.delete(current.key);
      await deletePresent(cookies, [name, ...otherChunks], cookieOptions(secure, 0));
      await deleteLegacy(cookies, secure);
    },

    async lock(cookies, fn) {
      const current = await locate(cookies);
      if (!current || current === 'invalid' || !store.withLock) return fn();
      return store.withLock(current.key, fn);
    },

    async discard(cookies) {
      const current = await locate(cookies);
      if (current && current !== 'invalid') await store.delete(current.key);
    },
  };

  if (store.findMatching) {
    storage.findMatching = async (match) => {
      const entries = (await store.findMatching?.(match)) ?? [];
      return entries.map(({ key, record: found }) => ({
        sealed: found.data,
        correlationId: found.correlationId,
        async remove() {
          const take = async () => {
            const latest = await store.get(key);
            await store.delete(key);
            return latest?.data ?? null;
          };
          return store.withLock ? store.withLock(key, take) : take();
        },
      }));
    };
  }
  return storage;
}
