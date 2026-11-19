// The session lifecycle: create, read, refresh, update and end, written once
// over a SessionStorage. These rules hold in both storages:
//
// 1. A login never continues the session the browser arrived with.
// 2. `expiresAt` is fixed at creation and checked on every read.
// 3. A refresh or an update changes the contents, never the identity or the lifetime.
// 4. A session is read whole or not at all.
// 5. Concurrent refreshes of one session in one process share one provider call.
//    Under cookie storage, so does a refresh that comes just after, from a
//    request that still carries the cookie from before.
// 8. A refresh and an update of one session take turns, in this process and
//    under a store's lock, and each starts from what the other saved. Saved
//    from an older read, an update would put a spent refresh token back.
// 6. A rejected reason means the same thing in both storages.
// 7. A refresh the provider refuses for good ends the session where that is
//    certain: under a store's lock. Elsewhere another instance may have
//    refreshed with the same token, so the session is left for the app to end.
//    Every request whose refresh learns that the stored session is over has
//    its cookie deleted: the one that ended it, those that shared its call to
//    the provider, and those that waited for the lock and found the record gone.
//
// One difference can't be hidden: a store drops an expired record with its TTL,
// after which store storage answers `session_not_found` where cookie storage
// answers `session_expired`. Both mean the session is over.

import type { FidesLogger } from '../shared/logger.js';
import { classifyRefreshFailure, getOAuthErrorLogContext } from '../protocol/logging.js';
import {
  SESSION_EVENT,
  logSessionEvent,
  type RefreshFailureCause,
  type SessionClearedTrigger,
  type SessionEvent,
  type SessionRejectedReason,
} from '../shared/session-events.js';
import type { DpopKey, Session, TokenResponse, Tokens } from '../shared/types.js';
import { hexToUint8Array } from '../session/utils.js';
import {
  checkSessionDuration,
  claimsOf,
  createRecord,
  isExpired,
  isSameSubject,
  keepIdentity,
  type MapRecordSession,
  type OpenedRecord,
  openSealed,
  presentationOfRecord,
  refreshRecord,
  sealRecord,
  type SessionRecord,
} from '../session/record.js';
import type { RolesClaim } from '../session/user-claims.js';
import type { CookieStore } from './cookie-store.js';
import {
  assertSessionSecret,
  deriveKey,
  hasRepeatedSecret,
  secretsOf,
  type SessionSecret,
  type SessionSecrets,
} from './session-secret.js';
import type { FoundSession, LookupFields, SaveResult, SessionStorage } from './session-storage.js';
import type { SessionMatch, StoreFields, StoreSetReason } from './session-store.js';

export type ReadRecordResult =
  | { record: SessionRecord; reason?: undefined }
  | { record: null; reason: SessionRejectedReason };

export type RefreshRecordResult =
  | {
    ok: true;
    record: SessionRecord;
    rotatedRefreshToken: boolean;
    /** Set when `unless` said the session needs no refresh. The provider wasn't asked. */
    skipped?: true;
  }
  | {
    ok: false;
    reason: SessionRejectedReason;
    /** Set only when the provider was asked, that is when `reason` is `refresh_failed`. */
    cause?: RefreshFailureCause;
    correlationId?: string;
    /**
     * The stored session is over for good: this refresh ended it, or read it
     * and then found it gone. Every request that gets this result has its
     * session cookie deleted, where cookies can be written.
     */
    ended?: true;
  };

/**
 * A stored session was ended, but its cookie couldn't be deleted: `end` was
 * called where cookies can't be written. The record is gone, so the handle
 * the browser keeps finds nothing. `ended` is what `end` would have returned,
 * and `cause` is what the cookie store threw.
 */
export class SessionCookieLeftError extends Error {
  override name = 'SessionCookieLeftError';

  constructor(
    readonly ended: SessionRecord | undefined,
    cause: unknown,
  ) {
    super('The session is ended, but its cookie could not be deleted', { cause });
  }
}

export interface SessionLifecycleOptions {
  storage: SessionStorage;
  /**
   * The keys that seal records, and the ones for the store's lookup hashes,
   * are derived from it. Of several, the first seals and all of them open.
   */
  secret: SessionSecrets;
  /**
   * Who the sessions are for, e.g. the provider and the client. It is part of
   * the key a record is sealed with, so an instance with another audience and
   * the same secret can't read them.
   * @default ''
   */
  audience?: string;
  /** @default 43200, which is 12 hours */
  sessionDurationSeconds?: number;
  /** Where the roles are in the ID token. False leaves them to `mapSession`. @default 'roles' */
  rolesClaim?: RolesClaim | false;
  mapSession?: MapRecordSession;
  /**
   * Changes the session a refresh leaves, the way `mapSession` does at login:
   * to follow claims the app keeps in `data`, say. It gets the refresh's token
   * response, the claims of its ID token, undefined without one, and the
   * session after the library's own changes. The identity and lifetime are
   * kept whatever it returns. A throw is logged and the session saved as the
   * refresh left it: the provider has spent the old refresh token by then, so
   * the refresh can no longer fail.
   */
  mapRefresh?: MapRecordSession;
  /** Plain fields to keep next to a stored session. Store storage only. */
  storeFields?(session: Session): StoreFields;
  /**
   * Cookie storage only. For this many seconds after a refresh that rotated
   * the refresh token, a request that still carries the cookie from before
   * gets that refresh's result instead of spending the old token again. 0
   * turns it off.
   * @default 10
   */
  refreshGraceSeconds?: number;
  /**
   * Store storage only. How long to wait before each new try at saving what a
   * refresh got, in milliseconds. The provider has spent the old refresh token
   * by then, so tokens that aren't saved are lost.
   * @default [200, 1000]
   */
  saveRetryDelaysMs?: readonly number[];
  /** Runs the refresh token grant, e.g. `oidc.refresh`. */
  refreshTokens(refreshToken: string, tokens: Tokens): Promise<TokenResponse>;
  logger: FidesLogger;
  /** Gets every lifecycle event, next to the logger. */
  onSessionEvent?(event: SessionEvent): void;
}

export interface SessionLifecycle {
  /** The session, or why there is none. Writes nothing. */
  read(cookies: CookieStore): Promise<ReadRecordResult>;
  /**
   * Starts a new session from a token response, discarding whatever the browser
   * held. `requestedScope` is the scope the login asked for: the session's
   * scopes when the response names none. `dpopKey` is the key the tokens were
   * bound to with DPoP, kept with them.
   */
  create(
    cookies: CookieStore,
    tokens: TokenResponse,
    options?: { requestedScope?: string; dpopKey?: DpopKey },
  ): Promise<SessionRecord>;
  /**
   * Refreshes the tokens, keeping the session's identity and lifetime. With
   * `unless`, a session it returns true for is handed back as it is.
   *
   * A store that fails, on any read or write a refresh makes, is reported as
   * `cause: 'store'`: that says nothing about the session, so it is a failure
   * to retry, not a throw.
   */
  refresh(
    cookies: CookieStore,
    options?: { unless?: (record: SessionRecord) => boolean },
  ): Promise<RefreshRecordResult>;
  /**
   * Changes the user, scopes or data. Null when there is no session to change.
   * It takes its turn after a refresh or an update of the session that is
   * running, under the store's lock where there is one, and `update` gets the
   * session as it is then. So `update` must not refresh, update or end the
   * same session: that call would wait for this one. Where the runtime can
   * tell, it rejects with a TypeError at once.
   *
   * Unlike a refresh, which reports a store that fails as `cause: 'store'`, an
   * update rejects with what the store threw: nothing was changed, and that is
   * for the caller to know.
   */
  update(
    cookies: CookieStore,
    update: (session: Session) => Session | Promise<Session>,
  ): Promise<SessionRecord | null>;
  /**
   * Ends the session. Under store storage, the record is deleted under the
   * store's lock. A refresh of the session still running in this process is
   * waited for first.
   *
   * @returns The record ended, with the tokens it held last, so they can be revoked.
   * @throws SessionCookieLeftError when a stored session's record is deleted
   * and its cookie can't be: the session is over, and the error carries the
   * record. Under cookie storage, what the cookie store threw: nothing is ended.
   */
  end(
    cookies: CookieStore,
    options?: { trigger?: SessionClearedTrigger },
  ): Promise<SessionRecord | undefined>;
  /**
   * Ends every stored session of one IdP user or IdP session, without their
   * cookies. Like {@link end}, it waits for a refresh still running in this
   * process and deletes under the store's lock. With `iss`, only sessions
   * whose ID token had exactly that issuer.
   *
   * @returns The records ended, with the tokens they held last, so they can be revoked.
   * @throws TypeError without `sub` or `sid`, or when the storage can't search.
   */
  endMatching(
    match: { iss?: string; sub?: string; sid?: string },
    options?: { trigger?: SessionClearedTrigger },
  ): Promise<SessionRecord[]>;
}

/** A call the app's own function is running inside: an update, or a `mapRefresh`. */
interface Inside {
  what: 'updateSession' | 'mapRefresh';
  /** False once the function has returned: what it left running is no longer inside it. */
  active: boolean;
}

/** The part of Node's `AsyncLocalStorage` that is used here. */
interface AsyncContext<T> {
  getStore(): T | undefined;
  run<R>(store: T, fn: () => R): R;
}

/**
 * Tells a call made from inside the app's function from one that only
 * overlaps it. Node, Deno, Bun and Workers with Node compatibility have
 * `AsyncLocalStorage`. It is looked up at run time, never imported, so the
 * module loads where there is none: such a call then waits for itself, as
 * the doc comments warn.
 */
function asyncContext<T>(): AsyncContext<T> | undefined {
  const runtime = globalThis as { process?: { getBuiltinModule?(id: string): unknown } };
  const hooks = runtime.process?.getBuiltinModule?.('node:async_hooks') as
    | { AsyncLocalStorage?: new () => AsyncContext<T> }
    | undefined;
  return hooks?.AsyncLocalStorage ? new hooks.AsyncLocalStorage() : undefined;
}

const LOOKUP_KEY_INFO = 'fides-auth session lookup v1';

/** The HMAC key for the lookup hashes: HKDF of the secret, so it never equals the sealing key. */
async function lookupKey(secret: SessionSecret): Promise<CryptoKey> {
  const ikm = typeof secret === 'string' ? hexToUint8Array(secret) : secret;
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(),
      info: new TextEncoder().encode(LOOKUP_KEY_INFO),
    },
    base,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign'],
  );
}

async function hmacHex(key: CryptoKey, value: string): Promise<string> {
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(mac), (b) => b.toString(16).padStart(2, '0')).join('');
}

function expiresInSeconds(record: SessionRecord): number | undefined {
  const at = record.tokens.accessTokenExpiresAt;
  const ms = at ? Date.parse(at) : Number.NaN;
  return Number.isFinite(ms) ? Math.round((ms - Date.now()) / 1000) : undefined;
}

/** Whether `after` holds tokens `before` didn't: someone refreshed in between. */
function refreshedSince(before: SessionRecord, after: SessionRecord): boolean {
  return (
    after.tokens.accessToken !== before.tokens.accessToken ||
    after.tokens.refreshToken !== before.tokens.refreshToken
  );
}

/**
 * The grace period in seconds, 10 unless given.
 *
 * @throws TypeError if it is not a finite number, 0 or more.
 */
export function checkRefreshGrace(seconds = 10): number {
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new TypeError(`refreshGraceSeconds must be a finite number >= 0, got ${seconds}`);
  }
  return seconds;
}

/** A refresh this process just did: the refresh token it spent, and what it got. */
interface RecentRefresh {
  spent: string;
  record: SessionRecord;
  /** Milliseconds since the epoch. */
  until: number;
}

/**
 * Creates the lifecycle over one storage. Two lifecycles share no state.
 *
 * @throws TypeError if `refreshGraceSeconds` is not a finite number, 0 or more.
 */
/**
 * What a session's sealing key is derived for: the instance's audience, and
 * where the record is kept. The HKDF `info` of that key.
 */
export function sessionKeyInfo(audience: string, binding: string): string {
  return JSON.stringify(['fides-auth session', audience, binding]);
}

/**
 * The reasons a read reports as a `session.rejected` event itself: a cookie
 * that is there and doesn't open. A caller that reports rejections of its own,
 * as the heartbeat does, leaves these to the read.
 */
export function isReportedOnRead(reason: SessionRejectedReason): boolean {
  return reason === 'unreadable_session' || reason === 'unsupported_session_version';
}

export function createSessionLifecycle(options: SessionLifecycleOptions): SessionLifecycle {
  const { storage, secret, rolesClaim, mapSession, mapRefresh, logger } = options;
  const sessionDurationSeconds = checkSessionDuration(options.sessionDurationSeconds);
  const refreshGraceSeconds = checkRefreshGrace(options.refreshGraceSeconds);
  if (hasRepeatedSecret(secret)) {
    // Harmless, and worth a line: someone who meant to replace the secret hasn't.
    logger.warn('The same session secret is listed more than once; it counts once, so nothing is being replaced');
  }
  const inflight = new Map<string, Promise<RefreshRecordResult>>();
  // By correlation id, oldest first. A store has no use for it: a request with
  // an old cookie holds the same handle, and reads the new record.
  const recent = new Map<string, RecentRefresh>();
  // By correlation id: what a refresh got from the provider and the store
  // didn't take. The store still holds the refresh token that refresh spent.
  const unsaved = new Map<string, RecentRefresh>();
  const saveRetryDelaysMs = options.saveRetryDelaysMs ?? [200, 1000];
  let lookupKeysPromise: Promise<CryptoKey[]> | undefined;
  const audience = options.audience ?? '';
  // The last keys derived. Cookie storage has one set; a request for a stored session asks for the same one a few times.
  let lastSealingKeys: { binding: string; keys: Promise<Uint8Array[]> } | undefined;

  /**
   * The keys a record may be sealed with, one for each secret: for this
   * instance's audience, and for where the record is kept. So a record
   * doesn't open for another instance that has the secret, under another
   * store key, or in the other storage.
   */
  function sealingKeys(binding: string): Promise<Uint8Array[]> {
    if (lastSealingKeys?.binding === binding) return lastSealingKeys.keys;
    const info = sessionKeyInfo(audience, binding);
    const keys = Promise.all(secretsOf(secret).map((one) => deriveKey(one, info)));
    const entry = { binding, keys };
    lastSealingKeys = entry;
    // A bad secret is reported each time it is used, not remembered.
    keys.catch(() => {
      if (lastSealingKeys === entry) lastSealingKeys = undefined;
    });
    return keys;
  }

  /** The key a record is sealed with now: the first secret's. */
  async function sealingKey(binding: string): Promise<Uint8Array> {
    const [key] = await sealingKeys(binding);
    if (!key) throw new TypeError('fides-auth: session secret is missing or empty');
    return key;
  }

  /**
   * Opens a sealed record with the first key that opens it. A record sealed
   * with an older secret is read as it is, and sealed with the first one the
   * next time it is saved.
   */
  async function open(sealed: string, binding: string): Promise<OpenedRecord> {
    let last: OpenedRecord = { record: null, why: 'unreadable' };
    for (const key of await sealingKeys(binding)) {
      const opened = await openSealed(sealed, key);
      if (opened.record) return opened;
      // It opened with this key, as a record of another version: that is the answer.
      if (opened.why === 'unsupported_version') last = opened;
    }
    return last;
  }
  // By correlation id: the end of the last refresh or update queued for a session.
  const turns = new Map<string, Promise<void>>();

  // By correlation id, for the call that is running now: the app's functions it is inside.
  const inside = asyncContext<ReadonlyMap<string, Inside>>();

  /** Runs the app's function for a session, so that a call it makes for the same session can be told. */
  async function within<T>(correlationId: string, what: Inside['what'], fn: () => T | Promise<T>): Promise<T> {
    if (!inside) return fn();
    const mark: Inside = { what, active: true };
    const marks = new Map(inside.getStore()).set(correlationId, mark);
    try {
      return await inside.run(marks, fn);
    } finally {
      mark.active = false;
    }
  }

  /**
   * A refresh, an update or an end of a session, asked for by the function
   * that is updating or mapping that same session, would wait for the turn or
   * the lock its caller holds, and so for ever.
   *
   * @throws TypeError when the call comes from inside such a function.
   */
  function notFromInside(correlationId: string | undefined, calling: string): void {
    const mark = correlationId === undefined ? undefined : inside?.getStore()?.get(correlationId);
    if (!mark?.active) return;
    throw new TypeError(
      `${calling} was called from inside ${mark.what} for the same session. ` +
        `It would wait for that ${mark.what} to finish, which waits for it: do it before or after instead`,
    );
  }

  /**
   * Runs `fn` when the refreshes and updates of this session that were asked
   * for earlier in this process have finished, whether they failed or not.
   */
  function inTurn<T>(correlationId: string, fn: () => Promise<T>): Promise<T> {
    const run = (turns.get(correlationId) ?? Promise.resolve()).then(fn);
    const settled = run.then(
      () => undefined,
      () => undefined,
    );
    turns.set(correlationId, settled);
    void settled.then(() => {
      if (turns.get(correlationId) === settled) turns.delete(correlationId);
    });
    return run;
  }

  /** Remembers a refresh that rotated the refresh token, until the grace period or the access token ends. */
  function remember(spent: string, record: SessionRecord): void {
    const correlationId = record.session.correlationId;
    recent.delete(correlationId);
    if (storage.mode !== 'cookie' || refreshGraceSeconds === 0 || record.tokens.refreshToken === spent) {
      return;
    }
    const now = Date.now();
    // Entries are added in time order, so the expired ones are at the front.
    for (const [id, entry] of recent) {
      if (entry.until > now) break;
      recent.delete(id);
    }
    const expiresAt = Date.parse(record.tokens.accessTokenExpiresAt ?? '');
    const until = now + refreshGraceSeconds * 1000;
    recent.set(correlationId, {
      spent,
      record,
      until: Number.isNaN(expiresAt) ? until : Math.min(until, expiresAt),
    });
  }

  /**
   * What a refresh in this process just got for the session `stale` belongs
   * to, when `stale` holds the refresh token that refresh spent: the request
   * was sent before the new cookies arrived.
   */
  function refreshedAfter(stale: SessionRecord): SessionRecord | undefined {
    const entry = recent.get(stale.session.correlationId);
    if (!entry || entry.spent !== stale.tokens.refreshToken) return undefined;
    if (entry.until <= Date.now()) {
      recent.delete(stale.session.correlationId);
      return undefined;
    }
    return entry.record;
  }

  /** At most this many refreshes are kept while the store can't take them. The oldest goes first. */
  const MAX_UNSAVED = 1000;

  /**
   * Keeps what a refresh got when the store didn't take it, for as long as
   * the session lasts: the next refresh or update of the session in this
   * process saves it. Without it, that refresh would send the provider a
   * refresh token it has spent, and the session would end there.
   */
  function keepUnsaved(spent: string, record: SessionRecord): void {
    const now = Date.now();
    for (const [id, entry] of unsaved) {
      if (entry.until <= now) unsaved.delete(id);
    }
    unsaved.delete(record.session.correlationId);
    if (unsaved.size >= MAX_UNSAVED) {
      const [oldest] = unsaved.keys();
      if (oldest !== undefined) unsaved.delete(oldest);
    }
    unsaved.set(record.session.correlationId, { spent, record, until: Date.parse(record.session.expiresAt) });
  }

  /**
   * What a refresh in this process got for the session `stored` belongs to
   * and couldn't save, when `stored` still holds the refresh token it spent.
   */
  function unsavedAfter(stored: SessionRecord): SessionRecord | undefined {
    const { correlationId } = stored.session;
    const entry = unsaved.get(correlationId);
    if (!entry) return undefined;
    if (entry.spent !== stored.tokens.refreshToken || entry.until <= Date.now()) {
      // The store has moved on, or the session is over.
      unsaved.delete(correlationId);
      return undefined;
    }
    return entry.record;
  }

  let warnedAboutRoles = false;

  /**
   * `mapSession` runs at login only, and a refresh that brings an ID token
   * reads the roles from `rolesClaim` again. Roles that `mapSession` set are
   * gone then, which shows only after the first refresh. Say so at the first
   * login that shows it.
   */
  function checkMappedRoles(built: Session, mapped: Session): void {
    // With `mapRefresh` the app has a say at every refresh too.
    if (warnedAboutRoles || rolesClaim === false || mapRefresh || !built.user || !built.idp) return;
    const before = built.user.roles ?? [];
    const after = mapped.user?.roles ?? [];
    if (after.length === before.length && after.every((role, i) => role === before[i])) return;
    warnedAboutRoles = true;
    logger.warn(
      { correlationId: built.correlationId },
      'mapSession changed user.roles, but a refresh that brings an ID token reads them from rolesClaim again. ' +
        'Make rolesClaim a function to read them from the claims, or false to keep what mapSession set',
    );
  }

  function emit(event: SessionEvent): void {
    logSessionEvent(logger, event);
    try {
      options.onSessionEvent?.(event);
    } catch (error) {
      logger.error({ error }, 'onSessionEvent threw');
    }
  }

  /**
   * The keyed hashes a store may hold in place of `sub` or `sid`, one for
   * each secret. A record keeps the hash it was saved with until it is saved
   * again, so a search asks for all of them.
   */
  async function lookupHashes(value: string): Promise<string[]> {
    lookupKeysPromise ??= Promise.all(secretsOf(secret).map(lookupKey));
    return Promise.all((await lookupKeysPromise).map((key) => hmacHex(key, value)));
  }

  /** The keyed hash a record is saved with: the first secret's. */
  async function lookupHash(value: string): Promise<string> {
    const [hash] = await lookupHashes(value);
    return hash ?? '';
  }

  /** The store's lookup fields. Cookie storage has no use for them. */
  async function lookupFields(record: SessionRecord): Promise<LookupFields | undefined> {
    const idp = record.session.idp;
    if (storage.mode !== 'server' || !idp) return undefined;
    return {
      iss: idp.iss,
      subHash: await lookupHash(idp.sub),
      idpSidHash: idp.sid ? await lookupHash(idp.sid) : undefined,
    };
  }

  async function save(
    cookies: CookieStore,
    record: SessionRecord,
    reason: StoreSetReason,
  ): Promise<SaveResult> {
    return storage.save(cookies, {
      seal: async (binding) => sealRecord(record, await sealingKey(binding)),
      expiresAt: record.session.expiresAt,
      correlationId: record.session.correlationId,
      lookup: await lookupFields(record),
      fields: storage.mode === 'server' ? options.storeFields?.(record.session) : undefined,
      continuation: reason !== 'login',
      reason,
    });
  }

  /** Reads the session and reports nothing: for a second look at one that was read already. */
  async function load(cookies: CookieStore): Promise<ReadRecordResult & { version?: number }> {
    assertSessionSecret(secret);
    const loaded = await storage.load(cookies);
    if (loaded.sealed === null) return { record: null, reason: loaded.reason };
    const opened = await open(loaded.sealed, loaded.binding);
    if (!opened.record) {
      return opened.why === 'unsupported_version'
        ? { record: null, reason: 'unsupported_session_version', version: opened.version }
        : { record: null, reason: 'unreadable_session' };
    }
    if (isExpired(opened.record)) return { record: null, reason: 'session_expired' };
    return { record: opened.record };
  }

  /**
   * Reads the session. A cookie that is there and doesn't open is an event:
   * after a change of secret, issuer or version it is every user's cookie,
   * and a deploy that logs everyone out should show in the logs.
   */
  async function read(cookies: CookieStore): Promise<ReadRecordResult> {
    const { version, ...result } = await load(cookies);
    if (!result.record && isReportedOnRead(result.reason)) {
      emit({ event: SESSION_EVENT.REJECTED, reason: result.reason, version });
    }
    return result;
  }

  /** A refresh the store failed: on a read or a write, or the lock couldn't be had in time. */
  function storeFailed(error: unknown, current?: SessionRecord): RefreshRecordResult {
    const correlationId = current?.session.correlationId;
    emit({
      event: SESSION_EVENT.REFRESH_FAILED,
      correlationId,
      cause: 'store',
      accessTokenExpiresAt: current?.tokens.accessTokenExpiresAt,
      error: getOAuthErrorLogContext(error),
    });
    return { ok: false, reason: 'refresh_failed', cause: 'store', correlationId };
  }

  function alreadyRefreshed(before: SessionRecord, after: SessionRecord): RefreshRecordResult {
    logger.debug(
      { correlationId: after.session.correlationId },
      'Session already refreshed by a concurrent request',
    );
    return {
      ok: true,
      record: after,
      rotatedRefreshToken: after.tokens.refreshToken !== before.tokens.refreshToken,
    };
  }

  async function refreshNow(
    cookies: CookieStore,
    current: SessionRecord,
    refreshToken: string,
  ): Promise<RefreshRecordResult> {
    const correlationId = current.session.correlationId;
    let tokens: TokenResponse;
    try {
      tokens = await options.refreshTokens(refreshToken, current.tokens);
    } catch (error) {
      const cause = classifyRefreshFailure(error);
      if (cause === 'invalid_grant' && storage.lock) {
        // With rotation, another instance may have spent this token first, and
        // then its result is ours too.
        const latest = await load(cookies);
        if (latest.record && refreshedSince(current, latest.record)) {
          return alreadyRefreshed(current, latest.record);
        }
      }
      const context = getOAuthErrorLogContext(error);
      emit({
        event: SESSION_EVENT.REFRESH_FAILED,
        correlationId,
        cause,
        status: context.status,
        accessTokenExpiresAt: current.tokens.accessTokenExpiresAt,
        error: context,
      });
      if (cause === 'invalid_grant' && storage.exclusive && storage.discard) {
        // Under the store's lock no other instance refreshed in between, so
        // the refresh token the store holds is dead and the session with it.
        // Left in place it would read as a session until `expiresAt`. The
        // cookie goes with it, on every request that waits for this result.
        await storage.discard(cookies);
        emit({ event: SESSION_EVENT.CLEARED, correlationId, trigger: 'rejected' });
        return { ok: false, reason: 'refresh_failed', cause, correlationId, ended: true };
      }
      return { ok: false, reason: 'refresh_failed', cause, correlationId };
    }

    if (!isSameSubject(current, tokens)) {
      // The provider answered for someone else. Saving that would hand this
      // session another user's tokens.
      emit({
        event: SESSION_EVENT.REFRESH_FAILED,
        correlationId,
        cause: 'idp_error',
        accessTokenExpiresAt: current.tokens.accessTokenExpiresAt,
        error: { message: "The refreshed ID token's iss or sub differs from the session's" },
      });
      return { ok: false, reason: 'refresh_failed', cause: 'idp_error', correlationId };
    }

    let updated = refreshRecord(current, tokens, { rolesClaim });
    if (mapRefresh) {
      try {
        const refreshed = updated.session;
        const mapped = await within(correlationId, 'mapRefresh', () =>
          mapRefresh(tokens, claimsOf(tokens), refreshed),
        );
        updated = { ...updated, session: keepIdentity(updated.session, mapped) };
      } catch (error) {
        // The old refresh token is spent. Failing here would lose the new
        // tokens and with them the session, so the app's changes are what goes.
        logger.error(
          { correlationId, error },
          'mapRefresh threw; the session is saved as the refresh left it',
        );
      }
    }
    return saveRefreshed(cookies, refreshToken, updated);
  }

  /**
   * Saves what a refresh got, and reports it. A store that fails is tried
   * again: the provider has spent `spent`, so the new tokens are all the
   * session has. If the store still won't take them they are kept in memory,
   * and the failure is thrown for the refresh to report.
   */
  async function saveRefreshed(
    cookies: CookieStore,
    spent: string,
    updated: SessionRecord,
  ): Promise<RefreshRecordResult> {
    const correlationId = updated.session.correlationId;
    const rotatedRefreshToken = updated.tokens.refreshToken !== spent;
    // Cookies that can't be written won't be writable a second later.
    const delays = storage.mode === 'server' ? saveRetryDelaysMs : [];
    let written: SaveResult;
    for (let attempt = 0; ; attempt += 1) {
      try {
        written = await save(cookies, updated, 'refresh');
        break;
      } catch (error) {
        const delay = delays[attempt];
        if (delay === undefined) {
          if (storage.mode === 'server' && rotatedRefreshToken) keepUnsaved(spent, updated);
          throw error;
        }
        logger.warn(
          { correlationId, attempt: attempt + 1, error: getOAuthErrorLogContext(error) },
          'Could not save the refreshed session; trying again',
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    unsaved.delete(correlationId);
    if (!written.saved) {
      logger.info({ correlationId }, 'Session ended during refresh; not saved');
      return { ok: false, reason: 'session_not_found', correlationId, ended: true };
    }
    remember(spent, updated);
    emit({
      event: SESSION_EVENT.REFRESHED,
      correlationId,
      expiresIn: expiresInSeconds(updated),
      rotatedRefreshToken,
      cookieBytes: written.cookieBytes,
      persistence: storage.mode,
    });
    return { ok: true, record: updated, rotatedRefreshToken };
  }

  return {
    read,

    async create(cookies, tokens, options) {
      assertSessionSecret(secret);
      let record = createRecord(tokens, {
        sessionDurationSeconds,
        rolesClaim,
        requestedScope: options?.requestedScope,
        dpopKey: options?.dpopKey,
      });
      if (mapSession) {
        const mapped = await mapSession(tokens, claimsOf(tokens), record.session);
        checkMappedRoles(record.session, mapped);
        record = { ...record, session: keepIdentity(record.session, mapped) };
      }
      const written = await save(cookies, record, 'login');
      emit({
        event: SESSION_EVENT.CREATED,
        correlationId: record.session.correlationId,
        hasRefreshToken: !!record.tokens.refreshToken,
        scopes: record.session.scopes,
        expiresIn: expiresInSeconds(record),
        cookieBytes: written.cookieBytes,
        persistence: storage.mode,
      });
      return record;
    },

    async refresh(cookies, { unless } = {}) {
      // Before the store is asked: a bad secret is the app's to fix, not a store that failed.
      assertSessionSecret(secret);
      let first: ReadRecordResult;
      try {
        first = await read(cookies);
      } catch (error) {
        // Only a store fails a read. Cookies that can't be read are the caller's mistake.
        if (storage.mode !== 'server') throw error;
        return storeFailed(error);
      }
      if (!first.record) return { ok: false, reason: first.reason };
      const current = first.record;
      if (unless?.(current)) return { ok: true, record: current, rotatedRefreshToken: false, skipped: true };
      const correlationId = current.session.correlationId;
      notFromInside(correlationId, 'A refresh');
      if (presentationOfRecord(current.tokens) === null) {
        // Written by a later version, or bound to a key that isn't there. A
        // refresh without the proof it needs could end the session at the
        // provider, so nothing is sent and the session is left as it is.
        logger.warn(
          { correlationId, tokenType: current.tokens.tokenType },
          'The session holds tokens of a type this version cannot use; not refreshed',
        );
        return { ok: false, reason: 'unsupported_token_type', correlationId };
      }
      const refreshToken = current.tokens.refreshToken;
      if (!refreshToken) return { ok: false, reason: 'no_refresh_token', correlationId };

      // A stored session that a refresh finds over leaves no cookie behind, on
      // any request that asked: the handle would find nothing from here on.
      const settle = async (pending: Promise<RefreshRecordResult>): Promise<RefreshRecordResult> => {
        const result = await pending;
        if (!result.ok && result.ended) await storage.forget?.(cookies);
        return result;
      };

      const running = inflight.get(correlationId);
      if (running) return settle(running);

      // The refresh token in this request's cookie was spent a moment ago.
      // Sending it again would fail, and a provider that takes reuse for theft
      // revokes the session. Hand on what that refresh got, and save it, so
      // this response carries the new cookies too.
      const already = refreshedAfter(current);
      if (already) {
        await save(cookies, already, 'refresh');
        return alreadyRefreshed(current, already);
      }

      // Read again when it is this refresh's turn, and under the lock: an
      // update may have changed the session while it waited, and another
      // instance may have refreshed or ended it.
      const attempt = async (): Promise<RefreshRecordResult> => {
        const latest = await load(cookies);
        if (!latest.record) {
          // It was there a moment ago: a logout or a refresh that was refused
          // ended it while this one waited.
          const gone = latest.reason === 'session_not_found';
          return { ok: false, reason: latest.reason, correlationId, ...(gone && { ended: true as const }) };
        }
        if (refreshedSince(current, latest.record)) return alreadyRefreshed(current, latest.record);
        const latestToken = latest.record.tokens.refreshToken;
        if (!latestToken) return { ok: false, reason: 'no_refresh_token', correlationId };
        // An earlier refresh here got new tokens that the store never took.
        // Save those: the token the store holds is one the provider has spent.
        const kept = unsavedAfter(latest.record);
        if (kept) return saveRefreshed(cookies, latestToken, kept);
        return refreshNow(cookies, latest.record, latestToken);
      };

      const run = async (): Promise<RefreshRecordResult> => {
        if (!storage.lock) return attempt();
        try {
          return await storage.lock(cookies, attempt);
        } catch (error) {
          return storeFailed(error, current);
        }
      };

      const shared = inTurn(correlationId, run).finally(() => inflight.delete(correlationId));
      inflight.set(correlationId, shared);
      return settle(shared);
    },

    async update(cookies, update) {
      const first = await read(cookies);
      if (!first.record) return null;
      const { correlationId } = first.record.session;
      notFromInside(correlationId, 'An update');

      const change = async (): Promise<SessionRecord | null> => {
        // Read again: a refresh may have saved new tokens while this waited.
        const latest = (await load(cookies)).record;
        if (!latest) return null;
        // Under cookie storage the refresh may have been another request's,
        // and this one still carries the cookie from before it.
        // Or, under store storage, the store never took what a refresh here
        // got: this save brings those tokens with it.
        const refreshed = refreshedAfter(latest) ?? unsavedAfter(latest);
        const current = refreshed ?? latest;
        const changed = await within(correlationId, 'updateSession', () => update(current.session));
        const updated = { ...current, session: keepIdentity(current.session, changed) };
        const written = await save(cookies, updated, 'update');
        if (!written.saved) return null;
        // The next request with the old cookie gets the update too.
        const entry = recent.get(correlationId);
        if (entry && entry.record === refreshed) entry.record = updated;
        if (unsaved.get(correlationId)?.record === refreshed) unsaved.delete(correlationId);
        return updated;
      };

      return inTurn(correlationId, () => (storage.lock ? storage.lock(cookies, change) : change()));
    },

    async end(cookies, { trigger } = {}) {
      // Read first, so the event names the session it ended.
      const current = (await read(cookies).catch(() => undefined))?.record ?? undefined;
      notFromInside(current?.session.correlationId, 'An end of the session');

      // A refresh of this session still running here would bring back tokens
      // after the end, and under cookie storage save the session again. Wait
      // for it, so the tokens it got are the ones ended.
      const running = current && inflight.get(current.session.correlationId);
      const refreshed = running ? await running.catch(() => undefined) : undefined;
      // Or one that finished just before, when this request still carries the cookie from before it.
      // Or one whose tokens the store never took: those are the ones to revoke.
      const kept = current && unsaved.get(current.session.correlationId);
      let ended =
        (refreshed?.ok
          ? refreshed.record
          : current && (refreshedAfter(current) ?? unsavedAfter(current))) ?? current;
      if (current) {
        recent.delete(current.session.correlationId);
        unsaved.delete(current.session.correlationId);
      }

      // What the cookie store threw, when the record went and the cookie couldn't.
      let cookieLeft: { cause: unknown } | undefined;
      const { lock, discard, clearCookies } = storage;
      if (lock && discard && clearCookies) {
        // A refresh on another instance holds the same lock: it either saved
        // first, and its tokens are the ones ended, or it finds the record gone.
        ended = await lock(cookies, async () => {
          const latest = (await load(cookies).catch(() => undefined))?.record;
          await discard(cookies);
          // What the store holds is the last word, unless it still holds the
          // refresh token of a refresh whose tokens it never took.
          if (latest && kept && latest.tokens.refreshToken === kept.spent) return kept.record;
          return latest ?? ended;
        });
        // The record is gone, so the session is over whatever becomes of the
        // cookie. The caller still gets the tokens that were ended, to revoke.
        try {
          await clearCookies(cookies);
        } catch (cause) {
          cookieLeft = { cause };
        }
      } else {
        await storage.remove(cookies);
      }

      if (trigger) {
        emit({
          event: SESSION_EVENT.CLEARED,
          correlationId: current?.session.correlationId,
          trigger,
        });
      }
      if (cookieLeft) throw new SessionCookieLeftError(ended, cookieLeft.cause);
      return ended;
    },

    async endMatching({ iss, sub, sid }, { trigger } = {}) {
      assertSessionSecret(secret);
      if (!storage.findMatching) {
        throw new TypeError('Ending sessions without their cookies needs a sessionStore with findMatching');
      }
      if (!sub && !sid) throw new TypeError('Ending sessions needs a sub or a sid to match');
      // An empty issuer is a variable that wasn't set. Read as "any issuer" it would match the most.
      if (iss === '') throw new TypeError('Ending sessions needs an iss that is not empty, or none');

      // One search for each secret: a record holds the hashes of the secret it
      // was last saved with. Only the keys to compare, so an adapter can hand
      // the match to its query as it is.
      const subHashes = sub ? await lookupHashes(sub) : [];
      const sidHashes = sid ? await lookupHashes(sid) : [];
      const found = new Map<string, FoundSession>();
      for (let i = 0; i < secretsOf(secret).length; i += 1) {
        const match: SessionMatch = {};
        if (iss) match.iss = iss;
        if (sub) match.subHash = subHashes[i];
        if (sid) match.idpSidHash = sidHashes[i];
        for (const entry of await storage.findMatching(match)) found.set(entry.binding, entry);
      }

      const ended: SessionRecord[] = [];
      for (const entry of found.values()) {
        // The plain fields are the store's word. Check them against the sealed
        // record, so a search that matches too much can't end someone else's session.
        const idp = (await open(entry.sealed, entry.binding)).record?.session.idp;
        if (idp && ((iss && idp.iss !== iss) || (sub && idp.sub !== sub) || (sid && idp.sid !== sid))) {
          logger.warn(
            { correlationId: entry.correlationId },
            'findMatching returned a session that does not match; left alone',
          );
          continue;
        }
        if (!idp) {
          // No session of a user: it has no ID token to match, or it doesn't
          // open. The store shouldn't have found it, and nothing says whose it is.
          logger.warn(
            { correlationId: entry.correlationId },
            'findMatching returned a record without a user to match; left alone',
          );
          continue;
        }

        notFromInside(entry.correlationId, 'An end of the session');
        // As in `end`: the tokens a running refresh brings back are the ones ended.
        const running = entry.correlationId ? inflight.get(entry.correlationId) : undefined;
        if (running) await running.catch(() => undefined);
        const sealed = await entry.remove();
        const record = sealed ? (await open(sealed, entry.binding)).record : null;
        if (record) ended.push(record);
        if (trigger && sealed) {
          emit({
            event: SESSION_EVENT.CLEARED,
            correlationId: record?.session.correlationId ?? entry.correlationId,
            trigger,
          });
        }
      }
      return ended;
    },
  };
}
