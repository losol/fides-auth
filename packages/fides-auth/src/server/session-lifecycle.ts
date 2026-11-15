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
import type { Session, TokenResponse } from '../shared/types.js';
import { hexToUint8Array } from '../session/utils.js';
import {
  checkSessionDuration,
  claimsOf,
  createRecord,
  isExpired,
  isSameSubject,
  keepIdentity,
  type MapRecordSession,
  openRecord,
  refreshRecord,
  sealRecord,
  type SessionRecord,
} from '../session/record.js';
import type { RolesClaim } from '../session/user-claims.js';
import type { CookieStore } from './cookie-store.js';
import { assertSessionSecret, type SessionSecret } from './session-secret.js';
import type { LookupFields, SaveResult, SessionStorage } from './session-storage.js';
import type { SessionMatch, StoreFields, StoreSetReason } from './session-store.js';

export type ReadRecordResult =
  | { record: SessionRecord; reason?: undefined }
  | { record: null; reason: SessionRejectedReason };

export type RefreshRecordResult =
  | { ok: true; record: SessionRecord; rotatedRefreshToken: boolean }
  | {
    ok: false;
    reason: SessionRejectedReason;
    /** Set only when the provider was asked, that is when `reason` is `refresh_failed`. */
    cause?: RefreshFailureCause;
    correlationId?: string;
  };

export interface SessionLifecycleOptions {
  storage: SessionStorage;
  /** Seals records and derives the key for the store's lookup hashes. */
  secret: SessionSecret;
  /** @default 43200, which is 12 hours */
  sessionDurationSeconds?: number;
  /** Where the roles are in the ID token. False leaves them to `mapSession`. @default 'roles' */
  rolesClaim?: RolesClaim | false;
  mapSession?: MapRecordSession;
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
  /** Runs the refresh token grant, e.g. `oidc.refresh`. */
  refreshTokens(refreshToken: string): Promise<TokenResponse>;
  logger: FidesLogger;
  /** Gets every lifecycle event, next to the logger. */
  onSessionEvent?(event: SessionEvent): void;
}

export interface SessionLifecycle {
  /** The session, or why there is none. Writes nothing. */
  read(cookies: CookieStore): Promise<ReadRecordResult>;
  /** Starts a new session from a token response, discarding whatever the browser held. */
  create(cookies: CookieStore, tokens: TokenResponse): Promise<SessionRecord>;
  /** Refreshes the tokens, keeping the session's identity and lifetime. */
  refresh(cookies: CookieStore): Promise<RefreshRecordResult>;
  /**
   * Changes the user, scopes or data. Null when there is no session to change.
   * It takes its turn after a refresh or an update of the session that is
   * running, under the store's lock where there is one, and `update` gets the
   * session as it is then. So `update` must not refresh or update the same
   * session: that call would wait for this one.
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
   */
  end(
    cookies: CookieStore,
    options?: { trigger?: SessionClearedTrigger },
  ): Promise<SessionRecord | undefined>;
  /**
   * Ends every stored session of one IdP user or IdP session, without their
   * cookies. Like {@link end}, it waits for a refresh still running in this
   * process and deletes under the store's lock.
   *
   * @returns The records ended, with the tokens they held last, so they can be revoked.
   * @throws TypeError without `sub` or `sid`, or when the storage can't search.
   */
  endMatching(
    match: { iss: string; sub?: string; sid?: string },
    options?: { trigger?: SessionClearedTrigger },
  ): Promise<SessionRecord[]>;
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
export function createSessionLifecycle(options: SessionLifecycleOptions): SessionLifecycle {
  const { storage, secret, rolesClaim, mapSession, logger } = options;
  const sessionDurationSeconds = checkSessionDuration(options.sessionDurationSeconds);
  const refreshGraceSeconds = checkRefreshGrace(options.refreshGraceSeconds);
  const inflight = new Map<string, Promise<RefreshRecordResult>>();
  // By correlation id, oldest first. A store has no use for it: a request with
  // an old cookie holds the same handle, and reads the new record.
  const recent = new Map<string, RecentRefresh>();
  let lookupKeyPromise: Promise<CryptoKey> | undefined;
  // By correlation id: the end of the last refresh or update queued for a session.
  const turns = new Map<string, Promise<void>>();

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

  let warnedAboutRoles = false;

  /**
   * `mapSession` runs at login only, and a refresh that brings an ID token
   * reads the roles from `rolesClaim` again. Roles that `mapSession` set are
   * gone then, which shows only after the first refresh. Say so at the first
   * login that shows it.
   */
  function checkMappedRoles(built: Session, mapped: Session): void {
    if (warnedAboutRoles || rolesClaim === false || !built.user || !built.idp) return;
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

  /** The keyed hash a store keeps in place of `sub` or `sid`. */
  async function lookupHash(value: string): Promise<string> {
    lookupKeyPromise ??= lookupKey(secret);
    return hmacHex(await lookupKeyPromise, value);
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
      sealed: await sealRecord(record, secret),
      expiresAt: record.session.expiresAt,
      correlationId: record.session.correlationId,
      lookup: await lookupFields(record),
      fields: storage.mode === 'server' ? options.storeFields?.(record.session) : undefined,
      continuation: reason !== 'login',
      reason,
    });
  }

  async function read(cookies: CookieStore): Promise<ReadRecordResult> {
    assertSessionSecret(secret);
    const loaded = await storage.load(cookies);
    if (loaded.sealed === null) return { record: null, reason: loaded.reason };
    const record = await openRecord(loaded.sealed, secret);
    if (!record) return { record: null, reason: 'unreadable_session' };
    if (isExpired(record)) return { record: null, reason: 'session_expired' };
    return { record };
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
      tokens = await options.refreshTokens(refreshToken);
    } catch (error) {
      const cause = classifyRefreshFailure(error);
      if (cause === 'invalid_grant' && storage.lock) {
        // With rotation, another instance may have spent this token first, and
        // then its result is ours too.
        const latest = await read(cookies);
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
        // cookie goes too where it can be written, so the browser stops
        // sending a handle that finds nothing.
        await storage.discard(cookies);
        emit({ event: SESSION_EVENT.CLEARED, correlationId, trigger: 'rejected' });
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

    const updated = refreshRecord(current, tokens, { rolesClaim });
    const rotatedRefreshToken = updated.tokens.refreshToken !== current.tokens.refreshToken;
    const written = await save(cookies, updated, 'refresh');
    if (!written.saved) {
      logger.info({ correlationId }, 'Session ended during refresh; not saved');
      return { ok: false, reason: 'session_not_found', correlationId };
    }
    remember(refreshToken, updated);
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

    async create(cookies, tokens) {
      assertSessionSecret(secret);
      let record = createRecord(tokens, { sessionDurationSeconds, rolesClaim });
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

    async refresh(cookies) {
      const first = await read(cookies);
      if (!first.record) return { ok: false, reason: first.reason };
      const current = first.record;
      const correlationId = current.session.correlationId;
      const refreshToken = current.tokens.refreshToken;
      if (!refreshToken) return { ok: false, reason: 'no_refresh_token', correlationId };

      const running = inflight.get(correlationId);
      if (running) return running;

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
        const latest = await read(cookies);
        if (!latest.record) return { ok: false, reason: latest.reason, correlationId };
        if (refreshedSince(current, latest.record)) return alreadyRefreshed(current, latest.record);
        const latestToken = latest.record.tokens.refreshToken;
        if (!latestToken) return { ok: false, reason: 'no_refresh_token', correlationId };
        return refreshNow(cookies, latest.record, latestToken);
      };

      const run = async (): Promise<RefreshRecordResult> => {
        if (!storage.lock) return attempt();
        try {
          return await storage.lock(cookies, attempt);
        } catch (error) {
          // The store failed, or the lock couldn't be had in time. That says
          // nothing about the session, so it is a failure to retry, not a throw.
          emit({
            event: SESSION_EVENT.REFRESH_FAILED,
            correlationId,
            cause: 'store',
            accessTokenExpiresAt: current.tokens.accessTokenExpiresAt,
            error: getOAuthErrorLogContext(error),
          });
          return { ok: false, reason: 'refresh_failed', cause: 'store', correlationId };
        }
      };

      const shared = inTurn(correlationId, run).finally(() => inflight.delete(correlationId));
      inflight.set(correlationId, shared);
      return shared;
    },

    async update(cookies, update) {
      const first = await read(cookies);
      if (!first.record) return null;
      const { correlationId } = first.record.session;

      const change = async (): Promise<SessionRecord | null> => {
        // Read again: a refresh may have saved new tokens while this waited.
        const latest = (await read(cookies)).record;
        if (!latest) return null;
        // Under cookie storage the refresh may have been another request's,
        // and this one still carries the cookie from before it.
        const refreshed = refreshedAfter(latest);
        const current = refreshed ?? latest;
        const changed = await update(current.session);
        const updated = { ...current, session: keepIdentity(current.session, changed) };
        const written = await save(cookies, updated, 'update');
        if (!written.saved) return null;
        // The next request with the old cookie gets the update too.
        const entry = recent.get(correlationId);
        if (entry && entry.record === refreshed) entry.record = updated;
        return updated;
      };

      return inTurn(correlationId, () => (storage.lock ? storage.lock(cookies, change) : change()));
    },

    async end(cookies, { trigger } = {}) {
      // Read first, so the event names the session it ended.
      const current = (await read(cookies).catch(() => undefined))?.record ?? undefined;

      // A refresh of this session still running here would bring back tokens
      // after the end, and under cookie storage save the session again. Wait
      // for it, so the tokens it got are the ones ended.
      const running = current && inflight.get(current.session.correlationId);
      const refreshed = running ? await running.catch(() => undefined) : undefined;
      // Or one that finished just before, when this request still carries the cookie from before it.
      let ended = (refreshed?.ok ? refreshed.record : current && refreshedAfter(current)) ?? current;
      if (current) recent.delete(current.session.correlationId);

      if (storage.lock) {
        // A refresh on another instance holds the same lock: it either saved
        // first, and its tokens are the ones ended, or it finds the record gone.
        ended = await storage.lock(cookies, async () => {
          const latest = (await read(cookies).catch(() => undefined))?.record;
          await storage.remove(cookies);
          return latest ?? ended;
        });
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
      return ended;
    },

    async endMatching({ iss, sub, sid }, { trigger } = {}) {
      assertSessionSecret(secret);
      if (!storage.findMatching) {
        throw new TypeError('Ending sessions without their cookies needs a sessionStore with findMatching');
      }
      if (!sub && !sid) throw new TypeError('Ending sessions needs a sub or a sid to match');

      // Only the keys to compare, so an adapter can hand the match to its query as it is.
      const match: SessionMatch = { iss };
      if (sub) match.subHash = await lookupHash(sub);
      if (sid) match.idpSidHash = await lookupHash(sid);
      const found = await storage.findMatching(match);

      const ended: SessionRecord[] = [];
      for (const entry of found) {
        // The plain fields are the store's word. Check them against the sealed
        // record, so a search that matches too much can't end someone else's session.
        const idp = (await openRecord(entry.sealed, secret))?.session.idp;
        if (idp && (idp.iss !== iss || (sub && idp.sub !== sub) || (sid && idp.sid !== sid))) {
          logger.warn(
            { correlationId: entry.correlationId },
            'findMatching returned a session that does not match; left alone',
          );
          continue;
        }

        // As in `end`: the tokens a running refresh brings back are the ones ended.
        const running = entry.correlationId ? inflight.get(entry.correlationId) : undefined;
        if (running) await running.catch(() => undefined);
        const sealed = await entry.remove();
        const record = sealed ? await openRecord(sealed, secret) : null;
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
