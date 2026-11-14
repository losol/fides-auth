// The session lifecycle: create, read, refresh, update and end, written once
// over a SessionStorage. These rules hold in both storages:
//
// 1. A login never continues the session the browser arrived with.
// 2. `expiresAt` is fixed at creation and checked on every read.
// 3. A refresh or an update changes the contents, never the identity or the lifetime.
// 4. A session is read whole or not at all.
// 5. Concurrent refreshes of one session in one process share one provider call.
// 6. A rejected reason means the same thing in both storages.
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
import type { TokenResponse } from '../shared/types.js';
import { hexToUint8Array } from '../session/utils.js';
import {
  claimsOf,
  createRecord,
  isExpired,
  keepIdentity,
  type MapRecordSession,
  openRecord,
  refreshRecord,
  sealRecord,
  type SessionData,
  type SessionRecord,
} from '../session/record.js';
import type { CookieStore } from './cookie-store.js';
import { assertSessionSecret, type SessionSecret } from './session-persistence.js';
import type { LookupFields, SaveResult, SessionStorage } from './session-storage.js';

/** Why there is no session: a storage's reason, or `session_expired` once the lifetime has run out. */
export type LifecycleRejectedReason = SessionRejectedReason | 'session_expired';

export type ReadRecordResult =
  | { record: SessionRecord; reason?: undefined }
  | { record: null; reason: LifecycleRejectedReason };

export type RefreshRecordResult =
  | { ok: true; record: SessionRecord; rotatedRefreshToken: boolean }
  | {
    ok: false;
    reason: LifecycleRejectedReason;
    /** Set only when the provider was asked, that is when `reason` is `refresh_failed`. */
    cause?: RefreshFailureCause;
    correlationId?: string;
  };

export interface SessionLifecycleOptions {
  storage: SessionStorage;
  /** Seals records and derives the key for the store's lookup hashes. */
  secret: SessionSecret;
  /** @default 30 */
  sessionDurationDays?: number;
  /** @default 'roles' */
  rolesClaim?: string;
  mapSession?: MapRecordSession;
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
  /** Changes the user, scopes or data. Null when there is no session to change. */
  update(
    cookies: CookieStore,
    update: (session: SessionData) => SessionData | Promise<SessionData>,
  ): Promise<SessionRecord | null>;
  /** Ends the session. Under store storage, the record is deleted. */
  end(cookies: CookieStore, options?: { trigger?: SessionClearedTrigger }): Promise<void>;
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

/** Creates the lifecycle over one storage. Two lifecycles share no state. */
export function createSessionLifecycle(options: SessionLifecycleOptions): SessionLifecycle {
  const { storage, secret, sessionDurationDays = 30, rolesClaim, mapSession, logger } = options;
  const inflight = new Map<string, Promise<RefreshRecordResult>>();
  let lookupKeyPromise: Promise<CryptoKey> | undefined;

  function emit(event: SessionEvent): void {
    logSessionEvent(logger, event);
    try {
      options.onSessionEvent?.(event);
    } catch (error) {
      logger.error({ error }, 'onSessionEvent threw');
    }
  }

  /** The store's lookup fields. Cookie storage has no use for them. */
  async function lookupFields(record: SessionRecord): Promise<LookupFields | undefined> {
    const idp = record.session.idp;
    if (storage.mode !== 'server' || !idp) return undefined;
    lookupKeyPromise ??= lookupKey(secret);
    const key = await lookupKeyPromise;
    return {
      iss: idp.iss,
      subHash: await hmacHex(key, idp.sub),
      idpSidHash: idp.sid ? await hmacHex(key, idp.sid) : undefined,
    };
  }

  async function save(
    cookies: CookieStore,
    record: SessionRecord,
    continuation: boolean,
  ): Promise<SaveResult> {
    return storage.save(cookies, {
      sealed: await sealRecord(record, secret),
      expiresAt: record.session.expiresAt,
      correlationId: record.session.correlationId,
      lookup: await lookupFields(record),
      continuation,
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
      { sid: after.session.correlationId },
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
        sid: correlationId,
        cause,
        status: context.status,
        accessTokenExpiresAt: current.tokens.accessTokenExpiresAt,
        error: context,
      });
      return { ok: false, reason: 'refresh_failed', cause, correlationId };
    }

    const updated = refreshRecord(current, tokens);
    const rotatedRefreshToken = updated.tokens.refreshToken !== current.tokens.refreshToken;
    const written = await save(cookies, updated, true);
    if (!written.saved) {
      logger.info({ sid: correlationId }, 'Session ended during refresh; not saved');
      return { ok: false, reason: 'session_not_found', correlationId };
    }
    emit({
      event: SESSION_EVENT.REFRESHED,
      sid: correlationId,
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
      let record = createRecord(tokens, { sessionDurationDays, rolesClaim });
      if (mapSession) {
        const mapped = await mapSession(tokens, claimsOf(tokens), record.session);
        record = { ...record, session: keepIdentity(record.session, mapped) };
      }
      const written = await save(cookies, record, false);
      emit({
        event: SESSION_EVENT.CREATED,
        sid: record.session.correlationId,
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

      const run = async (): Promise<RefreshRecordResult> => {
        if (!storage.lock) return refreshNow(cookies, current, refreshToken);
        return storage.lock(cookies, async () => {
          // Re-read under the lock: another instance may have refreshed, or
          // ended, this session while we waited.
          const latest = await read(cookies);
          if (!latest.record) return { ok: false, reason: latest.reason, correlationId };
          if (refreshedSince(current, latest.record)) return alreadyRefreshed(current, latest.record);
          const latestToken = latest.record.tokens.refreshToken;
          if (!latestToken) return { ok: false, reason: 'no_refresh_token', correlationId };
          return refreshNow(cookies, latest.record, latestToken);
        });
      };

      const shared = run().finally(() => inflight.delete(correlationId));
      inflight.set(correlationId, shared);
      return shared;
    },

    async update(cookies, update) {
      const current = await read(cookies);
      if (!current.record) return null;
      const changed = await update(current.record.session);
      const updated = { ...current.record, session: keepIdentity(current.record.session, changed) };
      const written = await save(cookies, updated, true);
      return written.saved ? updated : null;
    },

    async end(cookies, { trigger } = {}) {
      // Read first, so the event names the session it ended.
      const current = await read(cookies).catch(() => undefined);
      await storage.remove(cookies);
      if (trigger) {
        emit({
          event: SESSION_EVENT.CLEARED,
          sid: current?.record?.session.correlationId,
          trigger,
        });
      }
    },
  };
}
