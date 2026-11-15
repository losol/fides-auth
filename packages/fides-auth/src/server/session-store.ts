// server/session-store.ts
//
// The store contract behind server persistence: the session lives here, keyed
// by a hash of the handle the browser holds. Database adapters (Mongo, Redis, …)
// belong in consumers; this package ships only the in-memory one.

/**
 * Plain fields an app keeps next to a session, from `storeFields` in the
 * config: its own user id, say, to list or count who is signed in.
 */
export type StoreFields = Record<string, string | number | boolean | null>;

/** One persisted session, as the store sees it. */
export interface StoredSession {
  /** The session, encrypted under the session secret. Opaque to the store. */
  data: string;
  /**
   * Absolute session expiry, ISO 8601. Adapters map it to a TTL; the library
   * also checks it on read, so a late TTL sweep never revives a session.
   */
  expiresAt: string;
  /** Correlation id of the session, so a record can be found from a log line. Not a secret. */
  correlationId?: string;
  /** The ID token's issuer. With `subHash` or `idpSidHash`, finds a user's sessions for back-channel logout. */
  iss?: string;
  /** HMAC-SHA-256 of the ID token's `sub`, under a key derived from the session secret. Never `sub` itself. */
  subHash?: string;
  /** HMAC-SHA-256 of the ID token's `sid` claim, under the same key. */
  idpSidHash?: string;
  /**
   * What `storeFields` returned for this session, in the clear. Absent
   * without `storeFields`. Written again on every save, so it follows the session.
   */
  fields?: StoreFields;
}

/** What a `set` is for, so an adapter can insert or update. */
export interface StoreSetContext {
  /**
   * True for a refresh or an update of a session the store already has. False
   * for a new session, which always comes with a new key.
   */
  continuation: boolean;
}

/**
 * Which sessions {@link SessionStore.findMatching} looks for. A record must
 * match every key that is given, each against the field of the same name. A
 * key that isn't compared is left out, never set to undefined.
 */
export interface SessionMatch {
  iss: string;
  subHash?: string;
  idpSidHash?: string;
}

/** A record {@link SessionStore.findMatching} found, with the key it is stored under. */
export interface StoredSessionEntry {
  key: string;
  record: StoredSession;
}

/**
 * Server-side session storage. Methods may be sync or async.
 *
 * Keys are hex SHA-256 digests of the handle, never the handle itself, so a
 * store dump or a logged key cannot be replayed as a cookie.
 */
export interface SessionStore {
  /** Returns the record, or null/undefined when there is none. May return an expired record. */
  get(key: string): StoredSession | null | undefined | Promise<StoredSession | null | undefined>;
  /** Creates or replaces the record. `context` says whether the session is new. */
  set(key: string, record: StoredSession, context: StoreSetContext): void | Promise<void>;
  /** Removes the record. Deleting a missing key is not an error. */
  delete(key: string): void | Promise<void>;
  /**
   * Optional: runs `fn` while holding a lock on `key`, so refreshes of one
   * session are serialized across instances. Without it they are serialized
   * within the process only. `fn` calls `get` and `set` while the lock is held,
   * and the lock is held across the call to the provider. Implementations
   * should expire the lock if the holder dies. A rejection fails the refresh
   * with `cause: 'store'`, which the heartbeat answers with 503.
   */
  withLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
  /**
   * Optional: the records whose lookup fields match, for ending a user's
   * sessions without their cookies (`endUserSessions`). The library computes
   * the hashes; compare them as plain strings. May return expired records.
   */
  findMatching?(match: SessionMatch): StoredSessionEntry[] | Promise<StoredSessionEntry[]>;
}

/**
 * In-memory store for tests and single-instance development. Sessions do not
 * survive a restart, and expired records are dropped on read.
 */
export function createMemorySessionStore(): SessionStore {
  const records = new Map<string, StoredSession>();
  const locks = new Map<string, Promise<void>>();

  return {
    get(key) {
      const record = records.get(key);
      if (!record) return null;
      if (!(Date.parse(record.expiresAt) > Date.now())) {
        records.delete(key);
        return null;
      }
      return record;
    },
    set(key, record) {
      records.set(key, record);
    },
    delete(key) {
      records.delete(key);
    },
    findMatching({ iss, subHash, idpSidHash }) {
      return Array.from(records, ([key, record]) => ({ key, record })).filter(
        ({ record }) =>
          record.iss === iss &&
          (subHash === undefined || record.subHash === subHash) &&
          (idpSidHash === undefined || record.idpSidHash === idpSidHash),
      );
    },
    withLock(key, fn) {
      // One promise chain per key. The chain never rejects, so a failed holder
      // does not poison the next.
      const previous = locks.get(key) ?? Promise.resolve();
      const run = previous.then(fn);
      const settled = run.then(() => undefined, () => undefined);
      locks.set(key, settled);
      void settled.then(() => {
        if (locks.get(key) === settled) locks.delete(key);
      });
      return run;
    },
  };
}
