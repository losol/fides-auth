// server/session-store.ts
//
// The store contract behind server persistence: the session lives here, keyed
// by a hash of the handle the browser holds. Database adapters (Mongo, Redis, …)
// belong in consumers; this package ships only the in-memory one.

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
  sid?: string;
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
  /** Creates or replaces the record. */
  set(key: string, record: StoredSession): void | Promise<void>;
  /** Removes the record. Deleting a missing key is not an error. */
  delete(key: string): void | Promise<void>;
  /**
   * Optional: runs `fn` while holding a lock on `key`, so refreshes of one
   * session are serialized across instances. Without it they are serialized
   * within the process only. Implementations should expire the lock if the
   * holder dies.
   */
  withLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
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
