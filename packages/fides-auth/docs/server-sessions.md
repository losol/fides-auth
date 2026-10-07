# Server-side sessions

By default fides-auth keeps the whole session, tokens included, encrypted in
three cookies. That stops working when one token alone is bigger than a cookie.
OpenIddict, for one, encrypts access and refresh tokens (JWE); once fides-auth
encrypts and base64-encodes them again, a split cookie crosses 4096 bytes, the
browser drops it, and the login loops.

Server persistence is the opt-in fix: the session lives in a `SessionStore` you
provide, and the browser holds one small cookie with a random handle. It also
buys three things a cookie cannot offer: real revocation, one refresh per
session under concurrency, and a cookie that is worthless without the store.

## Wiring

```ts
import {
  handleOidcCallback,
  handleHeartbeat,
  handleOidcLogout,
  serverPersistence,
  tryReadSession,
  clearSession,
} from "@eventuras/fides-auth/server";

const persistence = serverPersistence({
  store: sessionStore, // your SessionStore — see below
  secret: process.env.SESSION_SECRET!,
});

// Handlers: pass `persistence` where you passed `secret`.
handleOidcCallback(request, { oauthConfig, applicationUrl, cookies, persistence });
handleHeartbeat(request, { oauthConfig, cookies, persistence });
handleOidcLogout(request, { oauthConfig, cookies, postLogoutRedirectUri, persistence });

// Session helpers: `persistence` goes in the secret's position.
const { session, reason } = await tryReadSession(cookies, persistence);
await clearSession(cookies, { trigger: "logout", persistence });
```

Cookie persistence stays the default: a bare secret means
`cookiePersistence(secret)`, and nothing changes for consumers that don't opt in.

`serverPersistence` takes two more options: `cookieName` (default
`session_ref`) and `sessionDurationDays` (default 30), the absolute lifetime of
a session from login, refreshes notwithstanding.

## The store contract

```ts
interface SessionStore {
  get(key: string): StoredSession | null | undefined | Promise<StoredSession | null | undefined>;
  set(key: string, record: StoredSession): void | Promise<void>;
  delete(key: string): void | Promise<void>;
  withLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
}

interface StoredSession {
  data: string;       // the session, encrypted under the secret
  expiresAt: string;  // ISO 8601, absolute
  sid?: string;       // correlation id, so a record can be found from a log line
}
```

Keys are `SHA-256(handle)` as hex, never the handle itself. On the library's
side:

- `data` is encrypted before `set` and decrypted after `get`. A store dump alone
  yields no tokens.
- `expiresAt` is checked on every read. An expired record is rejected and
  deleted whatever the adapter returned, so a late TTL sweep never revives a
  session.
- `expiresAt` is fixed at login and kept across refreshes.

`createMemorySessionStore()` ships for tests and single-instance development;
sessions do not survive a restart. Database adapters belong in your app. A
MongoDB one, with the TTL index doing the sweeping:

```ts
import type { SessionStore, StoredSession } from "@eventuras/fides-auth/server";

type Doc = Omit<StoredSession, "expiresAt"> & { _id: string; expiresAt: Date };
const sessions = db.collection<Doc>("sessions");
await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const sessionStore: SessionStore = {
  async get(key) {
    const doc = await sessions.findOne({ _id: key });
    return doc && { data: doc.data, sid: doc.sid, expiresAt: doc.expiresAt.toISOString() };
  },
  async set(key, record) {
    await sessions.replaceOne(
      { _id: key },
      { _id: key, ...record, expiresAt: new Date(record.expiresAt) },
      { upsert: true },
    );
  },
  async delete(key) {
    await sessions.deleteOne({ _id: key });
  },
};
```

## Refresh under concurrency

Two requests refreshing one session at once is the failure mode of rotating
refresh tokens: both spend the token, one wins, the other now holds a dead one.
OpenIddict goes further and treats the reuse as theft, revoking the whole
authorization. Under server persistence `tryRefreshSessionInStore`:

- coalesces concurrent calls within one process into a single token request,
  and hands every caller the same result;
- takes `store.withLock(key)` when the adapter provides it, and re-reads the
  record under the lock, so a refresh that already happened on another instance
  is reused rather than repeated;
- on `invalid_grant`, re-reads once more before ending the session, in case a
  concurrent refresh elsewhere spent the token first.

Implement `withLock` when you run more than one instance. Give the lock a
timeout, so a crashed holder does not wedge the session.

## Security notes

- **Handle.** 256 bits from `crypto.getRandomValues`, hex-encoded, in
  `session_ref` with `httpOnly`, `secure`, `SameSite=Lax` and a max-age equal
  to the session lifetime. The library never logs it.
- **Key.** `SHA-256(handle)`. Neither a leaked store nor a logged key can be
  replayed as a cookie.
- **Fixation.** Every login mints a new handle and deletes the record the old
  one pointed at. Only a refresh keeps the handle.
- **Revocation.** `clearSession` deletes the record before the cookie. From
  then on a copied cookie reads as `session_not_found`.
- **At rest.** Records are encrypted with the same secret as cookie sessions.
  Rotating the secret ends stored sessions (`unreadable_session`), as it ends
  cookie ones.

## Switching from cookies

A browser that arrives with the old `session` / `session_at` / `session_it`
cookies and no handle reads as `stale_legacy_session`: one re-login, logged as
such rather than as corruption. The next write under server persistence, and
any logout, deletes the old cookies.

## What the logs say

`session.created` and `session.refreshed` carry `persistence: "server"` and no
`cookieBytes`. The one new rejection reason is `session_not_found`: a handle was
sent, but no live record exists for it. Revoked, expired or evicted. See
[session-events.md](./session-events.md).
