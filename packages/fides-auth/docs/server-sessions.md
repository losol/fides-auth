# Server-side sessions

By default fides-auth seals the whole session, tokens included, into the
`__Host-session` cookie, cut into up to three chunks. That stops working when
the tokens are bigger than three cookies. OpenIddict, for one, encrypts access
and refresh tokens (JWE). Once fides-auth seals them again, the session no
longer fits, and the callback answers 431.

A `SessionStore` is the opt-in fix: the session lives in a store you provide,
and the browser holds one small cookie with a random handle. It also buys four
things a cookie can't offer: real revocation, one refresh per session across
instances, a cookie that is worthless without the store, and ending a user's
sessions wherever they are signed in.

## Wiring

```ts
import { createFidesAuth } from "@eventuras/fides-auth/server";

export const auth = createFidesAuth({
  oauthConfig,
  secret: process.env.SESSION_SECRET!,
  sessionStore, // your SessionStore, see below
});
```

Every handler and session member on `auth` then uses the store. `secret` is
still required: it seals the records and the login transaction. Next.js apps
pass the same option to `createFidesAuth` from `@eventuras/fides-auth-next`.

A session lasts `sessionDurationDays` (30 by default) from login, and refreshes
don't extend it. The handle cookie expires with it.

## The store contract

```ts
interface SessionStore {
  get(key: string): StoredSession | null | undefined | Promise<StoredSession | null | undefined>;
  set(key: string, record: StoredSession, context: { continuation: boolean }): void | Promise<void>;
  delete(key: string): void | Promise<void>;
  withLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
  findMatching?(match: SessionMatch): StoredSessionEntry[] | Promise<StoredSessionEntry[]>;
}

interface StoredSession {
  data: string;           // the sealed session; opaque to the store
  expiresAt: string;      // ISO 8601, absolute
  correlationId?: string; // so a record can be found from a log line
  iss?: string;           // the ID token's issuer
  subHash?: string;       // HMAC of the ID token's sub, never sub itself
  idpSidHash?: string;    // HMAC of the ID token's sid claim
  fields?: Record<string, string | number | boolean | null>; // from storeFields
}

interface SessionMatch { iss: string; subHash?: string; idpSidHash?: string }
interface StoredSessionEntry { key: string; record: StoredSession }
```

Keys are `SHA-256(handle)` as hex, never the handle itself. Save every field the
library sets: `iss`, `subHash` and `idpSidHash` are what finds a user's sessions,
for [`endUserSessions`](#ending-a-users-sessions) and for back-channel logout.
`set` gets `continuation: false` for a new session, which always comes with a
new key, and `true` for a refresh or an update of one the store has, so an
adapter can insert or update. On the library's side:

- `data` is sealed before `set` and opened after `get`. A store dump alone
  yields no tokens.
- `expiresAt` is checked on every read, so a late TTL sweep never revives a
  session. An expired record reads as `session_expired`; a store that drops it
  first reads as `session_not_found`.
- `expiresAt` is fixed at login and kept across refreshes.

`createMemorySessionStore()` ships for tests and single-instance development;
sessions don't survive a restart. Database adapters belong in your app. A
MongoDB one, with the TTL index doing the sweeping:

```ts
import type { SessionStore, StoredSession } from "@eventuras/fides-auth/server";

type Doc = Omit<StoredSession, "expiresAt"> & { _id: string; expiresAt: Date };
const sessions = db.collection<Doc>("sessions");
await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
await sessions.createIndex({ iss: 1, subHash: 1 }); // for findMatching

export const sessionStore: SessionStore = {
  async get(key) {
    const doc = await sessions.findOne({ _id: key });
    if (!doc) return null;
    const { _id, expiresAt, ...record } = doc;
    return { ...record, expiresAt: expiresAt.toISOString() };
  },
  async set(key, record) {
    // On an insert, the new document takes its `_id` from the filter.
    await sessions.replaceOne(
      { _id: key },
      { ...record, expiresAt: new Date(record.expiresAt) },
      { upsert: true },
    );
  },
  async delete(key) {
    await sessions.deleteOne({ _id: key });
  },
  async findMatching(match) {
    // `match` holds only the keys to compare: iss, and subHash or idpSidHash.
    const docs = await sessions.find(match).toArray();
    return docs.map(({ _id, expiresAt, ...record }) => ({
      key: _id,
      record: { ...record, expiresAt: expiresAt.toISOString() },
    }));
  },
};
```

## Your own fields

A store sees a sealed record and hashes, so it can't tell whose session a
record is. `storeFields` puts fields of your choice next to it, in the clear:

```ts
export const auth = createFidesAuth({
  oauthConfig,
  secret,
  sessionStore,
  mapSession: async (tokens, claims, session) => ({
    ...session,
    data: { userId: await userIdFor(claims?.sub) },
  }),
  storeFields: (session) => ({ userId: (session.data?.userId as string | undefined) ?? null }),
});
```

The store gets them as `record.fields` on every `set`, so they follow the
session through refreshes and `updateSession`. Index them to list or count who
is signed in. They aren't sealed: return only what the store may show, and
never a token. Without a `sessionStore`, `storeFields` does nothing.

## Ending a user's sessions

`endUserSessions` ends every session of one user without their cookies, for
"sign out everywhere" or when an account is closed:

```ts
const ended = await auth.endUserSessions({ sub }); // how many it ended
```

`sub` is the provider's, from the ID token: `session.idp.sub`, which stays the
same whatever `mapSession` does to `user`. `iss` defaults to the provider's
issuer. The instance hashes `sub`, asks the store's `findMatching` for the
records, and for each one:

- checks the sealed record's own `iss` and `sub` against the request, so a
  search that returns too much can't end someone else's session;
- waits for a refresh of it still running in this process, and deletes it under
  `withLock`, like a logout;
- revokes the refresh token it held last, where the provider has a
  `revocation_endpoint`.

The browsers keep their handle cookies, which then read as `session_not_found`.
It needs a store with `findMatching` and throws a `TypeError` without one,
cookie sessions included, rather than answer that it ended nobody's. Index
`iss` with `subHash` for it, as the MongoDB example does.

## Refresh under concurrency

Two requests refreshing one session at once is the failure mode of rotating
refresh tokens: both spend the token, one wins, and the other now holds a dead
one. OpenIddict goes further and treats the reuse as theft, revoking the whole
authorization. The instance:

- joins concurrent refreshes of one session within one process into a single
  token request, and hands every caller the same result;
- takes `store.withLock(key)` when the adapter provides it, and re-reads the
  record under the lock, so a refresh another instance already did is reused
  rather than repeated;
- on `invalid_grant`, re-reads once more before giving up, in case a concurrent
  refresh elsewhere spent the token first;
- ends a session under the same lock, so a refresh on another instance either
  saved first, and the logout revokes its refresh token, or finds the record
  gone and saves nothing;
- deletes the record when the provider refuses a refresh for good
  (`invalid_grant`) under `withLock`: no other instance can have refreshed, so
  the session's tokens are dead, and the handle then reads as
  `session_not_found`. Without `withLock` the record is left, since another
  instance may hold newer tokens.

Implement `withLock` when you run more than one instance, above all with a
provider that rotates refresh tokens. Without it, two instances can refresh one
session with the same token. The one that loses gets `invalid_grant` and
re-reads the record, which rescues it only if the winner has already saved.
Otherwise the refresh fails and the user logs in again, and a provider that
treats the reuse as theft revokes the winner's tokens too.

What a lock must allow:

- `fn` calls `get` and `set` on the same key while the lock is held. Don't make
  those calls wait for the lock's own resources: an adapter that holds the lock
  on one pooled connection, and needs another for each query, deadlocks once as
  many sessions refresh at once as the pool has connections.
- The lock is held across the call to the provider, which openid-client gives
  up on after 30 seconds. A lock that expires sooner lets a second holder
  refresh with the same token.
- Give the lock a timeout, so a crashed holder doesn't wedge the session. When
  `withLock` rejects, for a timeout or anything else, the refresh fails with
  `cause: 'store'` and the heartbeat answers `503`, so the browser retries. A
  logout that can't take the lock answers `500`.

A refresh keeps the handle, so it writes no cookie. It works where cookies
can't be set, such as a Next.js Server Component.

## Security notes

- **Handle.** 256 bits from `crypto.getRandomValues`, hex-encoded, in
  `__Host-session` with `HttpOnly`, `Secure`, `SameSite=Lax` and a max-age
  equal to the time left in the session. The library never logs it.
- **Key.** `SHA-256(handle)`. Neither a leaked store nor a logged key can be
  replayed as a cookie.
- **Fixation.** Every login mints a new handle and deletes the record the old
  one pointed at. Only a refresh or an update keeps the handle.
- **Revocation.** Logout and `clearSession` delete the record before the
  cookie. From then on a copied cookie reads as `session_not_found`.
- **Plain fields.** `iss`, the two hashes, `correlationId` and whatever
  `storeFields` returns are stored in the clear. The hashes are HMACs under a
  key derived from `secret`, so a store dump doesn't give up `sub`; your own
  fields are as readable as you make them.
- **At rest.** Records are sealed with the same secret as cookie sessions.
  Rotating the secret ends stored sessions (`unreadable_session`), as it ends
  cookie ones.

## Switching from cookies

A browser that still carries a cookie session when the app moves to a store
sends a value that isn't a handle. It reads as `unreadable_session`, which
costs one re-login. The login deletes the cookie chunks.

## What the logs say

`session.created` and `session.refreshed` carry `persistence: "server"` and no
`cookieBytes`. The store adds one rejection reason, `session_not_found`: a
handle was sent, but no live record exists for it. Revoked, expired or evicted.
See [session-events.md](./session-events.md).
