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

A session lasts `sessionDurationSeconds` (12 hours by default) from login, and refreshes
don't extend it. The handle cookie expires with it.

## The store contract

```ts
interface SessionStore {
  get(key: string): StoredSession | null | undefined | Promise<StoredSession | null | undefined>;
  set(key: string, record: StoredSession, context: StoreSetContext): void | Promise<void>;
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
  fields?: Record<string, string | number | boolean | null | string[]>; // from storeFields
}

interface StoreSetContext {
  continuation: boolean; // false for a new session, true for a refresh or an update
  reason: "login" | "refresh" | "update";
}

interface SessionMatch { iss?: string; subHash?: string; idpSidHash?: string }
interface StoredSessionEntry { key: string; record: StoredSession }
```

Keys are `SHA-256(handle)` as hex, never the handle itself. Save every field the
library sets: `iss`, `subHash` and `idpSidHash` are what finds a user's sessions,
for [`endUserSessions`](#ending-a-users-sessions) and for back-channel logout.
`set` gets `continuation: false` for a new session, which always comes with a
new key, and `true` for a refresh or an update of one the store has, so an
adapter can insert or update. For a continuation it must update only, and do
nothing when the record is gone: the session was then ended while the refresh
or the update ran, and an upsert would bring it back. The library checks that
the record is there before it writes, but without `withLock` a logout on
another instance can land between the check and the write. `reason` says why the record is written:
`'login'` for a new session, `'refresh'` when the tokens were refreshed, and
`'update'` when the app changed the session with `updateSession`. On the
library's side:

- `data` is sealed before `set` and opened after `get`. A store dump alone
  yields no tokens.
- `expiresAt` is checked on every read, so a late TTL sweep never revives a
  session. An expired record reads as `session_expired`; a store that drops it
  first reads as `session_not_found`.
- `expiresAt` is fixed at login and kept across refreshes.
- `get` answers null only when there is no record. A store that can't be
  reached must throw: a refresh that reads a session and then finds it gone
  takes it for ended, and deletes its cookie.

`createMemorySessionStore()` ships for tests and single-instance development;
sessions don't survive a restart. Database adapters belong in your app.

The library stops reading a record once it has expired, but it never deletes
one: sweeping is the store's job. A record whose cookie has expired in the
browser is never asked for again, so a store that doesn't sweep only grows.

A MongoDB adapter, with the TTL index doing the sweeping:

```ts
import type { SessionStore, StoredSession } from "@eventuras/fides-auth/server";

type Doc = Omit<StoredSession, "expiresAt"> & { _id: string; expiresAt: Date };
const sessions = db.collection<Doc>("sessions");
await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
await sessions.createIndex({ subHash: 1 }); // for findMatching

export const sessionStore: SessionStore = {
  async get(key) {
    const doc = await sessions.findOne({ _id: key });
    if (!doc) return null;
    const { _id, expiresAt, ...record } = doc;
    return { ...record, expiresAt: expiresAt.toISOString() };
  },
  async set(key, record, { continuation }) {
    // Only a new session may insert. A refresh or an update that finds no
    // document must leave it so: the session was ended while it ran. On an
    // insert, the new document takes its `_id` from the filter.
    await sessions.replaceOne(
      { _id: key },
      { ...record, expiresAt: new Date(record.expiresAt) },
      { upsert: !continuation },
    );
  },
  async delete(key) {
    await sessions.deleteOne({ _id: key });
  },
  async findMatching(match) {
    // `match` holds only the keys to compare: subHash or idpSidHash, and iss
    // when the caller named one.
    const docs = await sessions.find(match).toArray();
    return docs.map(({ _id, expiresAt, ...record }) => ({
      key: _id,
      record: { ...record, expiresAt: expiresAt.toISOString() },
    }));
  },
};
```

An adapter can use `reason` to record when a session was last refreshed. It
must then merge the record into what it has, since a `set` that replaces would
drop the stamp at the next update. The rule for a continuation holds for a
merge too: one that creates what it doesn't find would bring back a session
that was just ended.

```ts
async set(key, record, { continuation, reason }) {
  const fields = {
    ...record,
    ...(reason === "refresh" && { refreshedAt: new Date() }),
  };
  // Only a new session creates. A refresh or an update merges into what is there.
  if (continuation) await db.sessions.mergeIfExists(key, fields);
  else await db.sessions.create(key, fields);
},
```

## A PostgreSQL store

The same for PostgreSQL with [pg](https://node-postgres.com), and with
`withLock`, which an app that runs more than one instance needs: see
[Refresh under concurrency](#refresh-under-concurrency). The lock is an
advisory lock, held on a connection from a pool of its own.

```sql
create table sessions (
  key text primary key,
  data text not null,
  expires_at timestamptz not null,
  correlation_id text,
  iss text,
  sub_hash text,
  idp_sid_hash text,
  fields jsonb
);
create index on sessions (sub_hash);   -- for findMatching
create index on sessions (expires_at); -- for the sweep
```

```ts
import type { SessionStore, StoredSession } from "@eventuras/fides-auth/server";
import pg from "pg";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
// A lock keeps a connection of its own for as long as it is held, so the
// queries inside `fn` never wait for one.
const lockPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20, // how many sessions this instance can refresh at once
  connectionTimeoutMillis: 5_000, // one more than that waits this long, then fails
  options: "-c lock_timeout=35s", // how long a refresh waits for another's lock
});
// An idle connection that is lost emits "error". Without a listener, that ends the process.
for (const each of [pool, lockPool]) each.on("error", (error) => console.error(error));

interface Row {
  key: string;
  data: string;
  expires_at: Date;
  correlation_id: string | null;
  iss: string | null;
  sub_hash: string | null;
  idp_sid_hash: string | null;
  fields: StoredSession["fields"] | null;
}

const toRecord = (row: Row): StoredSession => ({
  data: row.data,
  expiresAt: row.expires_at.toISOString(),
  ...(row.correlation_id && { correlationId: row.correlation_id }),
  ...(row.iss && { iss: row.iss }),
  ...(row.sub_hash && { subHash: row.sub_hash }),
  ...(row.idp_sid_hash && { idpSidHash: row.idp_sid_hash }),
  ...(row.fields && { fields: row.fields }),
});

const columns = { iss: "iss", subHash: "sub_hash", idpSidHash: "idp_sid_hash" } as const;

export const sessionStore: SessionStore = {
  async get(key) {
    const { rows } = await pool.query<Row>("select * from sessions where key = $1", [key]);
    return rows[0] ? toRecord(rows[0]) : null;
  },
  async set(key, record, { continuation }) {
    const values = [
      key,
      record.data,
      record.expiresAt,
      record.correlationId ?? null,
      record.iss ?? null,
      record.subHash ?? null,
      record.idpSidHash ?? null,
      record.fields ? JSON.stringify(record.fields) : null,
    ];
    // Only a new session inserts. A refresh or an update that finds no row
    // leaves it so: the session was ended while it ran.
    await pool.query(
      continuation
        ? `update sessions set data = $2, expires_at = $3, correlation_id = $4, iss = $5,
             sub_hash = $6, idp_sid_hash = $7, fields = $8
           where key = $1`
        : `insert into sessions (key, data, expires_at, correlation_id, iss, sub_hash, idp_sid_hash, fields)
           values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      values,
    );
  },
  async delete(key) {
    await pool.query("delete from sessions where key = $1", [key]);
  },
  async withLock(key, fn) {
    const client = await lockPool.connect();
    // The connection sits idle while `fn` runs. If it is lost then, in a
    // failover say, there is no query to reject, and its "error" event would
    // end the process without this listener.
    const lost = (): void => undefined;
    client.on("error", lost);
    try {
      await client.query("select pg_advisory_lock(hashtextextended($1, 0))", [key]);
    } catch (error) {
      client.off("error", lost);
      client.release();
      throw error;
    }
    try {
      return await fn();
    } finally {
      // A connection that can't unlock is closed, and PostgreSQL lets go of its locks.
      const unlocked = await client
        .query("select pg_advisory_unlock(hashtextextended($1, 0))", [key])
        .then(() => true, () => false);
      client.off("error", lost);
      client.release(!unlocked);
    }
  },
  async findMatching(match) {
    // `match` holds only the keys to compare: subHash or idpSidHash, and iss
    // when the caller named one.
    const keys = (Object.keys(columns) as (keyof typeof columns)[]).filter(
      (name) => match[name] !== undefined,
    );
    const where = keys.map((name, i) => `${columns[name]} = $${i + 1}`).join(" and ");
    const { rows } = await pool.query<Row>(
      `select * from sessions where ${where}`,
      keys.map((name) => match[name]),
    );
    return rows.map((row) => ({ key: row.key, record: toRecord(row) }));
  },
};
```

What the lock relies on:

- **Two pools.** A lock holds its connection for as long as the refresh takes,
  up to 30 seconds when the provider is slow. Taken from the pool the queries
  use, the locks would starve the `get` and `set` they are waiting for. The
  lock pool's `max` is how many sessions one instance refreshes at once. One
  more waits `connectionTimeoutMillis` for a connection and then fails with
  `cause: 'store'`, which the browser retries.
- **`lock_timeout`** is how long a refresh waits for a lock another holds, not
  how long a lock lasts. It is longer than the 30 seconds a holder may spend
  on the provider, so a waiter doesn't give up on a holder that is still at
  work. The lock itself has no lifetime: it is held until it is unlocked or
  its connection ends, so an instance that crashes lets go of its locks when
  its connections close.
- **A real session.** The lock belongs to the connection. Connect the lock
  pool to PostgreSQL directly, or through a pooler in session mode: PgBouncer
  in transaction mode hands the unlock to another connection.

PostgreSQL has no TTL index, so sweep on a schedule, hourly say, from
`pg_cron` or the app's own scheduler:

```sql
delete from sessions where expires_at < now();
```

## Your own fields

A store sees a sealed record and hashes, so it can't tell whose session a
record is. `storeFields` puts fields of your choice next to it, in the clear:

```ts
export const auth = createFidesAuth<{ userId: string }>({
  oauthConfig,
  secret,
  sessionStore,
  mapSession: async (tokens, claims, session) => ({
    ...session,
    data: { userId: await userIdFor(claims?.sub) },
  }),
  storeFields: (session) => ({ userId: session.data?.userId ?? null }),
});
```

A value is a string, number, boolean or null, or a list of strings, for roles
say: `storeFields: (session) => ({ roles: session.user?.roles ?? [] })`.
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
same whatever `mapSession` does to `user`. The sessions are found by `sub`
alone. The lookup hash is keyed with the session secret, so it already belongs
to this app, and nothing is asked of the provider: it works while the provider
is down.

Pass `iss` only when sessions from more than one provider share the store and
the secret, and two of them could use the same `sub`. It must then be the ID
token's `iss` to the letter, as in `session.idp.iss`: an issuer spelled any
other way, with another case or a trailing slash, matches no session.

The instance hashes `sub`, asks the store's `findMatching` for the records,
and for each one:

- checks the sealed record's own `sub`, and `iss` when one was given, against
  the request, so a search that returns too much can't end someone else's
  session;
- waits for a refresh of it still running in this process, and deletes it under
  `withLock`, like a logout;
- revokes the refresh token it held last, where the provider has a
  `revocation_endpoint`.

The browsers keep their handle cookies, which then read as `session_not_found`.
It needs a store with `findMatching` and throws a `TypeError` without one,
cookie sessions included, rather than answer that it ended nobody's. Index
`subHash` for it, as the MongoDB example does: the match may hold no `iss`, so
an index that starts with `iss` wouldn't serve it.

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
  the session's tokens are dead. The handle's cookie is deleted with it, on
  every request whose refresh learns of it: the one that ended the session,
  those that shared its call to the provider, and those on other instances
  that waited for the lock and found the record gone. Where cookies can only
  be read, a Next Server Component say, the handle stays and reads as
  `session_not_found`, as it does for a request that comes after. Without `withLock`
  the record is left, since another instance may hold newer tokens.

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
  up on after 30 seconds, and a second or so more when the save has to be
  tried again. A lock that expires sooner lets a second holder
  refresh with the same token.
- Give the lock a timeout, so a crashed holder doesn't wedge the session. What
  happens when `withLock` rejects, for a timeout or anything else, is the same
  as for any other call to the store that fails, see below.

A refresh keeps the handle, so it writes no cookie. It works where cookies
can't be set, such as a Next.js Server Component.

## When the store can't be reached

A store that throws, from `get`, `set`, `delete` or `withLock`, says nothing
about the session, so nothing is ended and no cookie is deleted. What the
caller gets depends on what it asked for:

| Call | Answer |
|---|---|
| `refreshSession`, `refreshInProxy` | `{ ok: false, reason: 'refresh_failed', cause: 'store' }`. The proxy passes the request on. |
| `handleHeartbeat` | `503`, so the browser retries |
| `handleSessionInfo` | `503` without a body: whether there is a session isn't known |
| `handleOidcCallback` | The login fails with `login_failed`, see [When a login fails](../README.md#when-a-login-fails) |
| `handleOidcLogout` | The user stays logged in, and the logout fails with `logout_failed` |
| `readSession`, `tryReadSession`, `getTokens`, `readSessionWithTokens`, `authorizedFetch`, `updateSession`, `clearSession`, `endUserSessions` | Rejects with what the store threw |

The reads reject rather than answer null: null would send a logged-in user to
the login page, and that login would fail on the same store. Let the error
reach the app's error page, or catch it where a page can do without the
session. A refresh answers instead, since it is asked for on the way to
something else, and the session it couldn't refresh is probably fine.

Each failed refresh is a `session.refresh_failed` event with `cause: 'store'`,
logged at `error`.

One moment is worse than the others: the provider has answered a refresh, and
the store won't take the new tokens. With a provider that rotates refresh
tokens, the one the store holds is then spent. So the save is tried twice
more, after 0.2 and 1 second, and if the store still fails the instance keeps
the tokens in memory. The next refresh or update of that session on the same
instance saves them, and a logout revokes them. They don't survive a restart,
and another instance doesn't have them: a refresh there sends the spent token,
and the session ends as for any refresh the provider refuses.

## Security notes

- **Handle.** 256 bits from `crypto.getRandomValues`, hex-encoded, in
  `__Host-session` with `HttpOnly`, `Secure`, `SameSite=Lax` and a max-age
  equal to the time left in the session. The library never logs it.
- **Key.** `SHA-256(handle)`. Neither a leaked store nor a logged key can be
  replayed as a cookie.
- **Bound to its key.** A record is sealed with a key derived from `secret`,
  the provider and client, and its own store key. Copied over another row it
  doesn't open, so someone who can write to the store can't put one user's
  session under their own handle. Nor does it open as a cookie, on an instance
  that runs cookie storage with the same secret.
- **What sealing can't cover.** A row put back under its own key after a
  logout reads again, until `expiresAt`, for whoever kept the handle. Write
  access to the store is trusted to that extent: guard it like the secret.
- **Fixation.** Every login mints a new handle and deletes the record the old
  one pointed at. Only a refresh or an update keeps the handle.
- **Revocation.** Logout and `clearSession` delete the record before the
  cookie. From then on a copied cookie reads as `session_not_found`.
- **Plain fields.** `iss`, the two hashes, `correlationId` and whatever
  `storeFields` returns are stored in the clear. The hashes are HMACs under a
  key derived from `secret`, so a store dump doesn't give up `sub`; your own
  fields are as readable as you make them.
- **At rest.** The sealing keys are derived from the same secret as for
  cookie sessions. Rotating the secret ends stored sessions
  (`unreadable_session`), as it ends cookie ones. So does a change of
  `issuer` or `clientId`.

## Switching from cookies

A browser that still carries a cookie session when the app moves to a store
sends a value that isn't a handle. It reads as `unreadable_session`, which
costs one re-login. The login deletes the cookie chunks.

## What the logs say

`session.created` and `session.refreshed` carry `persistence: "server"` and no
`cookieBytes`. The store adds one rejection reason, `session_not_found`: a
handle was sent, but no live record exists for it. Revoked, expired or evicted.
See [session-events.md](./session-events.md).
