# Server-side sessions

By default fides-auth seals the whole session, tokens included, into the
`__Host-session` cookie, cut into up to three chunks. That stops working when
the tokens are bigger than three cookies. OpenIddict, for one, encrypts access
and refresh tokens (JWE). Once fides-auth seals them again, the session no
longer fits, and the callback answers 431.

A `SessionStore` is the opt-in fix: the session lives in a store you provide,
and the browser holds one small cookie with a random handle. It also buys three
things a cookie can't offer: real revocation, one refresh per session across
instances, and a cookie that is worthless without the store.

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
  set(key: string, record: StoredSession): void | Promise<void>;
  delete(key: string): void | Promise<void>;
  withLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
}

interface StoredSession {
  data: string;           // the sealed session; opaque to the store
  expiresAt: string;      // ISO 8601, absolute
  correlationId?: string; // so a record can be found from a log line
  iss?: string;           // the ID token's issuer
  subHash?: string;       // HMAC of the ID token's sub, never sub itself
  idpSidHash?: string;    // HMAC of the ID token's sid claim
}
```

Keys are `SHA-256(handle)` as hex, never the handle itself. Save every field the
library sets: `iss`, `subHash` and `idpSidHash` are what finds a user's sessions
for back-channel logout. On the library's side:

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

export const sessionStore: SessionStore = {
  async get(key) {
    const doc = await sessions.findOne({ _id: key });
    if (!doc) return null;
    const { _id, expiresAt, ...record } = doc;
    return { ...record, expiresAt: expiresAt.toISOString() };
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
refresh tokens: both spend the token, one wins, and the other now holds a dead
one. OpenIddict goes further and treats the reuse as theft, revoking the whole
authorization. The instance:

- joins concurrent refreshes of one session within one process into a single
  token request, and hands every caller the same result;
- takes `store.withLock(key)` when the adapter provides it, and re-reads the
  record under the lock, so a refresh another instance already did is reused
  rather than repeated;
- on `invalid_grant`, re-reads once more before giving up, in case a concurrent
  refresh elsewhere spent the token first.

Implement `withLock` when you run more than one instance. Give the lock a
timeout, so a crashed holder doesn't wedge the session.

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
