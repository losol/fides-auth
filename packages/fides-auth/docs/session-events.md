# Session events

Every logout looks the same from the outside: the user says "I had to log in
again". This page describes the events fides-auth emits so a production operator
can tell *which* path ended a session — without reading library source.

## The vocabulary

Event names are `<area>.<outcome>`, dotted and past tense. Dotted so a dashboard
can match a whole area with one prefix (`event=~"session\\..*"`); past tense
because every event records something that already happened.

The name is a **field**, not the message. Query on `event`, not on free text —
messages are for humans and may be reworded, names are the contract.

| `event`                  | Level             | Always present       | May be absent                                   |
| ------------------------ | ----------------- | -------------------- | ----------------------------------------------- |
| `session.created`        | info              | `hasRefreshToken`    | `correlationId`, `scopes`, `expiresIn`, `cookieBytes`, `persistence` |
| `session.refreshed`      | info              | `rotatedRefreshToken`| `correlationId`, `expiresIn`, `cookieBytes`, `persistence` |
| `session.rejected`       | per `reason`      | `reason`             | `correlationId`, `source`                        |
| `session.refresh_failed` | per `cause`       | `cause`              | `correlationId`, `status`, `accessTokenExpiresAt` |
| `session.cleared`        | info              | `trigger`            | `correlationId`                                  |

A "may be absent" field is *omitted* when unknown, never logged as `null` —
the library drops undefined values, so an absent field costs the log backend
nothing. Write queries that tolerate absence.

`correlationId` is absent when no session was read to take it from, as for a
request rejected with `no_session_cookie` or `unreadable_session`.

Every read of a session, `readSession` and `refreshInProxy` among them, emits
`session.rejected` when a cookie is there and doesn't open: `unreadable_session`
and `unsupported_session_version`. After a change that makes old sessions
unreadable that is every user's cookie, once for each request until they log in
again, so a deploy that logs everyone out shows as a burst. The other reasons
are ordinary, and only the heartbeat reports them.

Every 1.x reads a session written by any 1.x. A session of another version is
never read as one of this, and never silently dropped either.

`session.cleared` has `trigger: "logout"` for a logout, `clearSession` or
`endUserSessions`, and `trigger: "rejected"` when the library ended a stored
session because the provider refused its refresh for good. That one follows a
`session.refresh_failed` with `cause: "invalid_grant"`.

Import the names rather than typing them, so a rename is a compile error instead
of a silently dead dashboard:

```ts
import { SESSION_EVENT } from "@eventuras/fides-auth/session-events";
```

### `reason` — why a session could not be used

One vocabulary for the whole package. A proxy, a status route and the heartbeat
endpoint all report the same word for the same situation.

| `reason`               | Level | Means                                                          |
| ---------------------- | ----- | -------------------------------------------------------------- |
| `no_session_cookie`    | debug | No cookie was sent. The ordinary anonymous case.                |
| `session_not_found`    | info  | A handle was sent but the server store has no live record: revoked, expired or evicted. Server persistence only. |
| `session_expired`      | info  | The session's lifetime has run out. Refreshes don't extend it, so the user logs in again. |
| `refresh_failed`       | info  | The provider rejected the refresh token. See `cause`.           |
| `unreadable_session`   | warn  | A cookie arrived but would not decrypt. Corruption, or a changed `issuer` or `clientId`, or a secret replaced without keeping the old one in the list. |
| `unsupported_session_version` | error | The session opened, but a later major of the library wrote it. A rollback, or two versions running side by side. Comes with `version`. |
| `no_refresh_token`     | warn  | The session has no refresh token — usually `offline_access` was never granted. |

The level follows the **reason**, not the event. A single level for the whole
event would be wrong in both directions: an anonymous request hitting a protected
route is not a warning, and a session cookie that won't decrypt is not routine.
Getting this wrong is how a warn stream becomes unreadable and an operator
concludes there is "nothing in the logs".

### `cause` — why a refresh failed

| `cause`         | Level | Means                                                         | Session |
| --------------- | ----- | ------------------------------------------------------------- | ------- |
| `invalid_grant` | info  | The provider says the refresh token is dead.                   | Over    |
| `transport`     | warn  | The provider was never reached — DNS, TCP, TLS, timeout.       | Probably fine |
| `idp_error`     | error | The provider answered with an error or something unparseable, or with an ID token for another user. | Probably fine |
| `store`         | error | The session store failed, or `withLock` couldn't take the lock. | Probably fine |

Only `invalid_grant` ends a session. The heartbeat endpoint answers `401` for it
and `503` for the others, so a provider or store outage doesn't log out users
whose sessions were valid.

## `correlationId`

Minted when the session is created, carried across refreshes, and attached to
every event above. It is **not** derived from the refresh token: a hash of that
would change every time the provider rotates it — on every refresh for a default
Keycloak — and following one session through its whole life is the point.
Rotation stays visible through `rotatedRefreshToken` instead.

It is not the provider's `sid` claim. The session keeps that one as `idp.sid`.

> **Cardinality.** `correlationId` is high-cardinality by design. Keep it a log *field*.
> Never promote it to a Loki label, a Prometheus dimension or a Datadog tag — one
> series per session will melt the index. `event`, `reason`, `cause` and
> `trigger` are the low-cardinality fields; group on those.

## Questions these answer

**Which path ended this session?**

```logql
{app="web"} | json | correlationId = `a3f81c92`
```

One query, whole lifetime: creation, every refresh, and whatever finally ended it.

**Was the refresh token really dead, or did we give up early?**

```logql
sum by (cause) (
  count_over_time({app="web"} | json | event = `session.refresh_failed` [1h])
)
```

`invalid_grant` climbing means sessions genuinely expiring. `transport` or
`idp_error` climbing means an infrastructure problem wearing a logout costume.

**Does the provider rotate refresh tokens?**

```logql
sum by (rotatedRefreshToken) (
  count_over_time({app="web"} | json | event = `session.refreshed` [1h])
)
```

If this is `true`, a lost cookie write bricks the session — worth knowing before
you debug one.

**Did the provider grant `offline_access`?**

```logql
{app="web"} | json | event = `session.created` | hasRefreshToken = `false`
```

Any hit here guarantees logouts at access-token TTL. Alert on it: it should be
zero.

**Are sessions about to outgrow the cookies?**

```logql
{app="web"} | json | event =~ `session\.(created|refreshed)` | cookieBytes > 10000
```

The session is cut into at most three cookies of up to 4096 bytes, and
`cookieBytes` counts them all. A session that doesn't fit fails at login with
431, rather than being dropped by the browser. With a
[`sessionStore`](./server-sessions.md) the cookie holds only a handle, so
`cookieBytes` is absent and `persistence` is `server`.

## Suggested alerts

| Condition | Why |
| --------- | --- |
| any `session.created` with `hasRefreshToken=false` | Guaranteed logouts at access-token TTL. |
| `session.refresh_failed` with `cause=idp_error` above baseline | The provider is failing. |
| `session.refresh_failed` with `cause=store` above ~0 | The session store or its lock is failing. |
| `session.rejected` with `reason=unreadable_session` above ~0 | Corruption, or a secret, `issuer` or `clientId` changed without draining sessions. |
| any `session.rejected` with `reason=unsupported_session_version` | Sessions written by a later major are reaching this one: a rollback, or a fleet on two versions. |
| `cookieBytes` p99 approaching 12000 | Sessions about to stop fitting: logins start failing with 431. |

Rate-of-`invalid_grant` is deliberately *not* on this list — it rises whenever an
SSO lifetime ends, which is normal.

## Browser events

`createHeartbeat` and `startSessionMonitor`, from `@eventuras/fides-auth/browser`,
write to the browser console, which production never sees. Both take an `onEvent` callback carrying the same names
and the same `reason` vocabulary:

```ts
useHeartbeat({
  onEvent: (event) => navigator.sendBeacon("/api/telemetry", JSON.stringify(event)),
});
```

The library ships no transport — where these go, and whether they go anywhere, is
yours to decide.

The shapes differ where the browser genuinely knows less. It never learns *why* a
refresh failed server-side, only the status it got back, so there is no `cause`
on the client — just `status` and `attempt`. The `reason` on a client
`session.rejected` is whatever the heartbeat endpoint put in its 401 body, and an
unrecognised value is dropped rather than passed through.

## Consuming the vocabulary

The library logs these events through its `logger`. To send them somewhere
else as well, a metrics pipeline say, pass `onSessionEvent` to
`createFidesAuth`: it gets every event above as an object, with the same fields.

`tryReadSession` and `refreshSession` on the `createFidesAuth` instance return
the reason and cause instead of a bare `null`, so your own proxy and status
routes can log the same words the library does:

```ts
import { SESSION_EVENT } from "@eventuras/fides-auth/session-events";

const { session, reason } = await auth.tryReadSession(cookies);
if (!session) {
  logger.info({ event: SESSION_EVENT.REJECTED, reason, source: "proxy" }, "Session rejected");
  return unauthorized();
}
```

Take the level from the `reason` table above, as the library does, so your
lines and the library's agree.

`refreshSession` returns `cause` on failure, so a route can answer 503 rather
than end a session over a provider blip.

In Next.js, `createFidesAuth` from `@eventuras/fides-auth-next` has the same
members without the cookie argument. Its `tryReadSession` is cached per render
together with `readSession`, so asking for the reason costs no extra decrypt:

```ts
const { session, reason } = await auth.tryReadSession();
```
