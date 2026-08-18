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
| `session.created`        | info              | `hasRefreshToken`    | `sid`, `scopes`, `expiresIn`, `cookieBytes`      |
| `session.refreshed`      | info              | `rotatedRefreshToken`| `sid`, `expiresIn`, `cookieBytes`               |
| `session.rejected`       | per `reason`      | `reason`             | `sid`, `source`                                  |
| `session.refresh_failed` | per `cause`       | `cause`              | `sid`, `status`, `accessTokenExpiresAt`          |
| `session.cleared`        | info              | `trigger`            | `sid`                                            |

A "may be absent" field is *omitted* when unknown, never logged as `null` —
`logSessionEvent` drops undefined values, so an absent field costs the log
backend nothing. Write queries that tolerate absence.

`sid` may be absent on every event: sessions created before `Session.sid` existed
carry none, and a request rejected for `no_session_cookie` or
`unreadable_session` never had a session to take one from. It fills in for
everyone after one re-login.

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
| `stale_legacy_session` | info  | A pre-split single-cookie session. Costs one re-login.          |
| `refresh_failed`       | info  | The provider rejected the refresh token. See `cause`.           |
| `unreadable_session`   | warn  | A cookie arrived but would not decrypt. Corruption, or a rotated secret. |
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
| `idp_error`     | error | The provider answered with an error or something unparseable.  | Probably fine |

Only `invalid_grant` ends a session. The heartbeat endpoint answers `401` for it
and `503` for the other two, so a provider outage no longer logs out users whose
sessions were valid.

## `sid` — the correlation id

Minted when the session is created, carried across refreshes, and attached to
every event above. It is **not** derived from the refresh token: a hash of that
would change every time the provider rotates it — on every refresh for a default
Keycloak — and following one session through its whole life is the point.
Rotation stays visible through `rotatedRefreshToken` instead.

> **Cardinality.** `sid` is high-cardinality by design. Keep it a log *field*.
> Never promote it to a Loki label, a Prometheus dimension or a Datadog tag — one
> series per session will melt the index. `event`, `reason`, `cause` and
> `trigger` are the low-cardinality fields; group on those.

## Questions these answer

**Which path ended this session?**

```logql
{app="web"} | json | sid = `a3f81c92`
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

**Are sessions about to outgrow the cookie?**

```logql
{app="web"} | json | event =~ `session\.(created|refreshed)` | cookieBytes > 3500
```

Browsers drop a cookie over ~4096 bytes silently, producing a login that appears
to work and then doesn't.

## Suggested alerts

| Condition | Why |
| --------- | --- |
| any `session.created` with `hasRefreshToken=false` | Guaranteed logouts at access-token TTL. |
| `session.refresh_failed` with `cause=idp_error` above baseline | The provider is failing. |
| `session.rejected` with `reason=unreadable_session` above ~0 | Corruption, or a secret rotated without draining sessions. |
| `cookieBytes` p99 approaching 4096 | Sessions about to break silently. |

Rate-of-`invalid_grant` is deliberately *not* on this list — it rises whenever an
SSO lifetime ends, which is normal.

## Browser events

`createHeartbeat` and `startSessionMonitor` write to the browser console, which
production never sees. Both take an `onEvent` callback carrying the same names
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

`tryReadSession` and `tryRefreshSessionInStore` return the reason and cause
instead of a bare `null`, so your own proxy and status routes can log the same
words the library does:

```ts
import { tryReadSession } from "@eventuras/fides-auth/server";
import { SESSION_EVENT, logSessionEvent } from "@eventuras/fides-auth/session-events";

const { session, reason } = await tryReadSession(cookies, secret);
if (!session) {
  logSessionEvent(logger, {
    event: SESSION_EVENT.REJECTED,
    reason,
    source: "proxy",
  });
  return unauthorized();
}
```

`logSessionEvent` picks the level from the policy above, so every caller stays
consistent without repeating it.
