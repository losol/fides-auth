---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': minor
---

The session is the login; access-token freshness is the caller's concern. An
expired access token no longer reads as "no session".

Previously every session read treated an expired access token as "logged out":
`refreshSessionInStore` could never refresh a token that had actually expired,
and the heartbeat endpoint answered 401 — the client then showed "session
expired, log in again" even though the refresh token was still perfectly valid.
Any missed proactive-refresh window (hidden tab, laptop asleep, throttled
timers, a transient network error) logged the user out.

Now `decodeSessionCookies` / `readSession` / `getCurrentSession` return the
session whenever the session cookie itself decrypts and validates, with the
stored access token attached whether it is fresh or expired. The refresh paths
(`refreshSessionInStore`, `handleHeartbeat`, `refreshCurrentSession`) therefore
recover an expired-but-refreshable session instead of discarding it; a 401 from
the heartbeat once again means what it should — no session, or a dead refresh
token.

Callers that hand `session.tokens.accessToken` to an API must check freshness
first (`accessTokenExpires` / `accessTokenExpiresAt`) or refresh on 401; the
library no longer withholds the session to enforce this.

Legacy single-cookie sessions (written before the split-cookie format) are
supported only while their embedded access token is still valid: active users
migrate seamlessly on their next refresh, while stale legacy sessions read as
"no session" and cost one re-login. Old sessions are dropped, not migrated.
