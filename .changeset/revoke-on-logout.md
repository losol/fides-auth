---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

Logout and `clearSession` revoke the session's refresh token (RFC 7009) when the provider has a
`revocation_endpoint`, so a refresh that was running at logout, or a copy of the cookie, can't renew
the session. A refresh running in the same process is waited for, and the token it brought back is
the one revoked. With a `sessionStore`, the session ends under `withLock`, so a refresh on another
instance can't save it again. `OidcClient` gets `revoke(token, { tokenTypeHint })`.
