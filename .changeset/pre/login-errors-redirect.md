---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

A login that fails always redirects to `defaultRedirectPath` with `?login=error&error=<code>`. A callback
without a live login answered 400 with English text, a failed code exchange 500, and a session too large for
the cookies 431; they now carry `login_expired`, `login_failed` and `session_too_large`. `handleOidcLogin` no
longer throws when the login can't be started, because the provider can't be reached say: it redirects with
`login_unavailable`. `onLoginError` answers a failed login in another way.
