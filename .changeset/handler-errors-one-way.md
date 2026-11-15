---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

A rate-limited login now goes through `onLoginError` with the code `rate_limited`, and redirects like any other failed login. A logout that fails, because of the rate limit or because the session couldn't be ended, redirects to `defaultRedirectPath` with `?logout=error&error=<code>` instead of answering with text. The new `onLogoutError` option answers it in another way.
