---
'@eventuras/fides-auth': patch
---

`handleOidcCallback` redirects an IdP error response (`?error=access_denied`) to
`defaultRedirectPath` with `?login=error&error=<code>` instead of returning 500.
The login transaction cookies are now cleared after every callback, not only on
success.
