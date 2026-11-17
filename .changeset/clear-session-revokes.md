---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

`clearSession` called where cookies can't be written, after the response's cookies were taken with `fetchCookieStore` or in a Next Server Component, deleted a stored session's record and then threw on the cookie, before the refresh token was revoked. The session was gone and its token lived on at the provider. The token is now revoked first, and then the call rejects with what the cookie store threw, as before: the cookie is still in the browser, where it finds no session. `handleOidcLogout` in the same place goes on to the provider, since the user is logged out. With cookie storage nothing changes: the cookie is the session, so nothing is ended and nothing revoked.
