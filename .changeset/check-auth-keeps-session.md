---
'@eventuras/fides-auth': minor
---

`checkAuth` no longer logs the user out when the session check fails. A network error or a 5xx, such as the 503
`handleSessionInfo` answers while the session store is down, is not an answer, so a session the browser store holds
is kept, with the failure as `error`, until a check answers. That is what the session monitor already did. A check
that answers "no session" logs out as before, and a store without a session still ends logged out with the `error`.
