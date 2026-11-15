---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`mapRefresh` changes the session a refresh leaves, the way `mapSession` does at login. What `mapSession` put
in `data` from the ID token claims stayed as it was at login; with `mapRefresh` it can follow each refresh. It
is also where roles that only the access token carries are set again. It can't fail the refresh: if it throws,
the error is logged and the session is saved as the refresh left it.
