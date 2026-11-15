---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

`updateSession` could undo a refresh. An update that overlapped a refresh saved the session it had read before
it, with the refresh token the refresh had just spent, so the next refresh failed with `invalid_grant`. A
refresh and an update of one session now take turns, in the process and under the store's lock, and each starts
from what the other saved.
