---
'@eventuras/fides-auth': patch
---

`authorizedFetch` with a `signal` no longer needs `AbortSignal.any`, so it works
on Node before 18.17.
