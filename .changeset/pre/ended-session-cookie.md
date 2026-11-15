---
'@eventuras/fides-auth': patch
---

When a refresh ends a stored session, every request that was waiting for it has its session cookie deleted,
not only the one that asked the provider. Requests that shared the refresh in the same process kept the cookie,
and so did a request on another instance that waited for the store's lock and then found the record gone.
