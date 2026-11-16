---
'@eventuras/fides-auth': patch
---

`authorizedFetch` times out a body that stalls while `parse` reads it, also after Node's garbage collector has
run. Node's fetch stops passing an abort on to the body once its own request object has been collected, so the
read could hang for minutes, long past `timeoutMs`. The read is now held to the timeout and to the caller's
signal by `authorizedFetch` itself.
