---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

A refresh that ends a stored session, because the provider refused it for good, deletes the session cookie
too, where cookies can be set. The browser kept sending a handle that found no session, and a proxy that
checks for the cookie took the user for signed in.
