---
'@eventuras/fides-auth': patch
---

A login callback opened again by a browser that is already logged in, with the back button or a reload, now redirects to `defaultRedirectPath` instead of failing with `login_expired`. A browser without a session still gets `login_expired`.
