---
'@eventuras/fides-auth': patch
---

`validateReturnUrl` now uses the default path when a `returnTo` such as `/.//evil.test` resolves to a path that starts with `//`, which code that navigates to the pathname could take for another site. The cookie reader of `fetchCookieStore` trims only space and tab around names and values, as a browser does, and skips a name that is not a valid cookie name. A `Cookie` header with a name padded by a non-breaking space can no longer stand in for a `__Host-` cookie. A `returnTo` is kept in the login cookie only up to 512 serialized bytes, down from 1024, so that a few logins started from another site stay under the header limit of common web servers.
