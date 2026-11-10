---
'@eventuras/fides-auth': patch
---

The default `returnTo` validator in `handleOidcLogin` accepts only printable
ASCII, and the 1 KB `returnTo` cap is measured after JSON escaping. If the login
transaction is still too large for a cookie, `handleOidcLogin` stores it without
`returnTo` instead of failing.
