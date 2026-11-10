---
'@eventuras/fides-auth': patch
---

At most three login transaction cookies (`oauth_tx_0`–`oauth_tx_2`) are kept; a
fourth login evicts the oldest. A `returnTo` over 1 KB is dropped, and
`persistTransaction` throws `CookieTooLargeError` instead of setting a cookie the
browser would drop. `clearTransaction` now takes the secret.
