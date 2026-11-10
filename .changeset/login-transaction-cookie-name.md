---
'@eventuras/fides-auth': patch
---

The login transaction cookie is `__Host-oauth_tx_<n>`, or a plain non-Secure
`oauth_tx_<n>` when `redirect_uri` is http. The transaction helpers take
`{ secure }` for custom flows. The callback passes on only `[a-z0-9_]` error
codes (others become `idp_error`), and an IdP error after the login has ended
redirects with `error=login_expired` instead of returning 400.
