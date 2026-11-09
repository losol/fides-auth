---
'@eventuras/fides-auth': minor
---

Each login is now one sealed `oauth_tx_<hash>` cookie (state, PKCE verifier,
returnTo, start time), replacing `oauth_state`, `oauth_code_verifier` and
`returnTo`. The callback rejects it after 10 minutes. New in `/server`:
`createTransaction`, `persistTransaction`, `readTransaction`, `clearTransaction`,
`validateCallback`.

Breaking: `handleOidcLogin` takes `secret` (default `SESSION_SECRET`); pass both
handlers the same one. Code reading the old cookies must use the new helpers.
Logins in progress during the upgrade must be restarted.
