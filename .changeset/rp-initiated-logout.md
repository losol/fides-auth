---
"@eventuras/fides-auth": minor
"@eventuras/fides-auth-next": minor
---

RP-initiated logout: send `id_token_hint`.

`Tokens.idToken` now holds the raw ID token — populated by `buildSessionFromTokens`,
kept fresh by `refreshSession`, and stored in its own `session_it` cookie so no cookie
has to carry two large JWTs. `readIdToken` reads it independently of session validity,
since logout needs the hint after the access token has expired.

`buildOidcLogoutUrl(oauthConfig, options)` accepts `idTokenHint`, `state`,
`logoutHint` and `includeClientId` alongside `postLogoutRedirectUri`. A string second
argument still means `postLogoutRedirectUri`, and it still returns `null` when the
provider advertises no `end_session_endpoint`.

New `handleOidcLogout` handler in `@eventuras/fides-auth/server` — `POST`-only by
default and same-origin checked via `Sec-Fetch-Site`/`Origin` — wrapped for Next.js at
`@eventuras/fides-auth-next/oidc-logout`. See
`packages/fides-auth/docs/rp-initiated-logout.md` for the full parameter set, where
the ID token is stored, and why `client_id` is still sent.

Also fixes the `./oidc-callback` and `./oidc-login` subpath exports in
`@eventuras/fides-auth-next`, which pointed at files the build never emitted.

`persistSession` now size-checks every cookie value before writing any of them.
Previously a value that exceeded the browser limit threw part-way through, leaving the
new session cookie next to the previous user's tokens.
