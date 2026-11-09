---
'@eventuras/fides-auth': minor
---

`OAuthConfig.scope` (and provider client configs) accept `string | string[]`;
arrays are joined with spaces on authorize, PAR, refresh and silent login. New
`OAuthConfig.authorizationParameters`, `buildPKCEOptions(config, { parameters })`
and `OidcLoginConfig.authorizationParameters(request)` add extra authorization
parameters. `state`, `code_challenge`, `code_challenge_method`, `redirect_uri`,
`client_id`, `response_type`, `request`, `request_uri` and `nonce` are reserved
and throw. Code that reads `OAuthConfig.scope` must handle an array; `joinScope()`
from `/oauth` returns the string.
