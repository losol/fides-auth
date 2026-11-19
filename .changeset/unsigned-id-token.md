---
'@eventuras/fides-auth': patch
---

An ID token that is not signed, with `alg: "none"`, is refused at the code exchange and at a refresh, whatever the provider's metadata lists. openid-client checks an ID token's `alg` against the provider's `id_token_signing_alg_values_supported`, so a provider that listed `none` there had an unsigned ID token taken. The login then fails as `login_failed`, and a refresh as `idp_error`. Found by the OpenID conformance suite's basic client plan.
