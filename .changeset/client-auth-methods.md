---
'@eventuras/fides-auth': minor
---

`OAuthConfig` and `ClientCredentialsConfig` take `clientAuth`: `client_secret_post`
(default), `client_secret_basic`, `private_key_jwt` with `privateKey`, or `none`
(`OAuthConfig` only). The discovery cache now tells entries apart by method and key.

Breaking (types only): `config.clientSecret` is no longer always a `string`. Narrow
on `clientAuth` before reading it. Configs that set `clientSecret` without
`clientAuth` work as before.
