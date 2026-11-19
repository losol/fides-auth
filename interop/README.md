# Interop tests

Runs `@eventuras/fides-auth` against a real OpenID provider,
[oidc-provider](https://github.com/panva/node-oidc-provider), in place of the
stubs the unit tests use. The stubs are written with the library and share its
reading of the specifications. Here the other side checks every request by its
own code: the client assertion, PAR, PKCE, the DPoP proofs and their nonces,
the binding of the code to `dpop_jkt`, the tokens it then accepts at UserInfo,
and the logout token it sends for a back-channel logout.

```bash
pnpm build                                        # the tests load the built package
pnpm --filter @eventuras/fides-auth-interop test
```

The provider and a small app run over https on loopback ports, with a
certificate made for the run that only the test process trusts. Nothing is
stubbed and nothing leaves the machine.

The same scenarios run in four setups:

| Setup | Client | Provider |
|---|---|---|
| A secret and bearer tokens | `client_secret_basic` | defaults |
| `private_key_jwt`, PAR and DPoP | `dpop`, `usePar` | defaults |
| DPoP with a nonce | `dpop`, `usePar` | insists on `DPoP-Nonce` |
| FAPI 2.0 on both sides | `profile: 'fapi2'` | its FAPI 2.0 profile |

oidc-provider and openid-client have the same author, so the two share a
reading of the specifications too. It is a real server, not a proof of
conformance: for that there is the OpenID Foundation's conformance suite.

The package is private and is never published.
