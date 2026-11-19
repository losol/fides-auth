# Conformance tests

Runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)'s
relying-party tests against `@eventuras/fides-auth`. The suite plays the
OpenID provider, and a small script logs in to it with the library, once for
each test module. In some modules the suite behaves; in most it answers with
something a client must refuse, and then watches whether the client stops.

It is the same software the OpenID Foundation certifies with, run locally in
Docker. The unit tests use stubs written with the library, and the
[interop tests](../interop) use a provider by the author of `openid-client`.
This is the third opinion, from people who wrote neither.

**It is not a certification.** See [what it does not prove](#what-it-does-and-does-not-prove).

## Running it

Docker with Compose, Node 22.19 or later, and the built packages:

```bash
pnpm install
pnpm build                                              # the script loads the built package
pnpm --filter @eventuras/fides-auth-conformance conformance
```

That starts the suite (`docker-compose.yml`), waits for it, runs the plan,
prints a table, stops the suite and removes its containers. It exits with 1
when a module failed, and 2 when the run itself broke.

The first run pulls about a gigabyte of images. After that a run takes about
three minutes: half a minute for the suite to start, and a few seconds for each
of the 34 modules, most of it the suite waiting to see that the client really
has stopped.

It is not part of `pnpm test` and no pull request runs it. The
[`Conformance` workflow](../.github/workflows/conformance.yml) runs it once a
week and when started by hand, and uploads `results/` as an artifact.

| Variable | |
|---|---|
| `CONFORMANCE_CLIENT_TYPES` | `oidc`, `plain_oauth` or both with a comma. Both by default. |
| `CONFORMANCE_KEEP_SUITE=1` | Leaves the suite running afterwards, to look at a test in its UI at <https://localhost:8443>. Stop it with `docker compose -f conformance/docker-compose.yml down`. |
| `CONFORMANCE_SUITE_URL` | Uses a suite that is already running there, and starts none. For a suite built from source. It must run in its dev mode, where its API needs no token. |
| `CONFORMANCE_SUITE_CA` | With `CONFORMANCE_SUITE_URL`: the PEM file of that suite's certificate. |

A run leaves `results/`, which is not committed:

- `results.md` and `results.json`: the table, and for each module where the
  client stopped and why, and the suite's own failures and warnings.
- `logs/`: the suite's full log of every module, each check it made.
- `suite-server.log`: what the suite's server printed.

## What is run

The plan is `fapi2-security-profile-final-client-test-plan`, the relying-party
tests for the final FAPI 2.0 Security Profile, with the variant

| | |
|---|---|
| `fapi_profile` | `plain_fapi` |
| `client_auth_type` | `private_key_jwt` |
| `sender_constrain` | `dpop` |
| `authorization_request_type` | `simple` |
| `fapi_client_type` | `oidc` (23 modules), then `plain_oauth` (11 modules) |

which is what `profile: 'fapi2'` of the library is: `private_key_jwt`, PAR,
PKCE and DPoP. The plan itself fixes the rest: an unsigned authorization
request and a plain response.

The client under test is [`src/client.ts`](src/client.ts). It does what an app
does and nothing more: `handleOidcLogin`, the browser's trip to the provider,
`handleOidcCallback`, then UserInfo (when there is an ID token) and
`authorizedFetch` to the suite's accounts endpoint, which is what ends a test
that is meant to pass. It has no knowledge of the modules. When the suite
sends a wrong `iss`, an ID token signed with `none`, or a callback without
`state`, the library refuses it or it doesn't.

A module that is meant to fail passes when the client makes no further
request, so a client that is simply broken would pass those. Two things guard
against that. Every one of those modules gets a whole, checked login up to the
bad answer, and the suite fails it on a bad client assertion, PAR request,
PKCE or DPoP proof on the way. And the runner ([`src/run.ts`](src/run.ts))
knows for each module where the client is meant to stop (at the login, at the
callback, or not at all), and fails the module when it stopped somewhere else,
whatever the suite said. The reason the library gave is in `results.md`.

### The suite's version

The suite is pinned to **`release-v5.3.4`** (October 2026), the latest release
when this was written, by the tags of its two images in `docker-compose.yml`.
It is pinned because the suite gets new checks all the time: a run that fails
should mean the library changed, not the suite. Moving to a newer release is a
change of its own: update the tag on both images, `SUITE_RELEASE` in
`src/suite.ts` and this paragraph, run it, and add any new modules to
`EXPECTED` in `src/run.ts`.

The images are the ones the suite's own pipeline publishes to
`registry.gitlab.com/openid/conformance-suite`. They are pinned by tag, not by
digest.

## What it does and does not prove

It shows that, against this release of the suite and in this one variant, the
library:

- sends an authorization request, a client assertion, a PAR request, PKCE and
  DPoP proofs (with and without a server nonce, at the token endpoint and at
  the resource server) that the suite accepts;
- refuses a discovery document with the wrong issuer;
- refuses an authorization response with a wrong or missing `iss`, or a wrong
  or missing `state`;
- refuses an ID token with a wrong or missing `iss`, `aud`, `exp` or `nonce`,
  an untrusted second audience, or signed with `none` or `RS256`;
- takes a token response without `expires_in`, a `token_type` in odd case, and
  a `DPoP` challenge in odd case.

It does not show:

- **Certification.** That is a submission to the OpenID Foundation: the tests
  run against the suite they host, and the logs are sent in with a signed
  declaration. A green run here is neither, and gives no right to call
  anything certified.
- **Anything about your application.** The script is the app here. The
  routes, the cookies, the session store and the redirect URI of a real one are
  not in the picture.
- **The other variants.** Not mTLS (the library has none), not signed request
  objects or JARM (FAPI 2.0 Message Signing, not implemented), not the other
  client authentication methods, not the basic OpenID Connect relying-party
  plans, not logout.
- **What the suite doesn't look at.** It checks the client's requests and
  whether it stops. It can't see how the session is stored, whether tokens
  leak into logs, or what the app does with the claims.

## Without the registry

If the images can't be pulled, the suite can be built from its source at the
same tag, with its own instructions (`mvn -B clean package -DskipTests=true`,
then its `Dockerfile` and `nginx/Dockerfile`). Tag the two images with the
names in `docker-compose.yml` and run as above, or start the suite its own way
and point `CONFORMANCE_SUITE_URL` and `CONFORMANCE_SUITE_CA` at it. The
suite's base URL must then be one its certificate is valid for.
