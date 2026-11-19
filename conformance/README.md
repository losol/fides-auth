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

That starts the suite (`docker-compose.yml`), waits for it, runs the plans,
prints a table, stops the suite and removes its containers. It exits with 1
when a module failed, and 2 when the run itself broke.

The first run pulls about a gigabyte of images. After that a run takes about
four minutes: half a minute for the suite to start, and a few seconds for each
of the 56 modules, most of it the suite waiting to see that the client really
has stopped.

It is not part of `pnpm test` and no pull request runs it. The
[`Conformance` workflow](../.github/workflows/conformance.yml) runs it once a
week and when started by hand, and uploads `results/` as an artifact.

| Variable | |
|---|---|
| `CONFORMANCE_PLANS` | `fapi2`, `basic`, `logout`, or several with a comma. All three by default. |
| `CONFORMANCE_CLIENT_TYPES` | For `fapi2`: `oidc`, `plain_oauth` or both with a comma. Both by default. |
| `CONFORMANCE_KEEP_SUITE=1` | Leaves the suite running afterwards, to look at a test in its UI at <https://localhost:8443>. Stop it with `docker compose -f conformance/docker-compose.yml down`. |
| `CONFORMANCE_SUITE_URL` | Uses a suite that is already running there, and starts none. For a suite built from source. It must run in its dev mode, where its API needs no token. |
| `CONFORMANCE_SUITE_CA` | With `CONFORMANCE_SUITE_URL`: the PEM file of that suite's certificate. |
| `CONFORMANCE_RP_HOST`, `CONFORMANCE_RP_BIND` | For `logout`: the name the suite reaches this machine by, and the address the client listens on. See [back-channel logout](#back-channel-logout). |

A run leaves `results/`, which is not committed:

- `results.md` and `results.json`: the table, and for each module where the
  client stopped and why, and the suite's own failures and warnings.
- `logs/`: the suite's full log of every module, each check it made.
- `suite-server.log`: what the suite's server printed.

## What is run

Three test plans, each with the client it is for. The client under test is
[`src/client.ts`](src/client.ts). It does what an app does and nothing more:
`handleOidcLogin`, the browser's trip to the provider, `handleOidcCallback`,
then UserInfo (when there is an ID token) and, for FAPI, `authorizedFetch` to
the suite's accounts endpoint. It has no knowledge of the modules. When the
suite sends a wrong `iss`, an ID token signed with `none`, or a callback
without `state`, the library refuses it or it doesn't.

A module that is meant to fail passes when the client makes no further
request, so a client that is simply broken would pass those. Two things guard
against that. Every one of those modules gets a whole, checked login up to the
bad answer, and the suite fails it on a bad request on the way. And the runner
([`src/run.ts`](src/run.ts)) knows for each module where the client is meant to
stop (`expected`, for each plan), and fails the module when it stopped
somewhere else, whatever the suite said. A module the runner doesn't know
fails too. The reason the library gave is in `results.md`.

### FAPI 2.0 Security Profile

`fapi2-security-profile-final-client-test-plan`, the relying-party tests for
the final FAPI 2.0 Security Profile, with the variant

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

### Basic OpenID Connect relying party

`oidcc-client-basic-certification-test-plan`, the 14 modules of the Basic RP
certification profile: the code flow with `client_secret_basic` and bearer
tokens, which is how most apps use the library. The plan fixes
`response_type=code`, `response_mode=default` and
`client_auth_type=client_secret_basic`. The two variants it leaves open are

| | |
|---|---|
| `client_registration` | `static_client`: the library has no dynamic registration |
| `request_type` | `plain_http_request`: it sends no request object |

The client is `createFidesAuth` with an issuer, a client id and secret, a
redirect URI and the scope `openid profile email`, and nothing else: the
library's defaults. A test that is meant to pass ends at UserInfo.

In three modules the suite takes either answer from the client, and the table
pins the one the library gives. All three come from the same thing:
openid-client checks the claims and the `alg` of an ID token that comes
straight from the token endpoint over TLS, and not its signature, which OpenID
Connect Core 3.1.3.7 allows.

| Module | The library | The suite |
|---|---|---|
| `kid-absent-multiple-jwks` | Logs in: it doesn't have to choose a key. | PASSED either way |
| `idtoken-sig-none` | Refuses the unsigned ID token, though the suite's metadata lists `none` among its algorithms. | SKIPPED when the client refuses, PASSED when it goes on |
| `invalid-sig-rs256` | Logs in with the wrong signature and calls UserInfo, which the suite then answers with an error. | SKIPPED: "clients are not required to validate the signatures on id tokens received over a TLS protected connection" |

`userinfo-invalid-sub` is the other way round: the suite ends the test at the
UserInfo request and can't see what the client made of the answer. That the
library refused the response for another `sub` is the runner's check alone.

### Back-channel logout

`oidcc-client-back-channel-logout-rp-basic`, the 8 modules of the Back-Channel
RP certification profile for a code-flow client, with `static_client`,
`plain_http_request`, `client_secret_basic` and `response_mode=default`.

The client is the basic one with `createMemorySessionStore()` and a small http
server whose one route hands the request to `handleBackChannelLogout`. After
the login the browser goes to the suite's end-session endpoint, with the URL of
`oidc.logoutUrl`. The suite posts a logout token to the route before it
answers, a good one in the first module and one to refuse in the other seven,
and checks the status: 200, or 400.

The browser does not go through `handleOidcLogout`. That ends the session
before the browser leaves, and the logout token would then find nothing to
end. Here the session is left alone, as when the user logs out of the provider
from another app, so the runner can check what the suite can't see: after a
200 the session must be gone (`logged-out`), and after a 400 it must still be
there (`logout-refused`).

The suite is in a container and the client is not. The suite's server gets
the name `host.docker.internal` for the host (`extra_hosts: host-gateway` in
`docker-compose.yml`), the runner asks the container what address that is, and
the client listens on exactly that address and a free port: on Linux the
Docker bridge's own address, which the containers reach and nothing outside
the machine does. The `backchannel_logout_uri` is plain http, which the
specification allows a confidential client. Where the machine has no such
address (Docker Desktop, where the name leads into a virtual machine that
forwards to the host), the client listens on `127.0.0.1` instead; that path
has not been run. `CONFORMANCE_RP_HOST` and `CONFORMANCE_RP_BIND` override
both, for a suite started some other way.

### The suite's version

The suite is pinned to **`release-v5.3.4`** (October 2026), the latest release
when this was written, by the tags of its two images in `docker-compose.yml`.
It is pinned because the suite gets new checks all the time: a run that fails
should mean the library changed, not the suite. Moving to a newer release is a
change of its own: update the tag on both images, `SUITE_RELEASE` in
`src/suite.ts` and this paragraph, run it, and add any new modules to
`expected` of their plan in `src/run.ts`.

The images are the ones the suite's own pipeline publishes to
`registry.gitlab.com/openid/conformance-suite`. They are pinned by tag, not by
digest.

## What it does and does not prove

It shows that, against this release of the suite and in these variants, the
library:

- with `profile: 'fapi2'`, sends an authorization request, a client
  assertion, a PAR request, PKCE and DPoP proofs (with and without a server
  nonce, at the token endpoint and at the resource server) that the suite
  accepts;
- refuses a discovery document with the wrong issuer;
- refuses an authorization response with a wrong or missing `iss`, or a wrong
  or missing `state`;
- with `profile: 'fapi2'`, refuses an ID token with a wrong or missing `iss`,
  `aud`, `exp` or `nonce`, an untrusted second audience, or signed with `none`
  or `RS256`;
- takes a token response without `expires_in`, a `token_type` in odd case, and
  a `DPoP` challenge in odd case;
- with its defaults and a client secret, sends an authorization request, a
  token request with `client_secret_basic` and a UserInfo request with the
  token in the `Authorization` header that the suite accepts;
- with its defaults, refuses an ID token with a wrong `iss`, `aud` or `nonce`,
  or without `sub` or `iat`, and a UserInfo response for another `sub`;
- ends the session a logout token names and answers 200, and answers 400 and
  leaves the session alone for a logout token signed with `none`, with a wrong
  `iss` or `aud`, with a `nonce`, or without the back-channel logout event.

One module fails, and is left failing:
`rp-backchannel-rpinitlogout-wrong-alg`. The suite signs the logout token with
`ES256`, with a key of its own that is in its JWKS, where the client's ID
tokens are signed with `RS256`, and expects a 400. `handleBackChannelLogout`
takes any asymmetric algorithm the provider has a key for, answers 200 and
ends the session. Back-Channel Logout 1.0 §2.6 asks for the `alg` to be
validated as an ID token's is. The run exits with 1 until the library
changes.

It does not show:

- **Certification.** That is a submission to the OpenID Foundation: the tests
  run against the suite they host, and the logs are sent in with a signed
  declaration. A green run here is neither, and gives no right to call
  anything certified.
- **Anything about your application.** The script is the app here. The
  routes, the cookies, the session store and the redirect URI of a real one are
  not in the picture.
- **That an ID token's signature is verified outside `profile: 'fapi2'`.** It
  is not, when the token comes from the token endpoint: see
  [the three modules above](#basic-openid-connect-relying-party). So
  `kid-absent-single-jwks` and `idtoken-sig-rs256` pass without showing that
  the library can pick the key or check an `RS256` signature.
- **The other variants and plans.** Not mTLS (the library has none), not
  signed request objects or JARM (FAPI 2.0 Message Signing, not implemented),
  not the other client authentication methods, not the implicit and hybrid
  flows, `form_post`, dynamic registration and discovery by WebFinger (the
  library has none of them), not the refresh token plan, and of logout only
  the back-channel: not RP-initiated logout on its own, front-channel logout
  or session management.
- **`handleOidcLogout`.** The back-channel modules start the logout at the
  provider without it.
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
