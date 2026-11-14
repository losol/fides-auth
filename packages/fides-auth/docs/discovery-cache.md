# Discovery cache

Every OIDC flow needs the provider's metadata — token endpoint, authorization
endpoint, end-session endpoint. An OIDC client from `createOidcClient` fetches
it once and reuses it for five minutes. The instance from `createFidesAuth` has
one such client.

## Why it matters

Without a cache, a refresh is two round-trips: a GET to
`/.well-known/openid-configuration`, then the token request. On the heartbeat
path that happens per user every few minutes. It doubles refresh latency,
doubles the load your provider sees, and doubles the surface on which a refresh
can fail — a discovery blip and a token-endpoint blip are indistinguishable to
the caller, and both end up as a `session.refresh_failed` your operators have to
explain.

Concurrent callers share one round-trip. A burst of heartbeats arriving together
does not become a burst of discovery requests, because the cache holds the
in-flight promise rather than waiting for a result to store.

## What is cached, and for how long

Keyed by issuer, client id and `clientAuth` method, for five minutes. The client
secret or private key is checked on every lookup: rotate it and the next call
rediscovers rather than authenticating with a credential the provider has
already retired. Keys are compared by identity, so reuse one `CryptoKey` object.

With `serverMetadata` nothing is fetched. The configuration is cached the same
way, against that metadata object: pass the same one each time.

Failures are never cached. A provider that was briefly unreachable is retried on
the next call — caching the rejection would turn one blip into five minutes of
downtime.

The TTL bounds only how long a *metadata* change takes to be noticed. Signing
keys are not covered by it: openid-client fetches JWKS on its own schedule, so a
key rollover does not wait for this cache.

## Changing it

Each client has its own cache, shared with no other client. Set its TTL when
you create it:

```ts
import { createOidcClient } from "@eventuras/fides-auth/oidc";

// Shorten the window, or pass 0 to discover on every call.
const oidc = createOidcClient(oauthConfig, { discoveryTtlMs: 60_000 });
```

A TTL that isn't a finite number of zero or more throws when the client is
created. `Number(process.env.DISCOVERY_TTL)` is `NaN` when the variable is
unset, and that would otherwise turn the cache off without a word in the logs.

To drop the cache, create a new client. The cache lives in memory, so each
instance of your app holds its own, and a deploy starts empty. Tests that
create a client per case need no cache resets.
