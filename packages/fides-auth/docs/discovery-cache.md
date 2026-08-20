# Discovery cache

Every OIDC flow needs the provider's metadata — token endpoint, authorization
endpoint, end-session endpoint. fides-auth fetches it once per provider and
reuses it for five minutes.

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

Keyed by issuer and client id, for five minutes. The client secret is checked on
every lookup: rotate it and the next call rediscovers rather than authenticating
with a credential the provider has already retired.

Failures are never cached. A provider that was briefly unreachable is retried on
the next call — caching the rejection would turn one blip into five minutes of
downtime.

The TTL bounds only how long a *metadata* change takes to be noticed. Signing
keys are not covered by it: openid-client fetches JWKS on its own schedule, so a
key rollover does not wait for this cache.

## Changing it

```ts
import { configureDiscoveryCache, clearDiscoveryCache } from "@eventuras/fides-auth/oidc-discovery";

// Shorten the window, or pass 0 to discover on every call.
configureDiscoveryCache({ ttlMs: 60_000 });

// Drop everything now — after changing provider configuration you need picked
// up immediately.
clearDiscoveryCache();
```

Both are process-local: the cache lives in memory, so each instance of your app
holds its own, and a deploy starts empty.

If you write tests that mock discovery, call `clearDiscoveryCache()` between
cases. The cache is module state and will otherwise serve one test's provider
metadata to the next.
