---
'@eventuras/fides-auth': minor
---

Cache the provider's OpenID configuration instead of discovering it before every
token operation, removing a round-trip from each refresh, login and logout.
Cached per issuer and client for five minutes; tune with
`configureDiscoveryCache({ ttlMs })` or drop entries with `clearDiscoveryCache()`
from `@eventuras/fides-auth/oidc-discovery`. See `docs/discovery-cache.md`.

Fixes `VippsLoginClient` caching a failed discovery for the client's lifetime.
