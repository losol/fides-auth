---
"@eventuras/fides-auth": patch
---

Widen the `jose` dependency from an exact pin to `^6.2.8`.

An exact pin in a library forces a second copy of `jose` into any consumer tree that
already resolves it through a range — `openid-client` depends on `jose: ^6.2.2`, so
this repo was carrying two copies itself — and it withholds patch releases from
consumers until we cut a release of our own. Reproducibility is the lockfile's job,
not a library's dependency range.
