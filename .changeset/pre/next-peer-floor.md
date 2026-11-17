---
'@eventuras/fides-auth-next': minor
---

The peer range for `next` is now `^16.4.1`, up from `^16.0.0`. Earlier 16 releases have known vulnerabilities:
below 16.2.11 a request can pass `proxy.ts` in some App Router setups, which is where an app guards its pages, and
below 16.4.1 there are several remote code execution advisories. An app on an older 16 gets a peer dependency
warning and should upgrade Next.
