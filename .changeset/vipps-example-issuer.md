---
'@eventuras/fides-auth': patch
---

The Vipps example in the README passed `VippsEnvironments.Production` as the issuer. That is the environment's
address, not its issuer: the example now uses `getVippsIssuer(VippsEnvironments.Production)`, and the doc
comments say which is which.
