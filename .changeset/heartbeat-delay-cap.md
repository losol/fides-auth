---
'@eventuras/fides-auth': patch
---

When the known access-token expiry was more than about 35 days ahead, the browser heartbeat passed a delay above 2^31-1 ms to `setTimeout`. The timer then fired at once, so the heartbeat posted in a tight loop and every post made the server refresh at the provider. The wait between beats is now at most 24 hours.
