---
'@eventuras/fides-auth': minor
---

`strictOriginCheck: true` makes logout and the heartbeat refuse a request that has neither `Sec-Fetch-Site` nor `Origin`. Such a request isn't a browser's, so it has passed the CSRF guard, and still does by default: a script or a server of the app's own can call the two. Every browser in use sends one of the headers on a POST, so an app that only browsers call can turn it on and refuse the rest with 403.
