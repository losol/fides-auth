---
'@eventuras/fides-auth': minor
---

`authorizedFetch` now refuses a path with `.` or `..` segments that are percent-encoded (once or twice), written with a backslash, or written as `..;`. Before, these were sent with the access token, path unchanged. A gateway that decodes before it routes could then serve a path outside `allowedBase`. An encoded slash inside one segment, such as `group%2Fproject`, still passes. An access token with CR, LF or NUL no longer puts the token in a `TypeError` message: the call fails with `no_access_token`.
