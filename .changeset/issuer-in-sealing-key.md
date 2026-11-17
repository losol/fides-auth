---
'@eventuras/fides-auth': patch
---

The key that seals a session no longer depends on how `issuer` is written in the config. It was derived from the string as given, so adding a trailing slash, or writing the host in another case, changed the key and logged everyone out. The issuer is now written one way before it goes into the key: scheme and host in lower case, no default port, no trailing slash. The path keeps its case.

An issuer already written without a trailing slash, with a lower-case host and no default port, gives the same key as in beta.7, so those sessions stay. An app whose config has it another way logs its users in once more with this release, and not again when the config is tidied.
