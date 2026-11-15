---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`rolesClaim` can be a function of the ID token claims, for roles that aren't in a top-level claim, such as
Keycloak's `realm_access.roles`. Roles that `mapSession` read from such a claim were gone after the first
refresh. `rolesClaim: false` leaves `user.roles` to `mapSession`, and a refresh then keeps them. A login where
`mapSession` sets roles that the next refresh would replace logs a warning, once.
