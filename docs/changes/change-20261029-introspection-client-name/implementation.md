---
change: change-20261029-introspection-client-name
role: implementation
---

<!-- lifecycle is owned by change.md -->

# Implementation

`extraTokenClaims` in `src/service.ts` looks up the issuing client and adds `client_name` beside `connection_id`, `azp` and `gate_approved` when the client has a registered name. `oidc-provider` stores extra claims with the opaque token, so introspection returns them; registrations cannot be edited, so the name is the one validated at registration.

The SDK's `GatePrincipal` gains optional `clientName`. `verifyToken` applies the registration rule and returns null for an absent or malformed value without changing any other check. `verifySession` is unchanged; browser sessions have no client name.

## Release impact

Access tokens issued before the release carry no `client_name` and expire within five minutes; resources must treat the name as optional. Resources using an older SDK ignore the claim. No storage, configuration or secret changes are required.
