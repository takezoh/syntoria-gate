---
change: change-20261019-dcr-only-mcp
role: requirements
---

<!-- lifecycle is owned by change.md -->

# Requirements

## Content

Gate public MCP clients register through the OAuth provider's RFC 7591 endpoint. Operators do not provision public client IDs or callbacks. Static confidential resource clients remain separate and continue to authenticate introspection; browser application registration remains unchanged. CIMD, client secrets for public clients, registration management and registration access tokens are not supported.

The registration boundary accepts bounded JSON and validates it before provider processing. HTTPS redirects define web clients; HTTP redirects are accepted only for native loopback hosts. Native loopback clients may use the RFC 8252 variable-port match while preserving the registered host and path. Authorization-code flow requires PKCE S256; token endpoint authentication is `none`; refresh tokens are optional. Unsupported auth methods, grants, redirect forms and metadata that could trigger server-side fetching are rejected. Inert unrecognized RFC 7591 metadata is ignored and is neither stored nor fetched.

Registration must not grant data access. A connection appears only after sign-in with Gate's configured immutable GitHub identity and an explicit consent decision. Consent shows the actual unverified client name and redirect safely. Access tokens remain opaque, resource-bound, online-revocable and tied to an approved connection. Browser session verification uses its separately configured browser client ID; bearer verification accepts a dynamically registered client ID and requires a consistent `client_id` and optional `azp`.

Provider Client records have no provider-supplied expiry and must persist durably. Gate bounds registration globally within a Firestore namespace using transactional total and fixed-minute counters shared across service instances. Capacity or rate exhaustion returns a clean `429`; storage failure fails closed with a generic `503`. The lifetime cap is intentionally finite and has no automatic reset or operator-facing management product.
