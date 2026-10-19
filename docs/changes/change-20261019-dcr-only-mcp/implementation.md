---
change: change-20261019-dcr-only-mcp
role: implementation
---

<!-- lifecycle is owned by change.md -->

# Implementation

## Content

The Gate runtime now uses `oidc-provider`'s built-in `/reg` endpoint. `src/registration.ts` projects input into the supported public-client profile, caps the body and redirect list, infers omitted `application_type` from redirect schemes, defaults omitted token authentication to `none`, and rejects unsupported grant profiles, secrets and server-fetch metadata before the provider sees the request. Unknown inert metadata is discarded. Provider configuration enables registration without initial access tokens or registration tokens and disables registration management and client metadata document identification. Only confidential resource clients remain in the provider's static client list.

`Storage` persists Client artifacts without an expiry and records a fixed lifetime quota plus a fixed-minute rate counter in Firestore state documents. A transaction reads and increments both counters together with the Client write, so concurrent Gate instances cannot exceed the configured limits. The stored minute window only moves forward, so a retry from an instance with a stale clock cannot reopen an earlier window. Defaults are 1,000 lifetime registrations and 20 per minute per namespace. Limit responses contain bounded public descriptions; Firestore failures map to generic `503` errors.

Approval uses `Client.redirectUriAllowed()` so OIDC provider matching permits native loopback port variation without widening host or path matching. The actual callback origin still passes URL safety checks before it is used for consent CSP. Consent and connection management escape the unverified client name, show the actual callback, and store the client name only for display. Introspection now requires an access token whose provider Client still exists and whose approved Gate connection matches the token; this makes orphaned tokens inactive instead of allowing a missing Client to cause a provider error.

The SDK removes `allowedClientIds` and requires the distinct `browserClientId`. Bearer verification accepts any DCR client identity after requiring a nonempty RFC 7662 `client_id`; `azp` is optional and must match when present. Browser sessions continue to compare their client ID exactly with `browserClientId`. Runtime rendering and configuration no longer provision public clients; legacy `clients` input is rejected by the runtime config parser.
