---
change: change-20261028-change-confirmation
role: implementation
---

<!-- lifecycle is owned by change.md -->

# Implementation

## Content

`src/confirmation.ts` validates the three resource requests with exact field sets. A summary over 120 title characters, 64 lines or 4000 characters in total is rejected, never truncated.

`Storage` keeps confirmations in `<namespace>_confirmations`, keyed by a SHA-256 hash of the 32-byte random ID. A marker in `<namespace>_confirmation_references` keeps each resource's references unique. Each transaction checks the requesting connection: approved, not revoked, owned by the subject, with an unexpired `Grant` artifact. The existing `hasActiveOAuthConnection` does not read grant expiry, so the new check reads both documents. Both records take the grant's `expiresAt`, so the new TTL policies remove them after the connection ends.

- Creation fails without writing for an inactive connection or a reused reference.
- A decision is final. Denial deletes the summary.
- Consumption answers `expired` for another resource, reference or hash, or a cancelled record. An approved record moves to `used` and loses its summary in the same transaction, so concurrent calls see one `consumed`.
- Cancellation deletes the summary and is idempotent.

`src/service.ts` routes `/confirmations`, `/confirmations/consume` and `/confirmations/cancel` through the existing resource Basic authentication, with a 16384-byte JSON limit. Their failures answer in JSON. `GET /confirm` shows a sign-in page for any well-formed ID until the identity session exists. `/confirm/sign-in` carries the confirmation ID through the GitHub login state, so the callback returns to it. `POST /confirm` applies the existing Origin, CSRF and exact-field rules, then redirects to the confirmation, which shows the approved, denied or no-longer-valid state.

Every page now uses one stylesheet. The Content Security Policy admits it by SHA-256 hash, and pages use classes only, with no external resources. The connections page groups AI clients and browsers, and shows each client's unverified name, shortened client ID and approval date. The existing approval pages keep their text and gain the shared button styles.

`jsonBody` now reads the body before parsing. An oversized JSON body therefore returns 413 instead of 400 on the existing browser JSON endpoints as well.

`createGateConfirmations` in the SDK posts the three requests with the resource's Basic credentials, one deadline per call, redirects refused and the existing response-size limit. It checks that a created ID and URL are well formed and on the configured issuer, and that a consume result has a known status; a `consumed` result must also carry its subject, connection and decision time. A 403 from creation, meaning an inactive connection, surfaces as `GateError(401)`; every other failure is `GateError(503)`.

The integration test port can be set with `GATE_TEST_PORT`; the default remains 55436. The test configuration adds a second resource, which checks that resources are isolated.
