---
change: change-20261020-pending-registration-expiry
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

## Content

`npm run typecheck` passed. `npm test` built the service and SDK and reported 69 unit tests passed, 0 failed, 0 skipped and 0 TODO.

`FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 npm run test:integration` passed against a disposable loopback Firestore Emulator: 1 provider integration test passed, 0 failed, 0 skipped and 0 TODO. In addition to the earlier DCR checks, it verifies that:

- a new registration stores `expiresAt` exactly 24 hours after `createdAt`, and a denied approval leaves it pending;
- the first approved connection removes `expiresAt`, and the Client still resolves after the pending period;
- an unapproved Client no longer resolves after the pending period, approval of it through `addConnection` fails without creating a connection, and an expired Client is rejected at the authorization endpoint;
- one registration exhausts a window limit of one with a capacity error, the next 24-hour window accepts a registration, and the earlier pending Client no longer resolves;
- the shared limits across two instances, the backward-moving minute window and fail-closed storage behave as before.

Two deliberate faults were injected into the built output only, and each made the integration test fail: removing the approval-time `expiresAt` deletion, and treating every Client as permanent. The build was then regenerated from unchanged source.

The run emitted the known `oidc-provider` already-parsed-body warning and default error-page notice. No hosted Firestore, Firestore TTL deletion timing, Cloud Run, GitHub OAuth or MCP host acceptance was exercised. The dev-skills implementation runtime could not open a formal unit (`production-composition-source-unavailable`), so this change was implemented and verified directly; no formal lifecycle gate is claimed.
