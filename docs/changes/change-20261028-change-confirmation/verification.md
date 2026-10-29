---
change: change-20261028-change-confirmation
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

## Content

`npm run check` passed: typecheck, build and 78 unit tests, 0 failed, 0 skipped and 0 TODO. These include four request-validation tests, and five SDK tests for the exact request, credentials, result validation, the 403-to-401 mapping, 204 handling, deadlines and the loopback restriction.

`FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 GATE_TEST_PORT=55446 npm run test:integration` passed against a loopback Firestore Emulator 1.21.0 started from the local Google Cloud CLI with Java 21: 1 provider integration test passed, 0 failed. Docker could not start the emulator image because the host's root filesystem was full, and port 55436 belonged to an unrelated local emulator. In addition to the existing checks, the test verifies that:

- creation rejects a missing or wrong resource credential, an invalid hash, a timer field, a 65-line summary, another subject, an unknown or revoked connection, a reused reference (409) and a body over 16 KiB (413). The same reference is accepted for another resource;
- a confirmation's `expiresAt` equals its connection grant's expiry;
- before sign-in, two IDs produce identical pages apart from the ID; sign-in returns to the confirmation;
- the page passes the hashed-stylesheet CSP, escapes the title, lines and client name, and contains no style attribute, script or external link;
- a decision is refused with another Origin, a wrong CSRF value, an extra field or an unknown decision, and a second decision returns 409;
- consumption by another resource or with another reference or hash returns `expired`; two concurrent consumptions return one `consumed` with the subject, connection and decision time and one `used`; the summary is then deleted;
- denial and cancellation delete the summary; consumption then returns `denied` and `expired`; another resource cannot cancel;
- after the connection is revoked, the page shows the request as no longer valid, approval returns 409 and consumption of an earlier approval returns `expired`; after the grant's lifetime, consumption and decision fail;
- the SDK client creates, consumes once (then `used`) and cancels against the real service, receives `GateError(401)` for a revoked connection and `GateError(503)` for wrong resource credentials.

Four deliberate faults were injected into the built output only, and each made the integration test fail. The faults were: no change-hash check on consumption; no `used` transition; no CSRF check on decisions; and decisions accepted on an inactive connection. The build was then regenerated from unchanged source.

Terraform is not installed on this host, so the two new TTL resources were not formatted or validated with Terraform, and no plan or apply ran. No hosted Firestore, TTL deletion timing, Cloud Run, GitHub OAuth, real browser rendering or MCP host was exercised. The dev-skills implementation runtime was not used, so no formal lifecycle gate is claimed.
