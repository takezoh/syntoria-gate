---
change: change-20261030-device-approval-provenance
role: verification
---

# Verification

## Local verification

- npm run check: 79 passed, no failures or skips.
- FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 GATE_TEST_PORT=55446 npm run test:integration: one full provider integration test passed, no failures or skips. Coverage includes missing-Origin approval with exact Referer, foreign and opaque Origin precedence, missing/foreign/opaque-scheme Referer, wrong CSRF, single-use consumption and replay rejection.
- A native Chromium form submission against the built service and isolated Firestore Emulator returned 200 for the approval page, advertised Referrer-Policy: same-origin, posted with the issuer Origin, returned 303 to the synthetic app and issued the shared Secure session cookie. GitHub identity was substituted and synthetic identity/approval state was seeded; this is not hosted personal-account acceptance.
- A separate synthetic browser experiment observed Origin: null under Referrer-Policy: no-referrer, and the expected Origin under same-origin. The incident request headers were not logged, so this does not prove the original incident used that policy.

## Incident evidence

Three new device-approval transactions on 2026-10-30 between 08:57 and 08:58 UTC each loaded their approval page successfully and received 403 on POST within 1–13 seconds. POST response latency was approximately 2–3 ms. Requests came from iPhone Chrome. The deployed issuer matched the request URL origin. The logs did not record the HTTP Origin header or a denial reason; early provenance rejection was the leading hypothesis, not a confirmed cause.

## Release

The candidate was built from base source bc3e38d plus the reviewed working-tree patch. Its build-input SHA-256 is 8bd08afa11329aec0f47a318eb0a511f5bd2561c3f391743f138e6e21e49edbd; its immutable image digest is sha256:69f79b7bb6c40d6a736a6aaa27ce0942becc18b9c7bd09e931060872ce00552c.

The no-traffic candidate returned 200 for readiness and discovery; missing provenance and explicit opaque/foreign Origin returned 403; an exact issuer Referer without Origin passed provenance validation and reached the unauthenticated 401 check. All probes carried HSTS. Readback confirmed runtime settings unchanged except the image. Candidate logs contained only event, reason and header classifications.

Documentation language, local-link and deployment-identifier checks passed. Structured document lint passed. Conformance lint reports existing missing change-classification errors in three older changes (20261019, 20261020 and 20261028); those historical records were not modified.

The original iPhone workflow still requires a fresh user attempt. After independent source review approved the patch without findings, revision gate-api-approval-8bd08afa1132 received 100% of production traffic on 2026-10-30. The public origin passed the same readiness, discovery and provenance/authentication boundary probes. Readback confirmed only the image changed in the runtime specification; the previous revision remains available for rollback.

The implementation Loop produced the candidate and independent approved review, but the review receipt returned readonly-world-changed after parent-authored release documentation was updated. The Loop receipt is not claimed as completed; the command results, source review and hosted probes above are the verification evidence.
