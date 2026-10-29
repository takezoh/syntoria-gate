---
change: change-20261029-sign-out-and-hsts
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

Local working tree on 2026-10-29 against the Firestore Emulator, before the change was committed as `52b383e`.

- `tests/provider.test.mjs`: device sign-out expires the identity cookie and the next `/browser/login` goes to GitHub; `/connections` shows the sign-out form; `POST /logout` with another Origin or a wrong CSRF value returns 403 and keeps the session; a valid one redirects to `/signed-out` with HSTS, expires both cookies, revokes the device connection, leaves an MCP grant active, and `/connections` then requires login; `/signed-out` uses the page CSP.
- `FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 GATE_TEST_PORT=55446 npm run test:integration`: 1 passed, 0 failed or skipped (the default port 55436 was taken by an unrelated local container).
- `npm run typecheck` passed; `npm test`: 78 passed, 0 failed, skipped or TODO.

## Production release

On 2026-10-29, source `d843db2`, which carries this change and a documentation-only commit, was released as revision `gate-api-signout-d843db2` with image `sha256:7fa131c1e1e3b8d356f4ffcf1dbfdb7a344584b434e925d6834503db23909862` (OCI index, built with Docker Buildx for linux/amd64).

- The revision reuses the serving configuration of the previous revision `gate-api-confirm-c2d093b` and changes only the image, deployed with `gcloud run deploy --image --no-traffic --tag`. Secret version references, runtime identity, Firestore identifiers and limits are unchanged. The previous revision is kept for rollback; it does not end Gate sign-in on device sign-out.
- Before traffic moved, the candidate revision returned 200 for readiness, OIDC discovery and `/signed-out`, `Strict-Transport-Security: max-age=31536000` on readiness, 403 for `POST /logout` without an Origin, and 401 for an unauthenticated confirmation create.
- After 100% traffic, the public origin returned 200 for readiness and `/signed-out`, the same HSTS header, and 401 for an unauthenticated confirmation create.
- Afterwards the ignored runtime config was rebuilt from the serving configuration, and the template's `GATE_RESOURCES` reference was moved from version 2 to version 7, the version production serves. A manifest rendered from them has the same environment and secret references as the serving revision.

Sign-out has not been exercised in a real browser in production, so the deletion of the identity session and the cleared cookies are verified only locally.
