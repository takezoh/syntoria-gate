---
change: change-20261029-sign-out-and-hsts
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

Local working tree on 2026-10-29 against the Firestore Emulator; not committed or deployed.

- `tests/provider.test.mjs`: device sign-out expires the identity cookie and the next `/browser/login` goes to GitHub; `/connections` shows the sign-out form; `POST /logout` with another Origin or a wrong CSRF value returns 403 and keeps the session; a valid one redirects to `/signed-out` with HSTS, expires both cookies, revokes the device connection, leaves an MCP grant active, and `/connections` then requires login; `/signed-out` uses the page CSP.
- `FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 GATE_TEST_PORT=55446 npm run test:integration`: 1 passed, 0 failed or skipped (the default port 55436 was taken by an unrelated local container).
- `npm run typecheck` passed; `npm test`: 78 passed, 0 failed, skipped or TODO.
