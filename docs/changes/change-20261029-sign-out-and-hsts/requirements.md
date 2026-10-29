---
change: change-20261029-sign-out-and-hsts
role: requirements
---

<!-- lifecycle is owned by change.md -->

# Requirements

- FR-001: When `POST /browser/logout` succeeds, Gate shall delete the identity session named by the browser's identity cookie and expire that cookie together with the shared session cookie.
- FR-002: `POST /logout` shall require the issuer Origin, exactly one `csrf` form field and, when an identity session is active, its CSRF value. It shall delete the identity session, end the current device session when one is active, expire the identity, login and (when ended) session cookies, and redirect to `/signed-out`.
- FR-003: Signing out shall not revoke AI connections or other devices.
- FR-004: Every Gate response shall carry `Strict-Transport-Security: max-age=31536000`.

Counterexamples: a cross-origin form signing the person out; a wrong CSRF value ending the session; `/browser/login` after device sign-out reaching the approval page without GitHub; sign-out revoking an MCP grant.
