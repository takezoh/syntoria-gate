---
change: change-20261018-connection-authorization
role: verification
---

# Verification

Verified on 2026-10-18 against the current source tree using Node.js 24 and the official Firestore Emulator. `npm run check` passed all 42 SDK/configuration tests, with no skipped, failed, cancelled or TODO tests. `npm run build` passed through both the check and integration commands. `FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 npm run test:integration` passed one comprehensive real-provider/HTTP/Firestore Emulator scenario. `docker build --tag syntoria-gate:firestore-local .` passed with the Firestore dependencies. Document graph lint with conformance passed without warnings. The parent independently reran the 42-test check and the final integration scenario (including consumed-marker preservation after upsert and rejection of another user's revocation); both passed with zero failures or skips. The integration run emitted a metadata-discovery timeout warning while using the emulator; the scenario completed successfully in approximately 14 seconds.

The integration suite uses a real Firestore Emulator and actual provider HTTP endpoints, with a synthetic GitHub identity exchange. It checks connection isolation, restart persistence, expiry without TTL deletion, code/refresh and login-state single consumption, refresh/revocation races, CSRF, path-scoped cookies and real SDK introspection. The emulator does not reproduce production concurrency modes, composite indexes or all production limits. Hosted Firestore, real GitHub, external MCP clients and Weave/Lore integration remain unverified. No deployment is included.

## Browser consent callback correction

A Chromium experiment reproduced that a consent page with `form-action 'self'` blocks a form-submission redirect chain to a different callback origin. The browser remains on the consent page; a repeated submission can then target an already consumed interaction. Consent pages now permit only self plus the safely parsed origin of the current exactly registered client redirect. Connections and revocation pages remain self-only. Explicit approval, PKCE, CSRF, identity and revocation contracts are unchanged.

`npm run check` passed all 44 tests, `npm run build` passed, and the real-provider/Firestore Emulator integration passed with explicit consent and management CSP assertions. Actual Chromium also completed the real local Gate provider flow through an external callback and PKCE token exchange. That browser fixture used an isolated synthetic local browser session; it does not prove a hosted user browser. See [source, image and browser evidence](evidence/consent-csp-release.json).

## Firestore TTL policy correction

Terraform 1.13.4 passed `terraform fmt -check` and `terraform validate` after adding `expiresAt` TTL policies for `gate_browser_login_attempts`, `gate_browser_approvals`, `gate_browser_sessions`, and `gate_identity_sessions`. The existing `entries` policy remains. A declaration check confirmed that `gate_connections` has no TTL policy. TTL deletion is asynchronous; Gate's existing expiry checks remain the authorization boundary. This verifies the tracked Terraform configuration only; no Terraform plan or apply was run. See [TTL policy evidence](evidence/firestore-ttl-policies.json).
