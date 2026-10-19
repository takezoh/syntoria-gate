---
change: change-20261019-dcr-only-mcp
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

## Content

`npm run check` passed, including TypeScript checks and the service/SDK build. Its unit suite reported 69 passed, 0 failed, 0 skipped, and 0 TODO. This verifies the SDK's dynamic `client_id` policy, optional matching `azp`, required separate browser client configuration, Gate config shape, runtime renderer removal of public clients, and existing browser/readiness behavior. Raw output is retained at `.local/dcr-gate-check.log`.

`FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 npm run test:integration` passed against the loopback Firestore Emulator: 1 provider integration test passed, 0 failed, 0 skipped, and 0 TODO. It exercises `/reg` for inferred HTTPS web and native loopback profiles, omitted `application_type` and auth method, optional refresh grants, PKCE exchange and refresh, consent escaping, unknown metadata projection, unsafe/fetch-capable metadata and oversized body rejection, persistence through provider restart, inactive introspection after removal of a DCR Client, native variable-port callback acceptance with host/path mismatch rejection, revocation, shared transactional quota/rate limits across two Storage instances, and a deterministic stale-clock regression that proves the minute window cannot move backward. The same suite also confirms an unavailable Firestore write fails closed with a generic `503`. Raw output is retained at `.local/dcr-gate-provider-integration.log`.

The emulator run emitted the `oidc-provider` already-parsed-body warning from the bounded metadata adapter, a Google metadata lookup warning while using local Firestore credentials, and the provider's default error-page notice for an intentionally failed registration-storage test. None caused a test failure. No hosted Firestore, Cloud Run, GitHub OAuth, ChatGPT, Claude or Codex host acceptance was performed. The parent execution separately reported a passing Gate plus real Weave HTTP/MCP/PostgreSQL integration using the same checked-in Gate DCR path; the source/artifact digests and boundary results are recorded in [local integration evidence](evidence/local-integration.json).


The final provider run also verifies a monotonic registration rate window with injected clocks: a stale window cannot overwrite a newer rate counter, and the next minute permits registration. Independent code review approved the corrected native redirect and rate-window behavior. Runtime and test evidence is complete locally; formal implementation-profile submission encountered candidate-root bookkeeping errors and is not reported as a completed lifecycle gate.
