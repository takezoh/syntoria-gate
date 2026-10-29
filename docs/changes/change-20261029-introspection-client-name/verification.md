---
change: change-20261029-introspection-client-name
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

Local working tree on 2026-10-29 against the Firestore Emulator; not committed or deployed.

- `tests/provider.test.mjs`: introspection of a token for a client registered as `<MCP & Client>` returns that `client_name`, also after refresh; the SDK returns it as `clientName`. A client registered without a name has no `client_name`, and the SDK returns null.
- `tests/sdk.test.mjs`: a valid relayed name is returned; empty, padded, oversized, multi-line, non-string and null values give `clientName: null` while the token still verifies with its client ID.
- `FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 GATE_TEST_PORT=55446 npm run test:integration`: 1 passed, 0 failed or skipped (the default port 55436 was taken by an unrelated local container). With the claim removed from `extraTokenClaims`, the same run failed on the expected name, then passed again after restoring it.
- `npm run typecheck` passed; `npm test`: 79 passed, 0 failed, skipped or TODO.
- Weave's `scripts/testing/verify-gate-integration.mjs`, run against this working tree with the Firestore Emulator and real PostgreSQL, verified that a DCR client registered as "MCP integration" reaches Weave with that name and that Weave records it with the client's write.

## Limitations

Hosted Gate, Cloud Run and real MCP clients are not exercised. A client's own name remains unverified.
