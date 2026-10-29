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

## Production release

On 2026-10-29, source `6b69431` was released as revision `gate-api-clientname-6b69431` with image `sha256:f2d1a57e27b466c1d63e3028cb6f2234732a6b7a3d9d8d06b24eae88ccde1026` (Docker Buildx, linux/amd64). `npm run check` passed on that source (79 tests, no failures, skips or TODOs).

- The revision reuses the serving configuration of the previous revision `gate-api-mcp-8a0441f` and changes only the image, deployed with `gcloud run deploy --image --no-traffic --tag`. Secret version references, runtime identity, Firestore identifiers and limits are unchanged. The previous revision is kept for rollback.
- Before traffic moved, the candidate returned 200 for readiness, OIDC discovery (with introspection and registration endpoints) and `/signed-out`, `Strict-Transport-Security: max-age=31536000`, 403 for `POST /logout` without an Origin, and 401 for an unauthenticated confirmation create.
- After 100% traffic and tag removal, the public origin returned 200 for readiness, discovery and `/signed-out`, the same HSTS header, and 401 for an unauthenticated confirmation create.
- Weave's matching release (`dc0b0ef`) reads the claim.

The relayed `client_name` has not been observed on a production token: access tokens issued before this release carry no name, and no MCP client has written through Weave since.

