---
change: change-20261030-connection-check
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

## Content

- `npm test`: 81 passed, including the request parser and the SDK client.
- Firestore Emulator integration: the exact active connection is valid for any configured resource; another client, account or unknown ID is not; a revoked connection becomes invalid; missing or wrong resource credentials return 401, malformed bodies 400 and oversized bodies 413.

## Production release

On 2026-10-30, source `485f7ba`, pushed to main as a fast-forward, was released as revision `gate-api-check-485f7ba`. It reuses the serving configuration of `gate-api-approval-8bd08afa1132` and changes only the image `sha256:1032915a62836a0727014c2d3310b0b93273632d40231b797b111d76f658e04a` (Docker Buildx, linux/amd64), deployed with `gcloud run deploy --image --no-traffic --tag`.

- Before traffic moved, the candidate returned 200 for readiness and OIDC discovery, and `POST /connections/check` returned 401 JSON without credentials and with wrong resource credentials.
- After 100% traffic and tag removal, the public origin returned 200 for readiness and discovery and 401 JSON for an unauthenticated connection check.
- Weave `e46d9d6` consumes the endpoint.

Not verified in production: a check with a resource's real credentials (reading the secret was not permitted in that session) and a valid answer for a live connection.
