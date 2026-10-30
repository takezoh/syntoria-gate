---
change: change-20261030-connection-check
role: implementation
---

<!-- lifecycle is owned by change.md -->

# Implementation

## Content

`src/connection-check.ts` parses the exact request. `Storage.connectionValid` reuses the transactional `activeConnection` rule that confirmations use, then compares the client. `src/service.ts` serves `POST /connections/check` beside the confirmation API with the same resource authentication and JSON failure handling. `packages/sdk` adds `createGateConnections`.
