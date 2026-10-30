---
change: change-20261030-connection-check
role: verification
---

<!-- lifecycle is owned by change.md -->

# Verification

## Content

- `npm test`: 81 passed, including the request parser and the SDK client.
- Firestore Emulator integration: the exact active connection is valid for any configured resource; another client, account or unknown ID is not; a revoked connection becomes invalid; missing or wrong resource credentials return 401, malformed bodies 400 and oversized bodies 413.
