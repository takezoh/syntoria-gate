---
change: change-20261020-pending-registration-expiry
role: implementation
---

<!-- lifecycle is owned by change.md -->

# Implementation

## Content

`Storage` writes each new Client artifact with `expiresAt` set to 24 hours after registration (`PENDING_REGISTRATION_TTL_MS`). The existing TTL policy on the `entries` collection group deletes abandoned records. Artifact reads now treat a Client as permanent only when it has no `expiresAt`; a pending Client follows the same read-time expiry check as other artifacts. `oidc-provider` caches only static clients, so every dynamic-client lookup goes through this check.

`addConnection` reads the connection and Client documents in one transaction. It rejects a missing, mismatched or expired Client, removes `expiresAt` with `FieldValue.delete()` when present, and creates the connection. Promotion and connection creation therefore commit together. If the transaction fails after the provider saved its grant, that grant has no connection and the existing connection guard keeps every artifact inactive.

The lifetime `quota` counter is replaced by a `capacity` state document holding a fixed 24-hour window and its request count. The shared `fixedWindow` helper validates stored counters and keeps both the 24-hour and the minute window from moving backward when an instance clock is stale. `RegistrationLimits` now uses `perWindow` and `perMinute`; the defaults are 1000 and 20. The old `quota` document is no longer read and is left in place.
