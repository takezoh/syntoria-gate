---
change: change-20261018-connection-authorization
role: implementation
---

# Implementation

The service embeds oidc-provider for protocol handling. Gate owns configured single-account GitHub login, explicit approval, connection management, and Firestore persistence. The resource SDK performs fresh introspection for every request.

Connections use the provider grant ID, exposed as `connection_id`. Browser login sessions are separate. Grant revocation persists a tombstone and serializes with grant-related writes so concurrent token persistence cannot restore access.

Terraform enables Firestore `expiresAt` TTL cleanup for provider artifact entries, browser login attempts, browser approvals, browser sessions, and identity sessions. Firestore removes expired documents asynchronously; application authorization still checks each record's expiry directly. Connection revocation records have no TTL and remain durable.

See [current architecture](../../../ARCHITECTURE.md) and [setup](../../../README.md). Implementation facts and verification status must match the source tree; this package does not claim a deployment.
