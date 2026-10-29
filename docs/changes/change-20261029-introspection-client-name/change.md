---
id: change-20261029-introspection-client-name
kind: change
title: Relay the client's registration name in access-token introspection
status: draft
created: '2026-10-29'
profile: sdd@1
intent: Let a resource show the person which connected client made a change by the
  name the person saw when approving it, instead of an opaque client ID.
outcomes:
- Access-token introspection includes the client's unverified registration name as
  client_name when the client registered one.
- The SDK returns it as GatePrincipal.clientName, or null when absent or malformed;
  it never affects verification.
scope:
- src/service.ts
- packages/sdk/src/index.ts
- tests/provider.test.mjs
- tests/sdk.test.mjs
- docs/api.md
- docs/integration.md
non_goals:
- Verifying or editing client names, or naming browser sessions.
- Using the name for authorization, grants or audit identity.
- Production deployment.
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261029-introspection-client-name/requirements.md
  required: true
- role: implementation
  path: changes/change-20261029-introspection-client-name/implementation.md
  required: true
- role: verification
  path: changes/change-20261029-introspection-client-name/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: Access-token introspection relays the unverified client_name; the SDK exposes
  it as clientName for display only.
---

## Summary

Weave's change review shows which connected client made each change. Gate already stores the DCR `client_name` and shows it, marked unverified, on the approval page, but introspection returned only the client ID. Access tokens now carry the name as an extra claim, so introspection returns `client_name`, and the SDK exposes it as `clientName`. Nothing is committed or deployed.

## Closure Notes
