---
id: change-20261028-change-confirmation
kind: change
title: Confirm one exact change with the signed-in person
status: active
created: '2026-10-28'
profile: sdd@1
intent: Let a resource record that the person, not the AI, approved one exact change,
  through a Gate page the AI cannot operate on the person's behalf through its connection.
outcomes:
- A resource can create, consume once and cancel a confirmation for an active OAuth
  connection of the configured account.
- The signed-in person sees the resource-rendered summary in full and approves or
  denies it on Gate.
- A confirmation is valid while its connection is active, with no separate timer
  and no pending limit.
- Gate pages share one hash-admitted stylesheet, and the connections page shows each
  AI client's unverified name, shortened client ID and approval date.
- The SDK's createGateConfirmations creates, consumes and cancels confirmations and
  fails closed.
scope:
- packages/sdk/src/index.ts
- tests/sdk.test.mjs
- src/confirmation.ts
- src/service.ts
- src/storage.ts
- tests/confirmation.test.mjs
- tests/provider.test.mjs
- scripts/run-tests.mjs
- infra/terraform/main.tf
- ARCHITECTURE.md
- docs/**
non_goals:
- Resource-server changes, including Lore's confirmation flow.
- User verification such as passkeys at approval.
- Production deployment or Terraform apply.
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261028-change-confirmation/requirements.md
  required: true
- role: implementation
  path: changes/change-20261028-change-confirmation/implementation.md
  required: true
- role: verification
  path: changes/change-20261028-change-confirmation/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: Resource-authenticated change confirmations with a signed-in approval page,
  single consumption and connection-bound validity; restyled Gate pages.
updated: '2026-10-28'
---

## Summary

A resource asks Gate to confirm one exact change. Gate shows the resource's summary to the signed-in person, records the decision and lets the resource consume an approval once. A confirmation lives as long as the requesting OAuth connection. Gate pages now share one stylesheet that the Content Security Policy admits by hash.
