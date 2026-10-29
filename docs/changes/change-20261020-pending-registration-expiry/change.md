---
id: change-20261020-pending-registration-expiry
kind: change
title: Expire unapproved registrations and define per-AI client identity
status: active
created: '2026-10-20'
profile: sdd@1
intent: Stop an anonymous caller from permanently exhausting DCR registration capacity,
  and give resource servers a stable per-AI client identity.
outcomes:
- An unapproved DCR registration expires after 24 hours; the first approved connection
  makes it permanent in the same transaction.
- Registration capacity is a fixed 24-hour window instead of a lifetime counter, so
  exhaustion recovers without operator intervention.
- Resource servers can rely on client_id as one AI installation and connection_id
  as one revocable approval.
scope:
- src/storage.ts
- tests/provider.test.mjs
- README.md
- ARCHITECTURE.md
- docs/**
non_goals:
- Production deployment or cleanup of existing registrations.
- Authenticating callers before registration, CIMD, or merging registrations by metadata.
- SDK, token, introspection response or resource-server changes.
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261020-pending-registration-expiry/requirements.md
  required: true
- role: implementation
  path: changes/change-20261020-pending-registration-expiry/implementation.md
  required: true
- role: verification
  path: changes/change-20261020-pending-registration-expiry/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: Pending DCR registrations expire unless approved; capacity resets per 24-hour
  window; client_id is the per-AI identity for resource servers.
updated: '2026-10-20'
---

## Summary

A DCR registration is pending until its first approved connection and expires after 24 hours otherwise. Registration capacity resets every fixed 24-hour window. Current documents also define `client_id` as one AI installation and `connection_id` as one approval, so resource servers can attribute work to each AI.
