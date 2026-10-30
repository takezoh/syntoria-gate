---
id: change-20261030-device-approval-provenance
kind: change
title: Preserve same-origin provenance for browser device approval
status: draft
created: '2026-10-30'
profile: sdd@1
intent: Restore legitimate browser device approval when Origin is omitted while preserving
  identity binding, CSRF and single-use checks.
outcomes:
- Valid bound device approval succeeds with absent Origin and an exact issuer Referer.
- Foreign and opaque Origins, missing provenance, invalid CSRF and replay remain rejected.
scope:
- src/service.ts
- tests/provider.test.mjs
- docs/api.md
- docs/security.md
- docs/troubleshooting.md
non_goals: []
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261030-device-approval-provenance/requirements.md
  required: true
- role: implementation
  path: changes/change-20261030-device-approval-provenance/implementation.md
  required: true
- role: verification
  path: changes/change-20261030-device-approval-provenance/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: Device approval sets a same-origin referrer policy, accepts an exact issuer
  Referer only when Origin is absent, and records bounded denial classifications.
---

## Summary

Restore browser device approval with explicit page provenance and a strict Referer fallback for absent Origin. Preserve CSRF and approval binding, and expose bounded denial classifications for any remaining hosted failure.

## Closure Notes

Local verification is complete. Hosted rollout and the original device retry are recorded in verification.md.
