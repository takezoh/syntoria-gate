---
id: change-20261030-connection-check
kind: change
title: Answer resources whether an exact connection is still valid
status: draft
created: '2026-10-30'
profile: sdd@1
intent: Weave delivers MCP Events webhooks after the subscribing request has ended, so it has no access token to introspect before each delivery. Resources need an online, uncached answer whether the exact connection that subscribed still authorizes them, so revocation stops delivery.
outcomes:
- A configured resource can ask POST /connections/check with {subject,connection_id,client_id} and receives {valid}, true only for the account's approved, unrevoked OAuth connection of exactly that client with an unexpired grant.
- The SDK exposes createGateConnections().check(), mapping every non-authoritative answer to GateError(503).
scope:
- src/**
- packages/sdk/src/**
- tests/**
- docs/**
- ARCHITECTURE.md
non_goals:
- Caching, listing or enumerating connections for resources.
- Changing approval, revocation or introspection behavior.
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261030-connection-check/requirements.md
  required: true
- role: implementation
  path: changes/change-20261030-connection-check/implementation.md
  required: true
- role: verification
  path: changes/change-20261030-connection-check/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
---

## Summary

## Closure Notes
