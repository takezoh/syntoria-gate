---
id: change-20261018-connection-authorization
kind: change
title: Common user identity and connection authorization
status: draft
created: '2026-10-18'
profile: sdd@1
intent: Provide one personal identity and explicitly revocable full-access client
  connections across Syntoria applications.
outcomes: []
scope: []
non_goals: []
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261018-connection-authorization/requirements.md
  required: true
- role: implementation
  path: changes/change-20261018-connection-authorization/implementation.md
  required: true
- role: verification
  path: changes/change-20261018-connection-authorization/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: Minimal personal OAuth service with GitHub login, explicit connection approval,
  Firestore persistence, and online resource verification.
---

# Personal connection authorization

Gate is the common identity and connection authorization service for one person's Syntoria applications. Implement a TypeScript/Node.js service using oidc-provider and Firestore. GitHub login admits only the configured immutable GitHub user ID. Each explicitly approved client connection has full access; connections can be inspected and individually revoked.

The earlier unfinished Keycloak/Java implementation is replaced. This change does not deploy Gate or alter Weave/Lore authentication. There is no public registration, organization management, role system, feature permission model, or general administration console.

Implementation and local verification are recorded in the package members. Hosted login and consumer integration remain separate acceptance boundaries.
