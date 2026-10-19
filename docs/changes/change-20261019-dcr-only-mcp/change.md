---
id: change-20261019-dcr-only-mcp
kind: change
title: Use dynamic registration for MCP authorization
status: active
created: '2026-10-19'
profile: sdd@1
intent: Use dynamic public-client registration without manual client IDs or callback
  provisioning while preserving personal approval and explicit user admission.
outcomes:
- MCP public clients register dynamically and gain access only after personal authentication,
  approval and enabled application-user admission.
- Registration metadata and persistence are bounded and the actual provider/storage/resource
  path is tested.
scope:
- src/**
- packages/**
- scripts/**
- tests/**
- infra/**
- README.md
- ARCHITECTURE.md
- docs/**
- config.example.env
non_goals:
- Production deployment, new roles or permission scopes, CIMD or fixed public-client
  compatibility.
- Changes to business data, browser-session trust boundaries or resource introspection
  secrets.
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261019-dcr-only-mcp/requirements.md
  required: true
- role: implementation
  path: changes/change-20261019-dcr-only-mcp/implementation.md
  required: true
- role: verification
  path: changes/change-20261019-dcr-only-mcp/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: DCR-only public MCP clients with explicit personal approval and enabled subject
  admission.
updated: '2026-10-19'
---

## Summary

Public MCP clients register dynamically with Gate. Personal authentication, connection approval and explicitly enabled application-user admission remain separate authorization boundaries. Current documents describe this contract; technical probes and runtime evidence are recorded in the package members.
