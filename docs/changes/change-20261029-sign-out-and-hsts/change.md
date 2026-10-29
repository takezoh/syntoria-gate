---
id: change-20261029-sign-out-and-hsts
kind: change
title: End Gate sign-in on sign-out and require HTTPS
status: draft
created: '2026-10-29'
profile: sdd@1
intent: A security review found that Gate sign-in outlived sign-out for 24 hours,
  letting a shared browser approve a device again without GitHub, and that Gate sent
  no HSTS. Sign-out now ends Gate sign-in, and every response requires HTTPS for a
  year.
outcomes:
- POST /browser/logout also deletes the browser's identity session and clears its
  cookie.
- POST /logout from /connections ends the identity session and the current device
  session, leaving AI connections and other devices active.
- Every Gate response carries Strict-Transport-Security max-age=31536000.
scope:
- src/service.ts
- src/storage.ts
- tests/provider.test.mjs
- README.md
- ARCHITECTURE.md
- docs/api.md
- docs/integration.md
- docs/security.md
non_goals:
- includeSubDomains or HSTS preload, which need every host under the cookie parent
  on HTTPS.
- Revoking identity sessions of other browsers.
- Production deployment.
change_classes: []
governance:
  gate: auto
  reasons: []
members:
- role: requirements
  path: changes/change-20261029-sign-out-and-hsts/requirements.md
  required: true
- role: implementation
  path: changes/change-20261029-sign-out-and-hsts/implementation.md
  required: true
- role: verification
  path: changes/change-20261029-sign-out-and-hsts/verification.md
  required: true
promotion: []
unresolved_decisions: []
tags: []
owners: []
relations: []
source_paths: []
summary: Sign-out ends Gate sign-in on the browser, POST /logout is added, and every
  response sends HSTS.
---

## Summary

Device sign-out from an application now also ends Gate sign-in on that browser, and `/connections` offers "Sign out of Gate on this browser" (`POST /logout`, issuer Origin and identity CSRF), which also ends that browser's device session and shows `/signed-out`. All responses send HSTS. Committed as `52b383e` and released to production on 2026-10-29; see the [verification](verification.md#production-release).

## Closure Notes
