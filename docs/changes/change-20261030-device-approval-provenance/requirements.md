---
change: change-20261030-device-approval-provenance
role: requirements
---

# Requirements

A legitimate device approval must work when a browser omits Origin but supplies an exact same-issuer HTTP Referer. A supplied foreign or opaque Origin must never be overridden by Referer. Missing provenance, invalid CSRF, expired or unbound approval state and replay must remain rejected. Identity admission, resource boundaries and storage transactions remain unchanged.

The approval page must explicitly establish its referrer policy. Denial diagnostics must contain only bounded reason codes and header classifications, with no raw URLs, credentials, cookies, approval identifiers or deployment identifiers.
