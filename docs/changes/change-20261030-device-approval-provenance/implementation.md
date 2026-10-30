---
change: change-20261030-device-approval-provenance
role: implementation
---

# Implementation

The device approval form posts explicitly to /browser/approve and its response sets Referrer-Policy: same-origin. The POST handler prefers Origin; only an absent Origin permits an exact same-issuer HTTP Referer fallback. Explicit null and foreign Origins remain denied. Existing identity, binding, CSRF and transactional consumption checks still apply.

Rejected POST requests emit browser_approval_denied with a bounded reason and Origin/Referer classifications. Other browser and management endpoints keep their existing contracts. See the current HTTP and security documentation for the resulting behavior.
