---
change: change-20261029-sign-out-and-hsts
role: implementation
---

<!-- lifecycle is owned by change.md -->

# Implementation

`Storage.deleteIdentity` deletes the hashed identity session document. `browserLogout` calls it after the existing atomic device logout and expires `__Host-gate_identity` with `__Secure-gate_session`; the cookie reaches Gate because the SPA's credentialed request is same-site. `signOut` serves `POST /logout`: it checks the Origin and form, compares the CSRF value with the identity session when one exists, deletes the identity session, ends a valid device session through `logoutBrowser`, and redirects to the `/signed-out` page. `/connections` renders the sign-out form with the identity CSRF value. The request handler sets HSTS before routing, so provider-owned and error responses carry it too.
