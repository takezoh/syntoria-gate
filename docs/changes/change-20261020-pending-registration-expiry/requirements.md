---
change: change-20261020-pending-registration-expiry
role: requirements
---

<!-- lifecycle is owned by change.md -->

# Requirements

## Content

The previous registration quota allowed 1000 registrations over a namespace lifetime and never decreased. An anonymous caller could reach it in about 50 minutes at the 20-per-minute rate, after which no new AI client could connect until an operator intervened.

Registration cannot require the person's authentication. MCP clients register from their own process or service, without Gate's browser cookies, and MCP clients have no way to obtain an initial access token. Authorization therefore stays at sign-in and explicit connection approval, and registration must remain inert and bounded.

- A new DCR registration is pending for 24 hours. After that, authorization, approval and introspection treat it as missing, and Firestore TTL deletes it.
- The first approved OAuth connection makes the registration permanent in the same transaction that creates the connection. Approval of a missing or expired registration fails and creates no connection.
- Client records without an expiry, including registrations created before this change, stay permanent.
- Capacity is 1000 registrations per fixed 24-hour window and 20 per fixed minute, shared across instances. Neither stored window moves backward. Exhaustion returns 429 and recovers when the window ends. Storage failure still fails closed with 503.

The owner defined one AI as one installation: the same AI app on another device is a different AI, and a client that registers again may be treated as a different AI. Documentation must state that `client_id` identifies one DCR registration and is never reused, that `connection_id` identifies one approval and is the revocation unit, and that resource servers may key per-AI state on issuer, subject and `client_id`. Registrations are not merged by name or redirect URI, because names are unverified and the same product on different devices registers identical metadata.
