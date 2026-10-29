---
change: change-20261029-introspection-client-name
role: requirements
---

<!-- lifecycle is owned by change.md -->

# Requirements

- FR-001: When Gate issues an access token to a client that registered `client_name`, active introspection of that token shall include `client_name` with the registered value. Tokens issued by refresh shall include it as well.
- FR-002: When the client registered no name, introspection shall omit `client_name`.
- FR-003: `verifyToken` and `authenticate` shall return `clientName` with the relayed value when it satisfies the registration rule (trimmed, 1–100 characters, no control characters), and null otherwise.
- FR-INV-001: The name shall not change whether a token is active, whom it identifies, or any other verification result; it is unverified display data.

Counterexamples: a malformed or absent name rejecting a valid token; a name replacing the client ID as identity; a browser session principal gaining a client name; an invalid name passed through to a resource.
