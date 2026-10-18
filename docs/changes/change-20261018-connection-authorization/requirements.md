---
change: change-20261018-connection-authorization
role: requirements
---

# Requirements

- Only the configured immutable GitHub user ID may establish a login. Mutable login names and email addresses do not identify the user.
- Authorization code requests require PKCE S256 and an exact registered redirect URI. Client and resource registrations are explicit configuration.
- Each new connection requires explicit approval for full personal access, including when the browser is already signed in. Denial and silent authorization must not grant access.
- A connection is an authorization grant, independent of the browser login session. Two connections from the same browser and client remain separate.
- The user can list connections and revoke one without revoking siblings. Writes to the management interface require browser authentication and CSRF validation.
- Revocation takes effect on the next resource-server introspection. Refresh and concurrent persistence must not revive a revoked connection.
- OAuth state, sessions, grants, and tokens persist in Firestore. Signing and cookie keys survive process restarts through explicit configuration.
- Resource servers verify tokens online and validate issuer, audience, client, user, expiration, token type, and connection identity. Provider outages fail closed.
- Do not implement public registration, organizations, roles, feature permissions, device-code flow, or a general administration console.

Real GitHub login, deployed HTTPS behavior, and consumer application integration require their own acceptance; local fakes do not establish them.
