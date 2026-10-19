# Syntoria Gate

Gate provides shared sign-in and connection approval for one person's Syntoria applications. Sign in with the configured GitHub account, approve a browser device once, and use registered applications through a common session. Each approved connection has full access, subject to the receiving application's explicit user admission and data boundaries.

Gate runs on Cloud Run with TypeScript, Node.js 24, `oidc-provider` and Firestore Native mode. It serves its own sign-in, approval and connection-management pages. Application SPAs call their APIs directly; Gate verifies sessions and tokens without forwarding application requests.

## Using Gate

Open a registered application and choose its sign-in action. Gate verifies the configured immutable GitHub account ID and asks for explicit device approval. An active approved browser session can be reused across registered applications without another approval for each app. Browser sessions expire after a fixed configured lifetime and can be revoked before expiry.

Open `/connections` at the operator-configured Gate origin to inspect and revoke browser devices or OAuth connections. Signing out a browser device invalidates its shared session across the suite. Independent devices and MCP OAuth connections remain active.

MCP clients dynamically register through OAuth DCR, then connect through authorization code with PKCE. Client registration does not authorize access: the configured person must sign in and approve the connection. Their approvals and Bearer credentials are separate from browser device sessions. Gate admits only the configured GitHub account and has no public signup, organizations, roles or selectable feature permissions.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Responsibilities, trust boundaries and persistence guarantees |
| [Application integration](docs/integration.md) | SPA sessions, API verification, MCP clients and the Node SDK |
| [HTTP interface](docs/api.md) | Browser endpoints, cookies, discovery and error behavior |
| [Configuration](docs/configuration.md) | Environment variables, registrations and secret handling |
| [Development](docs/development.md) | Local setup, build and verification boundaries |
| [Deployment](docs/deployment.md) | Infrastructure, DNS/TLS, release and recovery |
| [Troubleshooting](docs/troubleshooting.md) | Login, approval, authorization and certificate failures |

Actual domains, redirect registrations and credentials belong in ignored operator configuration. Examples use synthetic domains. Documentation and code comments are written in English.
