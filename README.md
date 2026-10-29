# Syntoria Gate

## Sign in once. Decide which AIs act for you.

**Gate is the shared sign-in service for your Syntoria applications. You approve each browser device and each AI connection yourself, see them in one place, revoke any of them, and approve the exact changes an AI asks to make for you.**

Syntoria Gate signs one person in to their own Syntoria services, such as [Syntoria Lore](https://github.com/takezoh/syntoria-lore) and [Syntoria Weave](https://github.com/takezoh/syntoria-weave), with a single GitHub account. It is shared infrastructure rather than another Syntoria capability: Gate decides who may connect, while each service keeps its own data, user admission and rules.

Connect one AI to Weave and another to Lore. Each sends you to Gate once to sign in and approve that connection. Both then appear on Gate's connections page, and revoking one stops only that AI. When an AI later asks Lore to record your own decision, Lore gives it a Gate link to show you: you read the exact change and approve or deny it, and the AI cannot approve it for you.

## Sign in once

Open a registered application and choose its sign-in action. Gate checks that you signed in to GitHub as the one configured account, then asks you to approve this browser device. Other registered applications reuse that approval, so you do not approve each app again. A browser session ends after a fixed lifetime set by the operator, or earlier when you sign out or revoke it.

## Approve each AI connection

An AI client registers itself with Gate through OAuth dynamic client registration (DCR), then sends you to Gate to sign in and approve the connection, using authorization code with PKCE. Registering gives the client nothing, and a registration you do not approve within 24 hours expires. Each AI installation is its own client, so the same AI app on another device asks for its own approval. AI connections are independent of browser device sessions.

An approved browser device is you, using an application. An approved AI connection is a client acting for you: it reaches the same applications, subject to each application's user admission and data boundaries, but it is not you, and applications tell its changes apart from yours.

## Approve the exact change yourself

When an AI asks an application to make a change that needs your own decision, the application gives the AI a Gate link to show you. Open it, sign in, read the change as the application describes it and approve or deny it. Nothing changes until you approve, an approval is used once, and the AI cannot approve on your behalf through its connection.

## See and revoke access

Open `/connections` at your Gate origin to see your approved AI clients and browser devices, with each AI's self-reported name and the date you approved it, and to revoke any of them. Signing out of a browser device ends its shared session across your applications and your Gate sign-in on that browser, so approving it again requires GitHub sign-in; other devices and AI connections stay active. `/connections` also lets you sign out of Gate on the browser you are using. Applications check every request with Gate, so later requests from a revoked connection are rejected.

## Who it is for

| Reader | Why Gate fits |
| --- | --- |
| The person who runs Syntoria for themselves | One GitHub account signs in to every registered application, and every device and AI connection needs that person's own approval |
| Builders of Syntoria applications and resource APIs | One online verification for browser sessions and AI tokens, per-AI client identifiers, and change confirmations through the Node SDK; see [application integration](docs/integration.md) |

## What Gate does not do

- Gate admits exactly one configured GitHub account. There is no public sign-up, organization, role or per-feature permission.
- Gate approval does not create a user in an application. Each application admits your Gate account separately and keeps its own data boundary.
- Gate does not host applications, proxy their API calls, store their data or register MCP tools.
- A client's name is self-reported and unverified. Gate shows the client's actual callback beside it when you approve.
- A change confirmation shows that your signed-in Gate session approved the change, not that you read it. Gate cannot tell an AI that controls your signed-in browser from you.

## Status

The latest recorded production release, on 2026-10-29, made sign-out end Gate sign-in on the browser and added HSTS to every response. An earlier release the same day added change confirmations and expiry for unapproved registrations. Their hosted probes covered readiness, OIDC discovery, the HSTS header and the rejection of unauthenticated confirmation and sign-out requests; the 2026-10-20 release probes covered dynamic registration. The release records do not include a hosted personal GitHub sign-in or sign-out, a connection approval and token exchange through a real AI host, or a real change confirmation. See the [sign-out and HSTS release](docs/changes/change-20261029-sign-out-and-hsts/verification.md#production-release), the [change confirmation release](docs/changes/change-20261028-change-confirmation/verification.md#production-release) and the [DCR release record](docs/note/note-20261020-dcr-production-release.md).

## How it works

Gate is an OpenID Connect provider built on `oidc-provider`, written in TypeScript for Node.js 24, running on Cloud Run with Firestore Native mode. It serves its own sign-in, approval, confirmation and connection-management pages. A device you approve receives a shared HttpOnly session cookie; an AI connection receives opaque Bearer tokens. Application SPAs call their own APIs directly, and each API verifies the credential with Gate on every protected request before applying its own user admission. Gate does not forward application requests.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Responsibilities, trust boundaries and persistence guarantees |
| [Identity and registration controls](docs/security.md) | Single-account restriction, public DCR limits, operator-only resource registration, approval boundaries and change confirmations |
| [Application integration](docs/integration.md) | SPA sessions, API verification, MCP clients and the Node SDK |
| [HTTP interface](docs/api.md) | Browser endpoints, change confirmations, cookies, discovery and error behavior |
| [Configuration](docs/configuration.md) | Environment variables, registrations and secret handling |
| [Development](docs/development.md) | Local setup, build and verification boundaries |
| [Deployment](docs/deployment.md) | Infrastructure, DNS/TLS, release and recovery |
| [Troubleshooting](docs/troubleshooting.md) | Login, approval, authorization and certificate failures |

Examples use synthetic domains. Actual domains, redirect registrations and credentials belong in ignored operator configuration. Dated change and release records are under [docs/changes](docs/changes/) and [docs/note](docs/note/).

## License

No license has been selected yet, so this repository does not grant terms for use.

[Architecture](ARCHITECTURE.md) · [Application integration](docs/integration.md) · [Development](docs/development.md)
