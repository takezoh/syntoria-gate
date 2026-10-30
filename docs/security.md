# Identity and registration controls

Gate is a personal authorization service. Only the configured GitHub account can
sign in and approve connections. Public OAuth client registration is a separate,
bounded operation and does not grant access to any application data.

## Account restriction

`GATE_GITHUB_USER_ID` contains the permitted account's immutable positive numeric
GitHub user ID. It is not a GitHub login name, email address, organization name or
OAuth App client ID. Configuration validation requires a positive decimal ID.
Gate represents this person as the subject `github:<numeric-id>`.

The GitHub callback follows these checks in [the service](../src/service.ts):

1. Require one authorization code and one state value. Resolve and consume the
   stored login attempt using the state and the browser's login-binding cookie.
   A callback URL alone is not a valid login attempt.
2. Exchange the code server-side using the configured GitHub OAuth App credentials
   and Gate callback URI. Use the resulting GitHub access token to request
   `https://api.github.com/user`; neither a caller-supplied ID nor profile text is
   accepted as the identity.
3. Require a successful response with a safe integer `id`, convert it to a string,
   and compare it exactly with `GATE_GITHUB_USER_ID`.
4. Return HTTP 403, `Account not allowed`, for another account, before creating
   Gate identity state or proceeding to connection approval. A successful GitHub
   login by itself therefore does not mean that Gate accepts the account.
5. For the permitted account, create a host-only identity session. The OIDC
   provider's `findAccount` also resolves only the configured subject.

GitHub OAuth App ownership does not enforce this personal-account restriction;
Gate's comparison against the authenticated GitHub API response does. There is no
signup, automatic enrollment, email-based admission or organization-membership
fallback.

## Identity is followed by explicit connection approval

An identity session permits approval and connection management; it is not a
resource API credential. Browser device approval and MCP OAuth connection approval
are independent flows.

The identity session is a host-only cookie that lasts at most 24 hours. It ends
earlier when the person signs out of Gate (`POST /logout`) or signs out the browser
device (`POST /browser/logout`), so a shared browser cannot approve a device,
connection or change again without GitHub sign-in.

For OAuth, Gate checks the authenticated identity against the interaction's account
and resolves the actual registered public client and redirect URI. The approval
page displays the escaped, **unverified** client name and actual redirect URI.
Submitting approval requires the same identity session, the exact Gate Origin and
a matching CSRF value. Denial creates no approved connection. Approval persists an
OIDC grant and a connection bound to the account and client.

For a browser device, approval is bound to the verified identity and login-binding
cookie. Its transaction expires after ten minutes and is consumed atomically with
creation of the shared browser session and device connection. The approval form
sets `Referrer-Policy: same-origin` and posts to an explicit same-origin path. Its
POST requires the exact Gate Origin, or, only when Origin is absent, an HTTP(S)
Referer whose parsed origin matches the issuer. Explicit `Origin: null`, foreign
origins, and missing or foreign Referer values are rejected. CSRF, identity, login-binding, expiry and
single-use checks still apply. Failed device-approval POSTs log bounded reason
codes and header classifications without recording header values or request data.
An already approved, active browser device can be reused by other registered
browser applications.

Approving a connection gives it access to Gate's registered suite resources,
subject to each resource API's own explicit user admission and data boundaries.
For OAuth, the grant includes the configured resources, while each issued access
token has its requested resource audience. Gate does not ask the user to select
individual tools or feature permissions.

## Change confirmations

A change confirmation records that the signed-in person approved one exact change
that a resource described. The AI that asked for the change takes no part in the
decision: it can only show the Gate URL.

- Only a configured resource, authenticated with its introspection credentials,
  can create, consume or cancel a confirmation, and only its own. Another resource
  receives the same `expired` answer as for a missing record.
- A confirmation must name the configured account and an active OAuth connection
  of that account. It stays valid only while that connection is approved, not
  revoked and backed by an unexpired grant.
- Before sign-in, Gate shows the same page for every well-formed ID. After sign-in,
  only the confirmation's subject can view or decide it. A decision needs the issuer
  Origin, the identity session's CSRF value and exactly the expected form fields,
  and it is final.
- Consumption checks the resource, reference and change hash and moves an approval
  to `used` in one Firestore transaction, so it succeeds once even under concurrent
  calls.
- The summary is resource-supplied memory or account data. Gate escapes it, never
  truncates it, and deletes it on denial, consumption or cancellation; otherwise
  Firestore TTL removes it after the connection's grant expires.

The confirmation shows that the person's signed-in Gate session approved the change.
It does not show that the person read the summary, and it does not stop an agent
that controls the person's signed-in browser. Gate requires no additional user
verification at approval.

All Gate pages use one stylesheet admitted by its hash in the Content Security
Policy. Pages load no scripts, fonts or other external resources, carry no inline
style attributes and cannot be framed.

## What registration means

Gate does not register MCP tool definitions or proxy MCP tool calls. Weave, Lore
and other resource servers publish and execute their own tools. The following
registrations have different authority:

| Registration | Who can create it | Enforcement |
| --- | --- | --- |
| Public MCP OAuth client | Any caller of the advertised DCR endpoint, within validation and quotas | Creates a public client record only; personal sign-in and explicit approval are still required |
| Resource API and introspection client | Operator through private `GATE_RESOURCES` configuration | Fixed audiences and server-side credentials; no public resource-registration endpoint |
| Browser application | Operator through `GATE_BROWSER_APPS` configuration | Exact registered app ID and HTTPS return URI, with allowed browser origins derived from those URIs |
| MCP tool | The resource server's implementation | Gate authorizes the connection, while the resource server validates the call and enforces its data boundary |

A DCR caller cannot add an API audience, supply resource introspection credentials,
or register an MCP tool inside Gate. Naming a client after a trusted application
also does not make it trusted. There is no vendor or callback-domain allowlist for
public MCP clients: HTTPS cloud callbacks and HTTP loopback native callbacks are
supported so clients can register their own callback URLs.

## Public client registration limits

The provider exposes `/reg` without an initial access token. Gate first projects
untrusted JSON to a constrained public authorization-code profile in
[registration.ts](../src/registration.ts):

- JSON body at most 8192 bytes; one to ten distinct redirect URIs, each at most
  2048 characters; optional client name at most 100 characters.
- Authorization code, optional refresh token, response type `code` and token
  endpoint authentication method `none`. PKCE S256 is required by the provider.
- Canonical HTTPS web redirects or HTTP native loopback redirects; no mixed
  classes, wildcards, embedded credentials or fragments. The provider validates
  redirects during authorization; native loopback matching permits a different
  port, without permitting a different host or callback path.
- No caller-chosen client ID or client secret. Remote key, sector and request
  metadata is rejected without fetching it; unsupported inert fields are omitted.

[Firestore storage](../src/storage.ts) transactionally permits at most 1000 client
registrations per fixed 24-hour window and 20 per fixed minute, shared across
service instances. Limit exhaustion returns HTTP 429; registration storage failure
fails closed. These are global capacity/rate limits, not per-user or per-IP
identity checks. Another caller can still exhaust new-registration capacity, but
only until the current 24-hour window ends. The limits bound pending registration
storage but do not eliminate request costs.

A new DCR Client record is pending for 24 hours. Authorization, approval and
introspection treat an expired pending client as missing, and Firestore TTL deletes
it later. The first approved connection removes the expiry in the same transaction
that creates the connection; approval fails without a connection when the client
is missing or expired. Approved Client records, and records created before pending
expiry was introduced, persist without TTL. Registration management, registration
access tokens and client-ID metadata-document discovery are disabled. There is no
public API to edit registrations or reset capacity. Fixed public-client aliases
are not supported.

Registration itself cannot require the person's authentication: MCP clients
register anonymously from their own process or service, without Gate's browser
cookies or an initial access token. Gate therefore keeps registration inert and
places the authorization decision at sign-in and connection approval.

## Resource and request boundaries

Resource audiences are configured explicitly and must use HTTPS under the shared
cookie parent. Each resource has its own confidential introspection client ID and
secret. These credentials remain server-side; DCR does not issue them. A resource
can introspect an OAuth access token only for its own configured audience. An
unknown resource cannot be added by placing it in an authorization request.

OAuth introspection also requires that the token's public client still exists and
that its grant has a matching active, approved account/client connection. Browser
introspection similarly requires the configured resource credentials and a current
approved device session. The SDK checks identity, audience, approval and expiry
online on each protected request; positive authorization is not cached.

Each receiving API separately maps the verified issuer and subject to an explicitly
enabled internal user, then enforces its own user-scoped data, validation and
transaction rules. Registration and Gate approval do not create that mapping.
CORS or possession of a registration ID is not authorization. Revocation keeps a
durable guard so later credential checks reject the connection; it cannot retract
an operation whose final authorization check already completed.

## Implementation and verification references

- [Configuration validation](../src/config.ts) and [operator configuration](configuration.md).
- [Service and GitHub exchange](../src/service.ts), [registration validation](../src/registration.ts),
  [transactional storage](../src/storage.ts) and [consumer SDK](../packages/sdk/src/index.ts).
- [Provider integration tests](../tests/provider.test.mjs) cover another GitHub
  account being rejected, DCR, explicit approval, PKCE, resource separation,
  shared quotas, revocation and change confirmations. Their GitHub exchange is synthetic; they do not
  establish live GitHub or a particular MCP host's acceptance.
- [Architecture](../ARCHITECTURE.md), [HTTP interface](api.md) and
  [application integration](integration.md).
