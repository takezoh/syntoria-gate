# Application integration

Register each browser application and resource API explicitly using the [configuration contract](configuration.md). MCP clients register dynamically through DCR. A browser app registration, a resource introspection client and an MCP OAuth client have separate identities and responsibilities.

## Browser applications

1. Serve the SPA and API over HTTPS beneath the configured shared cookie parent.
2. Navigate the browser to Gate's `/browser/login` with exactly one registered `app_id` and one exact `redirect_uri`. Use `URLSearchParams` to encode them.
3. Gate verifies GitHub identity and, when needed, presents device approval. An existing active device session returns directly to the registered app.
4. The static return page resumes or refreshes the application's session check. No token, code or session secret is added to that return URL.
5. Fetch the application's API with `credentials: 'include'`. JavaScript never reads the HttpOnly session cookie. The API verifies it online with Gate for each protected request.

The return page can signal its same-origin opener or application tab, but must validate message origins and preserve unsaved proposals. Gate does not implement application tab coordination or application state recovery.

### API verification

The Node SDK is the local workspace package `@syntoria/gate-sdk`. Build it with the repository's build command and use an explicitly versioned package or source copy in consumers; package metadata alone does not establish publication to a registry.

```ts
import { createGateVerifier, GateError } from '@syntoria/gate-sdk';

// Values are injected at server startup; no secret is sent to the SPA.
const verifier = createGateVerifier({
  issuer: settings.gateIssuer,
  audience: settings.resourceAudience,
  clientId: settings.resourceClientId,
  clientSecret: settings.resourceClientSecret,
  browserClientId: settings.browserClientId,
});

try {
  const principal = await verifier.verifySession(sessionCookieValue);
  // Apply the API's explicit enabled issuer/subject admission and user data scope.
  await handleAuthorizedRequest(principal);
} catch (error) {
  if (error instanceof GateError) {
    sendAuthorizationFailure(error.status, error.code);
  } else {
    throw error;
  }
}
```

`settings`, cookie parsing, admission, request handling and error responses in this example are consumer-owned integration points. Parse the single `__Secure-gate_session` cookie without accepting duplicate or malformed credentials. Reject ambiguous cookie/Bearer requests. Do not accept a user identity from public headers or request arguments.

| SDK method | Input and result |
| --- | --- |
| `verifySession(session)` | Browser cookie value; returns immutable `GateSessionPrincipal` with issuer, user ID, connection ID, browser client ID, expiry in epoch seconds and CSRF token |
| `verifyToken(token)` | Raw opaque access token; returns immutable `GatePrincipal` with issuer, user ID, connection ID, client ID and `clientName`, the client's unverified registration name for display or null |
| `authenticate(header)` | A single `Bearer <token>` Authorization value; same result as `verifyToken` |
| `protectedResourceMetadata(resource, issuer)` | HTTPS metadata for an API's OAuth protected-resource discovery response |

Every successful credential verification uses online introspection. OIDC discovery metadata may be reused, but positive authorization results are not cached. The default timeout is 3000 milliseconds; `timeoutMs` accepts 1 through 60000. Invalid/inactive credentials produce `GateError` 401 (`invalid_token`); timeouts, transport failures and unusable authorization responses produce 503 (`authorization_unavailable`). Configuration mistakes throw during verifier construction. Preserve the distinction so an outage does not appear to be a user sign-out.

For browser mutations, the resource API must enforce its exact registered SPA Origin, credentialed CORS and the session's CSRF token. Gate validates these for its own endpoints, not for downstream APIs. Authorization cannot undo an operation that has already passed its final check; an application needing tighter revocation ordering must define its own final authorization/commit boundary.

### Sign out the device

Fetch Gate's `GET /browser/session` with credentials from a registered SPA origin to obtain `{csrf_token}`. Then POST `{}` as JSON to `/browser/logout`, including credentials and `X-CSRF-Token`. A successful response is 204 and expires the shared cookie. This revokes the current browser connection across the suite without revoking independent MCP grants. It also ends Gate sign-in on this browser, so approving this browser again requires GitHub sign-in. Other tabs should recheck authorization and preserve their unsaved state.

## MCP OAuth clients

Use Gate's `/.well-known/openid-configuration` to obtain registration, authorization, token, introspection and revocation endpoints. Dynamically register a public client through the advertised registration endpoint and persist its returned client ID with the issuer and callback binding. Do not use a predefined public client ID. Use authorization code with PKCE S256, the exact registered redirect, `scope=openid`, an explicit resource audience and client-owned state validation. Public MCP clients use no client secret. Request only the registered audience; Gate uses opaque Bearer access tokens rather than self-contained access JWTs.

Resource services verify each Bearer token with `verifyToken` or `authenticate`. An ID token is an identity assertion, not an API access token. Refresh, authorization-code consumption and OAuth revocation remain owned by `oidc-provider`. Access and ID tokens have a configured lifetime of 300 seconds; authorization codes have 60 seconds, and grants/refresh tokens have a configured 30-day lifetime.

OAuth connection approval is independent of the common browser device approval. The resource API must map the verified issuer/subject to an explicitly enabled internal user, without a static MCP-client allowlist.

### Telling the person from an AI

Gate's two credentials stand for different actors. A browser session, verified with `verifySession`, is the person using a registered application on a device they approved. A Bearer token, verified with `verifyToken`, is a client connection: an AI or other program the person approved, acting for them. Its `subject` names the person, but the actor is the client. Record which of the two made each change, and do not treat a Bearer request as the person's own decision. When a change needs that decision, request a [change confirmation](#confirming-a-change). A click inside an AI host's embedded UI reaches the resource through that host's connection, so it counts as the client.

### Identifying each AI client

A verified `GatePrincipal` carries two client identifiers with different meanings:

| Field | Identifies | Changes when |
| --- | --- | --- |
| `clientId` | One AI installation: one DCR registration | The client registers again, for example on another device or after losing its stored registration |
| `connectionId` | One approval of that registration | The person approves the client again; revocation applies to one connection |

A registration that is never approved expires after 24 hours; the first approval makes it permanent, so an approved `clientId` stays stable across token refreshes and later approvals. Gate never reuses a `clientId`. A resource API that needs per-AI attribution can key it on issuer, subject and `clientId`; access still follows the person's connection approval, not the client identity. Treat a new `clientId` as a new AI, and do not merge registrations by client name or redirect URI: names are unverified, and the same product on different devices registers identical metadata. A client that registers separately for each resource receives a separate `clientId` for each one. `verifyToken` requires a nonempty `client_id`; when `azp` is present it must match. `verifySession` additionally checks the configured browser client ID. Keep tokens in client-managed secure storage and keep introspection credentials only on the resource server.

### Confirming a change

Connection approval lets an AI use a resource; it does not show that the person wanted a particular change. When a change needs the person's own approval, the resource asks Gate for a change confirmation:

1. Store the exact pending change, render a plain-text summary of every state-changing field from it, and compute a change hash that covers both. Never let the AI supply the summary.
2. `POST /confirmations` with the resource's introspection credentials, the verified subject and `connectionId` of the requesting connection, a unique `reference` for the stored change, the hash and the summary. Give the returned `url` to the AI to show the person.
3. When the AI reports back, `POST /confirmations/consume` with the same `id`, `reference` and hash, immediately before committing. Commit the stored change only on `consumed`, and only once. Treat `pending`, `denied`, `used` and `expired` as not approved.
4. `POST /confirmations/cancel` when the stored change becomes invalid, for example after the data it shows is deleted.

A confirmation stays valid while the requesting connection is active. If the resource's commit fails after `consumed`, the approval is spent and the person must approve again. The [HTTP interface](api.md#change-confirmations) defines the calls.

`createGateConfirmations({ issuer, clientId, clientSecret })` wraps them with the resource's introspection credentials. It applies the same deadline, response-size limit and redirect refusal as the verifier:

```ts
const confirmations = createGateConfirmations({ issuer, clientId, clientSecret });
const { id, url } = await confirmations.create({ subject, connectionId, reference, changeHash, summary });
const result = await confirmations.consume(id, reference, changeHash);
if (result.status === 'consumed') commitStoredChange();
await confirmations.cancel(id, reference);
```

`create` fails with `GateError(401)` when the requesting connection is no longer active. Any other failure, including an unexpected status or a malformed response, is `GateError(503)`.

## Shared-cookie trust boundary

The parent-scoped cookie is sent to matching sibling hosts. All services under that cookie scope must be trusted; do not place unrelated or user-controlled hosting beneath it. HttpOnly prevents JavaScript from reading the cookie but does not stop injected JavaScript from making authenticated requests. Applications remain responsible for XSS prevention, Origin/CSRF enforcement and user-scoped persistence. CORS governs browser access and is not a substitute for authentication.

Keep actual endpoints and secrets in runtime configuration. Gate's HTTP contracts and cookie lifetimes are described in [the API reference](api.md).
