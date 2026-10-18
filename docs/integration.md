# Application integration

Register each application, resource API and MCP client explicitly using the [configuration contract](configuration.md). A browser app registration, a resource introspection client and an MCP OAuth client have separate identities and responsibilities.

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
  allowedClientIds: [settings.browserClientId, settings.mcpClientId],
});

try {
  const principal = await verifier.verifySession(sessionCookieValue);
  // Apply the API's explicit issuer/subject/client admission and user data scope.
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
| `verifyToken(token)` | Raw opaque access token; returns immutable `GatePrincipal` |
| `authenticate(header)` | A single `Bearer <token>` Authorization value; same result as `verifyToken` |
| `protectedResourceMetadata(resource, issuer)` | HTTPS metadata for an API's OAuth protected-resource discovery response |

Every successful credential verification uses online introspection. OIDC discovery metadata may be reused, but positive authorization results are not cached. The default timeout is 3000 milliseconds; `timeoutMs` accepts 1 through 60000. Invalid/inactive credentials produce `GateError` 401 (`invalid_token`); timeouts, transport failures and unusable authorization responses produce 503 (`authorization_unavailable`). Configuration mistakes throw during verifier construction. Preserve the distinction so an outage does not appear to be a user sign-out.

For browser mutations, the resource API must enforce its exact registered SPA Origin, credentialed CORS and the session's CSRF token. Gate validates these for its own endpoints, not for downstream APIs. Authorization cannot undo an operation that has already passed its final check; an application needing tighter revocation ordering must define its own final authorization/commit boundary.

### Sign out the device

Fetch Gate's `GET /browser/session` with credentials from a registered SPA origin to obtain `{csrf_token}`. Then POST `{}` as JSON to `/browser/logout`, including credentials and `X-CSRF-Token`. A successful response is 204 and expires the shared cookie. This revokes the current browser connection across the suite without revoking independent MCP grants. Other tabs should recheck authorization and preserve their unsaved state.

## MCP OAuth clients

Use Gate's `/.well-known/openid-configuration` to obtain authorization, token, introspection and revocation endpoints. Use authorization code with PKCE S256, the exact registered redirect, `scope=openid`, an explicit resource audience and client-owned state validation. Public MCP clients use no client secret. Request only the registered audience; Gate uses opaque Bearer access tokens rather than self-contained access JWTs.

Resource services verify each Bearer token with `verifyToken` or `authenticate`. An ID token is an identity assertion, not an API access token. Refresh, authorization-code consumption and OAuth revocation remain owned by `oidc-provider`. Access and ID tokens have a configured lifetime of 300 seconds; authorization codes have 60 seconds, and grants/refresh tokens have a configured 30-day lifetime.

OAuth connection approval is independent of the common browser device approval. Register the permitted MCP client in the resource API's local admission policy as well as Gate. Keep tokens in client-managed secure storage and keep introspection credentials only on the resource server.

## Shared-cookie trust boundary

The parent-scoped cookie is sent to matching sibling hosts. All services under that cookie scope must be trusted; do not place unrelated or user-controlled hosting beneath it. HttpOnly prevents JavaScript from reading the cookie but does not stop injected JavaScript from making authenticated requests. Applications remain responsible for XSS prevention, Origin/CSRF enforcement and user-scoped persistence. CORS governs browser access and is not a substitute for authentication.

Keep actual endpoints and secrets in runtime configuration. Gate's HTTP contracts and cookie lifetimes are described in [the API reference](api.md).
