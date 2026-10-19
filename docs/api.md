# HTTP interface

All paths are relative to the configured HTTPS issuer. Gate serves HTML for its own login, approval and connection management, and JSON for session verification. It does not host application SPAs or forward their API calls. Implementation: [src/service.ts](../src/service.ts).

## Discovery and OAuth

Read `GET /.well-known/openid-configuration` for provider-owned endpoint URLs, supported PKCE methods and JWKS. Use the advertised endpoints rather than hard-coding `oidc-provider` routes. The metadata advertises `registration_endpoint` for public MCP clients. POST bounded JSON public-client metadata there to obtain a server-generated `client_id` with HTTP 201. Gate issues no client secret, registration access token or management endpoint. Registration alone grants no access; authorization requires personal login, connection approval and PKCE S256. Invalid metadata returns 400, oversized bodies 413, exhausted registration rate/capacity 429, and registration storage unavailability 503. See [registration constraints](configuration.md#registrations). Resource clients authenticate introspection using their private credentials and are restricted to their configured audience.

`GET /github/callback` is Gate's internal GitHub OAuth return endpoint. It consumes a bound, expiring, single-use state and checks the returned immutable numeric GitHub ID against the configured account. A different account is rejected with 403. Applications must start a login flow rather than constructing a callback URL or approval transaction themselves.

## Browser endpoints

| Method and path | Request | Result |
| --- | --- | --- |
| `GET /browser/login` | Exactly `app_id` and `redirect_uri`, matching a registration | 303 to GitHub, device approval or the registered return page for an active session |
| `GET /browser/approve` | Gate-issued `transaction`; host-only login and identity cookies | HTML device approval form |
| `POST /browser/approve` | Form fields `transaction`, `csrf`, `decision=approve\|deny`; issuer Origin and bound cookies | 303 to the registered return page; approval creates the connection/session and sets the common cookie |
| `GET /browser/session` | Registered SPA Origin, credentials; no Authorization header | 200 `{csrf_token}` for the active browser session |
| `POST /browser/logout` | Registered SPA Origin, credentials, JSON `{}`, `X-CSRF-Token` | 204, atomic current-device revocation and session deletion; clears the shared cookie |
| `POST /browser/session/introspect` | Resource Basic authentication and JSON `{session,resource}` | 200 active session claims or `{active:false}` |
| `OPTIONS /browser/session` | Registered Origin, requested method GET | 204 for allowed preflight |
| `OPTIONS /browser/logout` | Registered Origin, requested method POST | 204 for allowed preflight |

Browser preflights accept only `Content-Type` and `X-CSRF-Token` request headers. Credentialed responses echo the exact permitted Origin and use `Vary`; no wildcard origin is used. Server-to-server introspection is not a public SPA endpoint. Form and JSON bodies parsed by Gate's custom handlers are limited to 8192 bytes.

### Session introspection

The SDK handles the private resource Basic authentication encoding. A resource can introspect only its own configured `resource` audience. The endpoint does not accept browser login as a substitute for the resource credential.

```json
{
  "active": true,
  "iss": "https://gate.example.test",
  "sub": "github:12345",
  "connection_id": "opaque-browser-connection-id",
  "client_id": "actions-browser",
  "aud": "https://api.example.test/mcp",
  "exp": 1900000000,
  "gate_approved": true,
  "session_type": "browser",
  "csrf_token": "opaque-csrf-token"
}
```

`exp` is Unix epoch seconds. Inactive, expired, malformed session secrets or revoked connections return `{active:false}` after resource authentication. Missing/wrong resource credentials return 401, an audience mismatch returns 403, and malformed request structure returns 400. Storage failures on browser paths return 503. A successful response must still be checked by the resource's SDK and its local enabled issuer/subject admission policy.

## Management and health

| Method and path | Behavior |
| --- | --- |
| `GET /` | Redirect to `/connections` |
| `GET /login` | Start GitHub identity login or return an already identified user to `/connections` |
| `GET /connections` | HTML list of the configured user's active browser/OAuth connections; identity login required |
| `POST /connections/revoke` | Form `id` and identity-session `csrf`; issuer Origin required; revoke one connection, then redirect to `/connections` |
| `GET /healthz` | Process liveness, 200 `ok`; used by the Cloud Run liveness probe |
| `GET /readyz` | Read-only Firestore readiness, 200 `ok` or 503 `unavailable`; response deadline two seconds |

Management uses the host-only identity session, which is separate from authorization to application APIs. Revoke links or transaction URLs alone cannot authorize another account or browser. Hosted edge behavior for `/healthz` must be verified separately from the container probe; use `/readyz` for external readiness checks.

## Cookies and expiry

| Cookie | Scope and lifetime | Purpose |
| --- | --- | --- |
| `__Secure-gate_session` | Configured parent Domain; 1 hour to 30 days, fixed expiry | Shared approved browser device session |
| `__Host-gate_identity` | Host-only; 24 hours | Verified identity for Gate pages and approval |
| `__Host-gate_login` | Host-only; 10 minutes | Bind a login/approval flow to its initiating browser |

These cookies are Secure, HttpOnly, SameSite=Lax and Path=/. Provider-owned OIDC cookies are managed separately by `oidc-provider`. Login attempts and approval transactions expire after 10 minutes; completing or denying an approval consumes it. Browser sessions contain a random 32-byte secret; only its SHA-256 hash is used as the stored session document key. Firestore TTL cleanup is asynchronous; active checks enforce expiry without waiting for deletion.

## Errors and caching

Custom browser JSON failures use `unauthorized`, `forbidden` or `request_failed`. Other custom pages can return a bounded plain-text failure. OAuth errors follow provider protocol responses; consumers must not assume every error is JSON. Custom HTML and session responses disable caching. Rendered pages escape dynamic content and use a restrictive Content Security Policy.

Gate returns 401 for absent/invalid sessions, 403 for denied Origin/CSRF/approval, 400 for malformed requests and 413 for oversized custom-handler bodies where applicable. The SDK maps credential rejection to 401 and unavailable authorization to 503. Never treat a failed authorization request as successful or cache a positive principal across resource requests.
