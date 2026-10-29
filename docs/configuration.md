# Configuration

The authoritative runtime validation is in [src/config.ts](../src/config.ts). [config.example.env](../config.example.env) is a synthetic starting point, not a working production configuration. Supply environment values before starting the service; the application does not load an environment file itself.

## Environment variables

| Variable | Requirement |
| --- | --- |
| `NODE_ENV` | Set to `production` on Cloud Run. Production rejects `FIRESTORE_EMULATOR_HOST`. |
| `PORT` | Integer from 1 to 65535; defaults to 3000. |
| `GATE_ISSUER` | Canonical HTTPS origin without a trailing slash, path, query or fragment. Must be a proper subdomain of the cookie parent. |
| `GATE_SESSION_COOKIE_DOMAIN` | Shared DNS parent, without a leading dot, wildcard or trailing dot. Must be a domain that browsers permit as a cookie scope. |
| `GATE_BROWSER_SESSION_TTL_SECONDS` | Fixed session lifetime from 3600 to 2592000 seconds; defaults to 2592000 (30 days). Reads do not extend it. |
| `GATE_FIRESTORE_PROJECT_ID` | Explicit Google Cloud project ID. |
| `GATE_FIRESTORE_DATABASE_ID` | Explicit Firestore database ID, including `(default)` when applicable. |
| `GATE_GITHUB_USER_ID` | Permitted GitHub account's immutable positive numeric ID. The subject is `github:<numeric-id>`. |
| `GATE_GITHUB_CLIENT_ID` | GitHub OAuth App client ID. |
| `GATE_GITHUB_CLIENT_SECRET` | GitHub OAuth App secret; supply through Secret Manager in production. |
| `GATE_COOKIE_KEYS` | JSON array of independent random signing strings, each at least 32 characters. Persist across replicas and restarts. |
| `GATE_JWKS` | Private signing JWKS. Provision a persistent RSA key of at least 2048 bits with stable `kid`, `use: "sig"` and `alg: "RS256"`. Never publish private components. |
| `GATE_BROWSER_APPS` | Nonempty JSON array of browser applications and exact HTTPS return URIs. |
| `GATE_RESOURCES` | Nonempty private JSON array of resource audiences and introspection credentials. |

The complete configuration requires HTTPS, including local browser-session development. HTTP loopback redirect URIs are supported for OAuth clients; they do not make an HTTP Gate issuer valid. The SDK's isolated-test HTTP option does not relax service configuration.

For the account restriction and the distinction between public client registration, operator resource registration and connection approval, see [identity and registration controls](security.md).

## Registrations

MCP clients use the advertised DCR registration endpoint. Supply `redirect_uris` and public-client metadata, not a preassigned client ID. Supported fields are `client_name`, `application_type`, `grant_types`, `response_types`, `redirect_uris` and `token_endpoint_auth_method`. The authentication method is `none`, response type is `code`, and grants include `authorization_code` with optional `refresh_token`. Missing application type is inferred from all-HTTPS web callbacks or all-HTTP-loopback native callbacks. Mixed classes, wildcards, credentials and fragments are rejected. Native loopback port matching is handled by the OAuth provider.

```json
{"client_name":"Desktop","redirect_uris":["http://127.0.0.1:8080/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

Registration is public, while access requires the configured person's authentication and explicit connection approval. Client names are unverified metadata. Remote key, sector and request metadata is rejected; inert extras are omitted. Input is limited to 8192 bytes, ten redirects of at most 2048 characters and a name of at most 100 characters. The shared Firestore limits permit 1000 registrations per fixed 24-hour window and 20 per fixed minute. A registration that receives no approved connection within 24 hours expires; the first approval makes it permanent. There is no client-management API.

Browser apps use an `app_id`, `app_name` and exact HTTPS `redirect_uris` under the cookie parent. These app IDs are distinct from OAuth client IDs and resource verification credentials. Gate derives allowed browser CORS origins from these return URLs.

```json
[{"app_id":"actions","app_name":"Actions","redirect_uris":["https://actions.example.test/auth-return.html"]}]
```

Resources use a unique `audience`, `client_id`, `client_secret` of at least 32 characters and `browser_client_id`. The audience must be HTTPS under the cookie parent. The resource client authenticates server-to-server introspection; `browser_client_id` identifies approved browser callers to the receiving API. Keep these credentials out of SPAs.

```json
[{"audience":"https://api.example.test/mcp","client_id":"actions-api","client_secret":"replace-with-an-independent-random-secret","browser_client_id":"actions-browser"}]
```

The receiving API must explicitly admit an enabled Gate issuer/subject mapping; browser verification separately checks the configured browser client ID. Gate approval does not create application users, merge identities or grant database access automatically.

## GitHub callback and secrets

The GitHub OAuth App's Authorization callback URL must equal `GATE_ISSUER` followed by `/github/callback`. This is different from a SPA's static return URI or an MCP client's loopback callback. Update the GitHub registration when changing the issuer.

On Cloud Run, use the dedicated runtime identity and Application Default Credentials for Firestore. No database password or downloaded service-account key is needed. Pin Secret Manager versions for GitHub credentials, cookie keys, private signing keys and resource registrations. Keep replicas on compatible key and registration sets during rotation.

## Ignored deployment inputs

Copy [infra/runtime-config.example.json](../infra/runtime-config.example.json) to `.local/gate-runtime.json`. It contains `issuer`, `sessionCookieDomain`, `githubUserId`, `browserApps` and optional `browserSessionTtlSeconds`. The renderer supplies these nonsecret settings to the Cloud Run template; Firestore identifiers and secret references remain in the template. Resource registrations remain in the private `GATE_RESOURCES` secret.

Do not commit actual endpoint values, account IDs, redirect registrations, rendered manifests or secrets. The renderer's output inside the repository must be under `.local/`. See [deployment](deployment.md) before applying it.
