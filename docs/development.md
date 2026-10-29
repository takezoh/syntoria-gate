# Development

Use Node.js 24 and the npm version pinned in [package.json](../package.json). Install with `npm ci`; avoid unrelated dependency or lockfile changes. Documentation, code comments, schema descriptions and example annotations are written in English.

## Source layout

| Location | Responsibility |
| --- | --- |
| `src/config.ts` | Environment and browser/resource registration validation |
| `src/registration.ts` | Pure bounded DCR metadata projection and redirect validation |
| `src/confirmation.ts` | Pure change-confirmation request and summary validation |
| `src/service.ts` | HTTP composition, GitHub exchange, OIDC, HTML pages, change-confirmation endpoints, cookies and browser CORS/CSRF |
| `src/storage.ts` | Firestore persistence, transactional approval, single confirmation consumption, expiry and durable revocation |
| `src/main.ts` | Production configuration, storage composition and server startup |
| `packages/sdk/src/index.ts` | Online token/session verification and change-confirmation calls for Node resource services |
| `scripts/` | Runtime rendering, emulator and test runners |
| `tests/` | SDK/configuration/confirmation/renderer/readiness checks and provider integration |
| `infra/` | Cloud Run template, synthetic runtime input and Terraform resources |

Keep identity verification separate from application data admission. Do not add a request proxy, application data store or feature permission system to Gate. Preserve single-use login/approval records, transactional browser session creation and durable connection revocation guards.

## Commands

| Command | Verification or effect |
| --- | --- |
| `npm ci` | Install the locked dependencies |
| `npm run typecheck` | Check service and SDK TypeScript |
| `npm run build` | Compile the service to `dist/` and SDK to `packages/sdk/dist/` |
| `npm test` | Build, then run SDK, config, confirmation, readiness and runtime-renderer tests |
| `npm run check` | Typecheck, then build and run those tests |
| `npm run emulator` | Start the pinned Firestore Emulator container on loopback port 55435; requires Docker |
| `FIRESTORE_EMULATOR_HOST=127.0.0.1:55435 npm run test:integration` | Build and run `tests/provider.test.mjs` against the emulator |
| `npm start` | Start the built service using the current process environment |

The runners reject failures, skipped tests, TODO tests, cancellations and empty successful suites. `npm run check` does not include the emulator integration suite.

## Local configuration

Copy [config.example.env](../config.example.env) into an ignored `.local/` file and provide valid synthetic registrations and independently generated local keys. The example's empty JWKS and replacement strings are placeholders. A local process can load an operator-prepared file explicitly:

```sh
node --env-file=.local/development.env dist/main.js
```

Use an HTTPS development origin and a trusted local TLS proxy that replaces forwarded headers. Keep the plaintext backend isolated from untrusted traffic. The configured Gate origin must be below the cookie parent. A browser must trust the local certificate and accept the cookie parent. The integration harness supplies its own isolated configuration and identity substitute; it does not require production credentials.

The emulator command uses the synthetic `demo-gate-test` project and ephemeral container storage, without mounting host credentials or directories. Integration tests use random collection namespaces rather than resetting a database. Never point integration tests at hosted Firestore.

## Verification boundaries

Unit and adapter tests verify parsing, SDK response validation, timeout/outage handling, renderer behavior and readiness deadlines. Emulator integration verifies real `oidc-provider` HTTP flows, PKCE, Firestore transactions, replay rejection, session approval, logout, revocation and independent browser/OAuth connections. GitHub exchange is substituted at its boundary.

Real GitHub login, hosted Firestore IAM, public DNS/TLS, cookie behavior across deployed sites and a particular MCP client's acceptance require separate hosted checks. Record source, immutable image, configuration identifier, deployed revision and observed results. A passing test or a written runbook does not establish deployed acceptance.

For documentation-only changes, check English language, local references, JSON example syntax and agreement with implementation. Use the repository's dev-docs configuration for structured records; do not rewrite completed change history to describe current behavior.
