# Deployment

Gate uses the existing Cloud Run service, Firestore Native database, runtime service account, Artifact Registry repository and Secret Manager resources declared in `infra/terraform` and `infra/cloud-run/service.template.json`. Preserve their identities, database contents and secret versions during a release. Cloudflare provides authoritative DNS and application static hosting; Gate runs on Cloud Run and renders its own authentication and connection-management pages. There is no application API relay or load balancer. DNS and domain mappings are operator-managed; this repository does not provision a new public domain.

## Runtime configuration

Copy `infra/runtime-config.example.json` to `.local/gate-runtime.json`. The destination is ignored by Git and Docker. Replace the synthetic values locally with the operator-approved HTTPS issuer, cookie parent, immutable GitHub account ID, registered browser app redirects. Do not commit or publish this file, a rendered manifest, or endpoint values in evidence.

The issuer must be an HTTPS origin that is a proper subdomain of `sessionCookieDomain`. Every browser app redirect must be an exact HTTPS URL under that parent. Gate derives credentialed browser CORS origins from these redirect URLs. The configured cookie parent must be accepted by real browsers before any cutover; configuration validation does not substitute for public-suffix or host acceptance checks.

The `GATE_RESOURCES` Secret Manager payload remains private and must contain each resource's audience, resource client ID and secret, plus its `browser_client_id`. Set that browser client ID to the explicit client identity accepted by the resource API. Keep the resource secret separate from SPA runtime configuration. Public MCP clients obtain their own IDs and callback registrations through DCR; browser apps are registered separately in `browserApps`.

The GitHub OAuth App callback is the configured issuer followed by `/github/callback`. Register each browser app's exact static return URI in the Gate runtime configuration. Browser approval grants full suite access to a device. It is separate from MCP OAuth approval, and browser logout revokes only that device connection.

## Infrastructure and release

`infra/terraform/main.tf` declares Firestore, a dedicated runtime identity, database-scoped IAM, TTL policies for expiring artifact, browser-session and change-confirmation records, an image repository and Secret Manager containers. It contains no secret payloads. Initialize Terraform with a chosen state location outside the repository and import existing resources before planning. Review plans for replacement or deletion. Do not recreate the existing database or service identity. The Firestore deletion protection, `prevent_destroy` and existing `entries` TTL policy must remain in place. TTL cleanup is asynchronous and never determines whether a session or approval is active; Gate checks `expiresAt` on reads and transactions. The browser connection revocation records have no TTL and remain durable.

Provision required secret versions independently. Cookie keys must be independent random strings of at least 32 characters. The signing JWKS must contain a persistent private RS256 RSA key of at least 2048 bits with a stable `kid`. GitHub client credentials and resource credentials stay in Secret Manager. Never put secret values in images, manifests or verification output.

Run `npm ci`, `npm run check`, `npm run build` and the Firestore Emulator integration suite for the source being released. Build and publish the image through the operator's existing repository, then obtain its immutable digest. Render the service using the ignored runtime config:

```sh
node scripts/render-service.mjs "$IMAGE_REF" .local/gate-runtime.json .local/gate-service.json
```

The renderer injects issuer, cookie scope, account ID, browser app redirects into the existing Cloud Run template. Secret references and resource identities remain from the template. Before applying a rendered manifest, compare its version-pinned secret references, Firestore identifiers, runtime identity and limits with the intended serving configuration. The renderer does not discover current deployment values or automatically advance secret versions; template defaults are not proof of current production settings. Keep generated manifests under `.local/` or outside the repository. Deploy through the operator-authorized release workflow. Cloud Run must remain publicly invokable for standard OAuth redirects, discovery and token exchange; Gate still verifies the configured GitHub identity, explicit approval and resource credentials.

## DNS and HTTPS

Create a standard Cloud Run domain mapping from the operator's Gate origin to the existing service. Verify ownership of the base domain and use a supported region. Publish exactly the DNS records returned by Cloud Run. For Cloudflare, API/authentication CNAME records use DNS-only mode, without proxying; application SPA hosting is separate. Keep actual origins in ignored local settings.

Wait for `Ready=True` and `CertificateProvisioned=True`, then verify a real HTTPS request to `/readyz`. A DNS record, a successful container probe or a pending certificate does not establish usable public HTTPS. See [certificate troubleshooting](troubleshooting.md#managed-certificate-remains-pending) for failed validation. Cloud Run domain mapping is a Preview feature with known limitations; the [provider documentation](https://docs.cloud.google.com/run/docs/mapping-custom-domains) describes supported regions and certificate issuance.

## Coordinated release and recovery

Deploy the immutable candidate without normal traffic first. Verify its configuration and readiness. When the issuer or browser-session contract changes, fence affected resource writes and drain in-flight requests before switching consumers. Preserve exact unknown operation IDs for the owning application to reconcile. Provision the new issuer/subject mappings to the existing internal user; do not merge by email or create a new data identity implicitly.

Align the GitHub OAuth App callback, Gate issuer, resource audiences, browser registrations, shared cookie parent, consumer configuration and SPA runtime settings. Preserve signing/cookie keys, Firestore data and resource credentials unless rotation is part of the release. Switch the serving Gate and resource revisions in a coordinated maintenance window, verify real login and existing data display, then resume application writes through each resource's release process. Browser logout and MCP OAuth grants remain independent.

Retain previous image digests, revision IDs and version-pinned settings for recovery. Do not reset Firestore or delete revocation guards. A routing rollback is safe only when the previous consumer, issuer, GitHub callback and storage contracts remain compatible; restore a coherent configuration rather than mixing issuers across serving replicas. Application data changes after activation must be reconciled by the owning resource service.

## Hosted acceptance

Record the source revision, image digest, configuration identifier and service revision without publishing hostnames or redirect URLs. Verify health and readiness, OIDC discovery and JWKS through the configured HTTPS origin. Confirm that the JWKS exposes no private components and that the login flow issues Secure cookies.

Use a real browser to verify the configured parent cookie across suite applications, credentialed CORS, login callback, explicit device approval, cross-app session reuse, CSRF rejection, logout and connection revocation. Verify fresh session introspection through the resource SDK and DCR registration, standard PKCE/opaque Bearer introspection and refresh for MCP clients. Confirm that revoking a browser device does not revoke independent OAuth connections. Local identity substitutes, the Firestore Emulator and synthetic HTTPS acceptance do not establish real GitHub, hosted Firestore, DNS/TLS, public-suffix or MCP host behavior. Record performed and unverified checks separately; this runbook is not deployment evidence.
