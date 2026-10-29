# Troubleshooting

Use the operator-configured origins and current deployed revision. Keep URLs containing login state, approval transactions, authorization codes or tokens out of shared logs. Report status codes and sanitized paths instead.

## GitHub rejects the redirect URI

If GitHub shows "The redirect_uri is not associated with this application", compare the active Gate login redirect's `client_id` with the intended GitHub OAuth App. Its Authorization callback URL must equal the exact configured Gate issuer plus `/github/callback`.

This is not the SPA's `/auth-return.html` URL or the MCP client's loopback callback. Update the matching OAuth App registration, save it, and restart sign-in from the application. Changing Gate's settings alone does not update GitHub. Do not reuse an old callback or approval link.

## Login succeeds but approval or API access fails

GitHub identity login and full-access connection approval are distinct. A new browser device needs approval; an already approved active device can reuse its session across registered applications. A separate MCP OAuth connection needs its own grant. A copied approval URL cannot replace the initiating browser's bound cookies and identity.

Check the exact registered app ID and return URI, shared cookie parent, HTTPS trust, cookie flags and expiry. Confirm that the API uses the same Gate issuer and resource audience and explicitly admits the verified issuer/subject and validates its configured browser client separately. A successful Gate login does not create an application user mapping.

For repeated approval prompts, inspect whether the shared cookie is actually sent and whether the session is expired or revoked. An identity cookie alone does not authorize an API. Return to the application's sign-in action rather than refreshing a consumed approval transaction.

## Browser request returns 401, 403 or 503

| Symptom | Check |
| --- | --- |
| 401 | Session/Bearer credential is present, unexpired and not revoked; browser client matches when applicable and OAuth client identity is consistent; no duplicate or ambiguous credentials |
| 403 | Exact registered Origin, required CSRF token, audience and application-local user admission |
| 503 | Gate and Firestore readiness, resource credentials, introspection response validity and network timeout |

The SDK uses 503 for an authorization outage or unusable upstream response. Preserve the user's pending work and offer retry; do not automatically discard proposals or create a new mutation ID after an unknown result. Application-specific write fencing and recovery belong to the receiving API.

## Managed certificate remains pending

Compare Cloud Run's required DNS records with both authoritative and public DNS responses. For direct domain mapping, the Cloudflare API-host records must be DNS-only, pointing to the returned Google target. Check for conflicting records, stale responses and CAA restrictions along the name's resolution chain. Confirm that the mapping targets the intended service and region and that HTTP reaches Google Frontend.

A generic "challenge data was not visible" message does not prove that the currently published DNS is wrong. An HTTP-to-HTTPS 302 by itself is also inconclusive; compare it with a known working mapping. Do not bypass authentication, add user-agent exceptions or alter application routes solely to suppress that status.

Google-managed certificates usually take about 15 minutes and can take up to 24 hours, according to the [Cloud Run domain-mapping documentation](https://docs.cloud.google.com/run/docs/mapping-custom-domains). If configuration is correct and a mapping remains stuck, preserve its status and consider one controlled recreation only when it is not serving working traffic. This restarts provisioning; it does not prove a cause or guarantee success. Avoid repeated recreation loops. Treat recovery as complete only after `CertificateProvisioned=True`, `Ready=True` and a real verified HTTPS request succeeds.

## Revocation and storage

Use `/connections` or browser logout to revoke access. Do not delete connection guard records to clean up expired tokens: durable revocation guards prevent delayed writes from reviving credentials. TTL is appropriate only for expiring artifacts, identity sessions, login attempts, approvals, browser sessions, change confirmations and their reference markers.

For storage failures, verify the exact Firestore project/database and runtime identity's database-scoped IAM, then check `/readyz`. Do not point a local test at production or reset the database as a troubleshooting step. See [deployment and recovery](deployment.md).

## Dynamic client registration

Read the configured issuer's discovery metadata and use its `registration_endpoint`. Clients must use DCR and public authorization-code PKCE. An invalid callback error requires checking the callback sent in that client's DCR request and authorization request; no operator-maintained public callback list exists.

A client whose registration was never approved within 24 hours receives an unknown-client error. Remove the client's stored registration so that it registers again, then approve the new connection. A registration with at least one approved connection does not expire.

HTTP 429 means the namespace registration rate or capacity is exhausted: 20 registrations per fixed minute and 1000 per fixed 24-hour window. Both recover when their window ends. No public client-management endpoint is provided. Preserve active clients, connection revocation guards and quota consistency; do not reset Firestore as a shortcut. Existing approved clients do not register again for token refresh. These quotas do not constitute a general request-rate or spending cap.
