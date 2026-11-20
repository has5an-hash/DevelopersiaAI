# Security model

## Authentication boundaries

- ChatGPT authenticates to the MCP resource server using OAuth 2.1 Authorization Code + PKCE (S256).
- Dynamic client registration accepts public clients only and requires HTTPS redirect URIs, except loopback development callbacks.
- Access tokens are short-lived JWTs with issuer, audience, subject, scope and expiry claims.
- Refresh tokens are random, stored only as SHA-256 hashes, rotated on use and revoked on reuse.
- WordPress pairing codes are random, hashed in the database, one-time and time-limited.
- WordPress site credentials are random, hashed for lookup and AES-256-GCM encrypted at rest so the control plane can call the paired plugin.

## Authorization

- Every MCP site operation scopes queries to the account in the verified token.
- MCP tool scopes separate read operations from content-writing operations.
- The WordPress plugin binds its site token to the WordPress user who paired it.
- WordPress capability checks are repeated for every REST operation.
- Creating content always creates a draft. Updating is limited to draft and pending posts/pages.
- Published content, deletion, users, plugins, themes, options and arbitrary database operations are not exposed.

## Network safety

- WordPress site URLs must be HTTPS in production.
- Private, loopback, reserved and local network destinations are rejected.
- Outbound requests use a timeout and do not follow redirects.
- MCP host validation is enabled through the official Express adapter.

## Operational requirements before public launch

1. Terminate TLS at a trusted reverse proxy and keep the application bound to loopback or a private container network.
2. Keep PostgreSQL private and encrypted at rest.
3. Store environment secrets in a deployment secret manager, never in the repository.
4. Add rate limits/WAF rules to OAuth, registration and pairing endpoints.
5. Configure automated backups and test restoration.
6. Add monitoring, alerting and audit-log retention.
7. Review OAuth redirect domains and register only trusted MCP clients when using a static client allowlist.
8. Run dependency and container vulnerability scans before each release.
9. Restrict outbound network egress at infrastructure level to mitigate DNS rebinding and SSRF.
10. Rotate JWT and encryption keys only with a documented migration plan.

## Incident response

If a WordPress site token may have been exposed, disconnect the site in the platform, disconnect it in the WordPress plugin, generate a new pairing code and pair it again. If the JWT signing secret is exposed, replace it and force all users to authorize again. If the encryption key is exposed, treat all encrypted site credentials as compromised and re-pair connected sites after key rotation.
