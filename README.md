# Developersia AI

Developersia AI is a modular platform that connects AI clients to customer-owned WordPress sites through a secure remote MCP server.

## Repository status

This repository starts with the first implementation scaffold. It is designed as a deployable MVP foundation, not a claim of production readiness. Production deployment still requires managed secrets, a PostgreSQL instance, HTTPS, OAuth client registration and end-to-end tests against a real WordPress installation.

## Architecture

- `apps/mcp-server`: Node.js / TypeScript MCP server, Streamable HTTP endpoint and OAuth 2.1 authorization-code + PKCE endpoints.
- `apps/control-plane`: shared PostgreSQL persistence, site pairing and token services.
- `plugins/developersia-ai`: WordPress plugin installed on each customer site. Uses WordPress capability checks, REST nonces for wp-admin actions and an outbound HTTPS connection to the control plane.
- `packages/shared`: shared types and configuration.
- `docs`: setup, security, deployment and ChatGPT connection instructions.

The first vertical slice focuses on safe WordPress operations: site status, listing/searching posts, reading a post, creating a draft and updating a post. Publishing and destructive actions are intentionally excluded from the initial tool set.

## Requirements

- Node.js 22+
- npm 10+
- PostgreSQL 16+
- WordPress 6.5+ and PHP 8.1+
- HTTPS for all public endpoints

## Development

```bash
cp .env.example .env
npm install
npm run db:generate
npm run db:migrate
npm run dev
```

The exact commands and required environment variables are documented in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Important security notes

- Never commit API keys, OAuth secrets, WordPress application passwords or database credentials.
- Every connected site is scoped to the authenticated Developersia account.
- WordPress writes require an explicit tool call; the initial tool set creates drafts rather than publishing.
- Site pairing codes are one-time and short-lived.
- OAuth access tokens are short-lived; refresh tokens are rotated and stored hashed.
- The MCP endpoint is intended to be exposed only over HTTPS behind a trusted reverse proxy.

## Current limitations

This scaffold does not automatically install itself on developersia.ir, provision hosting, create customer accounts, process payments or register a ChatGPT app on behalf of the repository owner. Those steps require real infrastructure and credentials.

## License

Proprietary — all rights reserved unless a separate license is published.
