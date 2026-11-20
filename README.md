# Developersia AI

**Developersia AI** is the first implementation of a model-independent AI platform for the Developersia ecosystem. It connects ChatGPT, Claude and other MCP-compatible AI clients to customer-owned WordPress sites through a secure remote MCP service and a small WordPress connector plugin.

This repository is the first vertical slice of a larger product platform. It is not a WordPress-only brand or architecture: future modules can expose their own tools, scopes and adapters while reusing the same identity, OAuth, site-connection and audit foundations; billing can be added as a separate module later.

## What is implemented

### Remote platform
- Node.js 22.12+ and TypeScript API.
- MCP Streamable HTTP endpoint at `/mcp`.
- OAuth 2.1 Authorization Code flow with PKCE S256.
- Dynamic Client Registration for public OAuth clients.
- Short-lived JWT access tokens and rotating, hashed refresh tokens.
- PostgreSQL persistence through Prisma.
- One-time, expiring WordPress pairing codes.
- Encrypted-at-rest WordPress site credentials (AES-256-GCM).
- Ownership-scoped site records and audit events.
- Rate limits on OAuth registration, login and token endpoints.
- Docker Compose deployment scaffold and GitHub Actions CI.

### WordPress connector plugin
- Pair this site with a Developersia account.
- Bind the remote connection to the administrator who paired it.
- Check connection and WordPress/PHP versions.
- Search and list posts/pages.
- Read a post/page.
- Create a new post/page as a draft.
- Update content only while its status is draft or pending.
- Revoke the platform connection when disconnected.

### MCP tools
| Tool | Permission | Purpose |
|---|---|---|
| `account_get` | MCP | Get the signed-in Developersia account |
| `site_pairing_code` | `sites:write` | Generate a one-time WordPress connection code |
| `sites_list` | `sites:read` | List the account's connected sites |
| `site_status` | `sites:read` | Read live site status |
| `posts_list` | `sites:read` | Search/list posts and pages |
| `post_read` | `sites:read` | Read post/page content |
| `post_create_draft` | `sites:write` | Create a draft (never publish) |
| `post_update_draft` | `sites:write` | Edit draft/pending content |
| `site_disconnect` | `sites:write` | Revoke a connected site |

## Architecture

```text
ChatGPT / Claude / Developersia dashboard
                  |
           OAuth 2.1 + MCP
                  |
         Developersia AI Core
         /        |          \
      OAuth   PostgreSQL    MCP tools
                              |
                     Encrypted site token
                              |
                  WordPress connector plugin
                              |
                  WordPress REST + capabilities
```

The language model does not receive WordPress credentials. The server stores and uses them, checks account ownership and scopes, and the plugin re-checks WordPress capabilities for every request.

## Requirements

- Node.js 22.12+
- npm 10+
- PostgreSQL 16+
- WordPress 6.5+ and PHP 8.1+
- HTTPS for public deployments

## Local development

```bash
cp .env.example .env
# Edit .env and replace every placeholder with a unique secret.
npm install
npx prisma generate
npm run db:migrate
npm run db:seed
npm run dev
```

See [Development guide](docs/DEVELOPMENT.md) for details. `/health` is the service health endpoint. The MCP endpoint is `/mcp`.

## Pair a WordPress site

1. Sign in to Developersia AI through the OAuth connection, then ask the connected AI client to run `site_pairing_code`. You can also generate a code from a secured operator shell:

   ```bash
   npm run pair:code -- --email admin@example.com --ttl-minutes 15
   ```

2. Install and activate the plugin from `plugins/developersia-ai`.
3. Open WordPress **Settings → Developersia AI**.
4. Enter the public API base URL and the one-time code.
5. Confirm that the site appears in the connected-site list.

Create a distributable WordPress ZIP with:

```bash
cd plugins
zip -r developersia-ai-connector.zip developersia-ai
```

The CI workflow also packages this plugin as a downloadable workflow artifact after a successful run.

## Connect ChatGPT

Once the service is deployed with HTTPS and `PUBLIC_BASE_URL` matches its public origin, add a custom MCP connection in ChatGPT using:

`https://api.developersia.ir/mcp`

Complete the Developersia OAuth login and review the requested scopes. The exact ChatGPT settings labels and MCP availability can vary by account plan and workspace. See [ChatGPT connection guide](docs/CHATGPT.md).

## Deployment

The repository includes a Dockerfile and Compose setup:

```bash
docker compose up -d --build
docker compose exec api npm run db:seed
```

Configure the required environment variables first. See [Deployment checklist](docs/INSTALLATION.md). Keep PostgreSQL private and expose the API only through a trusted HTTPS reverse proxy.

## Security boundaries

- Pairing codes are random, single-use and expire after 15 minutes.
- WordPress site credentials are hashed for lookup and encrypted at rest.
- OAuth tokens are audience-bound, short-lived and scope-limited.
- Each MCP request is restricted to sites owned by the authenticated account.
- WordPress API requests run as the WordPress user who paired the site.
- Content creation results in drafts only.
- Updating published posts is blocked.
- The initial connector exposes no deletion, arbitrary options, user management, plugin/theme installation or database operations.
- Private-network and local destinations are rejected in production; HTTPS is required.

Review [Security model](docs/SECURITY.md) before exposing the service publicly.

## Not yet included

This repository does not yet include customer self-registration, a billing/subscription system, a full Developersia web dashboard, model API-key billing, a production server deployment, or ChatGPT store publication. Those require product and infrastructure decisions and should not be represented as live until separately implemented and verified.

## Project status

Initial MVP implementation — version 0.1.0. The code and CI are being validated in a feature branch before merging to `main`. A successful repository build is not the same as a production deployment or an end-to-end test against a real WordPress site.

## License

Proprietary — all rights reserved unless a separate license is published.
