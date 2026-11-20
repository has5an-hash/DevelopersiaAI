# Deployment checklist

## Before deployment

- [ ] Create a production PostgreSQL database.
- [ ] Set `PUBLIC_BASE_URL` to the final HTTPS origin.
- [ ] Generate a unique JWT secret and 32-byte encryption key.
- [ ] Set a strong bootstrap admin email/password.
- [ ] Configure firewall and TLS reverse proxy.
- [ ] Set egress restrictions for the application container.
- [ ] Configure backups, monitoring and log retention.

## Docker Compose

Create a production `.env` file with:

```env
POSTGRES_PASSWORD=use-a-long-random-password
PUBLIC_BASE_URL=https://api.developersia.ir
JWT_SECRET=use-a-long-random-random-secret
ENCRYPTION_KEY=64-hex-character-key-generated-with-openssl
```

Then run:

```bash
docker compose up -d --build
docker compose logs -f api
```

The API listens on container port 3000 and is bound to host loopback only. Configure your reverse proxy to forward HTTPS traffic to `127.0.0.1:3000`. Do not expose PostgreSQL or port 3000 directly to the public internet.

The first deployment applies Prisma migrations automatically. Seed the administrator once from a controlled environment with the same production `.env`:

```bash
docker compose exec api npm run db:seed
```

After seeding, generate pairing codes from an authenticated admin shell or the platform dashboard once that dashboard is implemented. For now, use the CLI on a secured operator environment connected to the same database.

## Reverse proxy expectations

- Forward the original `Host` header.
- Forward HTTPS requests only.
- Set a request body limit (1 MB is sufficient for the current API).
- Set sane upstream timeouts (at least 30 seconds).
- Do not rewrite the `/mcp` path.
- Preserve the `WWW-Authenticate` response header for OAuth discovery.

## Release artifacts

The WordPress plugin folder is self-contained. Create a ZIP from the `plugins` directory as documented in DEVELOPMENT.md. The Node.js service runs separately and is not installed as a WordPress plugin.
