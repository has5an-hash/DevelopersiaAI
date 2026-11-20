# Deployment checklist

## Environment configuration

Create a production `.env` file. Use a URL-safe hexadecimal PostgreSQL password because it is embedded in `DATABASE_URL`.

```env
POSTGRES_PASSWORD=generate-with-openssl-rand-hex-24
ADMIN_EMAIL=admin@your-domain.example
ADMIN_PASSWORD=use-a-long-unique-password-of-at-least-14-characters
PUBLIC_BASE_URL=https://api.developersia.ir
JWT_SECRET=generate-a-unique-random-secret
ENCRYPTION_KEY=generate-with-openssl-rand-hex-32
```

Generate the two cryptographic values with:

```bash
openssl rand -hex 48
openssl rand -hex 32
```

The first output is suitable for `JWT_SECRET`; the second is the 64-character `ENCRYPTION_KEY`. Do not reuse example values.

## Before deployment

- [ ] Create a production PostgreSQL database.
- [ ] Set `PUBLIC_BASE_URL` to the final HTTPS origin.
- [ ] Generate unique JWT, encryption and database secrets.
- [ ] Set the bootstrap admin email/password.
- [ ] Configure firewall and TLS reverse proxy.
- [ ] Configure outbound network restrictions for the application.
- [ ] Configure backups, monitoring and log retention.
- [ ] Review OAuth client registration and account access policy.

## Docker Compose

After creating the production `.env` file, run:

```bash
docker compose up -d --build
docker compose logs -f api
```

The API listens on container port 3000 and is bound to host loopback only. Configure your reverse proxy to forward HTTPS traffic to `127.0.0.1:3000`. Do not expose PostgreSQL or port 3000 directly to the public internet.

The first deployment applies Prisma migrations automatically. Seed the administrator once:

```bash
docker compose exec api npm run db:seed
```

Generate a one-time pairing code:

```bash
docker compose exec api npm run pair:code -- --email admin@your-domain.example --ttl-minutes 15
```

The code is printed once and expires automatically.

## Reverse proxy expectations

- Forward the original `Host` header.
- Forward HTTPS requests only.
- Set a request body limit (1 MB is sufficient for the current API).
- Set sane upstream timeouts (at least 30 seconds).
- Do not rewrite the `/mcp` path.
- Preserve the `WWW-Authenticate` response header for OAuth discovery.

## Release artifacts

The WordPress plugin folder is self-contained. Create a ZIP from the `plugins` directory as documented in DEVELOPMENT.md. The Node.js service runs separately and is not installed as a WordPress plugin.

## Rollback

Keep the previous Docker image and a database backup before applying a release. Do not roll back schema changes without checking Prisma migration compatibility.
