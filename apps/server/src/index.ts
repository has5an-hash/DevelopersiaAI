import { createMcpExpressApp, requireBearerAuth, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler } from "@modelcontextprotocol/server";
import express, { type Request, type Response, type NextFunction } from "express";
import { env, baseUrl, mcpUrl } from "./config.js";
import { prisma } from "./db.js";
import { createOAuthRouter, verifyAccessToken } from "./oauth.js";
import { buildMcpServer } from "./mcp.js";
import { randomToken, sha256, encryptSecret } from "./security.js";
import { assertSafeSiteUrl } from "./site-url.js";

const hostname = baseUrl.hostname;
const app = createMcpExpressApp({ host: "0.0.0.0", allowedHosts: [...new Set([hostname, "localhost", "127.0.0.1"])] });
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(createOAuthRouter());

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "developersia-ai", version: "0.1.0" });
});

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({ resource: mcpUrl, authorization_servers: [baseUrl.origin], bearer_methods_supported: ["header"], scopes_supported: ["mcp", "sites:read", "sites:write"] });
});

async function apiAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  try {
    const info = await verifyAccessToken(token);
    res.locals.authInfo = info;
    next();
  } catch {
    res.status(401).json({ error: "invalid_token" });
  }
}

app.get("/api/v1/me", apiAuth, async (_req, res) => {
  const userId = res.locals.authInfo.clientId as string;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, displayName: true, role: true, createdAt: true }
  });
  res.json({ user });
});

app.get("/api/v1/sites", apiAuth, async (_req, res) => {
  const userId = res.locals.authInfo.clientId as string;
  const sites = await prisma.site.findMany({
    where: { ownerId: userId, disconnectedAt: null },
    select: { id: true, siteUrl: true, siteName: true, wpVersion: true, pluginVersion: true, connectedAt: true, lastSeenAt: true },
    orderBy: { connectedAt: "desc" }
  });
  res.json({ sites });
});

app.post("/api/v1/pairing-codes", apiAuth, async (_req, res) => {
  const ownerId = res.locals.authInfo.clientId as string;
  const code = "DEV-" + randomToken(18).toUpperCase();
  await prisma.pairingCode.create({
    data: { codeHash: sha256(code), ownerId, expiresAt: new Date(Date.now() + 15 * 60 * 1000) }
  });
  res.status(201).json({ code, expires_in: 900, message: "Use this one-time code in the Developersia AI WordPress plugin. It will expire in 15 minutes." });
});

app.post("/api/v1/sites/pair", async (req, res) => {
  const body = req.body as Record<string, unknown>;
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const siteName = typeof body.site_name === "string" ? body.site_name.slice(0, 160) : "WordPress site";
  const rawSiteUrl = typeof body.site_url === "string" ? body.site_url : "";
  const wpVersion = typeof body.wp_version === "string" ? body.wp_version.slice(0, 40) : null;
  const pluginVersion = typeof body.plugin_version === "string" ? body.plugin_version.slice(0, 40) : null;
  if (!code || !rawSiteUrl) {
    res.status(400).json({ error: "invalid_request", message: "A pairing code and site URL are required." });
    return;
  }
  try {
    const siteUrl = await assertSafeSiteUrl(rawSiteUrl);
    const pairing = await prisma.pairingCode.findUnique({ where: { codeHash: sha256(code) } });
    if (!pairing || pairing.consumedAt || pairing.expiresAt <= new Date()) {
      res.status(400).json({ error: "invalid_pairing_code", message: "Pairing code is invalid, expired or already used." });
      return;
    }
    const existing = await prisma.site.findUnique({ where: { siteUrl } });
    if (existing && existing.ownerId !== pairing.ownerId) {
      res.status(409).json({ error: "site_already_connected", message: "This WordPress site is already connected to another account." });
      return;
    }
    const consumed = await prisma.pairingCode.updateMany({
      where: { id: pairing.id, consumedAt: null, expiresAt: { gt: new Date() } },
      data: { consumedAt: new Date() }
    });
    if (consumed.count !== 1) {
      res.status(409).json({ error: "pairing_code_used" });
      return;
    }
    const siteToken = randomToken(48);
    const site = existing
      ? await prisma.site.update({
          where: { id: existing.id },
          data: { siteName, tokenHash: sha256(siteToken), tokenCiphertext: encryptSecret(siteToken), wpVersion, pluginVersion, disconnectedAt: null, lastSeenAt: new Date() }
        })
      : await prisma.site.create({
          data: { ownerId: pairing.ownerId, siteUrl, siteName, tokenHash: sha256(siteToken), tokenCiphertext: encryptSecret(siteToken), wpVersion, pluginVersion, lastSeenAt: new Date() }
        });
    await prisma.auditLog.create({
      data: { userId: pairing.ownerId, siteId: site.id, action: "site.pair", status: "success", metadata: { siteUrl } }
    });
    res.status(201).json({ connected: true, site_id: site.id, site_token: siteToken, site_name: site.siteName });
  } catch (error) {
    res.status(400).json({ error: "pairing_failed", message: error instanceof Error ? error.message : "Unable to pair site." });
  }
});

app.post("/api/v1/sites/unpair", async (req, res) => {
  const header = req.header("authorization") ?? "";
  const siteToken = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!siteToken) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  const site = await prisma.site.findUnique({ where: { tokenHash: sha256(siteToken) } });
  if (!site || site.disconnectedAt) {
    res.status(404).json({ error: "site_not_connected" });
    return;
  }
  await prisma.site.update({
    where: { id: site.id },
    data: { disconnectedAt: new Date(), tokenHash: sha256(randomToken(48)) }
  });
  await prisma.auditLog.create({
    data: { userId: site.ownerId, siteId: site.id, action: "site.unpair", status: "success" }
  });
  res.json({ disconnected: true });
});

app.delete("/api/v1/sites/:siteId", apiAuth, async (req, res) => {
  const ownerId = res.locals.authInfo.clientId as string;
  const site = await prisma.site.findFirst({ where: { id: req.params.siteId, ownerId, disconnectedAt: null } });
  if (!site) {
    res.status(404).json({ error: "site_not_found" });
    return;
  }
  await prisma.site.update({ where: { id: site.id }, data: { disconnectedAt: new Date(), tokenHash: sha256(randomToken(48)) } });
  await prisma.auditLog.create({ data: { userId: ownerId, siteId: site.id, action: "site.disconnect", status: "success" } });
  res.json({ disconnected: true });
});

const verifier = { verifyAccessToken };
const mcpAuth = requireBearerAuth({
  verifier,
  requiredScopes: ["mcp"],
  resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(mcpUrl)),
  expectedResource: new URL(mcpUrl)
});
const mcpNodeHandler = toNodeHandler(createMcpHandler(buildMcpServer));
app.all("/mcp", mcpAuth, (req, res) => {
  void mcpNodeHandler(req, res, req.body);
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error("Developersia AI request failed:", error);
  res.status(500).json({ error: "internal_server_error" });
});

const server = app.listen(env.PORT, "0.0.0.0", () => {
  console.log("Developersia AI listening on port " + env.PORT + " (" + mcpUrl + ")");
});

async function shutdown() {
  server.close();
  await prisma.$disconnect();
}
process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
