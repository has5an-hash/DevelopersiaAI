import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const port = process.env.PORT ?? "3000";
const origin = "http://127.0.0.1:" + port;
const child = spawn(process.execPath, ["dist/apps/server/src/index.js"], {
  env: process.env,
  stdio: ["ignore", "inherit", "inherit"]
});

async function getJson(path) {
  const response = await fetch(origin + path);
  assert.equal(response.status, 200, path + " should return HTTP 200");
  return response.json();
}

try {
  let healthy = false;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (child.exitCode !== null) throw new Error("Developersia server exited before becoming healthy.");
    try {
      const response = await fetch(origin + "/health");
      if (response.ok) {
        healthy = true;
        break;
      }
    } catch {
      // The server is still starting.
    }
    await delay(500);
  }
  assert.equal(healthy, true, "server health endpoint did not become ready");

  const healthResponse = await fetch(origin + "/health");
  assert.equal(healthResponse.headers.get("x-content-type-options"), "nosniff");
  assert.equal(healthResponse.headers.get("x-frame-options"), "DENY");
  assert.equal(healthResponse.headers.get("x-powered-by"), null);
  assert.equal(healthResponse.headers.get("cache-control"), "no-store");

  const authorizationPage = await fetch(origin + "/oauth/authorize");
  assert.equal(authorizationPage.headers.get("cache-control"), "no-store");
  assert.match(authorizationPage.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);

  const health = await getJson("/health");
  assert.equal(health.service, "developersia-ai");

  const authorization = await getJson("/.well-known/oauth-authorization-server");
  assert.ok(authorization.authorization_endpoint);
  assert.ok(authorization.token_endpoint);
  assert.ok(authorization.registration_endpoint);
  assert.ok(authorization.scopes_supported.includes("offline_access"));

  const resource = await getJson("/.well-known/oauth-protected-resource/mcp");
  assert.equal(resource.resource, "http://localhost:" + port + "/mcp");

  const registration = await fetch(origin + "/oauth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({
      client_name: "Developersia CI smoke test",
      redirect_uris: ["https://chatgpt.com/oauth/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none"
    })
  });
  assert.equal(registration.status, 201, "dynamic client registration should work");
  const client = await registration.json();
  assert.ok(client.client_id);

  const challenge = await fetch(origin + "/mcp");
  assert.equal(challenge.status, 401, "MCP should require OAuth bearer authentication");
  assert.match(challenge.headers.get("www-authenticate") ?? "", /resource_metadata/i);

  const { prisma } = await import("../dist/apps/server/src/db.js");
  const { randomToken, sha256 } = await import("../dist/apps/server/src/security.js");
  try {
    const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
    assert.ok(email, "CI seed must provide ADMIN_EMAIL");
    const owner = await prisma.user.findUnique({ where: { email } });
    assert.ok(owner, "CI seed must create the bootstrap administrator");

    const pairingCode = "DEV-" + randomToken(18).toUpperCase();
    await prisma.pairingCode.create({
      data: {
        codeHash: sha256(pairingCode),
        ownerId: owner.id,
        expiresAt: new Date(Date.now() + 60_000)
      }
    });

    const pairingResponse = await fetch(origin + "/api/v1/sites/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        code: pairingCode,
        site_url: "http://localhost:" + port + "/wordpress/",
        site_name: "Developersia CI WordPress",
        wp_version: "6.8",
        plugin_version: "0.1.1"
      })
    });
    assert.equal(pairingResponse.status, 201, "a valid pairing code should connect a local test site");
    const paired = await pairingResponse.json();
    assert.equal(paired.connected, true);
    assert.ok(paired.site_id);
    assert.ok(paired.site_token);

    const replayResponse = await fetch(origin + "/api/v1/sites/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: pairingCode,
        site_url: "http://localhost:" + port + "/wordpress/"
      })
    });
    assert.equal(replayResponse.status, 400, "a consumed pairing code must not be reusable");

    const unpairResponse = await fetch(origin + "/api/v1/sites/unpair", {
      method: "POST",
      headers: { "Authorization": "Bearer " + paired.site_token }
    });
    assert.equal(unpairResponse.status, 200, "the paired site token should be revocable");
    const disconnected = await prisma.site.findUnique({ where: { id: paired.site_id } });
    assert.ok(disconnected?.disconnectedAt, "unpairing must mark the site as disconnected");
    assert.equal(disconnected.tokenCiphertext, "", "unpairing must erase the encrypted site credential");
    const pairAuditEvents = await prisma.auditLog.count({
      where: { siteId: paired.site_id, action: "site.pair" }
    });
    assert.equal(pairAuditEvents, 1, "pairing must create exactly one audit event");
  } finally {
    await prisma.$disconnect();
  }

  const { buildMcpServer } = await import("../dist/apps/server/src/mcp.js");
  const mcpServer = buildMcpServer();
  assert.ok(mcpServer, "MCP server and tool registrations should initialize");

  console.log("Runtime smoke passed: security headers, health, OAuth discovery, DCR, protected MCP endpoint, one-time WordPress pairing, replay rejection, token revocation and MCP tool registration.");
} finally {
  child.kill("SIGTERM");
}
