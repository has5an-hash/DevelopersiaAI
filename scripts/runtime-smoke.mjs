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

  const { buildMcpServer } = await import("../dist/apps/server/src/mcp.js");
  const mcpServer = buildMcpServer();
  assert.ok(mcpServer, "MCP server and tool registrations should initialize");

  console.log("Runtime smoke passed: health, OAuth discovery, DCR, protected MCP endpoint and tool registration.");
} finally {
  child.kill("SIGTERM");
}
