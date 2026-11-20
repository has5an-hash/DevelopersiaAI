import { Router, type Response } from "express";
import { createHash } from "node:crypto";
import bcrypt from "bcryptjs";
import { rateLimit } from "express-rate-limit";
import { SignJWT, jwtVerify } from "jose";
import { OAuthError, OAuthErrorCode } from "@modelcontextprotocol/server";
import { prisma } from "./db.js";
import { baseUrl, issuer, mcpUrl, env } from "./config.js";
import { randomToken, safeRedirectUri, sha256 } from "./security.js";

const signingKey = new TextEncoder().encode(env.JWT_SECRET);
const availableScopes = ["mcp", "sites:read", "sites:write", "offline_access"] as const;
const defaultScope = availableScopes.join(" ");

function escapeHtml(value: string): string {
  const entities: Record<string, string> = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  };
  return value.replace(/[&<>"']/g, (character) => entities[character] ?? character);
}

function page(title: string, body: string): string {
  return "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" +
    escapeHtml(title) + " · Developersia</title><style>body{font:16px system-ui;background:#f4f6f8;color:#172b4d;margin:0;min-height:100vh;display:grid;place-items:center}.card{width:min(440px,calc(100% - 40px));background:white;border:1px solid #e2e8f0;border-radius:18px;padding:28px;box-shadow:0 18px 60px #172b4d12}h1{font-size:22px;margin:0 0 8px}p{color:#526174;line-height:1.55}label{display:block;font-size:13px;margin:14px 0 6px}input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #cbd5e1;border-radius:9px;font:inherit}button{margin-top:18px;border:0;border-radius:9px;background:#172b4d;color:white;padding:12px 18px;font:inherit;font-weight:600;cursor:pointer;width:100%}.muted{font-size:12px;color:#64748b}</style><main class=\"card\">" +
    body + "</main></html>";
}

function renderLogin(params: Record<string, string>, error = ""): string {
  const hidden = Object.entries(params).map(([key, value]) =>
    "<input type=\"hidden\" name=\"" + escapeHtml(key) + "\" value=\"" + escapeHtml(value) + "\">"
  ).join("");
  return page("Sign in", "<h1>Connect Developersia AI</h1><p>Sign in to choose which WordPress sites this AI connection can access.</p>" +
    (error ? "<p style=\"color:#b91c1c\">" + escapeHtml(error) + "</p>" : "") +
    "<form method=\"post\" action=\"/oauth/authorize\">" + hidden +
    "<label>Email address</label><input name=\"email\" type=\"email\" autocomplete=\"username\" required>" +
    "<label>Password</label><input name=\"password\" type=\"password\" autocomplete=\"current-password\" required>" +
    "<button type=\"submit\">Continue</button></form><p class=\"muted\">Only connect accounts you control. Your password is checked by Developersia and is not shared with ChatGPT.</p>");
}

function renderConsent(id: string, csrf: string, clientName: string, scope: string): string {
  const labels: Record<string, string> = {
    "mcp": "Connect to Developersia AI",
    "sites:read": "Read connected WordPress site information and content",
    "sites:write": "Create drafts and edit draft content",
    "offline_access": "Keep the connection active by issuing refresh tokens"
  };
  const permissions = scope.split(" ").filter(Boolean).map((item) =>
    "<li>" + escapeHtml(labels[item] ?? item) + "</li>"
  ).join("");
  return page("Authorize access", "<h1>Allow access?</h1><p><strong>" + escapeHtml(clientName) +
    "</strong> is requesting access to your Developersia account.</p><ul>" + permissions + "</ul>" +
    "<form method=\"post\" action=\"/oauth/consent\"><input type=\"hidden\" name=\"id\" value=\"" + escapeHtml(id) +
    "\"><input type=\"hidden\" name=\"csrf\" value=\"" + escapeHtml(csrf) +
    "\"><button name=\"decision\" value=\"approve\">Authorize</button><button name=\"decision\" value=\"deny\" style=\"background:#e2e8f0;color:#172b4d\">Cancel</button></form>");
}

function readAuthorizeParams(source: Record<string, unknown>): Record<string, string> | null {
  const keys = ["client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "resource"];
  const result: Record<string, string> = {};
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.length <= 2048) result[key] = value;
  }
  return result;
}

async function validateClientRequest(params: Record<string, string>) {
  if (!params.client_id || params.response_type !== "code" || !params.redirect_uri ||
      !params.code_challenge || !/^[A-Za-z0-9_-]{43}$/.test(params.code_challenge) || params.code_challenge_method !== "S256") {
    throw new Error("The OAuth request is incomplete or does not use PKCE S256.");
  }
  const client = await prisma.oAuthClient.findUnique({ where: { clientId: params.client_id } });
  if (!client || !client.redirectUris.includes(params.redirect_uri)) throw new Error("Unregistered OAuth client or redirect URI.");
  if (!safeRedirectUri(params.redirect_uri)) throw new Error("The redirect URI must use HTTPS or a loopback address.");
  const resource = params.resource ?? mcpUrl;
  if (resource !== mcpUrl) throw new Error("The requested resource is not this Developersia MCP server.");
  const requested = (params.scope ?? defaultScope).split(/\s+/).filter(Boolean);
  if (!requested.includes("mcp") || requested.some((scope) => !availableScopes.includes(scope as typeof availableScopes[number]))) {
    throw new Error("The requested permission scope is not supported.");
  }
  return { client, resource, scope: [...new Set(requested)].join(" ") };
}

function invalidGrant(res: Response, description: string) {
  res.status(400).json({ error: "invalid_grant", error_description: description });
}

export function createOAuthRouter(): Router {
  const router = Router();
  const registrationLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: "draft-8", legacyHeaders: false });
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-8", legacyHeaders: false });
  const tokenLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: "draft-8", legacyHeaders: false });

  router.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer,
      authorization_endpoint: new URL("/oauth/authorize", baseUrl).toString(),
      token_endpoint: new URL("/oauth/token", baseUrl).toString(),
      registration_endpoint: new URL("/oauth/register", baseUrl).toString(),
      revocation_endpoint: new URL("/oauth/revoke", baseUrl).toString(),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [...availableScopes]
    });
  });

  router.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
    res.json({
      resource: mcpUrl,
      authorization_servers: [issuer],
      bearer_methods_supported: ["header"],
      scopes_supported: [...availableScopes]
    });
  });

  router.get("/oauth/register", (_req, res) => res.status(405).json({ error: "method_not_allowed" }));
  router.post("/oauth/register", registrationLimiter, async (req, res) => {
    const input = req.body as Record<string, unknown>;
    const redirectUris = Array.isArray(input.redirect_uris) ? input.redirect_uris.filter((item): item is string => typeof item === "string") : [];
    const name = typeof input.client_name === "string" ? input.client_name.slice(0, 120) : "MCP client";
    const grantTypes = Array.isArray(input.grant_types) ? input.grant_types : ["authorization_code", "refresh_token"];
    const responseTypes = Array.isArray(input.response_types) ? input.response_types : ["code"];
    if (!redirectUris.length || redirectUris.length > 20 ||
        redirectUris.some((uri) => !safeRedirectUri(uri)) ||
        !grantTypes.includes("authorization_code") || !responseTypes.includes("code")) {
      res.status(400).json({ error: "invalid_client_metadata" });
      return;
    }
    const clientId = randomToken(24);
    await prisma.oAuthClient.create({
      data: {
        clientId,
        clientName: name,
        redirectUris,
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"]
      }
    });
    res.status(201).json({
      client_id: clientId,
      client_name: name,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none"
    });
  });

  router.get("/oauth/authorize", async (req, res) => {
    const params = readAuthorizeParams(req.query as Record<string, unknown>);
    if (!params) {
      res.status(400).send("Invalid OAuth request.");
      return;
    }
    try {
      await validateClientRequest(params);
      res.type("html").send(renderLogin(params));
    } catch (error) {
      res.status(400).send(String(error instanceof Error ? error.message : error));
    }
  });

  router.post("/oauth/authorize", loginLimiter, async (req, res) => {
    const params = readAuthorizeParams(req.body as Record<string, unknown>);
    if (!params) {
      res.status(400).send("Invalid OAuth request.");
      return;
    }
    try {
      const validated = await validateClientRequest(params);
      const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
      const password = typeof req.body.password === "string" ? req.body.password : "";
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        res.status(401).type("html").send(renderLogin(params, "Email or password is incorrect."));
        return;
      }
      const csrf = randomToken(24);
      const pending = await prisma.pendingAuthorization.create({
        data: {
          userId: user.id,
          clientId: validated.client.clientId,
          redirectUri: params.redirect_uri!,
          codeChallenge: params.code_challenge!,
          state: params.state ?? null,
          scope: validated.scope,
          resource: validated.resource,
          csrfHash: sha256(csrf),
          expiresAt: new Date(Date.now() + 5 * 60 * 1000)
        }
      });
      res.type("html").send(renderConsent(pending.id, csrf, validated.client.clientName, validated.scope));
    } catch (error) {
      res.status(400).send(String(error instanceof Error ? error.message : error));
    }
  });

  router.post("/oauth/consent", async (req, res) => {
    const id = typeof req.body.id === "string" ? req.body.id : "";
    const csrf = typeof req.body.csrf === "string" ? req.body.csrf : "";
    const pending = await prisma.pendingAuthorization.findUnique({ where: { id } });
    if (!pending || pending.expiresAt <= new Date() || sha256(csrf) !== pending.csrfHash) {
      res.status(400).send("Authorization request expired. Please start again.");
      return;
    }
    await prisma.pendingAuthorization.delete({ where: { id } });
    const redirect = new URL(pending.redirectUri);
    if (req.body.decision !== "approve") {
      redirect.searchParams.set("error", "access_denied");
      if (pending.state) redirect.searchParams.set("state", pending.state);
      res.redirect(303, redirect.toString());
      return;
    }
    const code = randomToken(32);
    await prisma.authorizationCode.create({
      data: {
        codeHash: sha256(code),
        clientId: pending.clientId,
        userId: pending.userId,
        redirectUri: pending.redirectUri,
        codeChallenge: pending.codeChallenge,
        scope: pending.scope,
        resource: pending.resource,
        expiresAt: new Date(Date.now() + 90 * 1000)
      }
    });
    redirect.searchParams.set("code", code);
    if (pending.state) redirect.searchParams.set("state", pending.state);
    res.redirect(303, redirect.toString());
  });

  router.post("/oauth/token", tokenLimiter, async (req, res) => {
    const grantType = typeof req.body.grant_type === "string" ? req.body.grant_type : "";
    const clientId = typeof req.body.client_id === "string" ? req.body.client_id : "";
    const client = await prisma.oAuthClient.findUnique({ where: { clientId } });
    if (!client) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }

    if (grantType === "authorization_code") {
      const rawCode = typeof req.body.code === "string" ? req.body.code : "";
      const redirectUri = typeof req.body.redirect_uri === "string" ? req.body.redirect_uri : "";
      const verifier = typeof req.body.code_verifier === "string" ? req.body.code_verifier : "";
      const record = await prisma.authorizationCode.findUnique({ where: { codeHash: sha256(rawCode) } });
      if (!record || record.clientId !== clientId || record.redirectUri !== redirectUri ||
          record.usedAt || record.expiresAt <= new Date() || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
          (typeof req.body.resource === "string" && req.body.resource !== record.resource)) {
        invalidGrant(res, "Authorization code is invalid or expired.");
        return;
      }
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      if (challenge !== record.codeChallenge) {
        invalidGrant(res, "PKCE verification failed.");
        return;
      }
      const consumed = await prisma.authorizationCode.updateMany({
        where: { id: record.id, usedAt: null, expiresAt: { gt: new Date() } },
        data: { usedAt: new Date() }
      });
      if (consumed.count !== 1) {
        invalidGrant(res, "Authorization code has already been used.");
        return;
      }
      const tokens = await issueTokens(record.userId, clientId, record.scope, record.resource);
      res.json(tokens);
      return;
    }

    if (grantType === "refresh_token") {
      const rawRefresh = typeof req.body.refresh_token === "string" ? req.body.refresh_token : "";
      const record = await prisma.refreshToken.findUnique({ where: { tokenHash: sha256(rawRefresh) } });
      if (!record || record.clientId !== clientId || record.expiresAt <= new Date() ||
          (typeof req.body.resource === "string" && req.body.resource !== record.resource)) {
        invalidGrant(res, "Refresh token is invalid or expired.");
        return;
      }
      if (record.revokedAt) {
        await prisma.refreshToken.updateMany({ where: { familyId: record.familyId }, data: { revokedAt: new Date() } });
        invalidGrant(res, "Refresh token reuse detected. Please authorize again.");
        return;
      }
      const rotated = await prisma.refreshToken.updateMany({
        where: { id: record.id, revokedAt: null, expiresAt: { gt: new Date() } },
        data: { revokedAt: new Date() }
      });
      if (rotated.count !== 1) {
        await prisma.refreshToken.updateMany({
          where: { familyId: record.familyId, revokedAt: null },
          data: { revokedAt: new Date() }
        });
        invalidGrant(res, "Refresh token was already used. Please authorize again.");
        return;
      }
      res.json(await issueTokens(record.userId, clientId, record.scope, record.resource, record.familyId));
      return;
    }

    res.status(400).json({ error: "unsupported_grant_type" });
  });

  router.post("/oauth/revoke", async (req, res) => {
    const token = typeof req.body.token === "string" ? req.body.token : "";
    if (token) {
      await prisma.refreshToken.updateMany({
        where: { tokenHash: sha256(token), clientId: typeof req.body.client_id === "string" ? req.body.client_id : "" },
        data: { revokedAt: new Date() }
      });
    }
    res.status(200).json({});
  });

  return router;
}

async function issueTokens(
  userId: string,
  clientId: string,
  scope: string,
  resource: string,
  familyId = randomToken(18)
) {
  const expiresIn = 900;
  const now = Math.floor(Date.now() / 1000);
  const accessToken = await new SignJWT({ scope, client_id: clientId })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(issuer)
    .setSubject(userId)
    .setAudience(resource)
    .setIssuedAt(now)
    .setExpirationTime(now + expiresIn)
    .sign(signingKey);
  const response = {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    scope
  };

  if (!scope.split(/\s+/).includes("offline_access")) {
    return response;
  }

  const refreshToken = randomToken(48);
  await prisma.refreshToken.create({
    data: {
      tokenHash: sha256(refreshToken),
      familyId,
      userId,
      clientId,
      scope,
      resource,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });
  return { ...response, refresh_token: refreshToken };
}

export async function verifyAccessToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, signingKey, { issuer });
    const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!payload.sub || !audience.includes(mcpUrl) || typeof payload.exp !== "number") {
      throw new Error("Invalid token claims.");
    }
    const user = await prisma.user.findUnique({ where: { id: payload.sub }, select: { id: true } });
    if (!user) throw new Error("Unknown Developersia account.");
    const scopes = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
    return {
      token,
      clientId: user.id,
      scopes,
      expiresAt: payload.exp,
      resource: new URL(mcpUrl)
    };
  } catch {
    throw new OAuthError(OAuthErrorCode.InvalidToken, "The access token is invalid or expired.");
  }
}
