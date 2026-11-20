import { Router, type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import bcrypt from "bcryptjs";
import { prisma } from "./db.js";
import { env } from "./config.js";
import { randomToken, safeEqual, sha256 } from "./security.js";
import { wordpressRequest } from "./wordpress.js";

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const CSRF_TTL_SECONDS = 10 * 60;

type CookieMap = Record<string, string>;

function htmlEscape(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  })[character] ?? character);
}

function parseCookies(request: Request): CookieMap {
  const header = request.headers.cookie ?? "";
  const cookies: CookieMap = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = value;
    }
  }
  return cookies;
}

function cookieHeader(name: string, value: string, maxAge: number): string {
  const attributes = [
    name + "=" + encodeURIComponent(value),
    "Path=/",
    "SameSite=Lax",
    "HttpOnly",
    "Max-Age=" + String(maxAge)
  ];
  if (env.NODE_ENV === "production") attributes.push("Secure");
  return attributes.join("; ");
}

function setCookie(response: Response, name: string, value: string, maxAge: number): void {
  response.appendHeader("Set-Cookie", cookieHeader(name, value, maxAge));
}

function clearCookie(response: Response, name: string): void {
  setCookie(response, name, "", 0);
}

function setCsrfCookie(response: Response, name: string): string {
  const token = randomToken(24);
  setCookie(response, name, token, CSRF_TTL_SECONDS);
  return token;
}

function formValue(request: Request, name: string): string {
  const body = request.body as Record<string, unknown> | undefined;
  const value = body?.[name];
  return typeof value === "string" ? value : "";
}

function validCsrf(request: Request, cookieName: string): boolean {
  const cookie = parseCookies(request)[cookieName] ?? "";
  const submitted = formValue(request, "csrf_token");
  return cookie.length > 0 && submitted.length > 0 && safeEqual(cookie, submitted);
}

function renderPage(title: string, body: string): string {
  return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" + htmlEscape(title) + " · Developersia AI</title>" +
    "<style>" +
    ":root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f4f6f8;color:#172b4d;font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}" +
    ".wrap{width:min(940px,calc(100% - 32px));margin:42px auto}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}.brand{font-size:18px;font-weight:750;letter-spacing:-.03em}.muted{color:#64748b}.card{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:22px;margin:16px 0;box-shadow:0 10px 35px #172b4d08}" +
    "h1{font-size:25px;line-height:1.2;margin:0 0 8px}h2{font-size:17px;margin:0 0 12px}p{margin:8px 0}.field{display:block;width:100%;max-width:440px;padding:12px 13px;border:1px solid #cbd5e1;border-radius:9px;font:inherit;margin:6px 0 14px;background:#fff}label{display:block;font-size:13px;font-weight:650;margin-top:12px}button,.button{display:inline-block;border:0;border-radius:9px;background:#172b4d;color:#fff;padding:10px 15px;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}button.secondary,.button.secondary{background:#eef2f7;color:#172b4d}button.danger{background:#fff1f2;color:#be123c;border:1px solid #fecdd3}.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.site{border-top:1px solid #e2e8f0;padding:16px 0}.site:first-of-type{border-top:0}.code{display:inline-block;background:#eef2f7;padding:12px 15px;border-radius:10px;font:700 18px ui-monospace,monospace;letter-spacing:.04em;overflow-wrap:anywhere}.notice{padding:12px 14px;border-radius:9px;background:#eff6ff;color:#1e40af;margin:12px 0}.error{background:#fff1f2;color:#be123c}.small{font-size:12px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}a{color:#1d4ed8}.empty{padding:22px;border:1px dashed #cbd5e1;border-radius:12px;color:#64748b;text-align:center}" +
    "@media(max-width:600px){.wrap{margin:20px auto}.card{padding:16px}.top{align-items:flex-start}.row{align-items:flex-start}}" +
    "</style></head><body><main class=\"wrap\">" + body + "</main></body></html>";
}

function renderLogin(csrf: string, error = ""): string {
  return renderPage("Sign in", "<div class=\"card\" style=\"max-width:480px;margin:9vh auto\">" +
    "<div class=\"brand\">Developersia AI</div><h1 style=\"margin-top:22px\">Sign in</h1>" +
    "<p class=\"muted\">Manage the WordPress sites connected to your Developersia account.</p>" +
    (error ? "<div class=\"notice error\">" + htmlEscape(error) + "</div>" : "") +
    "<form method=\"post\" action=\"/login\">" +
    "<input type=\"hidden\" name=\"csrf_token\" value=\"" + htmlEscape(csrf) + "\">" +
    "<label for=\"email\">Email address</label><input class=\"field\" id=\"email\" name=\"email\" type=\"email\" autocomplete=\"username\" maxlength=\"254\" required>" +
    "<label for=\"password\">Password</label><input class=\"field\" id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>" +
    "<button type=\"submit\" style=\"width:100%;margin-top:8px\">Sign in</button></form>" +
    "<p class=\"muted small\" style=\"margin-top:18px\">Accounts are provisioned by a Developersia administrator. Public self-registration is not enabled in this version.</p></div>");
}

async function loadSession(request: Request) {
  const token = parseCookies(request).developersia_session ?? "";
  if (!token) return null;
  const session = await prisma.session.findUnique({
    where: { tokenHash: sha256(token) },
    include: {
      user: {
        select: { id: true, email: true, displayName: true, role: true }
      }
    }
  });
  if (!session || session.revokedAt || session.expiresAt <= new Date()) return null;
  return session;
}

function renderDashboard(user: { email: string; displayName: string | null; role: string }, sites: Array<{
  id: string;
  siteUrl: string;
  siteName: string;
  wpVersion: string | null;
  pluginVersion: string | null;
  connectedAt: Date;
  lastSeenAt: Date | null;
  disconnectedAt: Date | null;
}>, csrf: string): string {
  const siteMarkup = sites.length === 0
    ? "<div class=\"empty\">No WordPress sites connected yet. Generate a pairing code to connect your first site.</div>"
    : sites.map((site) => {
      const connected = !site.disconnectedAt;
      return "<div class=\"site\"><div class=\"row\"><div><strong>" + htmlEscape(site.siteName) + "</strong>" +
        "<div class=\"muted small\"><a href=\"" + htmlEscape(site.siteUrl) + "\" target=\"_blank\" rel=\"noopener noreferrer\">" + htmlEscape(site.siteUrl) + "</a></div>" +
        "<div class=\"muted small\">WordPress " + htmlEscape(site.wpVersion ?? "unknown") + " · Connector " + htmlEscape(site.pluginVersion ?? "unknown") +
        " · Last seen: " + htmlEscape(site.lastSeenAt ? site.lastSeenAt.toISOString() : "not yet checked") + "</div></div>" +
        "<div class=\"actions\"><span class=\"small\" style=\"color:" + (connected ? "#047857" : "#64748b") + "\">" + (connected ? "Connected" : "Disconnected") + "</span>" +
        (connected ? "<form method=\"post\" action=\"/dashboard/sites/" + encodeURIComponent(site.id) + "/disconnect\">" +
          "<input type=\"hidden\" name=\"csrf_token\" value=\"" + htmlEscape(csrf) + "\"><button class=\"danger\" type=\"submit\">Disconnect</button></form>" : "") +
        "</div></div></div>";
    }).join("");

  return renderPage("Dashboard", "<div class=\"top\"><div><div class=\"brand\">Developersia AI</div><div class=\"muted small\">Control panel</div></div>" +
    "<form method=\"post\" action=\"/dashboard/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + htmlEscape(csrf) + "\"><button class=\"secondary\" type=\"submit\">Sign out</button></form></div>" +
    "<section class=\"card\"><h1>Welcome, " + htmlEscape(user.displayName || user.email) + "</h1><p class=\"muted\">" + htmlEscape(user.email) + " · " + htmlEscape(user.role) + "</p>" +
    "<div class=\"notice\">Use this dashboard to connect and manage your WordPress sites. Content changes are still performed through explicitly authorized AI tools.</div></section>" +
    "<section class=\"card\"><div class=\"row\"><h2>Connected WordPress sites</h2><span class=\"muted small\">" + sites.filter((site) => !site.disconnectedAt).length + " active</span></div>" +
    siteMarkup + "</section>" +
    "<section class=\"card\"><h2>Connect a WordPress site</h2><p class=\"muted\">Generate a one-time code, then enter it in WordPress → Settings → Developersia AI. The code expires after 15 minutes and can only be used once.</p>" +
    "<form method=\"post\" action=\"/dashboard/pairing-code\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + htmlEscape(csrf) + "\"><button type=\"submit\">Generate pairing code</button></form></section>" +
    "<p class=\"muted small\">Developersia AI · Secure site connections · <a href=\"/health\">Service status</a></p>");
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const pairingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

export function createDashboardRouter(): Router {
  const router = Router();

  router.get("/", (_request, response) => {
    response.setHeader("Cache-Control", "no-store");
    response.type("html").send(renderPage("Developersia AI", "<div class=\"card\" style=\"margin-top:9vh\">" +
      "<div class=\"brand\">Developersia AI</div><h1 style=\"font-size:34px;margin-top:24px\">One control plane for your connected sites.</h1>" +
      "<p class=\"muted\">Connect WordPress sites to ChatGPT and other compatible AI clients, review content and manage site access.</p>" +
      "<p style=\"margin-top:24px\"><a class=\"button\" href=\"/login\">Open dashboard</a></p></div>"));
  });

  router.get("/login", async (request, response) => {
    const session = await loadSession(request);
    if (session) {
      response.redirect(303, "/dashboard");
      return;
    }
    const csrf = setCsrfCookie(response, "developersia_login_csrf");
    response.setHeader("Cache-Control", "no-store");
    response.type("html").send(renderLogin(csrf));
  });

  router.post("/login", loginLimiter, async (request, response) => {
    if (!validCsrf(request, "developersia_login_csrf")) {
      const csrf = setCsrfCookie(response, "developersia_login_csrf");
      response.status(403).setHeader("Cache-Control", "no-store");
      response.type("html").send(renderLogin(csrf, "The sign-in form expired. Please try again."));
      return;
    }

    const email = formValue(request, "email").trim().toLowerCase();
    const password = formValue(request, "password");
    const user = email ? await prisma.user.findUnique({ where: { email } }) : null;
    if (!user || !password || !(await bcrypt.compare(password, user.passwordHash))) {
      const csrf = setCsrfCookie(response, "developersia_login_csrf");
      response.status(401).setHeader("Cache-Control", "no-store");
      response.type("html").send(renderLogin(csrf, "Email address or password is incorrect."));
      return;
    }

    const token = randomToken(32);
    await prisma.session.create({
      data: {
        tokenHash: sha256(token),
        userId: user.id,
        expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
        userAgent: (request.get("user-agent") ?? "").slice(0, 512) || null
      }
    });
    await prisma.auditLog.create({
      data: { userId: user.id, action: "dashboard.login", status: "success" }
    });

    setCookie(response, "developersia_session", token, SESSION_TTL_SECONDS);
    clearCookie(response, "developersia_login_csrf");
    response.redirect(303, "/dashboard");
  });

  router.get("/dashboard", async (request, response) => {
    const session = await loadSession(request);
    if (!session) {
      clearCookie(response, "developersia_session");
      response.redirect(302, "/login");
      return;
    }
    const csrf = setCsrfCookie(response, "developersia_dashboard_csrf");
    const sites = await prisma.site.findMany({
      where: { ownerId: session.userId },
      select: {
        id: true,
        siteUrl: true,
        siteName: true,
        wpVersion: true,
        pluginVersion: true,
        connectedAt: true,
        lastSeenAt: true,
        disconnectedAt: true
      },
      orderBy: { connectedAt: "desc" }
    });
    response.setHeader("Cache-Control", "no-store");
    response.type("html").send(renderDashboard(session.user, sites, csrf));
  });

  router.post("/dashboard/pairing-code", pairingLimiter, async (request, response) => {
    const session = await loadSession(request);
    if (!session) {
      response.status(401).json({ error: "unauthorized" });
      return;
    }
    if (!validCsrf(request, "developersia_dashboard_csrf")) {
      response.status(403).json({ error: "csrf_validation_failed" });
      return;
    }

    const code = "DEV-" + randomToken(18).toUpperCase();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await prisma.pairingCode.create({
      data: { codeHash: sha256(code), ownerId: session.userId, expiresAt }
    });
    await prisma.auditLog.create({
      data: { userId: session.userId, action: "dashboard.pairing_code.create", status: "success" }
    });

    response.setHeader("Cache-Control", "no-store");
    response.type("html").send(renderPage("Pairing code", "<div class=\"card\"><div class=\"brand\">Developersia AI</div><h1 style=\"margin-top:20px\">One-time pairing code</h1>" +
      "<p class=\"muted\">Enter this code in WordPress → Settings → Developersia AI. It expires in 15 minutes and can be used once.</p>" +
      "<p class=\"code\">" + htmlEscape(code) + "</p><p class=\"muted small\">Expires: " + htmlEscape(expiresAt.toISOString()) + "</p>" +
      "<p><a class=\"button\" href=\"/dashboard\">Back to dashboard</a></p></div>"));
  });

  router.post("/dashboard/sites/:siteId/disconnect", async (request, response) => {
    const session = await loadSession(request);
    if (!session) {
      response.status(401).json({ error: "unauthorized" });
      return;
    }
    if (!validCsrf(request, "developersia_dashboard_csrf")) {
      response.status(403).json({ error: "csrf_validation_failed" });
      return;
    }

    const siteId = request.params.siteId;
    const site = await prisma.site.findFirst({
      where: { id: siteId, ownerId: session.userId, disconnectedAt: null }
    });
    if (!site) {
      response.status(404).type("html").send(renderPage("Site not found", "<div class=\"card\"><h1>Site not found</h1><p><a href=\"/dashboard\">Back to dashboard</a></p></div>"));
      return;
    }

    await prisma.site.update({
      where: { id: site.id },
      data: { disconnectedAt: new Date(), tokenHash: sha256(randomToken(48)), tokenCiphertext: "" }
    });

    let wordpressCleanup = "complete";
    try {
      await wordpressRequest(site, "disconnect", { method: "DELETE" });
    } catch {
      wordpressCleanup = "manual_disconnect_required";
    }

    await prisma.auditLog.create({
      data: {
        userId: session.userId,
        siteId: site.id,
        action: "dashboard.site.disconnect",
        status: "success",
        metadata: { wordpressCleanup }
      }
    });

    const note = wordpressCleanup === "complete"
      ? "The platform and WordPress connector have both been notified."
      : "The platform access was revoked. The local WordPress connector could not be notified; remove its connection from WordPress settings if needed.";
    response.setHeader("Cache-Control", "no-store");
    response.type("html").send(renderPage("Site disconnected", "<div class=\"card\"><h1>Site disconnected</h1><p>" + htmlEscape(note) + "</p><p><a class=\"button\" href=\"/dashboard\">Back to dashboard</a></p></div>"));
  });

  router.post("/dashboard/logout", async (request, response) => {
    const session = await loadSession(request);
    if (!session) {
      clearCookie(response, "developersia_session");
      response.redirect(303, "/login");
      return;
    }
    if (!validCsrf(request, "developersia_dashboard_csrf")) {
      response.status(403).json({ error: "csrf_validation_failed" });
      return;
    }

    await prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: new Date() }
    });
    await prisma.auditLog.create({
      data: { userId: session.userId, action: "dashboard.logout", status: "success" }
    });
    clearCookie(response, "developersia_session");
    clearCookie(response, "developersia_dashboard_csrf");
    response.redirect(303, "/login");
  });

  return router;
}
