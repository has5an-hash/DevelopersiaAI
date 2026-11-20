import { McpServer, requireScopes } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { prisma } from "./db.js";
import { wordpressRequest } from "./wordpress.js";
import { randomToken, sha256 } from "./security.js";

type RequestContext = { http?: { authInfo?: { clientId?: string; scopes?: string[] } } };

function jsonResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function errorResult(error: unknown) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: error instanceof Error ? error.message : "Unexpected Developersia error." }]
  };
}

async function ownedSite(ownerId: string, siteId: string) {
  const site = await prisma.site.findFirst({
    where: { id: siteId, ownerId, disconnectedAt: null }
  });
  if (!site) throw new Error("Connected site not found or access is revoked.");
  return site;
}

export function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "developersia-ai", version: "0.1.0" });

  server.registerTool(
    "account_get",
    {
      description: "Show the signed-in Developersia account and the available permissions.",
      inputSchema: z.object({})
    },
    async (_input, context) => {
      const auth = (context as RequestContext).http?.authInfo;
      if (!auth?.clientId) return errorResult(new Error("Authenticated account context is missing."));
      const user = await prisma.user.findUnique({
        where: { id: auth.clientId },
        select: { email: true, displayName: true, role: true, createdAt: true }
      });
      return user ? jsonResult({ account: user, scopes: auth.scopes ?? [] }) : errorResult(new Error("Account not found."));
    }
  );

  server.registerTool(
    "site_pairing_code",
    {
      description: "Generate a one-time code to connect a WordPress site to this Developersia account. The code expires after 15 minutes.",
      inputSchema: z.object({}),
      scopeChallenge: requireScopes("sites:write")
    },
    async (_input, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const code = "DEV-" + randomToken(18).toUpperCase();
        await prisma.pairingCode.create({
          data: { codeHash: sha256(code), ownerId, expiresAt: new Date(Date.now() + 15 * 60 * 1000) }
        });
        await prisma.auditLog.create({
          data: { userId: ownerId, action: "site.pairing_code.create", status: "success" }
        });
        return jsonResult({ code, expires_in: 900, message: "Enter this code in Settings > Developersia AI on the WordPress site. This code can only be used once." });
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "sites_list",
    {
      description: "List WordPress sites connected to the signed-in Developersia account.",
      inputSchema: z.object({}),
      scopeChallenge: requireScopes("sites:read")
    },
    async (_input, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const sites = await prisma.site.findMany({
          where: { ownerId, disconnectedAt: null },
          select: { id: true, siteUrl: true, siteName: true, wpVersion: true, pluginVersion: true, connectedAt: true, lastSeenAt: true },
          orderBy: { connectedAt: "desc" }
        });
        return jsonResult({ count: sites.length, sites });
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "site_status",
    {
      description: "Check the live status and WordPress version of one connected site.",
      inputSchema: z.object({ site_id: z.string().min(1) }),
      scopeChallenge: requireScopes("sites:read")
    },
    async ({ site_id }, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const site = await ownedSite(ownerId, site_id);
        const status = await wordpressRequest<Record<string, unknown>>(site, "status");
        await prisma.site.update({ where: { id: site.id }, data: { lastSeenAt: new Date() } });
        return jsonResult(status);
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "posts_list",
    {
      description: "Search or list posts and pages on a connected WordPress site. Results are paginated.",
      inputSchema: z.object({
        site_id: z.string().min(1),
        search: z.string().max(120).optional(),
        page: z.number().int().min(1).max(100).default(1),
        per_page: z.number().int().min(1).max(20).default(10)
      }),
      scopeChallenge: requireScopes("sites:read")
    },
    async ({ site_id, search, page, per_page }, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const site = await ownedSite(ownerId, site_id);
        const result = await wordpressRequest(site, "posts?page=" + page + "&per_page=" + per_page +
          (search ? "&search=" + encodeURIComponent(search) : ""));
        await prisma.site.update({ where: { id: site.id }, data: { lastSeenAt: new Date() } });
        return jsonResult(result);
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "post_read",
    {
      description: "Read the title, content, excerpt, status and metadata of a WordPress post or page.",
      inputSchema: z.object({ site_id: z.string().min(1), post_id: z.number().int().positive() }),
      scopeChallenge: requireScopes("sites:read")
    },
    async ({ site_id, post_id }, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const site = await ownedSite(ownerId, site_id);
        return jsonResult(await wordpressRequest(site, "posts/" + post_id));
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "post_create_draft",
    {
      description: "Create a new WordPress post or page as a draft. It will not be published.",
      inputSchema: z.object({
        site_id: z.string().min(1),
        title: z.string().min(1).max(180),
        content: z.string().min(1).max(100000),
        excerpt: z.string().max(500).optional(),
        post_type: z.enum(["post", "page"]).default("post")
      }),
      scopeChallenge: requireScopes("sites:write")
    },
    async ({ site_id, title, content, excerpt, post_type }, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const site = await ownedSite(ownerId, site_id);
        const created = await wordpressRequest(site, "posts", {
          method: "POST",
          body: { title, content, excerpt: excerpt ?? "", post_type }
        });
        await prisma.auditLog.create({
          data: { userId: ownerId, siteId: site.id, action: "post.create_draft", status: "success", metadata: { postType: post_type } }
        });
        return jsonResult({ message: "Draft created. It has not been published.", post: created });
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "post_update_draft",
    {
      description: "Update the title or content of a draft/pending WordPress post or page. Published content cannot be changed by this tool.",
      inputSchema: z.object({
        site_id: z.string().min(1),
        post_id: z.number().int().positive(),
        title: z.string().min(1).max(180).optional(),
        content: z.string().min(1).max(100000).optional(),
        excerpt: z.string().max(500).optional()
      }).refine((value) => Boolean(value.title || value.content || value.excerpt), "At least one field must be provided."),
      scopeChallenge: requireScopes("sites:write")
    },
    async ({ site_id, post_id, title, content, excerpt }, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const site = await ownedSite(ownerId, site_id);
        const updated = await wordpressRequest(site, "posts/" + post_id, {
          method: "POST",
          body: { ...(title ? { title } : {}), ...(content ? { content } : {}), ...(excerpt !== undefined ? { excerpt } : {}) }
        });
        await prisma.auditLog.create({
          data: { userId: ownerId, siteId: site.id, action: "post.update_draft", status: "success", metadata: { postId: post_id } }
        });
        return jsonResult({ message: "Draft updated.", post: updated });
      } catch (error) { return errorResult(error); }
    }
  );

  server.registerTool(
    "site_disconnect",
    {
      description: "Disconnect a WordPress site from this Developersia account and revoke its remote access token.",
      inputSchema: z.object({ site_id: z.string().min(1) }),
      scopeChallenge: requireScopes("sites:write")
    },
    async ({ site_id }, context) => {
      try {
        const ownerId = (context as RequestContext).http?.authInfo?.clientId;
        if (!ownerId) throw new Error("Authentication is required.");
        const site = await ownedSite(ownerId, site_id);
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
          data: { userId: ownerId, siteId: site.id, action: "site.disconnect", status: "success", metadata: { wordpressCleanup } }
        });
        return jsonResult({ disconnected: true, site_id, wordpress_cleanup: wordpressCleanup });
      } catch (error) { return errorResult(error); }
    }
  );

  return server;
}
