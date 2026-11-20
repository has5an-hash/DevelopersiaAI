import { describe, expect, it } from "vitest";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";
process.env.JWT_SECRET = "test-only-secret-with-more-than-32-characters";
process.env.ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.SITE_HTTP_ALLOW_LOCALHOST = "true";

const security = await import("../apps/server/src/security.js");
const siteUrl = await import("../apps/server/src/site-url.js");
const httpSecurity = await import("../apps/server/src/http-security.js");

describe("Developersia security primitives", () => {
  it("encrypts and decrypts site credentials", () => {
    const encrypted = security.encryptSecret("site-token-example");
    expect(encrypted).not.toContain("site-token-example");
    expect(security.decryptSecret(encrypted)).toBe("site-token-example");
  });

  it("rejects modified encrypted credentials", () => {
    const encrypted = security.encryptSecret("site-token-example");
    expect(() => security.decryptSecret(encrypted.slice(0, -2) + "xx")).toThrow();
  });

  it("hashes tokens consistently and generates high-entropy tokens", () => {
    expect(security.sha256("abc")).toBe(security.sha256("abc"));
    expect(security.randomToken(32).length).toBeGreaterThan(30);
  });

  it("accepts HTTPS redirects and loopback development redirects only", () => {
    expect(security.safeRedirectUri("https://chatgpt.com/oauth/callback")).toBe(true);
    expect(security.safeRedirectUri("http://localhost:3000/callback")).toBe(true);
    expect(security.safeRedirectUri("http://example.com/callback")).toBe(false);
    expect(security.safeRedirectUri("javascript:alert(1)")).toBe(false);
    expect(security.safeRedirectUri("https://example.com/callback#fragment")).toBe(false);
    expect(security.safeRedirectUri("https://user:pass@example.com/callback")).toBe(false);
  });
});

describe("WordPress site URL validation", () => {
  it("allows localhost HTTP only in development", async () => {
    await expect(siteUrl.assertSafeSiteUrl("http://localhost:8080/")).resolves.toBe("http://localhost:8080");
  });

  it("pins the development localhost target to IPv4 loopback", async () => {
    const target = await siteUrl.resolveSafeSiteTarget("http://localhost:8080/wordpress/");
    expect(target.address).toBe("127.0.0.1");
    expect(target.family).toBe(4);
    expect(target.baseUrl).toBe("http://localhost:8080/wordpress");
  });

  it("rejects local and reserved hostnames before network requests", async () => {
    await expect(siteUrl.resolveSafeSiteTarget("https://router.local/")).rejects.toThrow();
    await expect(siteUrl.resolveSafeSiteTarget("https://service.internal/")).rejects.toThrow();
    await expect(siteUrl.resolveSafeSiteTarget("https://example.test/")).rejects.toThrow();
  });

  it("rejects credentials, query strings, fragments and remote HTTP", async () => {
    await expect(siteUrl.resolveSafeSiteTarget("https://user:pass@example.com/")).rejects.toThrow();
    await expect(siteUrl.resolveSafeSiteTarget("https://example.com/?token=x")).rejects.toThrow();
    await expect(siteUrl.resolveSafeSiteTarget("https://example.com/#fragment")).rejects.toThrow();
    await expect(siteUrl.resolveSafeSiteTarget("http://example.com/")).rejects.toThrow();
  });

  it("rejects private network addresses", async () => {
    await expect(siteUrl.assertSafeSiteUrl("https://192.168.1.20/")).rejects.toThrow();
    await expect(siteUrl.assertSafeSiteUrl("https://127.0.0.1/")).rejects.toThrow();
  });

  it("supports WordPress installed in a localhost subdirectory", async () => {
    await expect(siteUrl.assertSafeSiteUrl("http://localhost:8080/wordpress/")).resolves.toBe("http://localhost:8080/wordpress");
  });
});

describe("HTTP security headers", () => {
  it("sets anti-clickjacking, no-sniff, no-referrer and no-store headers", () => {
    const headers = new Map<string, string>();
    httpSecurity.applySecurityHeaders({
      setHeader(name: string, value: string) {
        headers.set(name, value);
        return this;
      }
    });

    expect(headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(headers.get("X-Frame-Options")).toBe("DENY");
    expect(headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(headers.get("Cache-Control")).toBe("no-store");
    expect(headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(headers.get("Content-Security-Policy")).toContain("form-action 'self'");
  });
});
