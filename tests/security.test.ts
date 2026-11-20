import { beforeAll, describe, expect, it } from "vitest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";
  process.env.JWT_SECRET = "test-only-secret-with-more-than-32-characters";
  process.env.ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  process.env.SITE_HTTP_ALLOW_LOCALHOST = "true";
});

const security = await import("../apps/server/src/security.js");
const siteUrl = await import("../apps/server/src/site-url.js");

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
  });
});

describe("WordPress site URL validation", () => {
  it("allows localhost HTTP only in development", async () => {
    await expect(siteUrl.assertSafeSiteUrl("http://localhost:8080/")).resolves.toBe("http://localhost:8080");
  });

  it("rejects private network addresses", async () => {
    await expect(siteUrl.assertSafeSiteUrl("https://192.168.1.20/")).rejects.toThrow();
    await expect(siteUrl.assertSafeSiteUrl("https://127.0.0.1/")).rejects.toThrow();
  });

  it("rejects non-root WordPress paths", async () => {
    await expect(siteUrl.assertSafeSiteUrl("https://example.com/wordpress/")).rejects.toThrow();
  });
});
