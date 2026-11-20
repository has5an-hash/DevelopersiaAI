import "dotenv/config";
import { z } from "zod";

const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_BASE_URL: z.string().url().default("http://localhost:3000"),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  ENCRYPTION_KEY: z.string().regex(/^[a-fA-F0-9]{64}$/, "ENCRYPTION_KEY must be 32 bytes represented as 64 hex characters"),
  SITE_HTTP_ALLOW_LOCALHOST: z.string().default("true")
});

export const env = EnvSchema.parse(process.env);
export const baseUrl = new URL(env.PUBLIC_BASE_URL);

if (env.NODE_ENV === "production") {
  const hostname = baseUrl.hostname.toLowerCase().replace(/^\\[|\\]$/g, "");
  const isLoopback = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname.endsWith(".localhost");
  if (baseUrl.protocol !== "https:" || isLoopback) {
    throw new Error("Production PUBLIC_BASE_URL must use HTTPS and a public hostname.");
  }
  if (/^(replace|change|your-|example|dev-|test-)/i.test(env.JWT_SECRET)) {
    throw new Error("Replace the JWT_SECRET example value with a unique random production secret.");
  }
  if (/^([0-9a-f])\\1{63}$/i.test(env.ENCRYPTION_KEY)) {
    throw new Error("Replace the ENCRYPTION_KEY example value with 32 random bytes encoded as 64 hex characters.");
  }
}

export const mcpUrl = new URL("/mcp", baseUrl).toString();
export const issuer = baseUrl.origin;
export const allowLocalSites = env.NODE_ENV !== "production" && env.SITE_HTTP_ALLOW_LOCALHOST === "true";
