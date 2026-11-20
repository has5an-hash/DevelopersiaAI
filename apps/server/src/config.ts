import "dotenv/config";
import { isIP } from "node:net";
import { z } from "zod";

const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_BASE_URL: z.string().url().default("http://localhost:3000"),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  ENCRYPTION_KEY: z.string().regex(/^[a-fA-F0-9]{64}$/, "ENCRYPTION_KEY must be 32 bytes represented as 64 hex characters"),
  SITE_HTTP_ALLOW_LOCALHOST: z.string().default("true"),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0)
});

export function isWeakProductionSecret(value: string): boolean {
  return /^(replace|change|your-|example|dev-|test-)/i.test(value) ||
    new Set(value.toLowerCase()).size === 1;
}

export const env = EnvSchema.parse(process.env);
export const baseUrl = new URL(env.PUBLIC_BASE_URL);
if (baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash || baseUrl.pathname !== "/") {
  throw new Error("PUBLIC_BASE_URL must be an origin only, without credentials, path, query or fragment.");
}

if (env.NODE_ENV === "production") {
  const hostname = baseUrl.hostname.toLowerCase();
  const unbracketedHostname = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const isLoopback = unbracketedHostname === "localhost" ||
    unbracketedHostname === "127.0.0.1" ||
    unbracketedHostname === "::1" ||
    unbracketedHostname.endsWith(".localhost");
  if (baseUrl.protocol !== "https:" || isLoopback || isIP(unbracketedHostname) !== 0) {
    throw new Error("Production PUBLIC_BASE_URL must use HTTPS and a public DNS hostname, not a loopback or IP address.");
  }
  if (isWeakProductionSecret(env.JWT_SECRET)) {
    throw new Error("Replace the JWT_SECRET example value with a unique random production secret.");
  }
  if (new Set(env.ENCRYPTION_KEY.toLowerCase()).size < 10) {
    throw new Error("ENCRYPTION_KEY must contain a high-entropy random value in production.");
  }
}

export const mcpUrl = new URL("/mcp", baseUrl).toString();
export const issuer = baseUrl.origin;
export const allowLocalSites = env.NODE_ENV !== "production" && env.SITE_HTTP_ALLOW_LOCALHOST === "true";
