import type { NextFunction, Request, Response } from "express";
import { env } from "./config.js";

export const SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; style-src 'unsafe-inline'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-DNS-Prefetch-Control": "off",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Cache-Control": "no-store",
  "Pragma": "no-cache"
});

export function applySecurityHeaders(response: { setHeader(name: string, value: string): unknown }): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    response.setHeader(name, value);
  }
  if (env.NODE_ENV === "production") {
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  applySecurityHeaders(res);
  next();
}
