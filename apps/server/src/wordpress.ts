import type { Site } from "@prisma/client";
import { decryptSecret } from "./security.js";
import { assertSafeSiteUrl } from "./site-url.js";

export type WordPressPostSummary = {
  id: number;
  date: string;
  modified: string;
  slug: string;
  status: string;
  link: string;
  title: string;
  excerpt: string;
};

export async function wordpressRequest<T>(
  site: Site,
  endpoint: string,
  options: { method?: "GET" | "POST" | "DELETE"; body?: Record<string, unknown> } = {}
): Promise<T> {
  const origin = await assertSafeSiteUrl(site.siteUrl);
  const path = endpoint.replace(/^\/+/, "");
  if (path.includes("..")) throw new Error("Invalid WordPress API path.");
  const url = new URL("/wp-json/developersia/v1/" + path, origin);
  const token = decryptSecret(site.tokenCiphertext);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, {
      method: options.method ?? "GET",
      redirect: "error",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        Authorization: "Bearer " + token,
        ...(options.body ? { "Content-Type": "application/json" } : {})
      },
      ...(options.body ? { body: JSON.stringify(options.body) } : {})
    });
    const payload = await response.json().catch(() => null) as unknown;
    if (!response.ok) {
      const message = typeof payload === "object" && payload !== null && "message" in payload
        ? String((payload as { message: unknown }).message)
        : "WordPress returned HTTP " + response.status;
      throw new Error(message);
    }
    return payload as T;
  } finally {
    clearTimeout(timeout);
  }
}
