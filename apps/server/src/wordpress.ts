import * as http from "node:http";
import * as https from "node:https";
import type { Site } from "@prisma/client";
import { decryptSecret } from "./security.js";
import { resolveSafeSiteTarget } from "./site-url.js";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 12_000;

export async function wordpressRequest<T>(
  site: Site,
  endpoint: string,
  options: { method?: "GET" | "POST" | "DELETE"; body?: Record<string, unknown> } = {}
): Promise<T> {
  const target = await resolveSafeSiteTarget(site.siteUrl);
  const path = endpoint.replace(/^\/+/, "");
  const endpointPath = path.split("?")[0] ?? "";
  if (!endpointPath || endpointPath.split("/").some((part) => part === "." || part === "..") || path.includes("\\")) {
    throw new Error("Invalid WordPress API path.");
  }

  const siteBase = target.baseUrl.endsWith("/") ? target.baseUrl : target.baseUrl + "/";
  const url = new URL("wp-json/developersia/v1/" + path, siteBase);
  if (url.hostname.toLowerCase().replace(/\.$/, "") !== target.hostname || url.protocol !== target.protocol) {
    throw new Error("WordPress API URL escaped the validated site origin.");
  }

  const token = decryptSecret(site.tokenCiphertext);
  const method = options.method ?? "GET";
  const body = options.body === undefined ? undefined : JSON.stringify(options.body);
  const headers: http.OutgoingHttpHeaders = {
    Accept: "application/json",
    Authorization: "Bearer " + token,
    Host: url.host
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = Buffer.byteLength(body);
  }

  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const fail = (error: Error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    const handleResponse = (response: http.IncomingMessage) => {
      const chunks: Buffer[] = [];
      let size = 0;

      response.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > MAX_RESPONSE_BYTES) {
          response.destroy();
          fail(new Error("WordPress response exceeded the 2 MB safety limit."));
          return;
        }
        chunks.push(buffer);
      });

      response.on("error", fail);
      response.on("end", () => {
        if (settled) return;
        const raw = Buffer.concat(chunks).toString("utf8");
        let payload: unknown = null;
        if (raw) {
          try {
            payload = JSON.parse(raw);
          } catch {
            fail(new Error("WordPress returned an invalid JSON response."));
            return;
          }
        }

        const status = response.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          const message = typeof payload === "object" && payload !== null && "message" in payload
            ? String((payload as { message: unknown }).message)
            : "WordPress returned HTTP " + status;
          fail(new Error(message));
          return;
        }
        if (payload === null) {
          fail(new Error("WordPress returned an empty response."));
          return;
        }
        settled = true;
        resolve(payload as T);
      });
    };

    const commonOptions: http.RequestOptions = {
      hostname: target.address,
      family: target.family,
      port: url.port ? Number(url.port) : (target.protocol === "https:" ? 443 : 80),
      method,
      path: url.pathname + url.search,
      headers
    };

    const request = target.protocol === "https:"
      ? https.request({
          ...commonOptions,
          servername: target.hostname,
          rejectUnauthorized: true
        }, handleResponse)
      : http.request(commonOptions, handleResponse);

    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error("WordPress request timed out."));
    });
    request.on("error", fail);
    if (body !== undefined) request.write(body);
    request.end();
  });
}
