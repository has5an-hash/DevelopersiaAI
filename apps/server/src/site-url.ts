import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";
import { allowLocalSites } from "./config.js";

export type SafeSiteTarget = {
  baseUrl: string;
  hostname: string;
  address: string;
  family: 4 | 6;
  protocol: "https:" | "http:";
};

function isPrivateAddress(address: string): boolean {
  try {
    return ipaddr.process(address).range() !== "unicast";
  } catch {
    return true;
  }
}

function normalizedBaseUrl(url: URL): string {
  if (url.pathname.includes("\\") || /%2f|%5c/i.test(url.pathname)) {
    throw new Error("Encoded separators are not accepted in WordPress site paths.");
  }
  const pathname = url.pathname.replace(/\/+$/, "");
  return url.origin + (pathname === "/" ? "" : pathname);
}

/**
 * Resolve and validate a WordPress host once. The returned address is then
 * used directly by the HTTP transport so a second DNS lookup cannot silently
 * redirect the request to a private address (DNS rebinding).
 */
export async function resolveSafeSiteTarget(input: string): Promise<SafeSiteTarget> {
  const url = new URL(input);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Site URL must not contain credentials, query parameters or fragments.");
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const localHostname = hostname === "localhost";
  if (url.protocol !== "https:" && !(allowLocalSites && localHostname && url.protocol === "http:")) {
    throw new Error("WordPress sites must use HTTPS. HTTP is allowed only for localhost in development.");
  }

  if (localHostname) {
    if (!allowLocalSites || url.protocol !== "http:") {
      throw new Error("Local and private network sites cannot be connected.");
    }
    return {
      baseUrl: normalizedBaseUrl(url),
      hostname,
      address: "127.0.0.1",
      family: 4,
      protocol: "http:"
    };
  }

  if (isIP(hostname)) throw new Error("IP-address site URLs are not accepted.");
  const blockedSuffixes = [".localhost", ".local", ".internal", ".home.arpa", ".test", ".invalid", ".example"];
  if (blockedSuffixes.some((suffix) => hostname.endsWith(suffix)) || hostname === "metadata.google.internal") {
    throw new Error("Private and local hostnames cannot be connected.");
  }

  const records = await lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
    throw new Error("The site hostname resolves to a private or reserved network address.");
  }

  const selected = records[0];
  if (!selected) throw new Error("The site hostname could not be resolved safely.");
  return {
    baseUrl: normalizedBaseUrl(url),
    hostname,
    address: selected.address,
    family: selected.family as 4 | 6,
    protocol: "https:"
  };
}

export async function assertSafeSiteUrl(input: string): Promise<string> {
  return (await resolveSafeSiteTarget(input)).baseUrl;
}
