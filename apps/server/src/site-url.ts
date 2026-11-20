import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";
import { allowLocalSites } from "./config.js";

function isPrivateAddress(address: string): boolean {
  try {
    let parsed = ipaddr.parse(address);
    if (parsed.kind() === "ipv6" && parsed.isIPv4MappedAddress()) {
      parsed = parsed.toIPv4Address();
    }
    return parsed.range() !== "unicast";
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

export async function assertSafeSiteUrl(input: string): Promise<string> {
  const url = new URL(input);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Site URL must not contain credentials, query parameters or fragments.");
  }
  const localHostname = url.hostname.toLowerCase() === "localhost";
  if (url.protocol !== "https:" && !(allowLocalSites && localHostname && url.protocol === "http:")) {
    throw new Error("WordPress sites must use HTTPS. HTTP is allowed only for localhost in development.");
  }
  if (localHostname) {
    if (!allowLocalSites) throw new Error("Local and private network sites cannot be connected.");
    return normalizedBaseUrl(url);
  }
  if (isIP(url.hostname)) throw new Error("IP-address site URLs are not accepted.");
  if (url.hostname.endsWith(".localhost") || url.hostname.endsWith(".local") || url.hostname === "metadata.google.internal") {
    throw new Error("Private and local hostnames cannot be connected.");
  }
  const records = await lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
    throw new Error("The site hostname resolves to a private or reserved network address.");
  }
  return normalizedBaseUrl(url);
}
