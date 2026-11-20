import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { allowLocalSites } from "./config.js";

function isPrivateV4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

function isPrivateAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPrivateV4(address);
  if (version === 6) {
    const lower = address.toLowerCase();
    return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") ||
      lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") ||
      lower.startsWith("feb") || lower.startsWith("::ffff:127.") || lower.startsWith("::ffff:10.");
  }
  return true;
}

export async function assertSafeSiteUrl(input: string): Promise<string> {
  const url = new URL(input);
  if (url.username || url.password || url.search || url.hash) throw new Error("Site URL must not contain credentials, query parameters or fragments.");
  if (url.pathname !== "/" && url.pathname !== "") throw new Error("Connect the WordPress site's root URL, not a subdirectory.");
  const localHostname = url.hostname.toLowerCase() === "localhost";
  if (url.protocol !== "https:" && !(allowLocalSites && localHostname && url.protocol === "http:")) {
    throw new Error("WordPress sites must use HTTPS. HTTP is allowed only for localhost in development.");
  }
  if (localHostname) {
    if (!allowLocalSites) throw new Error("Local and private network sites cannot be connected.");
    return url.origin;
  }
  if (isIP(url.hostname)) throw new Error("IP-address site URLs are not accepted.");
  if (url.hostname.endsWith(".localhost") || url.hostname.endsWith(".local") || url.hostname === "metadata.google.internal") {
    throw new Error("Private and local hostnames cannot be connected.");
  }
  const records = await lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
    throw new Error("The site hostname resolves to a private or reserved network address.");
  }
  return url.origin;
}
