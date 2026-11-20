import { prisma } from "../db.js";
import { randomBytes, createHash } from "node:crypto";


function getArg(name: string): string | undefined {
  const index = process.argv.indexOf("--" + name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main() {
  const email = getArg("email")?.trim().toLowerCase();
  const ttl = Number(getArg("ttl-minutes") ?? "15");
  if (!email) throw new Error("Usage: npm run pair:code -- --email admin@example.com [--ttl-minutes 15]");
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 60) throw new Error("TTL must be between 1 and 60 minutes.");
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error("Account not found. Run the database seed first.");
  const code = "DEV-" + randomBytes(18).toString("base64url").toUpperCase();
  const codeHash = createHash("sha256").update(code).digest("hex");
  await prisma.pairingCode.create({
    data: { codeHash, ownerId: user.id, expiresAt: new Date(Date.now() + ttl * 60 * 1000) }
  });
  console.log("\nOne-time WordPress pairing code (shown once):\n" + code + "\nExpires in " + ttl + " minute(s).\n");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}).finally(async () => prisma.$disconnect());
