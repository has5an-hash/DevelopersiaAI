import { prisma } from "../apps/server/src/db.js";
import bcrypt from "bcryptjs";


async function main() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password || password.length < 14) {
    throw new Error("Set ADMIN_EMAIL and an ADMIN_PASSWORD of at least 14 characters before seeding.");
  }
  const passwordHash = await bcrypt.hash(password, 12);
  await prisma.user.upsert({
    where: { email },
    update: { role: "admin" },
    create: { email, passwordHash, role: "admin", displayName: "Developersia Admin" }
  });
  console.log("Administrator account is ready:", email);
}

main().finally(async () => prisma.$disconnect());
