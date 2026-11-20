import { prisma } from "../apps/server/src/db.js";
import bcrypt from "bcryptjs";


async function main() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  const isProduction = process.env.NODE_ENV === "production";
  const minimumLength = isProduction ? 20 : 14;
  const placeholderEmail = Boolean(email && (email === "admin@example.com" || email.endsWith(".example") || email.includes("your-domain")));
  if (!email || !password || password.length < minimumLength ||
      (isProduction && (placeholderEmail || password.startsWith("replace-with-")))) {
    throw new Error("Set a real ADMIN_EMAIL and a unique ADMIN_PASSWORD of at least " + minimumLength + " characters before seeding.");
  }
  const passwordHash = await bcrypt.hash(password, 12);
  await prisma.user.upsert({
    where: { email },
    update: { role: "admin", passwordHash, displayName: "Developersia Admin" },
    create: { email, passwordHash, role: "admin", displayName: "Developersia Admin" }
  });
  console.log("Administrator account is ready:", email);
}

main().finally(async () => prisma.$disconnect());
