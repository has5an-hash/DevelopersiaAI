FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json ./
COPY prisma ./prisma
COPY prisma.config.ts ./
RUN DATABASE_URL="postgresql://build:build@localhost:5432/build?schema=public" npm install
RUN DATABASE_URL="postgresql://build:build@localhost:5432/build?schema=public" npx prisma generate

COPY tsconfig.json ./
COPY apps ./apps
RUN npm run build

ENV NODE_ENV=production
EXPOSE 3000

CMD ["sh", "-c", "npx prisma migrate deploy && npm run start"]
