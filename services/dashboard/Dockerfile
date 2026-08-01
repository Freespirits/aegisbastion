# AegisBastion operator dashboard (doc 10) — MVP-A thin slice.
# Next.js standalone output: SPA + BFF in one container on the compose host
# (doc 00 §4). Backend URLs are runtime env — see .env.example.

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN addgroup -S aegisbastion && adduser -S aegisbastion -G aegisbastion
COPY --from=build --chown=aegisbastion:aegisbastion /app/.next/standalone ./
COPY --from=build --chown=aegisbastion:aegisbastion /app/.next/static ./.next/static
USER aegisbastion
EXPOSE 3000
# server.js is emitted by Next's standalone output.
CMD ["node", "server.js"]
