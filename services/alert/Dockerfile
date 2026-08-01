# AegisBastion alert module `herald` (doc 05) — MVP-A image.
# Build context: services/alert (self-contained: @aegisbastion/agent-sdk and
# @aegisbastion/gen ride along as vendored npm tarballs under vendor/, the same
# pattern as services/dashboard — regenerate them with bin/repack-vendor.sh
# after changing sdks/ts or gen/ts).

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --no-audit --no-fund --omit=dev

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S aegisbastion && adduser -S aegisbastion -G aegisbastion
COPY --from=build --chown=aegisbastion:aegisbastion /app/node_modules ./node_modules
COPY --from=build --chown=aegisbastion:aegisbastion /app/dist ./dist
COPY --chown=aegisbastion:aegisbastion package.json ./
# AlertEvent v1 / CloudEvents JSON Schemas are validated at ingress (C1).
COPY --chown=aegisbastion:aegisbastion schemas ./schemas
USER aegisbastion
EXPOSE 8086
ENV HERALD_HTTP_LISTEN=:8086 \
    SCHEMA_DIR=/app/schemas/alert/v1
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD wget -qO- http://127.0.0.1:8086/healthz >/dev/null 2>&1 || exit 1
CMD ["node", "dist/main.js"]
