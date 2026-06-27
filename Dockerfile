# PromptSentinel — production image (multi-stage; native better-sqlite3 built in
# the builder, slim runtime, non-root, healthchecked).
FROM node:22-bookworm-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=4000 \
    SENTINEL_DB_PATH=/data/sentinel.db
WORKDIR /app
COPY --from=builder /app /app
# Persistent, LOCAL-disk store (never bind a cloud-synced folder here).
RUN mkdir -p /data && chown -R node:node /data /app
USER node
EXPOSE 4000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||4000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/app.js"]
