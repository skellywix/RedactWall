# syntax=docker/dockerfile:1.7
# PromptWall production image. Native better-sqlite3 is built in the builder;
# the runtime contains only production dependencies and runtime source.
FROM node:22-bookworm-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev
COPY . .

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=4000 \
    SENTINEL_DB_PATH=/data/sentinel.db \
    SENTINEL_POLICY_PATH=/data/policy.json \
    SENTINEL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json \
    NPM_CONFIG_CACHE=/tmp/.npm \
    NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /app
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node server ./server
COPY --chown=node:node detection-engine ./detection-engine
COPY --chown=node:node config ./config
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node sensors ./sensors
# Persistent, local-disk runtime state. Keep /data mounted outside the image.
RUN mkdir -p /data /app/data /tmp/promptwall \
    && chown -R node:node /data /app /tmp/promptwall \
    && chmod 700 /data /tmp/promptwall
USER node
EXPOSE 4000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||4000)+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/app.js"]
