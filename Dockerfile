# syntax=docker/dockerfile:1.7
# RedactWall production image. Keep the Node runtime source pristine, build
# production dependencies in isolation, and let the artifact builder publish
# only the reviewed positive customer inventory.
FROM node:22-bookworm-slim AS node-runtime-source

FROM node:22-bookworm-slim AS production-dependencies
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
# Omit optional deps: the server never runs OCR (images return ocr_required),
# so the endpoint-only WASM OCR engine (tesseract.js) stays out of this image.
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --omit=optional

FROM node:22-bookworm-slim AS artifact-builder
WORKDIR /app
COPY console/package.json console/package-lock.json ./console/
RUN --mount=type=cache,target=/root/.npm npm ci --prefix console
# Build the console before the vendor/server source enters this stage. Vite can
# see only its reviewed console tree and the receipt-producing wrapper, so it
# cannot import vendor persistence, signing, lifecycle, or Owner route code.
COPY scripts/build-customer-console.js ./scripts/build-customer-console.js
COPY console/ ./console/
RUN node scripts/build-customer-console.js
COPY . .
RUN node scripts/validate-customer-dockerfile.js Dockerfile
# Build the customer image from one reviewed positive inventory. The staging
# gate verifies the exact console build receipt and fails when an authored file
# is missing, a local JS dependency escapes the inventory, or private key
# material reaches the customer artifact.
RUN node scripts/stage-customer-runtime.js --out /tmp/customer-runtime

# PostgreSQL's supported client image supplies pg_dump/pg_restore 17 so the
# documented backup and drill commands work inside the shipped container too.
# Node is copied from the pristine matching Debian source stage; the database
# server entrypoint is never used.
FROM postgres:17-bookworm AS runtime
ARG REDACTWALL_LICENSE_PUBLIC_KEY_B64=""
RUN groupadd --gid 1000 node \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin node
COPY --from=node-runtime-source /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime-source /usr/local/lib/node_modules/npm/ /usr/local/lib/node_modules/npm/
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
RUN node --version && npm --version && pg_dump --version && pg_restore --version
ENV NODE_ENV=production \
    PORT=4000 \
    REDACTWALL_DB_PATH=/data/redactwall.db \
    REDACTWALL_DATA_DIR=/data \
    REDACTWALL_POLICY_PATH=/data/policy.json \
    REDACTWALL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json \
    REDACTWALL_LICENSE_PUBLIC_KEY_B64=${REDACTWALL_LICENSE_PUBLIC_KEY_B64} \
    NPM_CONFIG_CACHE=/tmp/.npm \
    NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /app
COPY --from=production-dependencies --chown=node:node /app/node_modules ./node_modules
# This is the only authored/runtime source copied into the final stage. The
# console bundle was generated before staging and is included by its dedicated
# generated-tree rule in the manifest.
COPY --from=artifact-builder --chown=node:node /tmp/customer-runtime/ ./
RUN rm -f /etc/ssl/private/ssl-cert-snakeoil.key \
      /etc/ssl/certs/ssl-cert-snakeoil.pem \
      /usr/local/lib/node_modules/npm/.npmrc
RUN if [ -n "$REDACTWALL_LICENSE_PUBLIC_KEY_B64" ]; then \
      node scripts/check-license-trust-anchor.js; \
    fi
# Persistent, local-disk runtime state. Keep /data mounted outside the image.
RUN mkdir -p /data /gateway-data /license /app/data /tmp/redactwall \
    && chown -R node:node /data /gateway-data /license /app /tmp/redactwall \
    && chmod 700 /data /gateway-data /license /tmp/redactwall
# Scan the complete durable filesystem after the final COPY and mutation. The
# scanner skips only kernel/runtime pseudo-mounts and admits one exact,
# package-owned GnuTLS compiled test-vector identity.
RUN node scripts/verify-customer-image-content.js --root /
USER node
EXPOSE 4000
VOLUME ["/data", "/gateway-data"]
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||4000)+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["sh", "scripts/docker-entrypoint.sh"]
CMD ["node", "server/app.js"]
