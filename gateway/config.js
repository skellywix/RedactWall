'use strict';
/**
 * AI Gateway configuration.
 *
 * The gateway is a standalone reverse-proxy that sits between an application (or
 * agent) and an upstream LLM provider. It calls the RedactWall control plane to
 * gate every prompt and scan every response, and fails closed when the control
 * plane is unreachable. Config comes from env (with PROMPTWALL_/SENTINEL_ legacy
 * aliasing to REDACTWALL_) plus gateway/config.example.json for documentation.
 */
require('../server/env').loadEnv();

function envValue(...names) {
  for (const name of names) {
    if (process.env[name] !== undefined && process.env[name] !== '') return process.env[name];
  }
  return undefined;
}

function intValue(names, fallback, min, max) {
  const raw = envValue(...names);
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function config(env = process.env) {
  const prev = process.env;
  process.env = env;
  try {
    return {
      port: intValue(['GATEWAY_PORT', 'REDACTWALL_GATEWAY_PORT', 'PROMPTWALL_GATEWAY_PORT'], 4100, 1, 65535),
      // Control plane the gateway calls to gate/scan. Defaults to a local plane.
      controlPlaneUrl: (envValue('GATEWAY_CONTROL_PLANE_URL', 'REDACTWALL_CONTROL_PLANE_URL', 'PROMPTWALL_CONTROL_PLANE_URL') || 'http://127.0.0.1:4000').replace(/\/+$/, ''),
      ingestKey: envValue('INGEST_API_KEY', 'REDACTWALL_INGEST_API_KEY', 'PROMPTWALL_INGEST_API_KEY', 'GATEWAY_INGEST_KEY'),
      // Upstream provider: which adapter + its base URL + credentials.
      provider: (envValue('GATEWAY_PROVIDER', 'REDACTWALL_GATEWAY_PROVIDER', 'PROMPTWALL_GATEWAY_PROVIDER') || 'openai').toLowerCase(),
      upstreamBaseUrl: envValue('GATEWAY_UPSTREAM_URL', 'REDACTWALL_GATEWAY_UPSTREAM_URL', 'PROMPTWALL_GATEWAY_UPSTREAM_URL'),
      upstreamApiKey: envValue('GATEWAY_UPSTREAM_API_KEY', 'REDACTWALL_GATEWAY_UPSTREAM_API_KEY', 'PROMPTWALL_GATEWAY_UPSTREAM_API_KEY'),
      // Where agent tokens live (hashed). Own file so the gateway is self-contained.
      agentTokensPath: envValue('GATEWAY_AGENT_TOKENS_PATH', 'REDACTWALL_GATEWAY_AGENT_TOKENS_PATH', 'PROMPTWALL_GATEWAY_AGENT_TOKENS_PATH'),
      requestTimeoutMs: intValue(['GATEWAY_TIMEOUT_MS', 'REDACTWALL_GATEWAY_TIMEOUT_MS', 'PROMPTWALL_GATEWAY_TIMEOUT_MS'], 60000, 500, 600000),
      maxBodyBytes: intValue(['GATEWAY_MAX_BODY_BYTES', 'REDACTWALL_GATEWAY_MAX_BODY_BYTES', 'PROMPTWALL_GATEWAY_MAX_BODY_BYTES'], 2 * 1024 * 1024, 1024, 32 * 1024 * 1024),
      rateLimitPerMin: intValue(['GATEWAY_RATE_LIMIT_PER_MIN', 'REDACTWALL_GATEWAY_RATE_LIMIT_PER_MIN', 'PROMPTWALL_GATEWAY_RATE_LIMIT_PER_MIN'], 120, 1, 100000),
      // When true, an unauthenticated request (no agent token) is rejected. When
      // false, requests are allowed but attributed to 'unattributed@gateway'.
      requireAgentToken: envValue('GATEWAY_REQUIRE_AGENT_TOKEN', 'REDACTWALL_GATEWAY_REQUIRE_AGENT_TOKEN', 'PROMPTWALL_GATEWAY_REQUIRE_AGENT_TOKEN') !== 'false',
      streamScanWindow: intValue(['GATEWAY_STREAM_WINDOW', 'REDACTWALL_GATEWAY_STREAM_WINDOW', 'PROMPTWALL_GATEWAY_STREAM_WINDOW'], 512, 64, 8192),
    };
  } finally {
    process.env = prev;
  }
}

module.exports = { config };
