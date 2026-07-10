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
const { normalizeProvider, validateProviderConfig } = require('./providers');

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

function loopbackHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127(?:\.\d{1,3}){3}$/.test(host);
}

function normalizeGatewayUrl(value, opts = {}) {
  const label = opts.label || 'gateway service URL';
  let url;
  try { url = new URL(String(value || '')); } catch { throw new Error(`${label} is invalid`); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`${label} must use http or https`);
  if (url.username || url.password) throw new Error(`${label} must not contain credentials`);
  if (url.hash) throw new Error(`${label} must not contain a fragment`);
  if (opts.allowQuery !== true && url.search) throw new Error(`${label} must not contain a query`);
  const insecureDev = opts.allowInsecureDev === true && opts.production !== true;
  if (url.protocol === 'http:' && !loopbackHost(url.hostname) && !insecureDev) {
    throw new Error(`${label} must use https for a remote host`);
  }
  return url.toString().replace(/\/+$/, '');
}

function config(env = process.env) {
  const prev = process.env;
  process.env = env;
  try {
    const production = String(env.NODE_ENV || '').toLowerCase() === 'production';
    const allowInsecureDev = envValue('GATEWAY_ALLOW_INSECURE_HTTP', 'REDACTWALL_GATEWAY_ALLOW_INSECURE_HTTP') === 'true';
    const controlPlaneUrl = normalizeGatewayUrl(
      envValue('GATEWAY_CONTROL_PLANE_URL', 'REDACTWALL_CONTROL_PLANE_URL', 'PROMPTWALL_CONTROL_PLANE_URL') || 'http://127.0.0.1:4000',
      { label: 'gateway control-plane URL', allowInsecureDev, production }
    );
    const provider = normalizeProvider(
      envValue('GATEWAY_PROVIDER', 'REDACTWALL_GATEWAY_PROVIDER', 'PROMPTWALL_GATEWAY_PROVIDER')
    );
    const configuredUpstream = envValue('GATEWAY_UPSTREAM_URL', 'REDACTWALL_GATEWAY_UPSTREAM_URL', 'PROMPTWALL_GATEWAY_UPSTREAM_URL');
    const upstreamBaseUrl = configuredUpstream
      ? normalizeGatewayUrl(configuredUpstream, { label: 'gateway upstream URL', allowInsecureDev, production })
      : undefined;
    validateProviderConfig(provider, upstreamBaseUrl, { production });
    return {
      port: intValue(['GATEWAY_PORT', 'REDACTWALL_GATEWAY_PORT', 'PROMPTWALL_GATEWAY_PORT'], 4100, 1, 65535),
      // Control plane the gateway calls to gate/scan. Defaults to a local plane.
      controlPlaneUrl,
      ingestKey: envValue('INGEST_API_KEY', 'REDACTWALL_INGEST_API_KEY', 'PROMPTWALL_INGEST_API_KEY', 'GATEWAY_INGEST_KEY'),
      // Upstream provider: which adapter + its base URL + credentials.
      provider,
      upstreamBaseUrl,
      allowInsecureHttp: allowInsecureDev && !production,
      upstreamApiKey: envValue('GATEWAY_UPSTREAM_API_KEY', 'REDACTWALL_GATEWAY_UPSTREAM_API_KEY', 'PROMPTWALL_GATEWAY_UPSTREAM_API_KEY'),
      // Where agent tokens live (hashed). Own file so the gateway is self-contained.
      agentTokensPath: envValue('GATEWAY_AGENT_TOKENS_PATH', 'REDACTWALL_GATEWAY_AGENT_TOKENS_PATH', 'PROMPTWALL_GATEWAY_AGENT_TOKENS_PATH'),
      requestTimeoutMs: intValue(['GATEWAY_TIMEOUT_MS', 'REDACTWALL_GATEWAY_TIMEOUT_MS', 'PROMPTWALL_GATEWAY_TIMEOUT_MS'], 60000, 500, 600000),
      requestBodyTimeoutMs: intValue(['GATEWAY_REQUEST_BODY_TIMEOUT_MS', 'REDACTWALL_GATEWAY_REQUEST_BODY_TIMEOUT_MS', 'PROMPTWALL_GATEWAY_REQUEST_BODY_TIMEOUT_MS'], 15000, 100, 120000),
      maxBodyBytes: intValue(['GATEWAY_MAX_BODY_BYTES', 'REDACTWALL_GATEWAY_MAX_BODY_BYTES', 'PROMPTWALL_GATEWAY_MAX_BODY_BYTES'], 2 * 1024 * 1024, 1024, 32 * 1024 * 1024),
      maxUpstreamResponseBytes: intValue(['GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES', 'REDACTWALL_GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES'], 4 * 1024 * 1024, 1024, 32 * 1024 * 1024),
      maxControlPlaneResponseBytes: intValue(['GATEWAY_MAX_CONTROL_PLANE_RESPONSE_BYTES', 'REDACTWALL_GATEWAY_MAX_CONTROL_PLANE_RESPONSE_BYTES'], 512 * 1024, 1024, 4 * 1024 * 1024),
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

module.exports = { config, loopbackHost, normalizeGatewayUrl };
