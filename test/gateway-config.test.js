'use strict';
/**
 * gateway/config.js resolves settings from env with brand-alias fallbacks.
 * The RedactWall rebrand keeps the unprefixed GATEWAY_* names canonical and adds
 * a REDACTWALL_GATEWAY_* alias while still honoring the legacy PROMPTWALL_GATEWAY_*
 * names so existing gateway deployments keep working on upgrade.
 */
const test = require('node:test');
const assert = require('node:assert');
const { config } = require('../gateway/config');

test('canonical unprefixed GATEWAY_* names are read', () => {
  const c = config({
    GATEWAY_PORT: '4111',
    GATEWAY_CONTROL_PLANE_URL: 'https://plane.example/',
    GATEWAY_PROVIDER: 'anthropic',
    GATEWAY_UPSTREAM_URL: 'https://upstream.example',
    GATEWAY_REQUEST_BODY_TIMEOUT_MS: '4321',
  });
  assert.strictEqual(c.port, 4111);
  assert.strictEqual(c.controlPlaneUrl, 'https://plane.example');
  assert.strictEqual(c.provider, 'anthropic');
  assert.strictEqual(c.upstreamBaseUrl, 'https://upstream.example');
  assert.strictEqual(c.requestBodyTimeoutMs, 4321);
});

test('new REDACTWALL_GATEWAY_* aliases are honored', () => {
  const c = config({
    REDACTWALL_GATEWAY_PORT: '4222',
    REDACTWALL_CONTROL_PLANE_URL: 'https://rw-plane.example',
    REDACTWALL_GATEWAY_PROVIDER: 'anthropic',
    REDACTWALL_GATEWAY_REQUEST_BODY_TIMEOUT_MS: '5432',
    REDACTWALL_INGEST_API_KEY: 'rw-ingest',
  });
  assert.strictEqual(c.port, 4222);
  assert.strictEqual(c.controlPlaneUrl, 'https://rw-plane.example');
  assert.strictEqual(c.provider, 'anthropic');
  assert.strictEqual(c.requestBodyTimeoutMs, 5432);
  assert.strictEqual(c.ingestKey, 'rw-ingest');
});

test('legacy PROMPTWALL_GATEWAY_* aliases still work after the rebrand', () => {
  const c = config({
    PROMPTWALL_GATEWAY_PORT: '9999',
    PROMPTWALL_CONTROL_PLANE_URL: 'https://legacy-plane.example',
    PROMPTWALL_GATEWAY_PROVIDER: 'anthropic',
    PROMPTWALL_GATEWAY_UPSTREAM_URL: 'https://legacy-upstream.example',
    PROMPTWALL_INGEST_API_KEY: 'legacy-ingest',
  });
  assert.strictEqual(c.port, 9999);
  assert.strictEqual(c.controlPlaneUrl, 'https://legacy-plane.example');
  assert.strictEqual(c.provider, 'anthropic');
  assert.strictEqual(c.upstreamBaseUrl, 'https://legacy-upstream.example');
  assert.strictEqual(c.ingestKey, 'legacy-ingest');
});

test('canonical GATEWAY_* wins over a legacy alias when both are set', () => {
  const c = config({
    GATEWAY_PORT: '4100',
    PROMPTWALL_GATEWAY_PORT: '9999',
  });
  assert.strictEqual(c.port, 4100);
});

test('gateway service URLs require authenticated remote transport', () => {
  assert.throws(() => config({ GATEWAY_CONTROL_PLANE_URL: 'http://plane.example.test' }), /must use https for a remote host/);
  assert.throws(() => config({ GATEWAY_UPSTREAM_URL: 'https://user:pass@provider.example.test' }), /must not contain credentials/);
  assert.throws(() => config({ GATEWAY_UPSTREAM_URL: 'https://provider.example.test/#secret' }), /must not contain a fragment/);
  assert.strictEqual(config({ GATEWAY_CONTROL_PLANE_URL: 'http://127.0.0.1:4000' }).controlPlaneUrl, 'http://127.0.0.1:4000');
  assert.strictEqual(config({
    GATEWAY_UPSTREAM_URL: 'http://provider.example.test',
    GATEWAY_ALLOW_INSECURE_HTTP: 'true',
    NODE_ENV: 'development',
  }).upstreamBaseUrl, 'http://provider.example.test');
  assert.throws(() => config({
    GATEWAY_UPSTREAM_URL: 'http://provider.example.test',
    GATEWAY_ALLOW_INSECURE_HTTP: 'true',
    NODE_ENV: 'production',
  }), /must use https for a remote host/);
});

test('gateway provider selection is strict and rejects typos', () => {
  assert.throws(
    () => config({ GATEWAY_PROVIDER: 'opneai' }),
    /gateway provider must be one of/i
  );
  assert.throws(
    () => config({ GATEWAY_PROVIDER: 'gemini' }),
    /gateway provider must be one of/i
  );
  assert.strictEqual(config({ GATEWAY_PROVIDER: ' Anthropic ' }).provider, 'anthropic');
});

test('mock provider is available for tests but rejected in production', () => {
  assert.strictEqual(config({ NODE_ENV: 'test', GATEWAY_PROVIDER: 'mock' }).provider, 'mock');
  assert.throws(
    () => config({ NODE_ENV: 'production', GATEWAY_PROVIDER: 'mock' }),
    /mock gateway provider is not allowed in production/i
  );
});

test('custom OpenAI-compatible providers require an explicit upstream URL', () => {
  assert.throws(
    () => config({ GATEWAY_PROVIDER: 'internal-http' }),
    /internal-http.*requires GATEWAY_UPSTREAM_URL/i
  );
  const c = config({
    GATEWAY_PROVIDER: 'internal-http',
    GATEWAY_UPSTREAM_URL: 'https://provider.example.test',
  });
  assert.strictEqual(c.provider, 'internal-http');
  assert.strictEqual(c.upstreamBaseUrl, 'https://provider.example.test');
  assert.throws(
    () => config({ GATEWAY_PROVIDER: 'azure-openai', GATEWAY_UPSTREAM_URL: 'https://azure.example.test' }),
    /gateway provider must be one of/i
  );
});
