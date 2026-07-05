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
  });
  assert.strictEqual(c.port, 4111);
  assert.strictEqual(c.controlPlaneUrl, 'https://plane.example');
  assert.strictEqual(c.provider, 'anthropic');
  assert.strictEqual(c.upstreamBaseUrl, 'https://upstream.example');
});

test('new REDACTWALL_GATEWAY_* aliases are honored', () => {
  const c = config({
    REDACTWALL_GATEWAY_PORT: '4222',
    REDACTWALL_CONTROL_PLANE_URL: 'https://rw-plane.example',
    REDACTWALL_GATEWAY_PROVIDER: 'anthropic',
    REDACTWALL_INGEST_API_KEY: 'rw-ingest',
  });
  assert.strictEqual(c.port, 4222);
  assert.strictEqual(c.controlPlaneUrl, 'https://rw-plane.example');
  assert.strictEqual(c.provider, 'anthropic');
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
