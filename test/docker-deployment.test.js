'use strict';
/** Docker Compose config should preserve production secrets and readiness. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.yml'), 'utf8');
const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');
const deployment = fs.readFileSync(path.join(root, 'docs', 'DEPLOYMENT.md'), 'utf8');

function composeEnvironment() {
  const match = compose.match(/^\s+environment:\r?\n(?<body>[\s\S]*?)^\s+ports:/m);
  assert.ok(match, 'compose service environment block is present');
  const out = new Map();
  for (const raw of match.groups.body.split(/\r?\n/)) {
    const line = raw.trim();
    const item = line.match(/^([A-Z0-9_]+):\s*(.*)$/);
    if (item) out.set(item[1], item[2]);
  }
  return out;
}

test('docker compose passes production setup secrets into the container', () => {
  const env = composeEnvironment();
  for (const key of [
    'SENTINEL_SAAS_MODE',
    'PROMPTWALL_SAAS_MODE',
    'SENTINEL_TENANT_ID',
    'PROMPTWALL_TENANT_ID',
    'SENTINEL_SEAT_LIMIT',
    'PROMPTWALL_SEAT_LIMIT',
    'SENTINEL_REQUIRE_TENANT_CONTEXT',
    'PROMPTWALL_REQUIRE_TENANT_CONTEXT',
    'SENTINEL_REQUIRE_USER_IDENTITY',
    'PROMPTWALL_REQUIRE_USER_IDENTITY',
    'ADMIN_USER',
    'ADMIN_PASSWORD',
    'ADMIN_TOTP_SECRET',
    'AUDITOR_USER',
    'AUDITOR_PASSWORD',
    'SENTINEL_SECRET',
    'PROMPTWALL_SECRET',
    'SENTINEL_DATA_KEY',
    'PROMPTWALL_DATA_KEY',
    'INGEST_API_KEY',
    'PROMPTWALL_INGEST_API_KEY',
    'SCIM_BEARER_TOKEN',
    'PROMPTWALL_SCIM_BEARER_TOKEN',
    'SENTINEL_REQUEST_TIMEOUT_MS',
    'PROMPTWALL_REQUEST_TIMEOUT_MS',
  ]) {
    assert.ok(env.has(key), key);
    assert.match(env.get(key), new RegExp(`\\$\\{${key}`), key);
  }
  assert.doesNotMatch(env.get('INGEST_API_KEY'), /dev-ingest-key/);
  assert.doesNotMatch(env.get('SENTINEL_SAAS_MODE'), /false/);
  assert.doesNotMatch(env.get('SENTINEL_REQUEST_TIMEOUT_MS'), /10000/);
});

test('docker compose keeps sqlite state on a named local volume', () => {
  const env = composeEnvironment();
  assert.strictEqual(env.get('SENTINEL_DB_PATH'), '/data/sentinel.db');
  assert.match(compose, /-\s*promptwall-data:\/data/);
  assert.match(compose, /^volumes:\r?\n\s+promptwall-data:/m);
  assert.doesNotMatch(compose, /\.\.?:\/data/);
});

test('docker readiness uses preflight-aware readyz while image keeps process healthz', () => {
  assert.match(compose, /healthcheck:/);
  assert.match(compose, /\/readyz/);
  assert.match(compose, /process\.exit\(r\.ok\?0:1\)/);
  assert.match(dockerfile, /HEALTHCHECK[\s\S]+\/healthz/);
});

test('deployment docs describe compose readiness and persistent state', () => {
  assert.match(deployment, /Docker Compose/);
  assert.match(deployment, /SENTINEL_DB_PATH` to `\/data\/sentinel\.db`/);
  assert.match(deployment, /checks `\/readyz` for container\s+health/);
  assert.match(deployment, /production preflight readiness is blocked/);
});
