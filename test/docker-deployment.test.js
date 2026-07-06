'use strict';
/** Docker Compose config should preserve production secrets and readiness. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.yml'), 'utf8');
const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');
const dockerignore = fs.readFileSync(path.join(root, '.dockerignore'), 'utf8');
const gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
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
    'REDACTWALL_SAAS_MODE',
    'REDACTWALL_TENANT_ID',
    'REDACTWALL_SEAT_LIMIT',
    'REDACTWALL_REQUIRE_TENANT_CONTEXT',
    'REDACTWALL_REQUIRE_USER_IDENTITY',
    'ADMIN_USER',
    'ADMIN_PASSWORD',
    'ADMIN_TOTP_SECRET',
    'AUDITOR_USER',
    'AUDITOR_PASSWORD',
    'OPERATOR_USER',
    'OPERATOR_PASSWORD',
    'REDACTWALL_SECRET',
    'REDACTWALL_DATA_KEY',
    'REDACTWALL_DATA_KEY_PREVIOUS',
    'REDACTWALL_DB_DRIVER',
    'REDACTWALL_DATABASE_URL',
    'OIDC_ISSUER',
    'OIDC_CLIENT_ID',
    'OIDC_CLIENT_SECRET',
    'OIDC_REDIRECT_URI',
    'OIDC_SCOPE',
    'OIDC_AUTHORIZATION_ENDPOINT',
    'OIDC_TOKEN_ENDPOINT',
    'OIDC_JWKS_URI',
    'INGEST_API_KEY',
    'REDACTWALL_INGEST_API_KEY',
    'REDACTWALL_POLICY_PATH',
    'REDACTWALL_CUSTOM_DETECTORS_PATH',
    'SCIM_BEARER_TOKEN',
    'REDACTWALL_SCIM_BEARER_TOKEN',
    'REDACTWALL_REQUEST_TIMEOUT_MS',
  ]) {
    assert.ok(env.has(key), key);
    assert.match(env.get(key), new RegExp(`\\$\\{${key}`), key);
  }
  assert.doesNotMatch(env.get('INGEST_API_KEY'), /dev-ingest-key/);
  assert.doesNotMatch(env.get('REDACTWALL_SAAS_MODE'), /false/);
  assert.doesNotMatch(env.get('REDACTWALL_REQUEST_TIMEOUT_MS'), /10000/);
});

test('docker compose keeps sqlite state on a named local volume', () => {
  const env = composeEnvironment();
  assert.strictEqual(env.get('REDACTWALL_DB_PATH'), '/data/redactwall.db');
  assert.strictEqual(env.get('REDACTWALL_POLICY_PATH'), '${REDACTWALL_POLICY_PATH:-/data/policy.json}');
  assert.strictEqual(env.get('REDACTWALL_CUSTOM_DETECTORS_PATH'), '${REDACTWALL_CUSTOM_DETECTORS_PATH:-/data/custom-detectors.json}');
  assert.match(compose, /-\s*redactwall-data:\/data/);
  assert.match(compose, /^volumes:\r?\n\s+redactwall-data:/m);
  assert.doesNotMatch(compose, /\.\.?:\/data/);
});

test('docker readiness uses preflight-aware readyz in compose and image', () => {
  assert.match(compose, /healthcheck:/);
  assert.match(compose, /\/readyz/);
  assert.match(compose, /process\.exit\(r\.ok\?0:1\)/);
  assert.match(dockerfile, /HEALTHCHECK[\s\S]+\/readyz/);
});

test('docker runtime is hardened for customer-silo operation', () => {
  assert.match(compose, /init:\s+true/);
  assert.match(compose, /read_only:\s+true/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /cap_drop:\r?\n\s+- ALL/);
  assert.match(compose, /\/tmp:rw,noexec,nosuid,size=64m/);
  assert.match(compose, /stop_grace_period:\s+30s/);
});

test('docker image copies runtime files instead of the whole builder tree', () => {
  assert.doesNotMatch(dockerfile, /COPY --from=builder \/app \/app/);
  assert.match(dockerfile, /COPY --from=builder --chown=node:node \/app\/node_modules \.\/node_modules/);
  assert.match(dockerfile, /REDACTWALL_POLICY_PATH=\/data\/policy\.json/);
  assert.match(dockerfile, /NPM_CONFIG_CACHE=\/tmp\/\.npm/);
  for (const pattern of [/^test$/m, /^e2e$/m, /^docs$/m, /^PLANS$/m, /^dist$/m, /^data$/m]) {
    assert.match(dockerignore, pattern);
  }
});

test('runtime image ships the gateway source the gateway profile runs', () => {
  // The compose gateway profile runs `node gateway/server.js` from this image,
  // so the runtime stage must COPY gateway/ or the profile crash-loops.
  assert.match(compose, /command:\s*\["node",\s*"gateway\/server\.js"\]/);
  assert.match(dockerfile, /COPY --chown=node:node gateway \.\/gateway/);
  // gateway/ must not be excluded from the build context either.
  assert.doesNotMatch(dockerignore, /^gateway$/m);
});

test('deployment docs describe compose readiness and persistent state', () => {
  assert.match(deployment, /Docker Compose/);
  assert.match(deployment, /REDACTWALL_DB_PATH` to\s+`\/data\/redactwall\.db`/);
  assert.match(deployment, /REDACTWALL_POLICY_PATH` to\s+`\/data\/policy\.json`/);
  assert.match(deployment, /checks `\/readyz` for container\s+health/);
  assert.match(deployment, /production preflight readiness is blocked/);
  assert.match(deployment, /read-only root filesystem/);
});

test('local env files stay out of git', () => {
  assert.match(gitignore, /^\.env\*\.local$/m);
});
