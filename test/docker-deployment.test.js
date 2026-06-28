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
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const mechaScript = fs.readFileSync(path.join(root, 'scripts', 'mecha-docker.ps1'), 'utf8');
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
    'SENTINEL_POLICY_PATH',
    'PROMPTWALL_POLICY_PATH',
    'SENTINEL_CUSTOM_DETECTORS_PATH',
    'PROMPTWALL_CUSTOM_DETECTORS_PATH',
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
  assert.strictEqual(env.get('SENTINEL_POLICY_PATH'), '${SENTINEL_POLICY_PATH:-/data/policy.json}');
  assert.strictEqual(env.get('SENTINEL_CUSTOM_DETECTORS_PATH'), '${SENTINEL_CUSTOM_DETECTORS_PATH:-/data/custom-detectors.json}');
  assert.match(compose, /-\s*promptwall-data:\/data/);
  assert.match(compose, /^volumes:\r?\n\s+promptwall-data:/m);
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
  assert.match(dockerfile, /SENTINEL_POLICY_PATH=\/data\/policy\.json/);
  assert.match(dockerfile, /NPM_CONFIG_CACHE=\/tmp\/\.npm/);
  for (const pattern of [/^test$/m, /^e2e$/m, /^docs$/m, /^PLANS$/m, /^dist$/m, /^data$/m]) {
    assert.match(dockerignore, pattern);
  }
});

test('deployment docs describe compose readiness and persistent state', () => {
  assert.match(deployment, /Docker Compose/);
  assert.match(deployment, /SENTINEL_DB_PATH` to\s+`\/data\/sentinel\.db`/);
  assert.match(deployment, /SENTINEL_POLICY_PATH` to\s+`\/data\/policy\.json`/);
  assert.match(deployment, /checks `\/readyz` for container\s+health/);
  assert.match(deployment, /production preflight readiness is blocked/);
  assert.match(deployment, /read-only root filesystem/);
});

test('MECHA standing Docker test stack is repeatable and preserves its volume', () => {
  assert.match(gitignore, /^\.env\*\.local$/m);
  assert.match(mechaScript, /promptwall-mecha-20260628/);
  assert.match(mechaScript, /\.env\.mecha\.local/);
  assert.match(mechaScript, /HostPort = .*4027/);
  assert.match(mechaScript, /New-HexSecret/);
  assert.match(mechaScript, /New-Base32Secret/);
  assert.match(mechaScript, /docker compose --env-file \$EnvFile -p \$ProjectName/);
  assert.match(mechaScript, /Invoke-Compose @\('stop'\)/);
  assert.doesNotMatch(mechaScript, /down\s+-v/);
  assert.doesNotMatch(mechaScript, /MockAdminPassword2026/);
  assert.doesNotMatch(mechaScript, /ps_ingest_mock_mecha_20260628_local_32chars/);
  assert.match(deployment, /MECHA Standing Docker Test Environment/);
  assert.match(deployment, /promptwall-mecha-20260628_promptwall-data/);
  assert.strictEqual(packageJson.scripts['docker:mecha'], 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/mecha-docker.ps1 start');
  assert.strictEqual(packageJson.scripts['docker:mecha:smoke'], 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/mecha-docker.ps1 smoke');
});
