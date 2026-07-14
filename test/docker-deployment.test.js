'use strict';
/** Docker Compose config should preserve production secrets and readiness. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { validateCustomerDockerfile } = require('../scripts/validate-customer-dockerfile');

const root = path.join(__dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.yml'), 'utf8');
const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');
const entrypointPath = path.join(root, 'scripts', 'docker-entrypoint.sh');
const seedScriptPath = path.join(root, 'scripts', 'seed-runtime-policy.js');
const entrypoint = fs.readFileSync(entrypointPath, 'utf8');
const seedScript = fs.readFileSync(seedScriptPath, 'utf8');
const dockerignore = fs.readFileSync(path.join(root, '.dockerignore'), 'utf8');
const gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
const deployment = fs.readFileSync(path.join(root, 'docs', 'deployment', 'DEPLOYMENT.md'), 'utf8');

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
    'REDACTWALL_LICENSE_CUSTOMER_ID',
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
    'REDACTWALL_PG_MAINTENANCE_DATABASE',
    'REDACTWALL_AUDIT_DIR',
    'REDACTWALL_AUDIT_KEY',
    'REDACTWALL_LICENSE_PATH',
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
  assert.strictEqual(env.get('REDACTWALL_PG_MAINTENANCE_DATABASE'), '${REDACTWALL_PG_MAINTENANCE_DATABASE:-}');
  assert.strictEqual(env.get('REDACTWALL_AUDIT_DIR'), '${REDACTWALL_AUDIT_DIR:-}');
  assert.strictEqual(env.get('REDACTWALL_LICENSE_PATH'), '${REDACTWALL_LICENSE_PATH:-/data/redactwall.lic}');
  assert.match(compose, /-\s*redactwall-data:\/data/);
  assert.match(compose, /^volumes:\r?\n\s+redactwall-data:/m);
  assert.doesNotMatch(compose, /\.\.?:\/data/);
});

test('existing Compose SQLite sidecars survive a second boot with an empty audit override', {
  timeout: 300_000,
}, (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-compose-upgrade-'));
  const dbPath = path.join(dataDir, 'redactwall.db');
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    REDACTWALL_ENV_PATH: path.join(dataDir, 'missing.env'),
    REDACTWALL_DB_DRIVER: 'sqlite',
    REDACTWALL_DB_PATH: dbPath,
    REDACTWALL_DATA_DIR: dataDir,
    REDACTWALL_SECRET: 'compose-upgrade-secret-stable',
    REDACTWALL_AUDIT_KEY: 'compose-upgrade-audit-key-stable',
    REDACTWALL_AUDIT_STATE_PATH: '',
    REDACTWALL_AUDIT_CHECKPOINT_PATH: '',
    REDACTWALL_AUDIT_PENDING_PATH: '',
  };
  delete env.REDACTWALL_AUDIT_DIR;
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));

  const run = (seed, auditDir) => {
    const childEnv = { ...env };
    if (auditDir !== undefined) childEnv.REDACTWALL_AUDIT_DIR = auditDir;
    const script = `
      const db = require('./server/db');
      if (${JSON.stringify(seed)}) db.appendAudit({ action: 'COMPOSE_UPGRADE_BASELINE', actor: 'docker-test', detail: 'sanitized' });
      const verification = db.verifyAuditChain();
      console.log(JSON.stringify({ verification, paths: db._auditAnchorPaths }));
      db._db.close();
    `;
    const result = spawnSync(process.execPath, ['-e', script], {
      cwd: root,
      env: childEnv,
      encoding: 'utf8',
      timeout: 120_000,
      windowsHide: true,
    });
    assert.strictEqual(result.status, 0, result.stderr || result.stdout);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  };

  const first = run(true, undefined);
  const second = run(false, '');
  const expectedAuditDir = path.resolve(`${dbPath}.audit-integrity`);
  assert.strictEqual(first.verification.ok, true);
  assert.strictEqual(second.verification.ok, true);
  assert.strictEqual(path.dirname(first.paths.statePath), expectedAuditDir);
  assert.strictEqual(path.dirname(second.paths.statePath), expectedAuditDir);
  assert.strictEqual(fs.existsSync(path.join(dataDir, 'audit-integrity')), false);
});

test('gateway tokens use a separate private volume and never mount control-plane evidence', () => {
  const gatewaySection = compose.match(/\n  gateway:[\s\S]*?\nvolumes:/)?.[0] || '';
  assert.match(gatewaySection, /GATEWAY_AGENT_TOKENS_PATH:\s+\/gateway-data\/gateway-agent-tokens\.json/);
  assert.match(gatewaySection, /REDACTWALL_DATA_DIR:\s+\/gateway-data/);
  assert.match(gatewaySection, /REDACTWALL_SKIP_POLICY_SEED:\s+"1"/);
  assert.match(gatewaySection, /-\s*redactwall-gateway-data:\/gateway-data/);
  assert.doesNotMatch(gatewaySection, /redactwall-data:\/data/);
  assert.match(compose, /^\s+redactwall-gateway-data:\s*$/m);
  assert.match(dockerfile, /mkdir -p \/data \/gateway-data/);
  assert.match(dockerfile, /VOLUME \["\/data", "\/gateway-data"\]/);
});

test('optional gateway container health requires authenticated control-plane readiness', () => {
  const gatewaySection = compose.match(/\n  gateway:[\s\S]*?\nvolumes:/)?.[0] || '';
  assert.match(gatewaySection, /fetch\('http:\/\/localhost:4100\/readyz'\)/);
  assert.doesNotMatch(gatewaySection, /fetch\('http:\/\/localhost:4100\/healthz'\)/);
});

test('docker readiness uses preflight-aware readyz in compose and image', () => {
  assert.match(compose, /healthcheck:/);
  assert.match(compose, /\/readyz/);
  assert.match(compose, /process\.exit\(r\.ok\?0:1\)/);
  assert.match(dockerfile, /HEALTHCHECK[\s\S]+\/readyz/);
});

test('docker runtime is hardened for customer-silo operation', () => {
  assert.match(compose, /redactwall:\r?\n[\s\S]*?hostname:\s+redactwall/);
  assert.match(compose, /redactwall:[\s\S]*?REDACTWALL_LOCK_HOSTNAME:\s+redactwall/);
  assert.match(compose, /init:\s+true/);
  assert.match(compose, /read_only:\s+true/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /cap_drop:\r?\n\s+- ALL/);
  assert.match(compose, /\/tmp:rw,noexec,nosuid,size=64m/);
  assert.match(compose, /stop_grace_period:\s+30s/);
});

test('read-only non-root runtime keeps the mutable license on the writable data volume', () => {
  const env = composeEnvironment();
  assert.strictEqual(env.get('REDACTWALL_LICENSE_PATH'), '${REDACTWALL_LICENSE_PATH:-/data/redactwall.lic}');
  assert.match(compose, /redactwall:[\s\S]*?read_only:\s+true/);
  assert.match(compose, /-\s*redactwall-data:\/data/);
  assert.match(dockerfile, /RUN mkdir -p \/data[\s\S]*?chown -R node:node \/data/);
  assert.match(dockerfile, /USER node/);
  assert.match(dockerfile, /VOLUME \["\/data", "\/gateway-data"\]/);
});

test('docker host ports default to loopback and the gateway uses loopback control-plane transport', () => {
  assert.match(compose, /"\$\{REDACTWALL_BIND_ADDRESS:-127\.0\.0\.1\}:\$\{PORT:-4000\}:4000"/);
  assert.match(compose, /"\$\{REDACTWALL_GATEWAY_BIND_ADDRESS:-127\.0\.0\.1\}:\$\{GATEWAY_PORT:-4100\}:4100"/);
  assert.match(compose, /gateway:[\s\S]*?network_mode:\s+"service:redactwall"/);
  assert.match(compose, /gateway:[\s\S]*?REDACTWALL_LOCK_HOSTNAME:\s+redactwall-gateway/);
  assert.match(compose, /GATEWAY_CONTROL_PLANE_URL:\s+\$\{GATEWAY_CONTROL_PLANE_URL:-http:\/\/127\.0\.0\.1:4000\}/);
  assert.doesNotMatch(compose, /GATEWAY_CONTROL_PLANE_URL:[^\n]*http:\/\/redactwall:4000/);
});

test('docker image copies runtime files instead of the whole builder tree', () => {
  validateCustomerDockerfile(dockerfile);
  const runtimeMarker = dockerfile.match(/^FROM postgres:17-bookworm AS runtime\s*$/m);
  assert.ok(runtimeMarker, 'runtime stage marker is present');
  const runtimeCopies = dockerfile.slice(runtimeMarker.index).match(/^COPY .+$/gm) || [];
  assert.doesNotMatch(dockerfile, /COPY --from=[^ ]+ \/usr\/local\/ \/usr\/local\//);
  assert.match(dockerfile, /COPY --from=production-dependencies --chown=node:node \/app\/node_modules \.\/node_modules/);
  assert.match(dockerfile, /node scripts\/stage-customer-runtime\.js --out \/tmp\/customer-runtime/);
  assert.match(dockerfile, /COPY --from=artifact-builder --chown=node:node \/tmp\/customer-runtime\/ \.\//);
  assert.deepStrictEqual(runtimeCopies, [
    'COPY --from=node-runtime-source /usr/local/bin/node /usr/local/bin/node',
    'COPY --from=node-runtime-source /usr/local/lib/node_modules/npm/ /usr/local/lib/node_modules/npm/',
    'COPY --from=production-dependencies --chown=node:node /app/node_modules ./node_modules',
    'COPY --from=artifact-builder --chown=node:node /tmp/customer-runtime/ ./',
  ]);
  assert.match(dockerfile, /REDACTWALL_POLICY_PATH=\/data\/policy\.json/);
  assert.match(dockerfile, /NPM_CONFIG_CACHE=\/tmp\/\.npm/);
  assert.match(dockerfile, /ENTRYPOINT \["sh", "scripts\/docker-entrypoint\.sh"\]/);
  assert.match(dockerfile, /node scripts\/verify-customer-image-content\.js/);
  assert.match(dockerfile, /verify-customer-image-content\.js --root \//);
  assert.ok(fs.existsSync(entrypointPath), 'runtime policy-seeding entrypoint exists');
  for (const pattern of [/^test$/m, /^e2e$/m, /^docs$/m, /^PLANS$/m, /^dist$/m, /^data$/m]) {
    assert.match(dockerignore, pattern);
  }
});

test('docker runtime ships PostgreSQL 17 backup and restore clients', () => {
  assert.match(dockerfile, /FROM postgres:17-bookworm AS runtime/);
  assert.match(dockerfile, /pg_dump --version && pg_restore --version/);
  assert.match(dockerfile, /COPY --from=node-runtime-source \/usr\/local\/bin\/node \/usr\/local\/bin\/node/);
  assert.match(dockerfile, /ln -s \.\.\/lib\/node_modules\/npm\/bin\/npm-cli\.js \/usr\/local\/bin\/npm/);
  assert.match(dockerfile, /node --version && npm --version/);
});

test('docker image supports a build-time production license trust anchor', () => {
  assert.match(dockerfile, /ARG REDACTWALL_LICENSE_PUBLIC_KEY_B64=""/);
  assert.match(dockerfile, /REDACTWALL_LICENSE_PUBLIC_KEY_B64=\$\{REDACTWALL_LICENSE_PUBLIC_KEY_B64\}/);
  assert.match(dockerfile, /node scripts\/check-license-trust-anchor\.js/);
  assert.ok(
    dockerfile.indexOf('/tmp/customer-runtime/ ./')
      < dockerfile.indexOf('node scripts/check-license-trust-anchor.js'),
    'the trust-anchor checker is copied before the build gate runs',
  );
});

test('docker entrypoint fail-loud seeds policy and custom detectors before startup', () => {
  assert.match(entrypoint, /set -eu/);
  assert.match(entrypoint, /node scripts\/seed-runtime-policy\.js/);
  assert.ok(entrypoint.indexOf('seed-runtime-policy.js') < entrypoint.indexOf('exec "$@"'));
  assert.doesNotMatch(entrypoint, /seed-runtime-policy\.js\s*\|\|\s*true/);
  assert.match(entrypoint, /REDACTWALL_SKIP_POLICY_SEED/);
  assert.match(seedScript, /REDACTWALL_POLICY_PATH/);
  assert.match(seedScript, /REDACTWALL_CUSTOM_DETECTORS_PATH/);
  assert.match(seedScript, /config[^\n]+custom-detectors\.json/);
  assert.match(seedScript, /0o600/);
});

test('runtime image ships the gateway source the gateway profile runs', () => {
  const runtimeManifest = JSON.parse(fs.readFileSync(
    path.join(root, 'packaging', 'customer-runtime-files.json'), 'utf8',
  ));
  // The compose gateway profile runs `node gateway/server.js` from this image,
  // so the positive runtime inventory must stage that exact entrypoint.
  assert.match(compose, /command:\s*\["node",\s*"gateway\/server\.js"\]/);
  assert.ok(runtimeManifest.authoredFiles.includes('gateway/server.js'));
  assert.match(dockerfile, /COPY --from=artifact-builder --chown=node:node \/tmp\/customer-runtime\/ \.\//);
  // gateway/ must not be excluded from the build context either.
  assert.doesNotMatch(dockerignore, /^gateway$/m);
});

test('deployment docs describe compose readiness and persistent state', () => {
  assert.match(deployment, /Docker Compose/);
  assert.match(deployment, /REDACTWALL_DB_PATH` to\s+`\/data\/redactwall\.db`/);
  assert.match(deployment, /REDACTWALL_POLICY_PATH` to\s+`\/data\/policy\.json`/);
  assert.match(deployment, /REDACTWALL_LICENSE_PATH=\/data\/redactwall\.lic/);
  assert.match(deployment, /checks `\/readyz` for container\s+health/);
  assert.match(deployment, /production preflight readiness is blocked/);
  assert.match(deployment, /read-only root filesystem/);
  assert.match(deployment, /first boot[\s\S]{0,120}seeds `\/data\/policy\.json`/i);
  assert.match(deployment, /`\/data\/custom-detectors\.json`[\s\S]{0,160}mode `0600`/i);
  assert.match(deployment, /never overwrites[\s\S]{0,100}customer policy or detector pack/i);
  assert.match(deployment, /pins the control-plane container hostname to `redactwall`/);
  assert.match(deployment, /pins the gateway's lock\s+identity with `REDACTWALL_LOCK_HOSTNAME=redactwall-gateway`/);
  assert.match(deployment, /Linux PID-namespace generation/);
  assert.match(deployment, /do not scale multiple control-plane containers against the\s+same `\/data` volume/);
  assert.match(deployment, /host ports bind to `127\.0\.0\.1` by default/);
  assert.match(deployment, /shares the control-plane network namespace/);
});

test('local env files stay out of git', () => {
  assert.match(gitignore, /^\.env\*\.local$/m);
});
