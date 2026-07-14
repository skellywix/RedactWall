'use strict';
/** Docker first boot must seed runtime config atomically without clobbering customer state. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const repoRoot = path.join(__dirname, '..');
const seedScript = path.join(repoRoot, 'scripts', 'seed-runtime-policy.js');
const serverEntry = path.join(repoRoot, 'server', 'app.js');
const packagedPolicy = path.join(repoRoot, 'config', 'policy.json');
const packagedDetectors = path.join(repoRoot, 'config', 'custom-detectors.json');
const FIRST_BOOT_READY_TIMEOUT_MS = process.platform === 'win32' ? 60_000 : 20_000;
const { seedRuntimeConfiguration } = require(seedScript);

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-policy-seed-'));
}

function runtimePaths(root) {
  return {
    policy: path.join(root, 'data', 'policy.json'),
    customDetectors: path.join(root, 'data', 'custom-detectors.json'),
  };
}

function runSeed(options) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [seedScript], {
      cwd: repoRoot,
      env: {
        ...process.env,
        REDACTWALL_POLICY_SEED_PATH: options.policySource,
        REDACTWALL_POLICY_PATH: options.policyTarget,
        REDACTWALL_CUSTOM_DETECTORS_SEED_PATH: options.detectorSource,
        REDACTWALL_CUSTOM_DETECTORS_PATH: options.detectorTarget,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReadyzSettled(child, port, output, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited before readiness\n${output()}`);
    const response = await fetch(`http://127.0.0.1:${port}/readyz`, {
      signal: AbortSignal.timeout(1000),
    }).catch(() => null);
    if (response) {
      const body = await response.json().catch(() => null);
      // Boot is settled once the database is up and configuration evaluated;
      // connected licensing may still hold readiness closed by design.
      if (body && body.database === true && body.configuration === 'ok') {
        return { status: response.status, body };
      }
    }
    await delay(100);
  }
  throw new Error(`timed out waiting for a settled readyz\n${output()}`);
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once('exit', resolve);
    child.kill();
  });
}

function productionEnv(root, targets, port) {
  return {
    ...process.env,
    NODE_ENV: 'production',
    PORT: String(port),
    REDACTWALL_ENV_PATH: path.join(root, 'missing.env'),
    REDACTWALL_DATA_DIR: path.join(root, 'data'),
    REDACTWALL_DB_PATH: path.join(root, 'data', 'redactwall.db'),
    REDACTWALL_POLICY_PATH: targets.policy,
    REDACTWALL_CUSTOM_DETECTORS_PATH: targets.customDetectors,
    REDACTWALL_SECRET: 'session-secret-for-runtime-seed-test'.padEnd(40, 's'),
    REDACTWALL_DATA_KEY: 'data-key-for-runtime-seed-test'.padEnd(40, 'd'),
    INGEST_API_KEY: 'ingest-key-for-runtime-seed-test'.padEnd(40, 'i'),
    ADMIN_PASSWORD: 'runtime-seed-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXPJBSWY3DP',
    COOKIE_SECURE: 'true',
    HTTPS: 'true',
    APPROVER_USER: '',
    APPROVER_PASSWORD: '',
    AUDITOR_USER: '',
    AUDITOR_PASSWORD: '',
    SCIM_BEARER_TOKEN: '',
    REDACTWALL_SCIM_BEARER_TOKEN: '',
    OIDC_ISSUER: '',
    OIDC_CLIENT_ID: '',
    OIDC_CLIENT_SECRET: '',
    OIDC_REDIRECT_URI: '',
    OIDC_AUTHORIZATION_ENDPOINT: '',
    OIDC_TOKEN_ENDPOINT: '',
    OIDC_JWKS_URI: '',
    REDACTWALL_SAAS_MODE: '',
    REDACTWALL_TENANT_ID: 'customer_runtime_seed',
    REDACTWALL_LICENSE_CUSTOMER_ID: 'customer_runtime_seed',
    REDACTWALL_SEAT_LIMIT: '',
    REDACTWALL_REQUIRE_TENANT_CONTEXT: 'true',
    REDACTWALL_REQUIRE_USER_IDENTITY: 'true',
    REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED: 'false',
    REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED: 'false',
    // Production licensing is connected-first: a fresh volume boots with the
    // provisioned connected identity but stays unready until enrollment ACKs.
    REDACTWALL_LICENSE_MODE: 'connected',
    REDACTWALL_LICENSE_PATH: path.join(root, 'license.key'),
    REDACTWALL_LICENSE_SERVER_URL: 'https://license.vendor.example/',
    REDACTWALL_CONNECTED_DEPLOYMENT_ID: 'dep_0123456789abcdef0123456789abcdef',
    REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN: 'rwcp_heartbeat_0123456789abcdef0123456789',
    REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN: 'rwcp_acknowledgement_0123456789abcdef01',
    REDACTWALL_LICENSE_PUBLIC_KEY: connectedTestKeys.offline,
    REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: connectedTestKeys.verdict,
    REDACTWALL_ENTITLEMENT_PUBLIC_KEY: connectedTestKeys.entitlement,
    REDACTWALL_ENTITLEMENT_KEY_ID: connectedTestKeys.entitlementKeyId,
  };
}

const connectedTestKeys = (() => {
  const pem = (key) => key.export({ type: 'spki', format: 'pem' });
  const offline = crypto.generateKeyPairSync('ed25519').publicKey;
  const verdict = crypto.generateKeyPairSync('ed25519').publicKey;
  const entitlement = crypto.generateKeyPairSync('ed25519').publicKey;
  const entitlementFingerprint = crypto.createHash('sha256')
    .update(entitlement.export({ type: 'spki', format: 'der' })).digest('hex');
  return {
    offline: pem(offline),
    verdict: pem(verdict),
    entitlement: pem(entitlement),
    entitlementKeyId: `rw-entitlement-${entitlementFingerprint}`,
  };
})();

test('first boot seeds policy and custom detectors at mode 0600, then preserves customer edits', () => {
  const root = tempDir();
  try {
    const policySource = path.join(root, 'packaged-policy.json');
    const detectorSource = path.join(root, 'packaged-custom-detectors.json');
    const targets = runtimePaths(root);
    fs.writeFileSync(policySource, '{"enforcementMode":"block","marker":"packaged"}\n');
    fs.writeFileSync(detectorSource, '{"detectors":[],"marker":"packaged"}\n');
    const first = seedRuntimeConfiguration({
      policySourcePath: policySource,
      policyTargetPath: targets.policy,
      customDetectorsSourcePath: detectorSource,
      customDetectorsTargetPath: targets.customDetectors,
    });
    assert.strictEqual(first.policy.seeded, true);
    assert.strictEqual(first.customDetectors.seeded, true);
    assert.strictEqual(fs.readFileSync(targets.policy, 'utf8'), fs.readFileSync(policySource, 'utf8'));
    assert.strictEqual(fs.readFileSync(targets.customDetectors, 'utf8'), fs.readFileSync(detectorSource, 'utf8'));
    if (process.platform === 'win32') {
      const assertPrivatePath = require('../server/private-path').assertPrivatePath;
      assert.doesNotThrow(() => assertPrivatePath(path.dirname(targets.policy), {
        directory: true, label: 'runtime configuration directory',
      }));
      assert.doesNotThrow(() => assertPrivatePath(targets.policy, { label: 'runtime policy' }));
      assert.doesNotThrow(() => assertPrivatePath(targets.customDetectors, { label: 'runtime custom detectors' }));
    } else {
      assert.strictEqual(fs.statSync(path.dirname(targets.policy)).mode & 0o777, 0o700);
      assert.strictEqual(fs.statSync(targets.policy).mode & 0o777, 0o600);
      assert.strictEqual(fs.statSync(targets.customDetectors).mode & 0o777, 0o600);
    }

    fs.writeFileSync(targets.policy, '{"enforcementMode":"warn","marker":"customer"}\n');
    fs.writeFileSync(targets.customDetectors, '{"detectors":[],"marker":"customer"}\n');
    const second = seedRuntimeConfiguration({
      policySourcePath: policySource,
      policyTargetPath: targets.policy,
      customDetectorsSourcePath: detectorSource,
      customDetectorsTargetPath: targets.customDetectors,
    });
    assert.strictEqual(second.policy.seeded, false);
    assert.strictEqual(second.customDetectors.seeded, false);
    assert.strictEqual(fs.readFileSync(targets.policy, 'utf8'), '{"enforcementMode":"warn","marker":"customer"}\n');
    assert.strictEqual(fs.readFileSync(targets.customDetectors, 'utf8'), '{"detectors":[],"marker":"customer"}\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('concurrent first-boot seeders publish exactly one complete copy of each runtime file', async () => {
  const root = tempDir();
  try {
    const policySource = path.join(root, 'packaged-policy.json');
    const detectorSource = path.join(root, 'packaged-custom-detectors.json');
    const targets = runtimePaths(root);
    const policyBody = JSON.stringify({ marker: 'policy', padding: 'p'.repeat(256 * 1024) }) + '\n';
    const detectorBody = JSON.stringify({ detectors: [], marker: 'detectors', padding: 'd'.repeat(256 * 1024) }) + '\n';
    fs.writeFileSync(policySource, policyBody);
    fs.writeFileSync(detectorSource, detectorBody);

    const options = {
      policySource,
      policyTarget: targets.policy,
      detectorSource,
      detectorTarget: targets.customDetectors,
    };
    const results = await Promise.all(Array.from({ length: 6 }, () => runSeed(options)));
    for (const result of results) assert.strictEqual(result.status, 0, result.stderr || result.stdout);
    const reports = results.map((result) => JSON.parse(result.stdout));
    assert.strictEqual(reports.filter((report) => report.policy.seeded).length, 1);
    assert.strictEqual(reports.filter((report) => report.customDetectors.seeded).length, 1);
    assert.strictEqual(fs.readFileSync(targets.policy, 'utf8'), policyBody);
    assert.strictEqual(fs.readFileSync(targets.customDetectors, 'utf8'), detectorBody);
    assert.deepStrictEqual(fs.readdirSync(path.dirname(targets.policy)).sort(), ['custom-detectors.json', 'policy.json']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runtime seeding rolls back a first publication when directory durability fails', () => {
  const root = tempDir();
  try {
    const source = path.join(root, 'packaged-policy.json');
    const target = path.join(root, 'data', 'policy.json');
    fs.writeFileSync(source, '{"enforcementMode":"block"}\n');
    let targetLinked = false;
    const fsImpl = Object.create(fs);
    fsImpl.linkSync = (from, to) => {
      fs.linkSync(from, to);
      if (path.resolve(to) === path.resolve(target)) targetLinked = true;
    };
    fsImpl.fsyncSync = (descriptor) => {
      if (targetLinked && fs.fstatSync(descriptor).isDirectory()) {
        const error = new Error('synthetic directory durability failure');
        error.code = 'EIO';
        throw error;
      }
      return fs.fsyncSync(descriptor);
    };

    assert.throws(() => seedRuntimeConfiguration({
      fs: fsImpl,
      policySourcePath: source,
      policyTargetPath: target,
      customDetectorsTargetPath: '',
    }), (error) => error && error.code === 'EIO');
    assert.strictEqual(fs.existsSync(target), false);
    assert.deepStrictEqual(
      fs.readdirSync(path.dirname(target)).filter((name) => name.includes('.seed-')),
      [],
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runtime seeding never publishes staged bytes that could not be flushed', () => {
  const root = tempDir();
  try {
    const source = path.join(root, 'packaged-policy.json');
    const target = path.join(root, 'data', 'policy.json');
    fs.writeFileSync(source, '{"enforcementMode":"block"}\n');
    const stagingDescriptors = new Set();
    const fsImpl = Object.create(fs);
    fsImpl.openSync = (file, flags, ...rest) => {
      const descriptor = fs.openSync(file, flags, ...rest);
      if (String(file).startsWith(`${target}.seed-`)) stagingDescriptors.add(descriptor);
      return descriptor;
    };
    fsImpl.closeSync = (descriptor) => {
      stagingDescriptors.delete(descriptor);
      return fs.closeSync(descriptor);
    };
    fsImpl.fsyncSync = (descriptor) => {
      if (stagingDescriptors.has(descriptor)) {
        const error = new Error('synthetic staged-file flush failure');
        error.code = 'EIO';
        throw error;
      }
      return fs.fsyncSync(descriptor);
    };

    assert.throws(() => seedRuntimeConfiguration({
      fs: fsImpl,
      policySourcePath: source,
      policyTargetPath: target,
      customDetectorsTargetPath: '',
    }), (error) => error && error.code === 'EIO');
    assert.strictEqual(fs.existsSync(target), false);
    assert.deepStrictEqual(
      fs.readdirSync(path.dirname(target)).filter((name) => name.includes('.seed-')),
      [],
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runtime seeding rejects state planted before Windows data-directory trust', {
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, () => {
  const root = tempDir();
  try {
    const dataDir = path.join(root, 'data');
    const plantedDb = path.join(dataDir, 'redactwall.db');
    const targets = runtimePaths(root);
    const policySource = path.join(root, 'packaged-policy.json');
    const detectorSource = path.join(root, 'packaged-custom-detectors.json');
    fs.mkdirSync(dataDir);
    fs.writeFileSync(plantedDb, 'attacker-controlled-database');
    fs.writeFileSync(policySource, '{"enforcementMode":"block"}\n');
    fs.writeFileSync(detectorSource, '{"detectors":[]}\n');
    const broadGrant = spawnSync('icacls.exe', [dataDir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)', '/q'], {
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);

    assert.throws(() => seedRuntimeConfiguration({
      policySourcePath: policySource,
      policyTargetPath: targets.policy,
      customDetectorsSourcePath: detectorSource,
      customDetectorsTargetPath: targets.customDetectors,
    }), /before its permissions were trusted/);
    assert.strictEqual(fs.readFileSync(plantedDb, 'utf8'), 'attacker-controlled-database');
    assert.strictEqual(fs.existsSync(targets.policy), false);
    assert.strictEqual(fs.existsSync(targets.customDetectors), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('entrypoint seed fails loud when the packaged detector pack cannot be read', async () => {
  const root = tempDir();
  try {
    const policySource = path.join(root, 'packaged-policy.json');
    const targets = runtimePaths(root);
    fs.writeFileSync(policySource, '{"enforcementMode":"block"}\n');
    const result = await runSeed({
      policySource,
      policyTarget: targets.policy,
      detectorSource: path.join(root, 'missing-custom-detectors.json'),
      detectorTarget: targets.customDetectors,
    });
    assert.notStrictEqual(result.status, 0);
    assert.match(result.stderr, /runtime configuration seed failed/i);
    assert.strictEqual(fs.existsSync(targets.customDetectors), false);
    assert.deepStrictEqual(
      fs.readdirSync(path.dirname(targets.policy)).filter((name) => name.includes('.seed-')),
      [],
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('fresh runtime volume reaches production readyz after packaged config seeding', async () => {
  const root = tempDir();
  const targets = runtimePaths(root);
  let child;
  try {
    const seed = await runSeed({
      policySource: packagedPolicy,
      policyTarget: targets.policy,
      detectorSource: packagedDetectors,
      detectorTarget: targets.customDetectors,
    });
    assert.strictEqual(seed.status, 0, seed.stderr || seed.stdout);

    const port = await freePort();
    let stdout = '';
    let stderr = '';
    child = spawn(process.execPath, [serverEntry], {
      cwd: repoRoot,
      env: productionEnv(root, targets, port),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const settled = await waitForReadyzSettled(
      child,
      port,
      () => `${stdout}\n${stderr}`,
      FIRST_BOOT_READY_TIMEOUT_MS,
    );
    // A fresh connected production volume boots cleanly but must stay unready
    // until its first vendor enrollment acknowledgement is durably applied.
    assert.strictEqual(settled.status, 503, JSON.stringify(settled.body));
    assert.strictEqual(settled.body.ready, false);
    assert.strictEqual(settled.body.database, true);
    assert.strictEqual(settled.body.audit, true);
    assert.strictEqual(settled.body.configuration, 'ok');
    assert.strictEqual(settled.body.licensing, 'restricted');
    assert.match(String(settled.body.licensingReason || ''),
      /pending|acknowledgement|enrollment|generation/i);
  } finally {
    if (child) await stopChild(child);
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});
