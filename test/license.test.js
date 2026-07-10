'use strict';
/**
 * Offline Ed25519 license verification (server/license.js). Uses a throwaway
 * keypair injected via the publicKeyPem param, so no repo keypair is needed.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const license = require('../server/license');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ type: 'spki', format: 'pem' }).toString();

function sign(payload) {
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const sig = crypto.sign(null, Buffer.from(b64, 'utf8'), privateKey).toString('base64');
  return `${b64}.${sig}`;
}

const base = { customer: 'Test CU', customerId: 'cu-1', plan: 'standard', seats: 50, features: [], issued: '2026-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', graceDays: 30 };
const NOW = Date.parse('2026-07-05T00:00:00Z');
const EXPECTED_CUSTOMER = { expectedCustomerId: base.customerId };

function waitForFile(file, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (fs.existsSync(file)) return resolve();
      if (Date.now() >= deadline) return reject(new Error(`timed out waiting for ${file}`));
      setTimeout(poll, 10);
    };
    poll();
  });
}

function runLicenseWorker(environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'support', 'license-mutation-worker.js')], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, ...environment },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => resolve({ code, stdout, stderr }));
  });
}

test('license mutation lock prevents one replica rollback from overwriting another replica install', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-race-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const licensePath = path.join(root, 'redactwall.lic');
  const readyFile = path.join(root, 'rollback-ready');
  const attemptFile = path.join(root, 'commit-attempt');
  const contendedFile = path.join(root, 'commit-contended');
  const releaseFile = path.join(root, 'release-rollback');
  const priorBytes = Buffer.from('prior-license\r\n \t', 'utf8');
  fs.writeFileSync(licensePath, priorBytes);

  const rollbackWorker = runLicenseWorker({
    WORKER_MODE: 'rollback',
    LICENSE_PATH: licensePath,
    LICENSE_VALUE: 'candidate-from-rollback-worker',
    READY_FILE: readyFile,
    RELEASE_FILE: releaseFile,
  });
  await waitForFile(readyFile);
  const commitWorker = runLicenseWorker({
    WORKER_MODE: 'commit',
    LICENSE_PATH: licensePath,
    LICENSE_VALUE: 'candidate-from-committing-worker',
    ATTEMPT_FILE: attemptFile,
    CONTENDED_FILE: contendedFile,
  });
  await waitForFile(attemptFile);
  await waitForFile(contendedFile);
  fs.writeFileSync(releaseFile, 'release');

  const [rolledBack, committed] = await Promise.all([rollbackWorker, commitWorker]);
  assert.deepStrictEqual(
    [rolledBack.code, committed.code],
    [0, 0],
    `${rolledBack.stderr}\n${committed.stderr}`,
  );
  assert.strictEqual(rolledBack.stdout, 'rolled-back');
  assert.strictEqual(committed.stdout, 'committed');
  assert.deepStrictEqual(fs.readFileSync(licensePath), Buffer.from('candidate-from-committing-worker\n'));
});

test('verifies a well-formed license', () => {
  const v = license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW, ...EXPECTED_CUSTOMER });
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.payload.customer, 'Test CU');
});

test('rejects tampering, wrong key, malformed, and missing without throwing', () => {
  const good = sign(base);
  assert.strictEqual(license.verifyLicenseText(good.slice(0, 10) + 'X' + good.slice(11), { publicKeyPem: PUB, now: NOW }).reason, 'bad_signature');
  const otherPub = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.strictEqual(license.verifyLicenseText(good, { publicKeyPem: otherPub, now: NOW }).reason, 'bad_signature');
  assert.strictEqual(license.verifyLicenseText('not-a-license', { publicKeyPem: PUB }).reason, 'malformed');
  assert.strictEqual(license.verifyLicenseText('', { publicKeyPem: PUB }).reason, 'missing');
  assert.strictEqual(license.verifyLicenseText('garbage.garbage', { publicKeyPem: PUB }).reason, 'bad_signature');
});

test('rejects bad payloads (unknown plan, no seats, unparseable expiry)', () => {
  assert.strictEqual(license.verifyLicenseText(sign({ ...base, plan: 'ultra' }), { publicKeyPem: PUB, now: NOW }).reason, 'bad_payload');
  assert.strictEqual(license.verifyLicenseText(sign({ ...base, seats: 0 }), { publicKeyPem: PUB, now: NOW }).reason, 'bad_payload');
  assert.strictEqual(license.verifyLicenseText(sign({ ...base, expires: 'never' }), { publicKeyPem: PUB, now: NOW }).reason, 'bad_payload');
});

test('requires a customer id and binds it to explicit or tenant configuration', () => {
  assert.strictEqual(
    license.verifyLicenseText(sign({ ...base, customerId: '' }), { publicKeyPem: PUB, now: NOW, env: {} }).reason,
    'customer_id_missing',
  );
  assert.strictEqual(
    license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW, env: {} }).reason,
    'customer_binding_missing',
  );
  assert.strictEqual(
    license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW, expectedCustomerId: '' }).reason,
    'customer_binding_missing',
  );
  assert.strictEqual(
    license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW, expectedCustomerId: 'cu-other' }).reason,
    'customer_mismatch',
  );
  assert.strictEqual(
    license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW, env: { REDACTWALL_TENANT_ID: 'cu-other' } }).reason,
    'customer_mismatch',
  );
  assert.strictEqual(
    license.verifyLicenseText(sign(base), { publicKeyPem: PUB, now: NOW, env: { REDACTWALL_LICENSE_CUSTOMER_ID: 'CU-1' } }).ok,
    true,
  );
  assert.strictEqual(
    license.verifyLicenseText(sign(base), {
      publicKeyPem: PUB,
      now: NOW,
      env: { REDACTWALL_LICENSE_CUSTOMER_ID: 'cu-1', REDACTWALL_TENANT_ID: 'cu-other' },
    }).reason,
    'customer_binding_conflict',
  );
  for (const customerId of ['billing@example.test', 'x', 'x'.repeat(64)]) {
    assert.strictEqual(
      license.verifyLicenseText(sign({ ...base, customerId }), { publicKeyPem: PUB, now: NOW, env: {} }).reason,
      'customer_id_invalid',
      customerId,
    );
  }
  assert.strictEqual(
    license.verifyLicenseText(sign(base), {
      publicKeyPem: PUB,
      now: NOW,
      env: { REDACTWALL_LICENSE_CUSTOMER_ID: 'billing@example.test' },
    }).reason,
    'customer_binding_invalid',
  );
});

test('boot-time status loading applies the configured customer binding', () => {
  const status = license.loadStatus(NOW, {
    readFile: () => sign(base),
    publicKeyPem: PUB,
    env: { REDACTWALL_TENANT_ID: 'cu-other' },
  });
  assert.strictEqual(status.state, 'unlicensed');
  assert.strictEqual(status.reason, 'customer_mismatch');

  const missingBinding = license.loadStatus(NOW, {
    readFile: () => sign(base),
    publicKeyPem: PUB,
    env: {},
  });
  assert.strictEqual(missingBinding.state, 'unlicensed');
  assert.strictEqual(missingBinding.reason, 'customer_binding_missing');
});

test('state machine: active / grace / readonly with graceDays default', () => {
  assert.strictEqual(license.evaluate(base, NOW), 'active');
  const expired = { ...base, expires: '2026-07-01T00:00:00Z', graceDays: 30 };
  assert.strictEqual(license.evaluate(expired, NOW), 'grace'); // 4 days after expiry, within 30
  const pastGrace = { ...base, expires: '2026-05-01T00:00:00Z', graceDays: 30 };
  assert.strictEqual(license.evaluate(pastGrace, NOW), 'readonly');
  // Missing payload / unparseable expiry -> unlicensed (never gates).
  assert.strictEqual(license.evaluate(null, NOW), 'unlicensed');
  assert.strictEqual(license.evaluate({ ...base, expires: 'x' }, NOW), 'unlicensed');
  // Default grace is 30 days when unspecified.
  assert.strictEqual(license.DEFAULT_GRACE_DAYS, 30);
});

test('loadStatus reads a file and refresh audits state transitions', () => {
  const text = sign(base);
  const audits = [];
  const deps = { readFile: () => text, publicKeyPem: PUB, now: NOW, appendAudit: (r) => audits.push(r), ...EXPECTED_CUSTOMER };
  const s = license.loadStatus(NOW, deps);
  assert.strictEqual(s.state, 'active');
  license.refresh({ ...deps });
  // The first refresh from the module's default 'unlicensed' should audit a transition.
  assert.ok(audits.some((a) => a.action === 'LICENSE_STATE_CHANGED'));
});

test('requireWritable gates config writes but exempts /api/queries/ and license install', () => {
  // Force readonly by installing a past-grace license into the module cache.
  const pastGrace = sign({ ...base, expires: '2026-05-01T00:00:00Z', graceDays: 30 });
  license.refresh({ readFile: () => pastGrace, publicKeyPem: PUB, now: NOW, ...EXPECTED_CUSTOMER });
  assert.strictEqual(license.status().state, 'readonly');

  const run = (path, method = 'PUT') => {
    let code = null; let body = null; let nexted = false;
    license.requireWritable({ path, method }, { status: (c) => { code = c; return { json: (b) => { body = b; } }; } }, () => { nexted = true; });
    return { code, body, nexted };
  };
  assert.strictEqual(run('/api/policy').code, 403, 'policy write blocked in readonly');
  assert.strictEqual(run('/api/policy').body.error, 'license_readonly');
  assert.strictEqual(run('/api/queries/q1/reveal', 'POST').nexted, true, 'reveal passes (approval workflow)');
  assert.strictEqual(run('/api/billing/license', 'POST').nexted, true, 'license install always passes');
  assert.strictEqual(run('/api/admin/license/install', 'POST').nexted, true, 'admin license install always passes');

  // Restore to unlicensed so other tests are unaffected.
  license.refresh({ readFile: () => { throw new Error('none'); }, now: NOW });
  assert.strictEqual(license.status().state, 'unlicensed');
});

test('entitled: demo mode grants all, licensed installs need the flag or enterprise plan', () => {
  const check = (payload) => {
    license.refresh({
      publicKeyPem: PUB,
      now: NOW,
      ...EXPECTED_CUSTOMER,
      readFile: () => {
        if (!payload) throw new Error('missing');
        return sign(payload);
      },
    });
    return license.entitled('ncua_readiness');
  };

  assert.strictEqual(check(null), true); // unlicensed = demo mode: fully visible
  assert.strictEqual(check(base), false); // standard plan, no flag
  assert.strictEqual(check({ ...base, features: ['ncua_readiness'] }), true);
  assert.strictEqual(check({ ...base, plan: 'enterprise' }), true);
  // Entitlement survives expiry: payload persists through grace and readonly.
  const expired = { ...base, features: ['ncua_readiness'], expires: '2026-06-01T00:00:00Z', graceDays: 3 };
  license.refresh({ publicKeyPem: PUB, now: NOW, readFile: () => sign(expired), ...EXPECTED_CUSTOMER });
  assert.strictEqual(license.status().state, 'readonly');
  assert.strictEqual(license.entitled('ncua_readiness'), true);
  license.refresh({ publicKeyPem: PUB, now: NOW, readFile: () => { throw new Error('missing'); } });
});

test('vendor revocation overlays the file state, survives refresh, and only a signed active verdict clears it', () => {
  license.refresh({ publicKeyPem: PUB, now: NOW, readFile: () => sign(base), ...EXPECTED_CUSTOMER });
  assert.strictEqual(license.status().state, 'active');

  const entitledBefore = license.entitled('ncua_readiness');
  license.applyVendorVerdict(true);
  assert.strictEqual(license.status().state, 'revoked');
  assert.strictEqual(license.isRevoked(), true);
  assert.strictEqual(license.publicStatus().reason, 'vendor_revoked');
  // Entitlement is preserved (payload persists) — revocation does not zero it.
  assert.strictEqual(license.entitled('ncua_readiness'), entitledBefore);

  // A file refresh (e.g. reinstall) does NOT clear a vendor revocation.
  license.refresh({ publicKeyPem: PUB, now: NOW, readFile: () => sign(base), ...EXPECTED_CUSTOMER });
  assert.strictEqual(license.status().state, 'revoked');

  license.applyVendorVerdict(false);
  assert.strictEqual(license.status().state, 'active');
  license.refresh({ publicKeyPem: PUB, now: NOW, readFile: () => { throw new Error('none'); } });
});

test('license state changes roll back when their immutable audit cannot commit', () => {
  license.refresh({ publicKeyPem: PUB, now: NOW, readFile: () => sign(base), ...EXPECTED_CUSTOMER });
  const active = license.status();
  assert.throws(() => license.refresh({
    now: NOW,
    readFile: () => { throw new Error('missing'); },
    appendAudit: () => { throw new Error('audit down'); },
  }), /audit down/);
  assert.deepStrictEqual(license.status(), active);

  license.applyVendorVerdict(true);
  assert.throws(() => license.applyVendorVerdict(false, {
    appendAudit: () => { throw new Error('audit down'); },
  }), /audit down/);
  assert.strictEqual(license.isRevoked(), true);

  license.applyVendorVerdict(false);
  license.setVendorStale(true);
  assert.throws(() => license.setVendorStale(false, {
    appendAudit: () => { throw new Error('audit down'); },
  }), /audit down/);
  assert.strictEqual(license.isRevoked(), true);
  license.setVendorStale(false);
});
