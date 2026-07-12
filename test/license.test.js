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
const privatePaths = require('../server/private-path');

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

function privateLicenseRoot(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  privatePaths.withPrivateDirectoryMutationLockSync(root, () => {}, {
    fs,
    directory: true,
    label: 'test license directory',
    ownerLabel: 'test license directory',
    lockTimeoutMs: 60_000,
    lockTimeoutMaximumMs: 60_000,
  });
  return root;
}

test('license mutation rollback restores prior bytes only while the installed candidate is exact', (t) => {
  const root = privateLicenseRoot(t, 'redactwall-license-exact-rollback-');
  const target = path.join(root, 'redactwall.lic');
  fs.writeFileSync(target, 'prior-license\r\n', { mode: 0o600 });
  const failure = new Error('synthetic audit failure');
  assert.throws(() => license.withLicenseFileMutation(({ write }) => {
    write('candidate-license');
    throw failure;
  }, { path: target }), (error) => error === failure);
  assert.deepStrictEqual(fs.readFileSync(target), Buffer.from('prior-license\r\n'));
});

for (const priorExists of [true, false]) {
  test(`license rollback preserves a changed replacement when prior ${priorExists ? 'exists' : 'is absent'}`, (t) => {
    const root = priorExists
      ? privateLicenseRoot(t, 'redactwall-license-changed-rollback-')
      : fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-changed-rollback-'));
    if (!priorExists) t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const target = path.join(root, 'redactwall.lic');
    if (priorExists) fs.writeFileSync(target, 'prior-license', { mode: 0o600 });
    let failure;
    assert.throws(() => license.withLicenseFileMutation(({ write }) => {
      write('candidate-license');
      fs.writeFileSync(target, 'replacement-owned-by-another-writer', { mode: 0o600 });
      throw new Error('synthetic audit failure');
    }, { path: target }), (error) => {
      failure = error;
      return error?.code === 'LICENSE_ROLLBACK_FAILED';
    });
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'replacement-owned-by-another-writer');
    assert.strictEqual(failure.replacementPath, target);
  });
}

test('license rollback preserves a replacement created after candidate quarantine', (t) => {
  const root = privateLicenseRoot(t, 'redactwall-license-post-quarantine-race-');
  const target = path.join(root, 'redactwall.lic');
  fs.writeFileSync(target, 'prior-license', { mode: 0o600 });
  let replaced = false;
  const fsImpl = {
    ...fs,
    renameSync(source, destination) {
      const result = fs.renameSync(source, destination);
      if (!replaced && source === target && destination.includes('.failed-install.')) {
        replaced = true;
        fs.writeFileSync(target, 'replacement-owned-by-another-writer', { flag: 'wx', mode: 0o600 });
      }
      return result;
    },
  };
  let failure;
  assert.throws(() => license.withLicenseFileMutation(({ write }) => {
    write('candidate-license');
    throw new Error('synthetic audit failure');
  }, { path: target, fs: fsImpl }), (error) => {
    failure = error;
    return error?.code === 'LICENSE_ROLLBACK_FAILED';
  });
  assert.strictEqual(replaced, true);
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'replacement-owned-by-another-writer');
  assert.ok(failure.retainedPath && fs.existsSync(failure.retainedPath));
  assert.strictEqual(fs.readFileSync(failure.retainedPath, 'utf8'), 'candidate-license\n');
});

test('license publication applies the shared exact Windows private-file ACL contract', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-windows-acl-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'redactwall.lic');
  const principal = 'TEST\\license-user';
  const calls = [];
  const ownerIdentity = {
    processSid: 'S-1-5-21-100-200-300-1001',
    ownerSid: 'S-1-5-21-100-200-300-1001',
  };
  const exactAcl = (file) => [
    `${file} ${principal}:(F)`,
    '          NT AUTHORITY\\SYSTEM:(F)',
  ].join('\r\n');
  license.writeLicenseAtomically('candidate-license', {
    path: target,
    platform: 'win32',
    principal,
    ownerIdentity,
    spawn(command, args) {
      calls.push({ command, args: args.slice() });
      return args.length === 1
        ? { status: 0, stdout: exactAcl(args[0]) }
        : { status: 0, stdout: 'processed 1 file' };
    },
  });
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'candidate-license\n');
  assert.ok(calls.some(({ args }) => args.includes('/setowner')));
  assert.ok(calls.some(({ args }) => args.includes('/inheritance:r')));
  assert.ok(calls.some(({ args }) => args.length === 1 && path.resolve(args[0]) === target));
});

test('license publication failure never deletes a replaced staging pathname', (t) => {
  const root = privateLicenseRoot(t, 'redactwall-license-staging-replacement-');
  const target = path.join(root, 'redactwall.lic');
  const replacement = Buffer.from('replacement-owned-by-another-writer', 'utf8');
  const originalPublish = privatePaths.publishFileDurably;
  let stagingPath = '';
  let retainedOriginal = '';
  const publicationFailure = new Error('synthetic license publication failure');
  privatePaths.publishFileDurably = (temp) => {
    stagingPath = temp;
    retainedOriginal = `${temp}.original`;
    fs.renameSync(temp, retainedOriginal);
    fs.writeFileSync(temp, replacement, { flag: 'wx', mode: 0o600 });
    throw publicationFailure;
  };
  try {
    assert.throws(
      () => license.writeLicenseAtomically('candidate-license', { path: target }),
      (error) => error === publicationFailure && error.retainedPath === stagingPath,
    );
  } finally {
    privatePaths.publishFileDurably = originalPublish;
  }
  assert.ok(stagingPath);
  assert.deepStrictEqual(fs.readFileSync(stagingPath), replacement);
  assert.strictEqual(fs.readFileSync(retainedOriginal, 'utf8'), 'candidate-license\n');
  assert.strictEqual(fs.existsSync(target), false);
});

test('license mutation lock prevents one replica rollback from overwriting another replica install', async (t) => {
  const root = privateLicenseRoot(t, 'redactwall-license-race-');
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

test('license rollback snapshots reject Number-rounded path-to-handle file ID collisions', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-rounded-id-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const requested = path.join(root, 'redactwall.lic');
  const replacement = path.join(root, 'replacement.lic');
  fs.writeFileSync(requested, 'trusted-license', { mode: 0o600 });
  fs.writeFileSync(replacement, 'hostile-license', { mode: 0o600 });
  const requestedId = 10414574140023031n;
  const replacementId = 10414574140023032n;
  assert.strictEqual(Number(requestedId), Number(replacementId), 'fixture must reproduce Number rounding');
  const baseline = fs.lstatSync(requested, { bigint: true });
  const withSnapshot = (stat, exact, ino) => {
    const changed = Object.create(stat);
    Object.defineProperties(changed, {
      dev: { value: exact ? 3n : 3 },
      ino: { value: exact ? ino : Number(ino) },
      size: { value: exact ? baseline.size : Number(baseline.size) },
      mtimeNs: { value: baseline.mtimeNs },
      ctimeNs: { value: baseline.ctimeNs },
      mtimeMs: { value: exact ? baseline.mtimeMs : Number(baseline.mtimeMs) },
      ctimeMs: { value: exact ? baseline.ctimeMs : Number(baseline.ctimeMs) },
    });
    return changed;
  };
  const fsImpl = {
    ...fs,
    lstatSync(target, options) {
      const exact = options?.bigint === true;
      return withSnapshot(fs.lstatSync(target, options), exact, requestedId);
    },
    openSync(target, flags, mode) {
      return fs.openSync(target === requested ? replacement : target, flags, mode);
    },
    fstatSync(descriptor, options) {
      const exact = options?.bigint === true;
      return withSnapshot(fs.fstatSync(descriptor, options), exact, replacementId);
    },
  };

  assert.throws(
    () => license._internal.licenseFileSnapshot(requested, { fs: fsImpl }),
    (error) => error && error.code === 'LICENSE_FILE_READ_FAILED'
      && /changed while opening/.test(error.message),
  );
});

test('public license writers cannot forge parent trust for planted state', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-planted-parent-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'redactwall.lic');
  fs.writeFileSync(target, 'planted-license', { mode: 0o600 });

  assert.throws(() => license.writeLicenseAtomically('candidate-license', {
    path: target,
    parentTrustHeld: true,
  }), (error) => error && error.code === 'PRIVATE_DIRECTORY_UNTRUSTED_STATE');
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'planted-license');
  assert.throws(() => license.withLicenseFileMutation(({ write }) => write('candidate-license'), {
    path: target,
    parentTrustHeld: true,
  }), (error) => error && error.code === 'PRIVATE_DIRECTORY_UNTRUSTED_STATE');
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'planted-license');
});

test('default runtime license loading is bounded and rejects linked paths', (t) => {
  const oversizedRoot = privateLicenseRoot(t, 'redactwall-license-runtime-bounded-');
  const oversized = path.join(oversizedRoot, 'redactwall.lic');
  license.writeLicenseAtomically(sign(base), { path: oversized });
  assert.strictEqual(license.loadStatus(NOW, {
    licensePath: oversized,
    publicKeyPem: PUB,
    ...EXPECTED_CUSTOMER,
  }).state, 'active');
  fs.writeFileSync(oversized, Buffer.alloc(64 * 1024 + 1, 0x61), { mode: 0o600 });
  assert.strictEqual(license.loadStatus(NOW, {
    licensePath: oversized,
    publicKeyPem: PUB,
    ...EXPECTED_CUSTOMER,
  }).reason, 'storage_unavailable');

  const linkedRoot = privateLicenseRoot(t, 'redactwall-license-runtime-linked-');
  const outside = path.join(linkedRoot, 'outside-license');
  const linked = path.join(linkedRoot, 'redactwall.lic');
  fs.writeFileSync(outside, sign(base), { mode: 0o600 });
  try { fs.symlinkSync(outside, linked, 'file'); }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error.code)) return;
    throw error;
  }
  assert.strictEqual(license.loadStatus(NOW, {
    licensePath: linked,
    publicKeyPem: PUB,
    ...EXPECTED_CUSTOMER,
  }).reason, 'storage_unavailable');
});

test('post-publication license verification failure restores the exact prior file', (t) => {
  const root = privateLicenseRoot(t, 'redactwall-license-post-publish-verify-');
  const target = path.join(root, 'redactwall.lic');
  fs.writeFileSync(target, 'prior-license', { mode: 0o600 });
  let identityCaptured = false;
  let targetStatsAfterCapture = 0;
  let injected = false;
  const fsImpl = {
    ...fs,
    lstatSync(candidate, options) {
      if (identityCaptured && path.resolve(String(candidate)) === target
          && options && options.bigint === true) {
        targetStatsAfterCapture += 1;
        if (targetStatsAfterCapture === 2) {
          injected = true;
          const error = new Error('synthetic post-publication license verification EIO');
          error.code = 'EIO';
          throw error;
        }
      }
      return fs.lstatSync(candidate, options);
    },
  };

  assert.throws(() => license.withLicenseFileMutation(({ write }) => write('candidate-license'), {
    path: target,
    fs: fsImpl,
    onPublishedIdentity() { identityCaptured = true; },
  }), /license file could not be inspected|post-publication license verification EIO/);
  assert.strictEqual(injected, true);
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'prior-license');
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
