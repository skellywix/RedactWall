'use strict';
/** Native endpoint handoff events must be signed metadata, not file payloads. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const handoff = require('../sensors/endpoint-agent/native-handoff');

const SECRET = 'native-handoff-secret-000000000000000001';
const HANDOFF_MODULE = path.join(__dirname, '..', 'sensors', 'endpoint-agent', 'native-handoff.js');

function waitForFiles(directory, count, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const poll = () => {
      const found = fs.existsSync(directory) ? fs.readdirSync(directory).filter((name) => name.endsWith('.ready')).length : 0;
      if (found === count) return resolve();
      if (Date.now() >= deadline) return reject(new Error(`only ${found}/${count} native handoff workers became ready`));
      setTimeout(poll, 20);
    };
    poll();
  });
}

function claimWorker(handoffDir, coordinationDir, index) {
  const source = `
    const fs = require('node:fs');
    const path = require('node:path');
    const handoff = require(process.env.HANDOFF_MODULE);
    fs.writeFileSync(path.join(process.env.COORDINATION_DIR, process.env.WORKER_ID + '.ready'), 'ready');
    while (!fs.existsSync(path.join(process.env.COORDINATION_DIR, 'go'))) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
    const now = new Date().toISOString();
    const signed = handoff.signHandoffEvent({
      version: handoff.EVENT_VERSION,
      id: 'concurrent-' + process.env.WORKER_ID,
      createdAt: now,
      operation: 'upload',
      filePath: path.join(process.env.HANDOFF_DIR, 'source-' + process.env.WORKER_ID + '.txt'),
      destination: { app: 'Desktop AI' },
      user: '',
      nonce: 'nonce-' + process.env.WORKER_ID,
    }, process.env.HANDOFF_SECRET);
    handoff.ensurePrivateDirectory(process.env.HANDOFF_DIR);
    const result = handoff.claimHandoffEvent(signed, path.join(process.env.HANDOFF_DIR, 'event-' + process.env.WORKER_ID + '.json'), {
      secret: process.env.HANDOFF_SECRET,
    });
    process.stdout.write(JSON.stringify(result));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', source], {
      env: {
        ...process.env,
        HANDOFF_MODULE,
        HANDOFF_DIR: handoffDir,
        HANDOFF_SECRET: SECRET,
        COORDINATION_DIR: coordinationDir,
        WORKER_ID: String(index),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code !== 0) return reject(new Error(`native handoff worker ${index} failed (${code}): ${stderr}`));
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
    });
  });
}

function assertWindowsPrivateDirectory(target) {
  const principal = String(spawnSync(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'whoami.exe'), [], { encoding: 'utf8', windowsHide: true }).stdout || '').trim();
  const acl = spawnSync('icacls.exe', [target], { encoding: 'utf8', windowsHide: true });
  assert.strictEqual(acl.status, 0, acl.stderr);
  assert.strictEqual(
    require('../server/private-path').privateAclListing(acl.stdout, principal),
    true,
    acl.stdout,
  );
}

function event(overrides = {}) {
  return {
    version: handoff.EVENT_VERSION,
    id: 'evt_unit_1',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: path.join(os.tmpdir(), 'loan.txt'),
    destination: { app: 'Desktop AI', process: 'desktop-ai.exe' },
    user: 'analyst@example.test',
    nonce: 'nonce-1',
    ...overrides,
  };
}

test('native handoff events sign and validate without file content', () => {
  const signed = handoff.signHandoffEvent(event(), SECRET);
  assert.match(signed.signature, /^[0-9a-f]{64}$/);
  assert.strictEqual(JSON.stringify(signed).includes('contentBase64'), false);

  const validated = handoff.validateHandoffEvent(signed, {
    secret: SECRET,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  assert.strictEqual(validated.id, 'evt_unit_1');
  assert.strictEqual(validated.destination.app, 'Desktop AI');
  assert.strictEqual(handoff.publicDestination(validated.destination), 'Desktop AI');
});

test('signatureFor over a raw string-destination event validates after normalization', () => {
  // A third-party collector signs the raw event (destination as a plain string).
  // canonicalEvent must produce the same bytes before and after normalization or
  // the legitimately signed event is rejected.
  const raw = event({ destination: 'Claude Desktop' });
  const signed = { ...raw, signature: handoff.signatureFor(raw, SECRET) };
  const validated = handoff.validateHandoffEvent(signed, {
    secret: SECRET,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  assert.strictEqual(validated.destination.app, 'Claude Desktop');
});

test('native handoff rejects bad signatures, stale events, and raw payload keys', () => {
  const signed = handoff.signHandoffEvent(event(), SECRET);
  assert.throws(
    () => handoff.validateHandoffEvent({ ...signed, signature: '0'.repeat(64) }, {
      secret: SECRET,
      now: new Date('2026-06-26T15:01:00.000Z'),
    }),
    /signature/,
  );
  assert.throws(
    () => handoff.validateHandoffEvent(signed, {
      secret: SECRET,
      now: new Date('2026-06-26T15:30:00.000Z'),
    }),
    /time window/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ meta: { content_base64: 'abc' } }), SECRET),
    /prohibited payload field/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ RawText: 'secret' }), SECRET),
    /prohibited payload field/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ payloadRef: 'anything-extra' }), SECRET),
    /event contains an unsupported field/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ destination: { app: 'Desktop AI', extra: 'anything-extra' } }), SECRET),
    /event\.destination contains an unsupported field/,
  );
});

test('native handoff validates the event schema before trusting file metadata', () => {
  assert.throws(
    () => handoff.validateHandoffEvent([], { secret: SECRET }),
    /JSON object/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ destination: [] }), SECRET),
    /destination is not allowed/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ version: 2 }), SECRET),
    /version is unsupported/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ operation: 'download' }), SECRET),
    /operation is unsupported/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ filePath: 'loan.txt' }), SECRET),
    /filePath must be absolute/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ filePath: '\\\\server\\share\\loan.txt' }), SECRET),
    /local path/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ createdAt: 'not-a-date' }), SECRET),
    /createdAt is invalid/,
  );

  const signed = handoff.signHandoffEvent(event({ destination: 'Desktop AI\r\nApp' }), SECRET);
  // String destinations normalize to the same {app,process,url} shape as object
  // destinations, so signatureFor() is stable across a re-normalization pass.
  assert.deepStrictEqual(signed.destination, { app: 'Desktop AI  App', process: '', url: '' });
  assert.strictEqual(handoff.publicDestination('Claude Desktop'), 'Claude Desktop');
});

test('native handoff files are size-bounded and require a configured secret', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const handoffPath = path.join(dir, 'handoff.json');
  fs.writeFileSync(handoffPath, JSON.stringify(handoff.signHandoffEvent(event(), SECRET)));

  const validated = handoff.readHandoffFile(handoffPath, {
    secret: SECRET,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  assert.strictEqual(validated.filePath, path.join(os.tmpdir(), 'loan.txt'));
  assert.throws(() => handoff.readHandoffFile(handoffPath, {
    now: new Date('2026-06-26T15:01:00.000Z'),
  }), /secret/);

  const largePath = path.join(dir, 'large.json');
  fs.writeFileSync(largePath, 'x'.repeat(handoff.MAX_EVENT_BYTES + 1));
  assert.throws(() => handoff.readHandoffFile(largePath, { secret: SECRET }), /too large/);

  const malformedPath = path.join(dir, 'malformed.json');
  fs.writeFileSync(malformedPath, '{"raw-secret-524-71-9043"');
  assert.throws(
    () => handoff.readHandoffFile(malformedPath, { secret: SECRET }),
    (error) => error.message === 'native handoff event JSON is invalid' && !error.message.includes('524-71-9043'),
  );
});

test('native handoff event files cannot be supplied through a symbolic link', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-link-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, 'target.json');
  const linked = path.join(dir, 'linked.json');
  fs.writeFileSync(target, JSON.stringify(handoff.signHandoffEvent(event(), SECRET)));
  try {
    fs.symlinkSync(target, linked, 'file');
  } catch (error) {
    if (error.code === 'EPERM') return t.skip('file symlinks require Windows developer mode');
    throw error;
  }
  assert.throws(
    () => handoff.readHandoffFile(linked, { secret: SECRET, now: new Date('2026-06-26T15:01:00.000Z') }),
    /symbolic link|safe regular file|ELOOP/i,
  );
});

test('native handoff rejects distinct BigInt file identities that collide as Numbers', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-bigint-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const visible = path.join(dir, 'visible.json');
  const redirected = path.join(dir, 'redirected.json');
  fs.writeFileSync(visible, JSON.stringify(handoff.signHandoffEvent(event({ id: 'evt-visible' }), SECRET)));
  fs.writeFileSync(redirected, JSON.stringify(handoff.signHandoffEvent(event({ id: 'evt-redirected' }), SECRET)));
  const pathId = 10414574140023031n;
  const handleId = 10414574140023032n;
  assert.strictEqual(Number(pathId), Number(handleId));
  assert.strictEqual(handoff._internal.sameFile({ dev: 0n, ino: pathId }, { dev: 0n, ino: pathId }), false);
  assert.strictEqual(handoff._internal.sameFile({ dev: 1n, ino: 0n }, { dev: 1n, ino: 0n }), false);
  assert.strictEqual(
    handoff._internal.sameFile({ dev: 1, ino: Number(pathId) }, { dev: 1, ino: Number(handleId) }),
    false,
  );
  const safeNumberStat = { dev: 1, ino: 2, size: 3, mtimeMs: 4.5, ctimeMs: 5.5 };
  assert.strictEqual(handoff._internal.sameSnapshot(safeNumberStat, { ...safeNumberStat }), true);

  const originals = {
    openSync: fs.openSync,
    statSync: fs.statSync,
    lstatSync: fs.lstatSync,
    fstatSync: fs.fstatSync,
  };
  const withIdentity = (stat, id) => {
    const exact = typeof stat.dev === 'bigint';
    const changed = Object.create(stat);
    Object.defineProperties(changed, {
      dev: { value: exact ? 1n : 1 },
      ino: { value: exact ? id : Number(id) },
      nlink: { value: exact ? 1n : 1 },
    });
    return changed;
  };
  const callStat = (method, target, options) => options === undefined
    ? method(target) : method(target, options);
  try {
    fs.openSync = (target, ...args) => originals.openSync(
      path.resolve(String(target)) === visible ? redirected : target,
      ...args,
    );
    fs.statSync = (target, options) => withIdentity(
      callStat(originals.statSync, target, options),
      path.resolve(String(target)) === visible ? pathId : handleId,
    );
    fs.lstatSync = (target, options) => withIdentity(
      callStat(originals.lstatSync, target, options),
      path.resolve(String(target)) === visible ? pathId : handleId,
    );
    fs.fstatSync = (fd, options) => withIdentity(callStat(originals.fstatSync, fd, options), handleId);

    assert.throws(
      () => handoff.readHandoffFile(visible, { secret: SECRET, now: new Date('2026-06-26T15:01:00.000Z') }),
      /safe regular file|changed during inspection/,
    );
  } finally {
    Object.assign(fs, originals);
  }
});

test('native handoff rejects multiply linked event files', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-hardlink-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const visible = path.join(dir, 'visible.json');
  fs.writeFileSync(visible, JSON.stringify(handoff.signHandoffEvent(event(), SECRET)));
  fs.linkSync(visible, path.join(dir, 'alias.json'));

  assert.throws(
    () => handoff.readHandoffFile(visible, { secret: SECRET, now: new Date('2026-06-26T15:01:00.000Z') }),
    /safe regular file/,
  );
});

test('native handoff rejects in-place changes during the final path snapshot', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-final-path-race-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const visible = path.join(dir, 'visible.json');
  fs.writeFileSync(visible, JSON.stringify(handoff.signHandoffEvent(event(), SECRET)));
  const originalStatSync = fs.statSync;
  let targetStats = 0;
  try {
    fs.statSync = function mutateDuringFinalPathStat(target, options) {
      if (path.resolve(String(target)) === visible) {
        targetStats += 1;
        fs.appendFileSync(visible, 'HOSTILE-AFTER-READ');
      }
      return originalStatSync.call(fs, target, options);
    };
    assert.throws(
      () => handoff.readHandoffFile(visible, {
        secret: SECRET,
        now: new Date('2026-06-26T15:01:00.000Z'),
      }),
      /changed during inspection/,
    );
    assert.strictEqual(targetStats, 1, 'the mutation occurred during the final path stat');
  } finally {
    fs.statSync = originalStatSync;
  }
});

test('native handoff consumed claims are durable, opaque, exclusive, and private', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-claim-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const handoffFile = path.join(dir, 'event.json');
  const signed = handoff.signHandoffEvent(event({ id: 'member-sensitive-id', nonce: 'member-sensitive-nonce' }), SECRET);
  handoff.ensurePrivateDirectory(dir);
  fs.writeFileSync(handoffFile, JSON.stringify(signed));

  const first = handoff.claimHandoffEvent(signed, handoffFile, { secret: SECRET });
  const second = handoff.claimHandoffEvent(signed, handoffFile, { secret: SECRET });
  assert.strictEqual(first.claimed, true);
  assert.strictEqual(second.claimed, false);
  assert.strictEqual(first.claimFile, second.claimFile);
  assert.ok(!first.claimFile.includes('member-sensitive'));
  assert.match(path.basename(first.claimFile), /^[0-9a-f]{64}\.claim$/);
  assert.strictEqual(fs.lstatSync(first.claimFile, { bigint: true }).nlink, 1n);
  assert.deepStrictEqual(
    fs.readdirSync(path.dirname(first.claimFile)).filter((entry) => entry.includes('.tmp')),
    [],
    'exclusive claim publication consumes its staging link',
  );
  if (process.platform !== 'win32') {
    assert.strictEqual(fs.statSync(path.dirname(first.claimFile)).mode & 0o777, 0o700);
    assert.strictEqual(fs.statSync(first.claimFile).mode & 0o777, 0o600);
  }

  delete require.cache[require.resolve('../sensors/endpoint-agent/native-handoff')];
  const reloaded = require('../sensors/endpoint-agent/native-handoff');
  assert.strictEqual(reloaded.claimHandoffEvent(signed, handoffFile, { secret: SECRET }).claimed, false);

  const old = new Date(Date.now() - Math.floor(1.5 * reloaded.DEFAULT_CLAIM_RETENTION_MS));
  fs.utimesSync(first.claimFile, old, old);
  assert.strictEqual(reloaded.pruneConsumedClaims(path.dirname(first.claimFile), {
    forceClaimPrune: true,
    ttlMs: reloaded.DEFAULT_CLAIM_RETENTION_MS,
    claimRetentionMs: reloaded.DEFAULT_TTL_MS * 2,
  }), 0, 'claims live at least twice a configured extended event TTL');
  assert.strictEqual(reloaded.pruneConsumedClaims(path.dirname(first.claimFile), {
    forceClaimPrune: true,
    claimRetentionMs: reloaded.DEFAULT_TTL_MS * 2,
  }), 1);
  assert.strictEqual(fs.existsSync(first.claimFile), false);
});

test('claim pruning skips non-terminal claims even after the retention window', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-claimed-prune-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  handoff.ensurePrivateDirectory(dir);
  const claim = path.join(dir, `${'a'.repeat(64)}.claim`);
  fs.writeFileSync(claim, `${JSON.stringify({
    version: 1,
    state: 'claimed',
    claimedAt: '2026-06-26T15:00:00.000Z',
    attemptAt: '2026-06-26T15:00:00.000Z',
  })}\n`, { mode: 0o600 });
  const old = new Date(Date.now() - 2 * handoff.DEFAULT_CLAIM_RETENTION_MS);
  fs.utimesSync(claim, old, old);
  assert.strictEqual(handoff.pruneConsumedClaims(dir, {
    forceClaimPrune: true,
    claimRetentionMs: handoff.DEFAULT_TTL_MS * 2,
  }), 0);
  assert.strictEqual(fs.existsSync(claim), true);
});

test('claim pruning preserves a replacement published at the quarantine boundary', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-prune-race-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  handoff.ensurePrivateDirectory(dir);
  const claim = path.join(dir, `${'b'.repeat(64)}.claim`);
  const prior = `${JSON.stringify({
    version: 1,
    state: 'terminal',
    decision: 'block',
    status: 'blocked',
    completedAt: '2026-06-26T15:00:00.000Z',
  })}\n`;
  const replacement = `${JSON.stringify({
    version: 1,
    state: 'terminal',
    decision: 'allow',
    status: 'allowed',
    completedAt: new Date().toISOString(),
  })}\n`;
  fs.writeFileSync(claim, prior, { mode: 0o600 });
  const old = new Date(Date.now() - 2 * handoff.DEFAULT_CLAIM_RETENTION_MS);
  fs.utimesSync(claim, old, old);
  const originalRenameSync = fs.renameSync;
  let replaced = false;
  try {
    fs.renameSync = function replaceAtPruneBoundary(source, destination) {
      if (!replaced && path.resolve(String(source)) === claim) {
        replaced = true;
        fs.unlinkSync(claim);
        fs.writeFileSync(claim, replacement, { mode: 0o600 });
      }
      return originalRenameSync.call(fs, source, destination);
    };
    assert.strictEqual(handoff.pruneConsumedClaims(dir, {
      forceClaimPrune: true,
      claimRetentionMs: handoff.DEFAULT_TTL_MS * 2,
    }), 0);
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.strictEqual(replaced, true);
  assert.strictEqual(fs.readFileSync(claim, 'utf8'), replacement);
});

test('native handoff rejects a claim planted before the Windows consumed directory was trusted', {
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-native-planted-'));
  const handoffDir = path.join(root, 'handoff');
  const consumedDir = path.join(handoffDir, handoff.CONSUMED_DIR_NAME);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  handoff.ensurePrivateDirectory(handoffDir);
  fs.mkdirSync(consumedDir);
  const broadGrant = spawnSync('icacls.exe', [consumedDir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);

  const signed = handoff.signHandoffEvent(event({ id: 'planted-event', nonce: 'planted-nonce' }), SECRET);
  const claimFile = path.join(consumedDir, `${handoff._internal.claimFingerprint(signed, SECRET)}.claim`);
  const planted = Buffer.from(`${JSON.stringify({ version: 1, claimedAt: '2026-06-26T15:00:00.000Z' })}\n`);
  fs.writeFileSync(claimFile, planted);

  assert.throws(
    () => handoff.claimHandoffEvent(signed, path.join(handoffDir, 'event.json'), { secret: SECRET }),
    /before its permissions were trusted/,
  );
  assert.deepStrictEqual(fs.readFileSync(claimFile), planted);
});

test('initialized Windows handoff directories are asserted and never repaired after ACL drift', {
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-native-assert-only-'));
  const handoffDir = path.join(root, 'handoff');
  const consumedDir = path.join(handoffDir, handoff.CONSUMED_DIR_NAME);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  handoff.ensurePrivateDirectory(handoffDir);
  handoff.ensurePrivateDirectory(consumedDir);

  const broadGrant = spawnSync('icacls.exe', [consumedDir, '/grant', '*S-1-5-32-545:(OI)(CI)(M)', '/q'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.strictEqual(broadGrant.status, 0, broadGrant.stderr);
  assert.throws(() => handoff.ensurePrivateDirectory(consumedDir), /ACL verification failed/);
  const acl = spawnSync('icacls.exe', [consumedDir], { encoding: 'utf8', windowsHide: true });
  assert.strictEqual(acl.status, 0, acl.stderr);
  assert.match(acl.stdout.toLowerCase(), /builtin\\users/);
});

test('eight native handoff processes serialize fresh Windows handoff and consumed-directory trust', {
  timeout: 120_000,
  skip: process.platform !== 'win32' && 'Windows ACL bootstrap is Windows-specific',
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-native-bootstrap-race-'));
  const handoffDir = path.join(root, 'handoff');
  const coordinationDir = path.join(root, 'coordination');
  fs.mkdirSync(coordinationDir);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const workers = Array.from({ length: 8 }, (_, index) => claimWorker(handoffDir, coordinationDir, index));
  await waitForFiles(coordinationDir, 8);
  fs.writeFileSync(path.join(coordinationDir, 'go'), 'go');
  const results = await Promise.all(workers);

  assert.ok(results.every((result) => result.claimed === true));
  assert.strictEqual(fs.readdirSync(path.join(handoffDir, handoff.CONSUMED_DIR_NAME)).filter((name) => name.endsWith('.claim')).length, 8);
  assertWindowsPrivateDirectory(handoffDir);
  assertWindowsPrivateDirectory(path.join(handoffDir, handoff.CONSUMED_DIR_NAME));
});

test('native handoff claim rejects directory-fsync EIO without consuming the event', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-durable-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const handoffFile = path.join(dir, 'event.json');
  const signed = handoff.signHandoffEvent(event({
    id: 'evt_durable_claim',
    nonce: 'nonce-durable-claim',
    filePath: path.join(dir, 'source.txt'),
  }), SECRET);
  handoff.ensurePrivateDirectory(dir);
  handoff.ensurePrivateDirectory(path.join(dir, handoff.CONSUMED_DIR_NAME));
  const originalFsync = fs.fsyncSync;
  fs.fsyncSync = (fd) => {
    if (fs.fstatSync(fd).isDirectory()) {
      const error = new Error('synthetic claim directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsync(fd);
  };
  try {
    assert.throws(
      () => handoff.claimHandoffEvent(signed, handoffFile, { secret: SECRET }),
      /synthetic claim directory fsync EIO/,
    );
  } finally {
    fs.fsyncSync = originalFsync;
  }
  const consumed = path.join(dir, handoff.CONSUMED_DIR_NAME);
  const retained = fs.readdirSync(consumed);
  assert.deepStrictEqual(retained.filter((entry) => entry.endsWith('.claim')), []);
  assert.ok(retained.every((entry) => entry.includes('.tmp') || entry.includes('.unlink-guard.')),
    'only opaque failed-publication recovery artifacts may remain');
});

test('native handoff claim cleanup fsync failure rolls back without consuming the event', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-cleanup-eio-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const handoffFile = path.join(dir, 'event.json');
  const signed = handoff.signHandoffEvent(event({
    id: 'evt_claim_cleanup_eio',
    nonce: 'nonce-claim-cleanup-eio',
    filePath: path.join(dir, 'source.txt'),
  }), SECRET);
  handoff.ensurePrivateDirectory(dir);
  const consumed = path.join(dir, handoff.CONSUMED_DIR_NAME);
  handoff.ensurePrivateDirectory(consumed);
  const originalFsync = fs.fsyncSync;
  let directoryFsyncs = 0;
  fs.fsyncSync = (fd) => {
    if (fs.fstatSync(fd).isDirectory()) {
      directoryFsyncs += 1;
      if (directoryFsyncs === 2) {
        const error = new Error('synthetic claim staging cleanup EIO');
        error.code = 'EIO';
        throw error;
      }
    }
    return originalFsync(fd);
  };
  try {
    assert.throws(
      () => handoff.claimHandoffEvent(signed, handoffFile, { secret: SECRET }),
      (error) => error && error.cause
        && /synthetic claim staging cleanup EIO/.test(error.cause.message),
    );
  } finally {
    fs.fsyncSync = originalFsync;
  }

  const entries = fs.readdirSync(consumed);
  assert.deepStrictEqual(entries.filter((entry) => entry.endsWith('.claim')), []);
  const recovery = entries.filter((entry) => entry.includes('.unlink-guard.'));
  assert.ok(entries.every((entry) => entry.includes('.tmp') || entry.includes('.unlink-guard.')),
    `only opaque staging recovery artifacts may remain: ${entries.join(', ')}`);
  assert.ok(recovery.length === 0 || recovery.some((entry) => {
    try {
      const parsed = JSON.parse(fs.readFileSync(path.join(consumed, entry), 'utf8'));
      return parsed.version === handoff.EVENT_VERSION && Number.isFinite(Date.parse(parsed.claimedAt));
    } catch {
      return false;
    }
  }));
});

test('native handoff accepts RedactWall endpoint env aliases', () => {
  const oldSecret = process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
  const oldRedactWallSecret = process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET;
  delete process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
  process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET = SECRET;
  try {
    assert.strictEqual(
      handoff.defaultHandoffDir({ REDACTWALL_ENDPOINT_AGENT_HANDOFF_DIR: 'C:/RedactWall/handoff' }),
      'C:/RedactWall/handoff',
    );
    assert.strictEqual(handoff.configuredHandoffSecret(), SECRET);
  } finally {
    if (oldSecret === undefined) delete process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
    else process.env.ENDPOINT_AGENT_HANDOFF_SECRET = oldSecret;
    if (oldRedactWallSecret === undefined) delete process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET;
    else process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET = oldRedactWallSecret;
  }
});
