'use strict';
/** Backup/verify/restore workflow for the SQLite evidence store. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const Database = require('better-sqlite3');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-backup-test-'));
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'redactwall.db');
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';

const db = require('../server/db');
const backup = require('../scripts/backup-store');
const auditIntegrity = require('../server/audit-integrity');
const auditAnchor = require('../server/audit-anchor')._internal;
const privatePaths = require('../server/private-path');

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(message); },
  };
}

function permissionBits(file) {
  return fs.statSync(file).mode & 0o777;
}

function canonicalDacl(sddl) {
  const firstAce = sddl.indexOf('(');
  return {
    control: firstAce < 0 ? sddl : sddl.slice(0, firstAce),
    aces: (sddl.match(/\([^)]*\)/g) || []).sort(),
  };
}

const FAKE_WINDOWS_ACL = {
  ownerIdentity: { processSid: 'S-1-5-21-100-200-300-1001', ownerSid: 'S-1-5-21-100-200-300-1001' },
  captureDacl: () => 'D:P(A;;FA;;;SY)',
  restoreDacl: () => {},
  privatePathSecurity: {
    platform: 'win32',
    principal: 'TEST\\backup-user',
    ownerIdentity: { processSid: 'S-1-5-21-100-200-300-1001', ownerSid: 'S-1-5-21-100-200-300-1001' },
    spawn(_command, args) {
      const target = String(args[0] || 'artifact');
      return {
        status: 0,
        stdout: `${target} TEST\\backup-user:(F)\n  NT AUTHORITY\\SYSTEM:(F)\n`,
      };
    },
  },
};

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function manifestArtifact(file) {
  const stat = fs.statSync(file);
  return {
    file: path.basename(file),
    bytes: stat.size,
    sha256: sha256File(file),
  };
}

function portableAuditPaths(file) {
  return {
    statePath: `${file}.audit-state.json`,
    checkpointPath: `${file}.audit-checkpoint.json`,
  };
}

function preparePrivateRestoreDirectory(directory, callback = () => {}, security = {}) {
  return privatePaths.withPrivateDirectoryMutationLockSync(directory, callback, {
    ...(security.privatePathSecurity || security),
    directory: true,
    label: 'test SQLite restore directory',
    ownerLabel: 'test SQLite restore directory',
  });
}

function restoredServerDbEnv(dbPath) {
  const env = {
    ...process.env,
    NODE_ENV: 'production',
    REDACTWALL_ENV_PATH: path.join(tempRoot, 'no.env'),
    REDACTWALL_DB_DRIVER: 'sqlite',
    REDACTWALL_DB_PATH: dbPath,
    REDACTWALL_SECRET: 'unit-secret-stable',
    REDACTWALL_DATA_KEY: 'unit-data-key-stable',
  };
  delete env.REDACTWALL_AUDIT_DIR;
  delete env.REDACTWALL_AUDIT_STATE_PATH;
  delete env.REDACTWALL_AUDIT_CHECKPOINT_PATH;
  delete env.REDACTWALL_AUDIT_PENDING_PATH;
  delete env.REDACTWALL_DATABASE_URL;
  delete env.DATABASE_URL;
  return env;
}

test('backup workflow verifies and restores audit evidence without leaking manifest prompt data', async () => {
  const secret = '524-71-9043';
  const q = db.createQuery({
    status: 'pending',
    user: 'analyst@example.test',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'Member SSN ' + secret,
    findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
  });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'analyst@example.test', detail: 'structured pii detected' });

  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'backups'), dbModule: db });
  assert.strictEqual(result.ok, true);
  assert.ok(fs.existsSync(result.file));
  assert.ok(fs.existsSync(result.manifestFile));
  assert.ok(fs.existsSync(result.auditStateFile));
  assert.ok(fs.existsSync(result.auditCheckpointFile));
  assert.strictEqual(result.auditIntegrity.ok, true);
  assert.strictEqual(result.manifest.schemaVersion, 2);
  assert.strictEqual(result.manifest.driver, 'sqlite');
  assert.strictEqual(result.manifest.backupSha256, result.backupSha256);
  assert.deepStrictEqual(
    Object.keys(result.manifest.manifestAuthentication).sort(),
    ['algorithm', 'mac', 'version'],
  );
  assert.match(result.manifest.manifestAuthentication.mac, /^[a-f0-9]{64}$/);
  assert.deepStrictEqual(Object.keys(result.manifest.artifacts).sort(), [
    'auditCheckpoint',
    'auditState',
    'database',
  ]);
  const manifestArtifacts = {
    database: result.file,
    auditState: result.auditStateFile,
    auditCheckpoint: result.auditCheckpointFile,
  };
  for (const [name, artifact] of Object.entries(manifestArtifacts)) {
    assert.strictEqual(result.manifest.artifacts[name].file, path.basename(artifact));
    assert.strictEqual(result.manifest.artifacts[name].bytes, fs.statSync(artifact).size);
    assert.strictEqual(result.manifest.artifacts[name].sha256, sha256File(artifact));
  }
  assert.ok(!JSON.stringify(result.manifest).includes(secret));
  assert.ok(!JSON.stringify(result.manifest).includes(tempRoot));
  assert.strictEqual(result.manifest.sourceDbFile, 'redactwall.db');
  assert.match(result.manifest.sourceDbPathHash, /^[a-f0-9]{64}$/);

  const verified = backup.verifyBackup({ file: result.file, manifestFile: result.manifestFile });
  assert.strictEqual(verified.ok, true);
  assert.strictEqual(verified.backupSha256, result.backupSha256);

  const restoredPath = path.join(tempRoot, 'restored', 'redactwall.db');
  const restored = backup.restoreBackup({ file: result.file, to: restoredPath });
  assert.strictEqual(restored.ok, true);
  assert.strictEqual(restored.restoredTo, restoredPath);
  assert.strictEqual(restored.unverifiable, false, 'the source manifest was verified before restore');
  assert.ok(fs.existsSync(restored.auditStateFile));
  assert.ok(fs.existsSync(restored.auditCheckpointFile));
  // The restored copy has no sibling manifest, but its runtime sidecars still
  // authenticate the exact snapshot head.
  const restoredVerify = backup.verifyBackup({ file: restoredPath });
  assert.strictEqual(restoredVerify.auditIntegrity.ok, true);
  assert.strictEqual(restoredVerify.unverifiable, true);

  const productionLoad = spawnSync(process.execPath, ['-e', `
    const db = require('./server/db');
    const result = db.verifyAuditChain();
    if (!result.ok) throw new Error(JSON.stringify(result));
    db._db.close();
  `], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    env: restoredServerDbEnv(restoredPath),
  });
  assert.strictEqual(productionLoad.status, 0, productionLoad.stderr || productionLoad.stdout);
});

test('SQLite manifest counts come from the copied snapshot despite writes around backup', async () => {
  const beforeQueries = db.stats().total;
  const beforeAudit = db.verifyAuditChain().count;
  const originalBackup = db._db.backup.bind(db._db);
  const racingDb = {
    ...db,
    _db: {
      async backup(target) {
        const included = db.createQuery({
          status: 'allowed',
          redactedPrompt: 'included in snapshot',
          findings: [],
          entityCounts: { SNAPSHOT_ONLY: 2 },
        });
        db.appendAudit({ action: 'ALLOWED', queryId: included.id, actor: 'snapshot-test' });
        await originalBackup(target);
        const excluded = db.createQuery({
          status: 'denied',
          redactedPrompt: 'written after snapshot',
          findings: [],
          entityCounts: { AFTER_SNAPSHOT: 4 },
        });
        db.appendAudit({ action: 'DENIED', queryId: excluded.id, actor: 'snapshot-test' });
      },
    },
  };

  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'sqlite-snapshot-race'),
    dbModule: racingDb,
  });
  const snapshot = new Database(result.file, { readonly: true, fileMustExist: true });
  let snapshotQueries;
  let snapshotAudit;
  let snapshotStats;
  let snapshotHead;
  try {
    snapshotQueries = snapshot.prepare('SELECT COUNT(*) n FROM queries').get().n;
    snapshotAudit = snapshot.prepare('SELECT COUNT(*) n FROM audit').get().n;
    snapshotStats = backup._internal.snapshotStatsFromRows(
      snapshot.prepare('SELECT status, createdAt, data FROM queries ORDER BY seq ASC').all(),
    );
    const lastAudit = snapshot.prepare('SELECT entry FROM audit ORDER BY seq DESC LIMIT 1').get();
    snapshotHead = lastAudit ? JSON.parse(lastAudit.entry).hash : auditIntegrity.ZERO;
  } finally {
    snapshot.close();
  }

  assert.strictEqual(snapshotQueries, beforeQueries + 1);
  assert.strictEqual(snapshotAudit, beforeAudit + 1);
  assert.strictEqual(db.stats().total, beforeQueries + 2, 'live store advanced after the snapshot');
  assert.strictEqual(db.verifyAuditChain().count, beforeAudit + 2, 'live audit advanced after the snapshot');
  assert.deepStrictEqual(result.manifest.stats, snapshotStats);
  assert.strictEqual(result.manifest.sourceIntegrity.count, snapshotAudit);
  assert.strictEqual(result.manifest.backupIntegrity.count, snapshotAudit);
  const checkpoint = JSON.parse(fs.readFileSync(result.auditCheckpointFile, 'utf8'));
  assert.strictEqual(checkpoint.count, snapshotAudit, 'staged checkpoint advances to the copied snapshot');
  assert.strictEqual(checkpoint.head, snapshotHead);
});

test('backup and restore publish the exact authenticated artifact set with private POSIX modes', async () => {
  const outDir = path.join(tempRoot, 'private-artifacts');
  const result = await backup.createBackup({ outDir, dbModule: db });
  assert.deepStrictEqual(fs.readdirSync(outDir).sort(), [
    path.basename(result.file),
    path.basename(result.auditStateFile),
    path.basename(result.auditCheckpointFile),
    path.basename(result.manifestFile),
  ].sort());

  if (process.platform !== 'win32') {
    for (const artifact of [
      result.file,
      result.auditStateFile,
      result.auditCheckpointFile,
      result.manifestFile,
    ]) assert.strictEqual(permissionBits(artifact), 0o600);
  }

  const restoreDir = path.join(tempRoot, 'private-restore');
  const target = path.join(restoreDir, 'redactwall.db');
  preparePrivateRestoreDirectory(restoreDir, () => {
    fs.writeFileSync(`${target}-wal`, 'stale sidecar');
  });
  assert.throws(() => backup.restoreBackup({ file: result.file, to: target }), /sidecar|already exists/);

  const restored = backup.restoreBackup({ file: result.file, to: target, force: true });
  assert.strictEqual(restored.ok, true);
  assert.deepStrictEqual(fs.readdirSync(restoreDir).sort(), [
    'redactwall.db',
    'redactwall.db.audit-integrity',
  ]);
  assert.deepStrictEqual(fs.readdirSync(`${target}.audit-integrity`).sort(), [
    '.audit-integrity-checkpoint.json',
    '.audit-integrity-state.json',
  ]);
  if (process.platform !== 'win32') {
    assert.strictEqual(permissionBits(target), 0o600);
    assert.strictEqual(permissionBits(`${target}.audit-integrity`), 0o700);
    assert.strictEqual(permissionBits(restored.auditStateFile), 0o600);
    assert.strictEqual(permissionBits(restored.auditCheckpointFile), 0o600);
  }
});

test('private staging directories are mode 0700 on POSIX', { skip: process.platform === 'win32' }, () => {
  const staging = backup._internal.createPrivateStagingDir(tempRoot);
  try {
    assert.strictEqual(permissionBits(staging), 0o700);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
});

test('Windows ACL hardening fails closed when icacls cannot protect a destination', () => {
  const target = path.join(tempRoot, 'acl-target.db');
  fs.writeFileSync(target, 'synthetic');
  assert.throws(() => backup._internal.restrictPath(target, {
    platform: 'win32',
    principal: 'TEST\\backup-user',
    ...FAKE_WINDOWS_ACL,
    spawn() { return { status: 5, stderr: 'access denied' }; },
  }), /failed to secure.*icacls/i);
});

test('Windows ACL hardening removes inheritance and grants only owner plus LocalSystem', () => {
  const target = path.join(tempRoot, 'acl-contract.db');
  fs.writeFileSync(target, 'synthetic');
  const invocations = [];
  backup._internal.restrictPath(target, {
    platform: 'win32',
    principal: 'TEST\\backup-user',
    ...FAKE_WINDOWS_ACL,
    spawn(command, args, options) {
      invocations.push({ command, args, options });
      return { status: 0, stdout: 'processed 1 file' };
    },
  });
  assert.deepStrictEqual(invocations.map((entry) => entry.command), ['icacls.exe', 'icacls.exe']);
  assert.deepStrictEqual(invocations.map((entry) => entry.args), [
    [target, '/reset', '/q'],
    [target, '/inheritance:r', '/grant:r', 'TEST\\backup-user:(F)', '*S-1-5-18:(F)', '/q'],
  ]);
  assert.ok(invocations.every((entry) => entry.options.windowsHide === true));
});

test('a second staging ACL failure cleans every partial staging directory', async () => {
  const outDir = path.join(tempRoot, 'acl-staging-cleanup');
  let calls = 0;
  await assert.rejects(() => backup.createBackup({
    outDir,
    dbModule: db,
    security: {
      platform: 'win32',
      principal: 'TEST\\backup-user',
      ...FAKE_WINDOWS_ACL,
      spawn() {
        calls += 1;
        return calls === 3 ? { status: 5, stderr: 'access denied' } : { status: 0 };
      },
    },
  }), /failed to secure.*icacls/i);
  assert.deepStrictEqual(fs.readdirSync(outDir), []);
});

test('failed staged unlink removes the linked target instead of leaving a partial backup set', async () => {
  const outDir = path.join(tempRoot, 'publish-unlink-cleanup');
  const file = path.join(outDir, 'redactwall.db');
  const manifestFile = `${file}.manifest.json`;
  const originalUnlinkSync = fs.unlinkSync;
  let injected = false;
  fs.unlinkSync = function failFirstStagedUnlink(target) {
    if (!injected && path.basename(path.dirname(String(target))).startsWith('.redactwall-backup-')) {
      injected = true;
      const error = new Error('synthetic staged unlink failure');
      error.code = 'EACCES';
      throw error;
    }
    return originalUnlinkSync.call(fs, target);
  };
  try {
    await assert.rejects(
      () => backup.createBackup({ file, manifestFile, dbModule: db }),
      /synthetic staged unlink failure/,
    );
  } finally {
    fs.unlinkSync = originalUnlinkSync;
  }
  assert.strictEqual(injected, true);
  assert.strictEqual(fs.existsSync(file), false);
  assert.strictEqual(fs.existsSync(manifestFile), false);
  assert.deepStrictEqual(fs.readdirSync(outDir), []);
});

test('forced backup replacement restores the complete prior artifact set when publish hardening fails', async () => {
  const outDir = path.join(tempRoot, 'force-backup-rollback');
  const file = path.join(outDir, 'redactwall.db');
  const manifestFile = `${file}.manifest.json`;
  const initial = await backup.createBackup({ file, manifestFile, dbModule: db });
  const before = new Map([
    [file, fs.readFileSync(file)],
    [initial.auditStateFile, fs.readFileSync(initial.auditStateFile)],
    [initial.auditCheckpointFile, fs.readFileSync(initial.auditCheckpointFile)],
    [manifestFile, fs.readFileSync(manifestFile)],
  ]);

  await assert.rejects(() => backup.createBackup({
    file,
    manifestFile,
    dbModule: db,
    force: true,
    security: {
      platform: 'win32',
      principal: 'TEST\\backup-user',
      ...FAKE_WINDOWS_ACL,
      spawn(_command, args) {
        return path.resolve(args[0]) === path.resolve(file)
          ? { status: 5, stderr: 'synthetic ACL failure' }
          : { status: 0 };
      },
    },
  }), /failed to secure.*icacls/i);

  for (const [artifact, bytes] of before) assert.deepStrictEqual(fs.readFileSync(artifact), bytes);
  assert.deepStrictEqual(
    fs.readdirSync(outDir).sort(),
    [...before.keys()].map((artifact) => path.basename(artifact)).sort(),
  );
});

test('forced backup publication rejects directory-fsync EIO and restores the exact artifact set', async () => {
  const outDir = path.join(tempRoot, 'force-backup-durability');
  const file = path.join(outDir, 'redactwall.db');
  const manifestFile = `${file}.manifest.json`;
  const initial = await backup.createBackup({ file, manifestFile, dbModule: db });
  const before = new Map([
    [file, fs.readFileSync(file)],
    [initial.auditStateFile, fs.readFileSync(initial.auditStateFile)],
    [initial.auditCheckpointFile, fs.readFileSync(initial.auditCheckpointFile)],
    [manifestFile, fs.readFileSync(manifestFile)],
  ]);
  const originalFsync = fs.fsyncSync;
  fs.fsyncSync = (fd) => {
    if (fs.fstatSync(fd).isDirectory()) {
      const error = new Error('synthetic backup directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return originalFsync(fd);
  };
  try {
    await assert.rejects(
      () => backup.createBackup({ file, manifestFile, dbModule: db, force: true }),
      /synthetic backup directory fsync EIO/,
    );
  } finally {
    fs.fsyncSync = originalFsync;
  }
  for (const [artifact, bytes] of before) assert.deepStrictEqual(fs.readFileSync(artifact), bytes);
  assert.deepStrictEqual(
    fs.readdirSync(outDir).sort(),
    [...before.keys()].map((artifact) => path.basename(artifact)).sort(),
  );
});

test('forced replacement refuses linked artifacts before moving or hardening them', async () => {
  const outDir = path.join(tempRoot, 'force-backup-linked-artifact');
  const result = await backup.createBackup({ outDir, dbModule: db });
  const unexpectedLink = path.join(outDir, 'unexpected-hardlink.db');
  fs.linkSync(result.file, unexpectedLink);
  try {
    await assert.rejects(() => backup.createBackup({
      file: result.file,
      manifestFile: result.manifestFile,
      dbModule: db,
      force: true,
    }), /unsafe replacement artifact/i);
    assert.ok(fs.existsSync(result.file));
    assert.ok(fs.existsSync(result.auditStateFile));
    assert.ok(fs.existsSync(result.auditCheckpointFile));
    assert.ok(fs.existsSync(result.manifestFile));
  } finally {
    fs.rmSync(unexpectedLink, { force: true });
  }
  assert.strictEqual(backup.verifyBackup({ file: result.file }).ok, true);
});

test('rollback cleanup failure retains the valid newly published backup set', async () => {
  const outDir = path.join(tempRoot, 'force-backup-cleanup-failure');
  const file = path.join(outDir, 'redactwall.db');
  const manifestFile = `${file}.manifest.json`;
  await backup.createBackup({ file, manifestFile, dbModule: db });
  const oldHash = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const added = db.createQuery({ status: 'allowed', redactedPrompt: 'new snapshot row', findings: [] });
  db.appendAudit({ action: 'ALLOWED', queryId: added.id, actor: 'cleanup-test' });

  const originalRmSync = fs.rmSync;
  let recoveryDir = '';
  fs.rmSync = function failRollbackCleanup(target, options) {
    const candidate = String(target);
    if (!recoveryDir && path.dirname(candidate) === outDir && fs.existsSync(candidate)
      && fs.statSync(candidate).isDirectory()
      && fs.readdirSync(candidate).some((name) => /^\d+-/.test(name))) {
      recoveryDir = candidate;
      throw new Error('synthetic rollback cleanup failure');
    }
    return originalRmSync.call(fs, target, options);
  };
  try {
    await assert.rejects(
      () => backup.createBackup({ file, manifestFile, dbModule: db, force: true }),
      /publish succeeded.*recovery director/i,
    );
  } finally {
    fs.rmSync = originalRmSync;
  }

  const verified = backup.verifyBackup({ file, manifestFile });
  assert.strictEqual(verified.ok, true, 'the newly published backup remains verifiable');
  assert.notStrictEqual(verified.backupSha256, oldHash, 'cleanup failure does not restore the old backup');
  const snapshot = new Database(file, { readonly: true, fileMustExist: true });
  try {
    assert.ok(snapshot.prepare('SELECT 1 FROM queries WHERE id = ?').get(added.id));
  } finally {
    snapshot.close();
  }
  assert.ok(recoveryDir && fs.existsSync(recoveryDir), 'old artifacts remain in the reported private recovery directory');
  originalRmSync(recoveryDir, { recursive: true, force: true });
});

test('forced restore restores the complete prior SQLite artifact set when sidecar validation fails', async () => {
  const created = await backup.createBackup({ outDir: path.join(tempRoot, 'force-restore-source'), dbModule: db });
  const outDir = path.join(tempRoot, 'force-restore-rollback');
  const target = path.join(outDir, 'redactwall.db');
  const before = new Map([
    [target, Buffer.from('prior database bytes')],
    [`${target}-wal`, Buffer.from('prior wal bytes')],
    [`${target}-shm`, Buffer.from('prior shm bytes')],
    [`${target}-journal`, Buffer.from('prior journal bytes')],
  ]);
  preparePrivateRestoreDirectory(outDir, () => {
    for (const [artifact, bytes] of before) fs.writeFileSync(artifact, bytes);
  }, FAKE_WINDOWS_ACL);
  const priorAuditDirectory = `${target}.audit-integrity`;
  const priorAuditState = path.join(priorAuditDirectory, '.audit-integrity-state.json');
  const priorAuditCheckpoint = path.join(priorAuditDirectory, '.audit-integrity-checkpoint.json');
  fs.mkdirSync(priorAuditDirectory);
  before.set(priorAuditState, Buffer.from('prior state bytes'));
  before.set(priorAuditCheckpoint, Buffer.from('prior checkpoint bytes'));
  fs.writeFileSync(priorAuditState, before.get(priorAuditState));
  fs.writeFileSync(priorAuditCheckpoint, before.get(priorAuditCheckpoint));

  assert.throws(() => backup.restoreBackup({
    file: created.file,
    manifestFile: created.manifestFile,
    to: target,
    force: true,
    security: {
      platform: 'win32',
      principal: 'TEST\\backup-user',
      ...FAKE_WINDOWS_ACL,
      spawn(_command, args) {
        if (path.resolve(args[0]) === path.resolve(target)) fs.writeFileSync(`${target}-wal`, 'synthetic racing sidecar');
        return { status: 0 };
      },
    },
  }), /unexpected sidecar/i);

  for (const [artifact, bytes] of before) assert.deepStrictEqual(fs.readFileSync(artifact), bytes);
  assert.deepStrictEqual(fs.readdirSync(outDir).sort(), [
    'redactwall.db',
    'redactwall.db.audit-integrity',
    'redactwall.db-journal',
    'redactwall.db-shm',
    'redactwall.db-wal',
  ].sort());
});

test('forced replacement hardens staged Windows artifacts and restores the original DACL on rollback', {
  skip: process.platform !== 'win32',
}, async () => {
  const outDir = path.join(tempRoot, 'force-backup-real-acl');
  const file = path.join(outDir, 'redactwall.db');
  const manifestFile = `${file}.manifest.json`;
  const initial = await backup.createBackup({ file, manifestFile, dbModule: db });
  const before = new Map();
  for (const artifact of [file, initial.auditStateFile, initial.auditCheckpointFile, manifestFile]) {
    const granted = spawnSync('icacls.exe', [artifact, '/grant', '*S-1-5-32-545:(R)', '/q'], {
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.strictEqual(granted.status, 0, granted.stderr);
    const sddl = backup._internal.captureWindowsDacl(artifact);
    assert.match(sddl, /;;;BU\)/, 'test fixture has an explicit Builtin Users read ACE');
    before.set(artifact, sddl);
  }

  const stagedDacls = [];
  const originalLinkSync = fs.linkSync;
  fs.linkSync = function inspectPrivateRollbackState() {
    for (const entry of fs.readdirSync(outDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const directory = path.join(outDir, entry.name);
      for (const name of fs.readdirSync(directory)) {
        if (/^\d+-/.test(name)) stagedDacls.push(backup._internal.captureWindowsDacl(path.join(directory, name)));
      }
    }
    throw new Error('synthetic publish interruption');
  };
  try {
    await assert.rejects(
      () => backup.createBackup({ file, manifestFile, dbModule: db, force: true }),
      /synthetic publish interruption/,
    );
  } finally {
    fs.linkSync = originalLinkSync;
  }

  assert.strictEqual(stagedDacls.length, 4);
  assert.ok(stagedDacls.every((sddl) => !/;;;BU\)/.test(sddl)), 'rollback copies exclude Builtin Users');
  for (const [artifact, sddl] of before) {
    assert.deepStrictEqual(
      canonicalDacl(backup._internal.captureWindowsDacl(artifact)),
      canonicalDacl(sddl),
      'rollback restores the original DACL semantics even if Windows canonicalizes ACE order',
    );
  }
});

test('manifest targets cannot alias SQLite sidecar paths', async () => {
  const outDir = path.join(tempRoot, 'sidecar-target-alias');
  const file = path.join(outDir, 'redactwall.db');
  for (const manifestFile of [
    `${file}-wal`,
    `${file}.audit-state.json`,
    `${file}.audit-checkpoint.json`,
  ]) {
    await assert.rejects(() => backup.createBackup({
      file,
      manifestFile,
      dbModule: db,
    }), /output paths overlap/i);
  }
  assert.strictEqual(fs.existsSync(outDir), false);
});

test('SQLite manifest artifact names are traversal-safe and cannot redirect verification', async () => {
  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'manifest-artifact-traversal'),
    dbModule: db,
  });
  const manifest = JSON.parse(fs.readFileSync(result.manifestFile, 'utf8'));
  manifest.artifacts.auditState.file = '..\\outside-state.json';
  fs.writeFileSync(result.manifestFile, JSON.stringify(manifest, null, 2));

  const verified = backup.verifyBackup({ file: result.file });
  assert.strictEqual(verified.auditIntegrity.ok, true, 'verification reads the deterministic sidecar path');
  assert.strictEqual(verified.manifestOk, false);
  assert.strictEqual(verified.manifestReason, 'artifact-mismatch');
  assert.throws(() => backup.restoreBackup({
    file: result.file,
    to: path.join(tempRoot, 'manifest-artifact-traversal-restore', 'redactwall.db'),
    force: true,
  }), /does not verify/i, 'force never bypasses a present malformed manifest');
});

test('missing, edited, and swapped authenticated sidecars fail verification and restore', async () => {
  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'sidecar-tampering'),
    dbModule: db,
  });
  const originals = new Map([
    [result.auditStateFile, fs.readFileSync(result.auditStateFile)],
    [result.auditCheckpointFile, fs.readFileSync(result.auditCheckpointFile)],
  ]);
  let attempt = 0;
  function assertRejected(label) {
    const verified = backup.verifyBackup({ file: result.file });
    assert.strictEqual(verified.ok, false, `${label} must not verify`);
    assert.strictEqual(verified.auditIntegrity.ok, false, `${label} breaks authenticated integrity`);
    assert.throws(() => backup.restoreBackup({
      file: result.file,
      to: path.join(tempRoot, 'sidecar-tampering-restore', `${attempt++}.db`),
      force: true,
    }), /does not verify|authenticated audit sidecars/i, `${label} must not restore with force`);
  }

  for (const artifact of [result.auditStateFile, result.auditCheckpointFile]) {
    const held = `${artifact}.held`;
    fs.renameSync(artifact, held);
    try { assertRejected(`missing ${path.basename(artifact)}`); }
    finally { fs.renameSync(held, artifact); }
  }

  for (const artifact of [result.auditStateFile, result.auditCheckpointFile]) {
    const parsed = JSON.parse(originals.get(artifact).toString('utf8'));
    parsed.mac = '0'.repeat(64);
    fs.writeFileSync(artifact, JSON.stringify(parsed));
    try { assertRejected(`edited ${path.basename(artifact)}`); }
    finally { fs.writeFileSync(artifact, originals.get(artifact)); }
  }

  const temporary = `${result.auditStateFile}.swap`;
  fs.renameSync(result.auditStateFile, temporary);
  fs.renameSync(result.auditCheckpointFile, result.auditStateFile);
  fs.renameSync(temporary, result.auditCheckpointFile);
  try { assertRejected('swapped state and checkpoint files'); }
  finally {
    fs.renameSync(result.auditStateFile, temporary);
    fs.renameSync(result.auditCheckpointFile, result.auditStateFile);
    fs.renameSync(temporary, result.auditCheckpointFile);
  }
  assert.strictEqual(backup.verifyBackup({ file: result.file }).ok, true, 'restoring exact sidecars restores verification');
});

test('external audit secret is required and wrong secrets cannot be forced through restore', async () => {
  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'external-audit-secret'),
    dbModule: db,
  });
  for (const env of [{}, { REDACTWALL_SECRET: 'wrong-secret' }]) {
    const verified = backup.verifyBackup({ file: result.file, env });
    assert.strictEqual(verified.manifestOk, false, 'the manifest cannot authenticate without the external key');
    assert.strictEqual(verified.manifestReason, 'audit-sidecar-unavailable');
    assert.strictEqual(verified.auditIntegrity.ok, false);
    assert.strictEqual(verified.ok, false);
    assert.throws(() => backup.restoreBackup({
      file: result.file,
      to: path.join(tempRoot, 'external-audit-secret-restore', crypto.randomUUID() + '.db'),
      env,
      force: true,
    }), /does not verify|authenticated audit sidecars/i);
  }
  assert.strictEqual(backup.verifyBackup({
    file: result.file,
    env: { REDACTWALL_SECRET: 'unit-secret-stable' },
  }).ok, true);
});

test('a valid checkpoint from an older backup cannot authenticate a newer snapshot head', async () => {
  const older = await backup.createBackup({
    outDir: path.join(tempRoot, 'checkpoint-swap-older'),
    dbModule: db,
  });
  const added = db.createQuery({ status: 'allowed', redactedPrompt: 'newer snapshot', findings: [] });
  db.appendAudit({ action: 'ALLOWED', queryId: added.id, actor: 'checkpoint-swap-test' });
  const newer = await backup.createBackup({
    outDir: path.join(tempRoot, 'checkpoint-swap-newer'),
    dbModule: db,
  });
  const original = fs.readFileSync(newer.auditCheckpointFile);
  fs.copyFileSync(older.auditCheckpointFile, newer.auditCheckpointFile);
  try {
    const verified = backup.verifyBackup({ file: newer.file });
    assert.strictEqual(verified.ok, false);
    assert.strictEqual(verified.auditIntegrity.reason, 'checkpoint-not-snapshot-head');
    assert.throws(() => backup.restoreBackup({
      file: newer.file,
      to: path.join(tempRoot, 'checkpoint-swap-restore', 'redactwall.db'),
      force: true,
    }), /does not verify/i);
  } finally {
    fs.writeFileSync(newer.auditCheckpointFile, original);
  }
});

test('Postgres verification requires an authenticated dump-to-checkpoint association like SQLite', async () => {
  const older = await backup.createBackup({
    outDir: path.join(tempRoot, 'metadata-association-sqlite-older'),
    dbModule: db,
  });
  const added = db.createQuery({ status: 'allowed', redactedPrompt: 'new association snapshot', findings: [] });
  db.appendAudit({ action: 'ALLOWED', queryId: added.id, actor: 'metadata-association-test' });
  const newer = await backup.createBackup({
    outDir: path.join(tempRoot, 'metadata-association-sqlite-newer'),
    dbModule: db,
  });

  fs.copyFileSync(newer.auditStateFile, older.auditStateFile);
  fs.copyFileSync(newer.auditCheckpointFile, older.auditCheckpointFile);
  const checkpoint = JSON.parse(fs.readFileSync(newer.auditCheckpointFile, 'utf8'));
  const sqliteManifest = JSON.parse(fs.readFileSync(older.manifestFile, 'utf8'));
  sqliteManifest.artifacts.auditState = manifestArtifact(older.auditStateFile);
  sqliteManifest.artifacts.auditCheckpoint = manifestArtifact(older.auditCheckpointFile);
  sqliteManifest.sourceIntegrity = { ok: true, count: checkpoint.count };
  sqliteManifest.backupIntegrity = { ok: true, count: checkpoint.count };
  fs.writeFileSync(older.manifestFile, JSON.stringify(sqliteManifest, null, 2));

  const sqliteVerified = backup.verifyBackup({ file: older.file });
  assert.strictEqual(sqliteVerified.manifestOk, false, 'rewritten SQLite metadata cannot forge the manifest MAC');
  assert.strictEqual(sqliteVerified.manifestReason, 'manifest-authentication');
  assert.strictEqual(sqliteVerified.auditIntegrity.ok, false, 'SQLite opens the snapshot and rejects the swapped checkpoint');
  assert.strictEqual(sqliteVerified.ok, false);

  const pgDir = path.join(tempRoot, 'metadata-association-postgres');
  const dumpFile = path.join(pgDir, 'redactwall.dump');
  const manifestFile = `${dumpFile}.manifest.json`;
  const pgAuditPaths = portableAuditPaths(dumpFile);
  fs.mkdirSync(pgDir, { recursive: true });
  fs.writeFileSync(dumpFile, Buffer.from('PGDMPsynthetic-unrelated-snapshot'));
  fs.copyFileSync(newer.auditStateFile, pgAuditPaths.statePath);
  fs.copyFileSync(newer.auditCheckpointFile, pgAuditPaths.checkpointPath);
  const artifacts = {
    database: manifestArtifact(dumpFile),
    auditState: manifestArtifact(pgAuditPaths.statePath),
    auditCheckpoint: manifestArtifact(pgAuditPaths.checkpointPath),
  };
  const pgManifest = {
    schemaVersion: 2,
    driver: 'postgres',
    format: 'pg_dump-custom',
    backupFile: artifacts.database.file,
    backupBytes: artifacts.database.bytes,
    backupSha256: artifacts.database.sha256,
    artifacts,
    sourceIntegrity: { ok: true, count: checkpoint.count },
    backupIntegrity: { ok: true, count: checkpoint.count },
  };
  fs.writeFileSync(manifestFile, JSON.stringify(pgManifest, null, 2));

  const pgVerified = backup.verifyBackup({ file: dumpFile, security: FAKE_WINDOWS_ACL });
  assert.strictEqual(pgVerified.ok, false, 'an unsigned manifest must not associate an arbitrary dump with a valid checkpoint');
  assert.strictEqual(pgVerified.manifestOk, false);
  assert.strictEqual(pgVerified.manifestReason, 'manifest-authentication');
});

test('Postgres backup output and manifest use the same private exact artifact contract', async () => {
  const outDir = path.join(tempRoot, 'private-pg-artifacts');
  const checkpoint = JSON.parse(fs.readFileSync(db._auditAnchorPaths.checkpointPath, 'utf8'));
  const result = await backup.createBackup({
    outDir,
    dbModule: {
      _driverKind: 'postgres',
      _auditAnchorPaths: db._auditAnchorPaths,
      verifyAuditChain: () => ({ ok: true, count: checkpoint.count }),
      stats: () => ({ total: 0 }),
    },
    connectionString: 'postgresql://backup@db.example.test/redactwall?sslmode=require',
    withPgSnapshot: (_connectionString, callback) => callback({
      snapshotId: '00000003-0000001A-1',
      sourceIntegrity: { ok: true, count: checkpoint.count },
      exactCheckpoint: checkpoint,
      stats: { total: 0, pending: 0, approved: 0, denied: 0, allowed: 0, todayBlocked: 0, topEntities: [] },
    }),
    runPgTool(tool, args) {
      assert.strictEqual(tool, 'pg_dump');
      const output = args.find((arg) => arg.startsWith('--file=')).slice('--file='.length);
      fs.writeFileSync(output, Buffer.from('PGDMPsynthetic'));
      return { status: 0 };
    },
  });
  assert.strictEqual(result.driver, 'postgres');
  assert.deepStrictEqual(fs.readdirSync(outDir).sort(), [
    path.basename(result.file),
    path.basename(result.auditStateFile),
    path.basename(result.auditCheckpointFile),
    path.basename(result.manifestFile),
  ].sort());
  assert.deepStrictEqual(result.manifest.checkpoint, checkpoint);
  assert.deepStrictEqual(Object.keys(result.manifest.manifestAuthentication).sort(), ['algorithm', 'mac', 'version']);
  assert.match(result.manifest.manifestAuthentication.mac, /^[a-f0-9]{64}$/);
  assert.strictEqual(backup.verifyBackup({ file: result.file }).ok, true);
  if (process.platform !== 'win32') {
    assert.strictEqual(permissionBits(result.file), 0o600);
    assert.strictEqual(permissionBits(result.auditStateFile), 0o600);
    assert.strictEqual(permissionBits(result.auditCheckpointFile), 0o600);
    assert.strictEqual(permissionBits(result.manifestFile), 0o600);
  }

  const originalManifest = fs.readFileSync(result.manifestFile);
  const tamperedManifests = [
    (manifest) => { delete manifest.manifestAuthentication; },
    (manifest) => { delete manifest.checkpoint; },
    (manifest) => { manifest.checkpoint.count += 1; },
  ];
  for (const mutate of tamperedManifests) {
    const manifest = JSON.parse(originalManifest.toString('utf8'));
    mutate(manifest);
    fs.writeFileSync(result.manifestFile, JSON.stringify(manifest, null, 2));
    const verified = backup.verifyBackup({ file: result.file });
    assert.strictEqual(verified.ok, false);
    assert.strictEqual(verified.manifestOk, false);
    assert.strictEqual(verified.manifestReason, 'manifest-authentication');
    if (!manifest.manifestAuthentication) {
      assert.throws(() => backup._internal.restorePgBackup({
        file: result.file,
        manifestFile: result.manifestFile,
        to: 'postgresql://restore@db.example.test/redactwall_restore?sslmode=require',
        force: true,
      }), /does not verify/i, 'force must not bypass a present unauthenticated Postgres manifest');
    }
  }
  fs.writeFileSync(result.manifestFile, originalManifest);
  assert.strictEqual(backup.verifyBackup({ file: result.file }).ok, true);
});

test('Postgres dump and manifest evidence share one exported snapshot', async () => {
  const events = [];
  const snapshotId = '00000003-0000001B-1';
  const checkpoint = JSON.parse(fs.readFileSync(db._auditAnchorPaths.checkpointPath, 'utf8'));
  const snapshotEvidence = {
    sourceIntegrity: { ok: true, count: checkpoint.count },
    exactCheckpoint: checkpoint,
    stats: {
      total: 5,
      pending: 1,
      approved: 1,
      denied: 1,
      allowed: 2,
      todayBlocked: 2,
      topEntities: [['US_SSN', 3]],
    },
  };
  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'pg-snapshot-orchestration'),
    dbModule: {
      _driverKind: 'postgres',
      _auditAnchorPaths: db._auditAnchorPaths,
      verifyAuditChain: () => ({ ok: true, count: 999 }),
      stats: () => { throw new Error('live stats must not enter a dump manifest'); },
    },
    connectionString: 'postgresql://backup@db.example.test/redactwall?sslmode=require',
    async withPgSnapshot(connectionString, callback) {
      assert.strictEqual(connectionString, 'postgresql://backup@db.example.test/redactwall?sslmode=require');
      events.push('snapshot-open');
      const value = await callback({ snapshotId, ...snapshotEvidence });
      events.push('snapshot-committed');
      return value;
    },
    runPgTool(tool, args) {
      events.push('dump');
      assert.strictEqual(tool, 'pg_dump');
      assert.ok(args.includes(`--snapshot=${snapshotId}`));
      const output = args.find((arg) => arg.startsWith('--file=')).slice('--file='.length);
      fs.writeFileSync(output, Buffer.from('PGDMPsynthetic'));
      return { status: 0 };
    },
  });

  assert.deepStrictEqual(events, ['snapshot-open', 'dump', 'snapshot-committed']);
  assert.deepStrictEqual(result.manifest.sourceIntegrity, snapshotEvidence.sourceIntegrity);
  assert.deepStrictEqual(result.manifest.stats, snapshotEvidence.stats);
});

test('Postgres snapshot coordinator holds a repeatable-read read-only transaction through callback', async () => {
  const events = [];
  const today = new Date().toISOString();
  const key = crypto.createHash('sha256')
    .update(`redactwall:audit-auth:v1:${process.env.REDACTWALL_SECRET}`)
    .digest();
  const checkpoint = auditIntegrity.createCheckpoint(0, auditIntegrity.ZERO, key, 0);
  const client = {
    async connect() { events.push('connect'); },
    async query(sql) {
      events.push(sql);
      if (sql.includes('pg_export_snapshot')) {
        return { rows: [{ snapshot_id: '00000003-0000001C-1' }] };
      }
      if (sql === 'SELECT seq, entry FROM audit ORDER BY seq ASC') return { rows: [] };
      if (sql.startsWith('SELECT status,')) {
        return {
          rows: [{
            status: 'pending',
            createdAt: today,
            data: JSON.stringify({ entityCounts: { US_SSN: 1 } }),
          }],
        };
      }
      return { rows: [] };
    },
    async end() { events.push('end'); },
  };

  const result = await backup._internal.withPgSnapshot(
    'postgresql://backup@db.example.test/redactwall?sslmode=require',
    async (evidence) => {
      events.push('callback');
      assert.strictEqual(events.includes('COMMIT'), false, 'exporting transaction remains open during pg_dump callback');
      assert.strictEqual(evidence.sourceIntegrity.count, 0);
      assert.deepStrictEqual(evidence.exactCheckpoint, checkpoint);
      assert.strictEqual(evidence.stats.total, 1);
      return 'dump-finished';
    },
    { createClient: () => client, sourceAnchor: { key, checkpoint } },
  );

  assert.strictEqual(result, 'dump-finished');
  assert.deepStrictEqual(events, [
    'connect',
    'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY',
    'SELECT pg_export_snapshot() AS snapshot_id',
    'SELECT seq, entry FROM audit ORDER BY seq ASC',
    'SELECT status, "createdAt" AS "createdAt", data FROM queries ORDER BY seq ASC',
    'callback',
    'COMMIT',
    'end',
  ]);
});

test('Postgres snapshot integrity verifies both the hash chain and bound query evidence', async () => {
  const query = { id: 'q_snapshot', status: 'blocked', redactedPrompt: 'Member [US_SSN]' };
  const body = {
    id: 'a_snapshot',
    ts: new Date().toISOString(),
    prevHash: auditIntegrity.ZERO,
    action: 'BLOCKED',
    queryId: query.id,
    actor: 'snapshot-test',
    detail: '',
    contentHash: auditIntegrity.sha(auditIntegrity.canonical(query)),
  };
  const entry = {
    ...body,
    hash: auditIntegrity.sha(auditIntegrity.canonical(body)),
  };
  const key = crypto.createHash('sha256')
    .update(`redactwall:audit-auth:v1:${process.env.REDACTWALL_SECRET}`)
    .digest();
  const checkpoint = auditIntegrity.createCheckpoint(1, entry.hash, key, 1);
  const anchor = { key, checkpoint };
  const clientFor = (storedQuery) => ({
    async query(sql, params) {
      if (sql.startsWith('SELECT seq, entry FROM audit')) return { rows: [{ seq: 1, entry: JSON.stringify(entry) }] };
      assert.deepStrictEqual(params, [[query.id]]);
      return storedQuery === null
        ? { rows: [] }
        : { rows: [{ id: query.id, data: JSON.stringify(storedQuery) }] };
    },
  });

  const verified = await backup._internal.verifyPgSnapshotIntegrity(clientFor(query), anchor);
  assert.strictEqual(verified.ok, true);
  assert.strictEqual(verified.count, 1);
  assert.deepStrictEqual(verified.exactCheckpoint, checkpoint);
  assert.strictEqual(
    (await backup._internal.verifyPgSnapshotIntegrity(clientFor({ ...query, status: 'allowed' }), anchor)).reason,
    'evidence',
  );
  assert.strictEqual(
    (await backup._internal.verifyPgSnapshotIntegrity(clientFor(null), anchor)).reason,
    'evidence-missing',
  );
});

test('N6: a backup with a missing or unsigned manifest is refused even with --force', async () => {
  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'no-manifest'), dbModule: db });
  const originalManifest = fs.readFileSync(result.manifestFile, 'utf8');
  fs.rmSync(result.manifestFile); // an operator/attacker drops the manifest
  const verified = backup.verifyBackup({ file: result.file });
  assert.strictEqual(verified.auditIntegrity.ok, true, 'DB itself is intact');
  assert.strictEqual(verified.unverifiable, true, 'no manifest => unverifiable');
  assert.strictEqual(verified.ok, false, 'a manifest-less backup is not a pass');
  assert.throws(
    () => backup.restoreBackup({ file: result.file, to: path.join(tempRoot, 'no-manifest-restore', 'redactwall.db') }),
    /authenticated manifest/,
    'restore refuses a manifest-less backup',
  );
  assert.throws(
    () => backup.restoreBackup({
      file: result.file,
      to: path.join(tempRoot, 'no-manifest-forced', 'redactwall.db'),
      force: true,
    }),
    /authenticated manifest/i,
    '--force replaces an existing target but never bypasses backup authentication',
  );

  const unsigned = JSON.parse(originalManifest);
  delete unsigned.manifestAuthentication;
  fs.writeFileSync(result.manifestFile, JSON.stringify(unsigned, null, 2));
  const unsignedVerification = backup.verifyBackup({ file: result.file });
  assert.strictEqual(unsignedVerification.manifestOk, false);
  assert.strictEqual(unsignedVerification.manifestReason, 'manifest-authentication');
  assert.throws(
    () => backup.restoreBackup({
      file: result.file,
      to: path.join(tempRoot, 'unsigned-manifest-forced', 'redactwall.db'),
      force: true,
    }),
    /does not verify/i,
    '--force must not bypass an unsigned SQLite manifest',
  );
});

test('verify CLI exits nonzero when the printed verification result is not ok', async () => {
  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'cli-unverifiable'), dbModule: db });
  fs.rmSync(result.manifestFile);

  const cli = spawnSync(process.execPath, [
    path.join(__dirname, '..', 'scripts', 'backup-store.js'),
    'verify',
    result.file,
  ], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    env: { ...process.env },
  });

  assert.strictEqual(cli.status, 1, cli.stderr || cli.stdout);
  const printed = JSON.parse(cli.stdout);
  assert.strictEqual(printed.ok, false);
  assert.strictEqual(printed.unverifiable, true);
});

test('manifest hash mismatch makes verification fail and blocks restore', async () => {
  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'manifest-mismatch'), dbModule: db });
  const manifest = JSON.parse(fs.readFileSync(result.manifestFile, 'utf8'));
  manifest.backupSha256 = '0'.repeat(64);
  fs.writeFileSync(result.manifestFile, JSON.stringify(manifest, null, 2));

  const verified = backup.verifyBackup({ file: result.file });
  assert.strictEqual(verified.auditIntegrity.ok, true);
  assert.strictEqual(verified.manifestOk, false);
  assert.strictEqual(verified.ok, false);
  assert.throws(
    () => backup.restoreBackup({ file: result.file, to: path.join(tempRoot, 'mismatched-restore', 'redactwall.db') }),
    /does not verify/,
  );
});

test('SQLite privileged-row tampering cannot be hidden by rewriting manifest size and SHA-256', async () => {
  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'manifest-privileged-row-tamper'),
    dbModule: db,
  });
  const attacker = new Database(result.file);
  try {
    const timestamp = new Date().toISOString();
    attacker.prepare(`
      INSERT INTO admin_users
        (id, orgId, userName, displayName, role, active, createdAt, updatedAt, data)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'forged-security-admin',
      'default',
      'forged-admin@example.test',
      'Forged Administrator',
      'security_admin',
      1,
      timestamp,
      timestamp,
      JSON.stringify({ passwordHash: 'attacker-controlled' }),
    );
  } finally {
    attacker.close();
  }

  const manifest = JSON.parse(fs.readFileSync(result.manifestFile, 'utf8'));
  const rewritten = manifestArtifact(result.file);
  manifest.artifacts.database = rewritten;
  manifest.backupFile = rewritten.file;
  manifest.backupBytes = rewritten.bytes;
  manifest.backupSha256 = rewritten.sha256;
  fs.writeFileSync(result.manifestFile, JSON.stringify(manifest, null, 2));

  const verified = backup.verifyBackup({ file: result.file });
  assert.strictEqual(verified.auditIntegrity.ok, true, 'the forged privileged row is outside query audit linkage');
  assert.strictEqual(verified.manifestOk, false);
  assert.strictEqual(verified.manifestReason, 'manifest-authentication');
  assert.strictEqual(verified.ok, false);
  assert.throws(() => backup.restoreBackup({
    file: result.file,
    to: path.join(tempRoot, 'manifest-privileged-row-tamper-restore', 'redactwall.db'),
    force: true,
  }), /does not verify/i);
});

test('SQLite rejects a manifest forged with the embedded key packaged beside the backup', async () => {
  const result = await backup.createBackup({
    outDir: path.join(tempRoot, 'embedded-manifest-key'),
    dbModule: db,
  });
  const attackerKey = Buffer.alloc(32, 0x41);
  const originalCheckpoint = JSON.parse(fs.readFileSync(result.auditCheckpointFile, 'utf8'));
  fs.writeFileSync(
    result.auditStateFile,
    JSON.stringify(auditAnchor.signedState(attackerKey, true, true)),
  );
  fs.writeFileSync(
    result.auditCheckpointFile,
    JSON.stringify(auditIntegrity.createCheckpoint(
      originalCheckpoint.count,
      originalCheckpoint.head,
      attackerKey,
      originalCheckpoint.seq,
    )),
  );

  const packagedState = JSON.parse(fs.readFileSync(result.auditStateFile, 'utf8'));
  assert.strictEqual(packagedState.key, attackerKey.toString('base64'), 'the attacker can recover the bundled key');
  const storedManifest = JSON.parse(fs.readFileSync(result.manifestFile, 'utf8'));
  const { manifestAuthentication: _oldAuthentication, ...forgedBody } = storedManifest;
  forgedBody.artifacts.auditState = manifestArtifact(result.auditStateFile);
  forgedBody.artifacts.auditCheckpoint = manifestArtifact(result.auditCheckpointFile);
  const forgedManifest = {
    ...forgedBody,
    manifestAuthentication: {
      version: 1,
      algorithm: 'hmac-sha256',
      mac: auditIntegrity.hmac(attackerKey, auditIntegrity.canonical(forgedBody)),
    },
  };
  fs.writeFileSync(result.manifestFile, JSON.stringify(forgedManifest, null, 2));

  const verified = backup.verifyBackup({ file: result.file, env: {} });
  assert.strictEqual(verified.ok, false);
  assert.strictEqual(verified.manifestOk, false);
  assert.strictEqual(verified.manifestReason, 'manifest-authentication-key');
  const restoreTarget = path.join(tempRoot, 'embedded-manifest-key-restore', 'redactwall.db');
  assert.throws(() => backup.restoreBackup({
    file: result.file,
    to: restoreTarget,
    force: true,
    env: {},
  }), /does not verify/i);
  assert.strictEqual(fs.existsSync(restoreTarget), false);
});

test('SQLite backup creation requires an external audit key', () => {
  const childRoot = path.join(tempRoot, 'embedded-key-create');
  const childDb = path.join(childRoot, 'redactwall.db');
  const childAudit = path.join(childRoot, 'audit');
  const childOut = path.join(childRoot, 'backups');
  fs.mkdirSync(childRoot, { recursive: true });
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    REDACTWALL_ENV_PATH: path.join(childRoot, 'no.env'),
    REDACTWALL_DB_DRIVER: 'sqlite',
    REDACTWALL_DB_PATH: childDb,
    REDACTWALL_AUDIT_DIR: childAudit,
  };
  delete env.REDACTWALL_AUDIT_KEY;
  delete env.REDACTWALL_SECRET;
  delete env.PROMPTWALL_SECRET;
  delete env.SENTINEL_SECRET;
  const script = `
    (async () => {
      const db = require('./server/db');
      const backup = require('./scripts/backup-store');
      try {
        await backup.createBackup({ outDir: ${JSON.stringify(childOut)}, dbModule: db, env: {} });
        process.exitCode = 2;
      } catch (error) {
        console.log(error.message);
        if (!/requires REDACTWALL_AUDIT_KEY or REDACTWALL_SECRET/.test(error.message)) process.exitCode = 3;
      } finally {
        db._db.close();
      }
    })();
  `;
  const run = spawnSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env,
    encoding: 'utf8',
    timeout: 30_000,
  });
  assert.strictEqual(run.status, 0, run.stderr || run.stdout);
  assert.match(run.stdout, /embedded audit keys are not independent of the backup/);
  assert.strictEqual(fs.existsSync(childOut), false, 'creation stops before staging backup artifacts');
});

test('restore refuses to overwrite an existing target unless forced', async () => {
  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'overwrite'), dbModule: db });
  const target = path.join(tempRoot, 'existing-restore', 'redactwall.db');
  preparePrivateRestoreDirectory(path.dirname(target), () => {
    fs.writeFileSync(target, 'already here');
  });
  assert.throws(() => backup.restoreBackup({ file: result.file, to: target }), /already exists/);
  assert.strictEqual(backup.restoreBackup({ file: result.file, to: target, force: true }).ok, true);
});

test('create refuses to overwrite an explicit backup target unless forced', async () => {
  const target = path.join(tempRoot, 'explicit', 'redactwall.db');
  await backup.createBackup({ file: target, dbModule: db });
  await assert.rejects(() => backup.createBackup({ file: target, dbModule: db }), /already exists/);
  const forced = await backup.createBackup({ file: target, dbModule: db, force: true });
  assert.strictEqual(forced.ok, true);
});

test('create refuses existing manifest before writing a backup file', async () => {
  const target = path.join(tempRoot, 'manifest-collision', 'redactwall.db');
  const manifest = `${target}.manifest.json`;
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(manifest, '{"reserved":true}');

  await assert.rejects(
    () => backup.createBackup({ file: target, manifestFile: manifest, dbModule: db }),
    /already exists/,
  );
  assert.strictEqual(fs.existsSync(target), false);
});

test('create refuses to back up a database with broken audit integrity', async () => {
  await assert.rejects(() => backup.createBackup({
    dbModule: {
      verifyAuditChain() {
        return { ok: false, reason: 'hash_mismatch' };
      },
    },
  }), /broken audit integrity: hash_mismatch/);
});

test('argument parser preserves positional paths for npm-run portability', () => {
  assert.deepStrictEqual(
    backup.parseArgs(['create', 'backups']),
    { _: ['create', 'backups'] },
  );
  assert.deepStrictEqual(
    backup.parseArgs(['verify', '--file', 'backups/redactwall.db', '--manifest', 'manifest.json']),
    { _: ['verify'], file: 'backups/redactwall.db', manifest: 'manifest.json' },
  );
  assert.deepStrictEqual(
    backup.parseArgs(['restore', 'backups/redactwall.db', 'data/restored.db', '--force']),
    { _: ['restore', 'backups/redactwall.db', 'data/restored.db'], force: true },
  );
});

test('main dispatches create, verify, and restore commands with JSON output', async () => {
  const io = captureConsole();
  const calls = [];
  const deps = {
    console: io,
    async createBackup(opts) {
      calls.push(['create', opts]);
      return { ok: true, command: 'create' };
    },
    verifyBackup(opts) {
      calls.push(['verify', opts]);
      return { ok: true, command: 'verify' };
    },
    restoreBackup(opts) {
      calls.push(['restore', opts]);
      return { ok: true, command: 'restore' };
    },
  };

  assert.deepStrictEqual(await backup.main(['create', 'out-dir', '--file', 'backup.db', '--manifest', 'manifest.json', '--force'], deps), { ok: true, command: 'create' });
  assert.deepStrictEqual(await backup.main(['verify', 'backup.db', '--manifest', 'manifest.json'], deps), { ok: true, command: 'verify' });
  assert.deepStrictEqual(await backup.main(['restore', 'backup.db', 'restore.db', '--force'], deps), { ok: true, command: 'restore' });
  await assert.rejects(() => backup.main(['unknown'], deps), /unknown command/);

  assert.deepStrictEqual(calls, [
    ['create', { outDir: 'out-dir', file: 'backup.db', manifestFile: 'manifest.json', force: true }],
    ['verify', { file: 'backup.db', manifestFile: 'manifest.json' }],
    ['restore', { file: 'backup.db', to: 'restore.db', manifestFile: undefined, force: true }],
  ]);
  assert.strictEqual(JSON.parse(io.lines[0]).command, 'create');
  assert.strictEqual(JSON.parse(io.lines[1]).command, 'verify');
  assert.strictEqual(JSON.parse(io.lines[2]).command, 'restore');
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
