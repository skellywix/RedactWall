'use strict';
/**
 * Data-key rotation workflow (scripts/rotate-data-key.js).
 * The crypto module derives keys from env at require time, so each phase runs
 * in a child process with explicit keys against a temp SQLite store.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { execFileSync, spawnSync } = require('node:child_process');
const Database = require('better-sqlite3');

// Needed so requiring the script (which requires server/crypto) sees a key.
process.env.REDACTWALL_DATA_KEY = process.env.REDACTWALL_DATA_KEY || 'unit-test-stable-key';
const rotateScript = path.join(__dirname, '..', 'scripts', 'rotate-data-key.js');
const rotate = require('../scripts/rotate-data-key');
const root = path.join(__dirname, '..');

const OLD_KEY = 'rotation-old-key-A';
const NEW_KEY = 'rotation-new-key-B';
const SECRET_SSN = '524-71-9043';

function childEnv(dbPath, keys = {}) {
  return {
    ...process.env,
    REDACTWALL_ENV_PATH: path.join(os.tmpdir(), 'ps-rotate-test-missing.env'),
    REDACTWALL_DB_PATH: dbPath,
    REDACTWALL_SECRET: '',
    REDACTWALL_DATA_KEY: '',
    REDACTWALL_DATA_KEY_PREVIOUS: '',
    REDACTWALL_SECRET: '',
    REDACTWALL_DATA_KEY: '',
    REDACTWALL_DATA_KEY_PREVIOUS: '',
    ...keys,
  };
}

const SEED_SCRIPT = `
  const db = require('./server/db');
  const c = require('./server/crypto');
  const specs = JSON.parse(process.argv[1]);
  const out = [];
  for (const spec of specs) {
    const record = { status: 'held', user: 'analyst@example.test', redactedPrompt: 'Member [US_SSN]' };
    if (spec.raw) record._rawPrompt = c.seal(spec.raw);
    if (spec.vault) record._tokenVault = c.seal(JSON.stringify(spec.vault));
    if (spec.presealedRaw) record._rawPrompt = spec.presealedRaw;
    const q = db.createQuery(record);
    out.push({ id: q.id, rawToken: q._rawPrompt || null, vaultToken: q._tokenVault || null });
  }
  db._db.close();
  process.stdout.write(JSON.stringify(out));
`;

function seedQueries(dbPath, sealKey, specs) {
  const out = execFileSync(process.execPath, ['-e', SEED_SCRIPT, JSON.stringify(specs)], {
    cwd: root,
    encoding: 'utf8',
    env: childEnv(dbPath, { REDACTWALL_DATA_KEY: sealKey }),
  });
  return JSON.parse(out);
}

function sealUnderKey(key, plaintext) {
  return execFileSync(process.execPath, ['-e', "process.stdout.write(require('./server/crypto').seal(process.argv[1]));", plaintext], {
    cwd: root,
    encoding: 'utf8',
    env: childEnv(path.join(os.tmpdir(), 'unused.db'), { REDACTWALL_DATA_KEY: key }),
  });
}

function openUnderKeys(dbPath, keys, token) {
  const out = execFileSync(process.execPath, ['-e', "process.stdout.write(JSON.stringify(require('./server/crypto').open(process.argv[1])));", token], {
    cwd: root,
    encoding: 'utf8',
    env: childEnv(dbPath, keys),
  });
  return JSON.parse(out);
}

function runRotation(dbPath, keys, args = []) {
  return spawnSync(process.execPath, [rotateScript, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: childEnv(dbPath, keys),
  });
}

function readStore(dbPath) {
  const sdb = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    return {
      queries: sdb.prepare('SELECT data FROM queries ORDER BY seq').all().map((r) => JSON.parse(r.data)),
      audit: sdb.prepare('SELECT entry FROM audit ORDER BY seq').all().map((r) => JSON.parse(r.entry)),
    };
  } finally {
    sdb.close();
  }
}

test('rotation reseals old-key tokens so they open with the new key only', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-rotate-test-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const dbPath = path.join(tempRoot, 'redactwall.db');
  const rotationKeys = { REDACTWALL_DATA_KEY: NEW_KEY, REDACTWALL_DATA_KEY_PREVIOUS: OLD_KEY };

  const seeded = seedQueries(dbPath, OLD_KEY, [
    { raw: 'Member SSN ' + SECRET_SSN, vault: { '[US_SSN]': SECRET_SSN } },
    { raw: 'card 4111 1111 1111 1111' },
    {}, // no sealed fields — scanned but untouched
  ]);

  // Dry run reports the work without writing anything.
  const dry = runRotation(dbPath, rotationKeys, ['--dry-run']);
  assert.strictEqual(dry.status, 0, dry.stderr || dry.stdout);
  assert.deepStrictEqual(JSON.parse(dry.stdout), { ok: true, dryRun: true, scanned: 3, resealed: 3, unreadable: 0 });
  const afterDry = readStore(dbPath);
  assert.strictEqual(afterDry.queries[0]._rawPrompt, seeded[0].rawToken, 'dry run leaves tokens untouched');
  assert.strictEqual(afterDry.queries[0]._tokenVault, seeded[0].vaultToken);
  assert.strictEqual(afterDry.audit.length, 0, 'dry run appends no audit entry');

  // Real run reseals every old-key token.
  const run = runRotation(dbPath, rotationKeys);
  assert.strictEqual(run.status, 0, run.stderr || run.stdout);
  assert.deepStrictEqual(JSON.parse(run.stdout), { ok: true, dryRun: false, scanned: 3, resealed: 3, unreadable: 0 });
  assert.ok(!run.stdout.includes(SECRET_SSN) && !run.stdout.includes(OLD_KEY) && !run.stdout.includes(NEW_KEY), 'output has no plaintext or key material');

  const after = readStore(dbPath);
  assert.notStrictEqual(after.queries[0]._rawPrompt, seeded[0].rawToken, 'raw prompt token was rewritten');
  assert.notStrictEqual(after.queries[0]._tokenVault, seeded[0].vaultToken, 'token vault was rewritten');
  const newKeyOnly = { REDACTWALL_DATA_KEY: NEW_KEY };
  assert.strictEqual(openUnderKeys(dbPath, newKeyOnly, after.queries[0]._rawPrompt), 'Member SSN ' + SECRET_SSN, 'opens with the new key alone');
  assert.deepStrictEqual(JSON.parse(openUnderKeys(dbPath, newKeyOnly, after.queries[0]._tokenVault)), { '[US_SSN]': SECRET_SSN });
  assert.strictEqual(openUnderKeys(dbPath, newKeyOnly, after.queries[1]._rawPrompt), 'card 4111 1111 1111 1111');
  assert.strictEqual(openUnderKeys(dbPath, { REDACTWALL_DATA_KEY: OLD_KEY }, after.queries[0]._rawPrompt), null, 'old key can no longer open the data');

  // One audit entry, counts only, no plaintext.
  assert.strictEqual(after.audit.length, 1);
  assert.strictEqual(after.audit[0].action, 'DATA_KEY_ROTATED');
  assert.strictEqual(after.audit[0].actor, 'operator');
  assert.deepStrictEqual(JSON.parse(after.audit[0].detail), { scanned: 3, resealed: 3, unreadable: 0 });
  assert.ok(!JSON.stringify(after.audit).includes(SECRET_SSN));

  // A second run is a no-op and appends no further audit entries.
  const again = runRotation(dbPath, rotationKeys);
  assert.strictEqual(again.status, 0, again.stderr || again.stdout);
  assert.deepStrictEqual(JSON.parse(again.stdout), { ok: true, dryRun: false, scanned: 3, resealed: 0, unreadable: 0 });
  assert.strictEqual(readStore(dbPath).audit.length, 1, 'no-op run appends no audit entry');
});

test('a sealed value unreadable with both keys exits 1 and is reported in counts', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-rotate-test-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const dbPath = path.join(tempRoot, 'redactwall.db');

  const orphanToken = sealUnderKey('some-lost-key-Z', 'Member SSN ' + SECRET_SSN);
  seedQueries(dbPath, OLD_KEY, [
    { raw: 'Member SSN ' + SECRET_SSN },
    { presealedRaw: orphanToken },
  ]);

  const run = runRotation(dbPath, { REDACTWALL_DATA_KEY: NEW_KEY, REDACTWALL_DATA_KEY_PREVIOUS: OLD_KEY });
  assert.strictEqual(run.status, 1, 'unreadable sealed data fails the run');
  assert.deepStrictEqual(JSON.parse(run.stdout), { ok: false, dryRun: false, scanned: 2, resealed: 1, unreadable: 1 });
  assert.ok(!run.stdout.includes(SECRET_SSN), 'failure output has no plaintext');
});

test('refuses to run without the new and previous keys configured', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-rotate-test-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const dbPath = path.join(tempRoot, 'redactwall.db');

  const noKeys = runRotation(dbPath, {});
  assert.strictEqual(noKeys.status, 1);
  assert.match(noKeys.stderr, /REDACTWALL_DATA_KEY/);

  const noPrevious = runRotation(dbPath, { REDACTWALL_DATA_KEY: NEW_KEY });
  assert.strictEqual(noPrevious.status, 1);
  assert.match(noPrevious.stderr, /REDACTWALL_DATA_KEY_PREVIOUS/);
  assert.strictEqual(fs.existsSync(dbPath), false, 'refusal happens before the store is touched');
});

test('parseArgs recognizes --dry-run and keeps positionals', () => {
  assert.deepStrictEqual(rotate.parseArgs([]), { _: [] });
  assert.deepStrictEqual(rotate.parseArgs(['--dry-run']), { _: [], dryRun: true });
  assert.deepStrictEqual(rotate.parseArgs(['extra', '--dry-run']), { _: ['extra'], dryRun: true });
});

test('main dispatches rotation, audits real reseals, and skips audit on dry runs', async () => {
  const lines = [];
  const auditEntries = [];
  const calls = [];
  const deps = {
    console: { log: (m) => lines.push(m) },
    dataCrypto: { rotationStatus: () => ({ enabled: true, previousKeyConfigured: true }) },
    db: { appendAudit: (e) => auditEntries.push(e) },
    rotateDataKey: (opts) => {
      calls.push(opts.dryRun);
      return { scanned: 2, resealed: 1, unreadable: 0 };
    },
  };

  const dry = await rotate.main(['--dry-run'], deps);
  assert.deepStrictEqual(dry, { ok: true, dryRun: true, scanned: 2, resealed: 1, unreadable: 0 });
  assert.strictEqual(auditEntries.length, 0, 'dry run never writes audit');

  const real = await rotate.main([], deps);
  assert.deepStrictEqual(real, { ok: true, dryRun: false, scanned: 2, resealed: 1, unreadable: 0 });
  assert.deepStrictEqual(calls, [true, false]);
  assert.strictEqual(auditEntries.length, 1);
  assert.strictEqual(auditEntries[0].action, 'DATA_KEY_ROTATED');
  assert.strictEqual(auditEntries[0].actor, 'operator');
  assert.deepStrictEqual(JSON.parse(auditEntries[0].detail), { scanned: 2, resealed: 1, unreadable: 0 });
  assert.strictEqual(JSON.parse(lines[1]).ok, true);

  await assert.rejects(
    () => rotate.main([], { ...deps, dataCrypto: { rotationStatus: () => ({ enabled: true, previousKeyConfigured: false }) } }),
    /REDACTWALL_DATA_KEY_PREVIOUS/,
  );
});
