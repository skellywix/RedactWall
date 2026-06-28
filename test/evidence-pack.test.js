'use strict';
/** Evidence-pack CLI must preserve backup proof without leaking prompt bodies. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const AdmZip = require('adm-zip');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-evidence-pack-test-'));
process.env.SENTINEL_DB_PATH = path.join(tempRoot, 'sentinel.db');
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';

const db = require('../server/db');
const backup = require('../scripts/backup-store');
const packer = require('../scripts/export-evidence-pack');

test('writes examiner pack with backup and restore evidence without raw prompt content', async () => {
  const ssn = '524-71-9043';
  const apiKey = 'sk-proj-test-secret-should-not-export';
  const releaseToken = 'release-token-should-not-export';
  const q = db.createQuery({
    status: 'pending',
    mode: 'block',
    user: 'analyst@example.test',
    source: 'browser_extension',
    channel: 'submit',
    destination: 'chatgpt.com',
    redactedPrompt: 'Member [US_SSN] with key [SECRET_KEY]',
    _rawPrompt: `Member Carter SSN ${ssn} has key ${apiKey}`,
    _releaseTokenHash: releaseToken,
    findings: [
      { type: 'US_SSN', severity: 4, score: 1, masked: '***-**-9043', value: ssn },
      { type: 'SECRET_KEY', severity: 4, score: 1, masked: 'sk-...export', value: apiKey },
    ],
    categories: [],
    reasons: ['Hard-stop entity present: US_SSN'],
    riskScore: 40,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    entityCounts: { US_SSN: 1, SECRET_KEY: 1 },
  });
  db.appendAudit({
    action: 'BLOCKED',
    queryId: q.id,
    actor: 'analyst@example.test',
    detail: `blocked raw prompt ${ssn} ${apiKey} ${releaseToken}`,
  });

  const backupResult = await backup.createBackup({ outDir: path.join(tempRoot, 'backups'), dbModule: db });
  const restoredPath = path.join(tempRoot, 'restore-drill', 'sentinel.db');
  backup.restoreBackup({ file: backupResult.file, to: restoredPath });

  const schedulePath = path.join(tempRoot, 'evidence-schedule.json');
  fs.writeFileSync(schedulePath, JSON.stringify({
    id: 'quarterly-examiner-pack',
    enabled: true,
    cadence: 'quarterly',
    nextRunAt: '2026-09-30T23:00:00.000Z',
    retentionDays: 730,
    outDir: path.join(tempRoot, 'configured-output'),
    queryLimit: 100,
    auditLimit: 100,
    secret: 'schedule-secret-should-not-export',
  }, null, 2));
  const schedule = packer.loadScheduleConfig(schedulePath);

  const result = packer.writeEvidencePack({
    outDir: path.join(tempRoot, 'packs'),
    zip: true,
    generatedBy: 'unit-test',
    scheduled: schedule.scheduled,
    schedule: schedule.schedule,
    queryLimit: schedule.queryLimit,
    auditLimit: schedule.auditLimit,
    backupFile: backupResult.file,
    backupManifestFile: backupResult.manifestFile,
    restoreDrillFile: restoredPath,
  });

  assert.ok(fs.existsSync(result.file));
  assert.ok(fs.existsSync(result.zipFile));
  const zip = new AdmZip(result.zipFile);
  assert.deepStrictEqual(zip.getEntries().map((entry) => entry.entryName), [path.basename(result.file)]);

  const pack = JSON.parse(fs.readFileSync(result.file, 'utf8'));
  const wire = JSON.stringify(pack);
  assert.strictEqual(pack.schemaVersion, 2);
  assert.strictEqual(pack.report.scheduled, true);
  assert.strictEqual(pack.report.schedule.cadence, 'quarterly');
  assert.strictEqual(pack.backup.ok, true);
  assert.strictEqual(pack.restoreDrill.ok, true);
  assert.ok(pack.controlMappings.some((item) => item.id === 'backup_recoverability' && item.state === 'covered'));
  assert.strictEqual(pack.scope.rawPromptBodiesIncluded, false);
  assert.strictEqual(pack.scope.auditDetailsIncluded, false);
  assert.ok(!wire.includes(ssn));
  assert.ok(!wire.includes(apiKey));
  assert.ok(!wire.includes(releaseToken));
  assert.ok(!wire.includes('Member Carter'));
  assert.ok(!wire.includes('schedule-secret-should-not-export'));
  assert.ok(!wire.includes(tempRoot));
});

test('argument parser supports npm-run paths and optional evidence inputs', () => {
  assert.deepStrictEqual(
    packer.parseArgs(['evidence-packs', '--backup', 'backups/sentinel.db', '--restore-drill', 'restore/sentinel.db', '--zip']),
    {
      _: ['evidence-packs'],
      backup: 'backups/sentinel.db',
      'restore-drill': 'restore/sentinel.db',
      zip: true,
    },
  );
  assert.deepStrictEqual(
    packer.cliOptionsFromArgs(
      packer.parseArgs(['evidence-packs', 'backups/sentinel.db', 'restore/sentinel.db']),
      {},
    ),
    {
      outDir: 'evidence-packs',
      file: undefined,
      zipFile: undefined,
      force: undefined,
      zip: undefined,
      backupFile: 'backups/sentinel.db',
      backupManifestFile: undefined,
      restoreDrillFile: 'restore/sentinel.db',
      queryLimit: undefined,
      auditLimit: undefined,
      reportId: undefined,
      generatedBy: undefined,
      periodStart: undefined,
      periodEnd: undefined,
      scheduled: false,
      schedule: undefined,
    },
  );
  assert.deepStrictEqual(
    packer.cliOptionsFromArgs(
      packer.parseArgs(['--schedule', 'config/evidence-schedule.json', 'backups/sentinel.db', 'restore/sentinel.db']),
      { outDir: 'scheduled-packs', scheduled: true, schedule: { id: 'quarterly' } },
    ),
    {
      outDir: 'scheduled-packs',
      file: undefined,
      zipFile: undefined,
      force: undefined,
      zip: undefined,
      backupFile: 'backups/sentinel.db',
      backupManifestFile: undefined,
      restoreDrillFile: 'restore/sentinel.db',
      queryLimit: undefined,
      auditLimit: undefined,
      reportId: undefined,
      generatedBy: undefined,
      periodStart: undefined,
      periodEnd: undefined,
      scheduled: true,
      schedule: { id: 'quarterly' },
    },
  );
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
