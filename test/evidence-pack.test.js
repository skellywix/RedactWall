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

test('runtime pack uses full query history for summaries while bounding exported rows', () => {
  const calls = [];
  const recent = {
    id: 'q_recent',
    createdAt: '2026-06-26T12:02:00.000Z',
    status: 'allowed',
    user: 'recent@example.test',
    source: 'browser_extension',
    channel: 'submit',
    destination: 'chatgpt.com',
    redactedPrompt: 'recent safe prompt',
    findings: [],
    categories: [],
  };
  const older = {
    id: 'q_older',
    createdAt: '2026-06-26T12:01:00.000Z',
    status: 'destination_blocked',
    user: 'older@example.test',
    source: 'endpoint_agent',
    channel: 'file_upload',
    destination: 'claude.ai',
    redactedPrompt: 'older sanitized prompt',
    findings: [{ type: 'US_SSN', severity: 4, score: 1, masked: '***-**-9043', value: '524-71-9043' }],
    categories: [],
  };
  const fakeDb = {
    listQueries(filter) {
      calls.push(filter);
      return filter && filter.all ? [recent, older] : [recent];
    },
    listAudit() { return []; },
    stats() { return { total: 2 }; },
    verifyAuditChain() { return { ok: true, count: 2 }; },
  };
  const fakeCoverage = {
    summarize(rows) {
      return {
        score: 100,
        totals: { events: rows.length },
        sensors: [],
        fleet: [],
        governedDestinations: [],
        ungovernedDestinations: [],
        shadowDestinations: [],
        posture: [],
      };
    },
  };

  const pack = packer.buildEvidencePackFromRuntime({
    dbModule: fakeDb,
    policyModule: { loadPolicy() { return {}; } },
    coverageModule: fakeCoverage,
    detectorModule: { listDetectors() { return []; } },
    customDetectorsModule: { loadCustomDetectors() { return []; } },
    packageInfo: { version: '0.3.0' },
    queryLimit: 1,
    auditLimit: 1,
    backupModule: {},
  });

  assert.deepStrictEqual(calls, [{ limit: 1 }, { all: true }]);
  assert.strictEqual(pack.queries.length, 1);
  assert.strictEqual(pack.queries[0].id, 'q_recent');
  assert.strictEqual(pack.coverage.totals.events, 2);
  assert.strictEqual(pack.scope.summaryRowsIncluded, 2);
  assert.strictEqual(pack.scope.summariesUseFullHistory, true);
  assert.ok(pack.lineage.byUser.some((item) => item.key === 'older@example.test'));
  assert.ok(pack.lineage.byDestination.some((item) => item.key === 'claude.ai'));
  assert.ok(!JSON.stringify(pack).includes('524-71-9043'));
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

test('schedule config loader accepts Windows UTF-8 BOM files', () => {
  const schedulePath = path.join(tempRoot, 'bom-evidence-schedule.json');
  fs.writeFileSync(schedulePath, `\uFEFF${JSON.stringify({
    id: 'bom-schedule',
    enabled: true,
    cadence: 'quarterly',
    outDir: 'evidence-packs',
    queryLimit: 100,
    auditLimit: 100,
  })}`);

  const schedule = packer.loadScheduleConfig(schedulePath);

  assert.strictEqual(schedule.id, 'bom-schedule');
  assert.strictEqual(schedule.scheduled, true);
  assert.strictEqual(schedule.schedule.cadence, 'quarterly');
});

test('CLI main prints a metadata-only summary with schedule options', async () => {
  assert.strictEqual(packer.boundedNumber('0', 100), 100);
  assert.strictEqual(packer.boundedNumber('9999', 100), 5000);
  assert.strictEqual(packer.boundedNumber('42.9', 100), 42);

  const logs = [];
  let optionsSeen;
  await packer.main([
    '--schedule',
    'config/evidence-schedule.json',
    '--zip',
    '--zip-file',
    'pack.zip',
    '--force',
    'backup.db',
    'restore.db',
  ], {
    console: { log: (line) => logs.push(String(line)) },
    loadScheduleConfig(file) {
      assert.strictEqual(file, 'config/evidence-schedule.json');
      return {
        outDir: 'scheduled-packs',
        queryLimit: 25,
        auditLimit: 50,
        generatedBy: 'scheduler',
        scheduled: true,
        schedule: { id: 'quarterly' },
      };
    },
    writeEvidencePack(options) {
      optionsSeen = options;
      return {
        file: path.join(tempRoot, 'pack.json'),
        bytes: 123,
        sha256: 'pack-sha',
        zipFile: path.join(tempRoot, 'pack.zip'),
        zipBytes: 456,
        zipSha256: 'zip-sha',
        pack: {
          schemaVersion: 2,
          scope: {
            rawPromptBodiesIncluded: false,
            auditDetailsIncluded: false,
          },
        },
      };
    },
  });

  assert.strictEqual(optionsSeen.outDir, 'scheduled-packs');
  assert.strictEqual(optionsSeen.backupFile, 'backup.db');
  assert.strictEqual(optionsSeen.restoreDrillFile, 'restore.db');
  assert.strictEqual(optionsSeen.queryLimit, 25);
  assert.strictEqual(optionsSeen.auditLimit, 50);
  assert.strictEqual(optionsSeen.generatedBy, 'scheduler');
  assert.strictEqual(optionsSeen.scheduled, true);
  assert.deepStrictEqual(optionsSeen.schedule, { id: 'quarterly' });
  const summary = JSON.parse(logs[0]);
  assert.strictEqual(summary.schemaVersion, 2);
  assert.strictEqual(summary.rawPromptBodiesIncluded, false);
  assert.strictEqual(summary.auditDetailsIncluded, false);
  assert.strictEqual(summary.sha256, 'pack-sha');
  assert.strictEqual(summary.zipSha256, 'zip-sha');
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
