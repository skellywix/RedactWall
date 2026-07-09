'use strict';
/** Evidence-pack CLI must preserve backup proof without leaking prompt bodies. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const AdmZip = require('adm-zip');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-evidence-pack-test-'));
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'redactwall.db');
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';

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
  const restoredPath = path.join(tempRoot, 'restore-drill', 'redactwall.db');
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
    packer.parseArgs(['evidence-packs', '--backup', 'backups/redactwall.db', '--restore-drill', 'restore/redactwall.db', '--zip']),
    {
      _: ['evidence-packs'],
      backup: 'backups/redactwall.db',
      'restore-drill': 'restore/redactwall.db',
      zip: true,
    },
  );
  assert.deepStrictEqual(
    packer.cliOptionsFromArgs(
      packer.parseArgs(['evidence-packs', 'backups/redactwall.db', 'restore/redactwall.db']),
      {},
    ),
    {
      outDir: 'evidence-packs',
      file: undefined,
      zipFile: undefined,
      force: undefined,
      zip: undefined,
      backupFile: 'backups/redactwall.db',
      backupManifestFile: undefined,
      restoreDrillFile: 'restore/redactwall.db',
      queryLimit: undefined,
      auditLimit: undefined,
      reportId: undefined,
      generatedBy: undefined,
      examinerProfile: undefined,
      periodStart: undefined,
      periodEnd: undefined,
      scheduled: false,
      schedule: undefined,
      format: undefined,
    },
  );
  assert.deepStrictEqual(
    packer.cliOptionsFromArgs(
      packer.parseArgs(['--schedule', 'config/evidence-schedule.json', 'backups/redactwall.db', 'restore/redactwall.db']),
      { outDir: 'scheduled-packs', scheduled: true, schedule: { id: 'quarterly' } },
    ),
    {
      outDir: 'scheduled-packs',
      file: undefined,
      zipFile: undefined,
      force: undefined,
      zip: undefined,
      backupFile: 'backups/redactwall.db',
      backupManifestFile: undefined,
      restoreDrillFile: 'restore/redactwall.db',
      queryLimit: undefined,
      auditLimit: undefined,
      reportId: undefined,
      generatedBy: undefined,
      examinerProfile: undefined,
      periodStart: undefined,
      periodEnd: undefined,
      scheduled: true,
      schedule: { id: 'quarterly' },
      format: undefined,
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

test('runtime build with --examiner-profile produces a schemaVersion-3 pack end to end', () => {
  const fakeDb = {
    listQueries(filter) {
      return filter && filter.all
        ? [{ id: 'q_m', createdAt: '2026-07-01T00:00:00.000Z', status: 'pending', findings: [{ type: 'MEMBER_ID', masked: '**** 1234', value: '99881234' }], categories: [] }]
        : [];
    },
    listAudit() { return []; },
    stats() { return { total: 1 }; },
    verifyAuditChain() { return { ok: true, count: 1 }; },
  };
  const options = packer.cliOptionsFromArgs(
    packer.parseArgs(['--examiner-profile', 'federal_credit_union']),
    {},
  );
  assert.strictEqual(options.examinerProfile, 'federal_credit_union');

  const pack = packer.buildEvidencePackFromRuntime({
    ...options,
    dbModule: fakeDb,
    policyModule: {
      loadPolicy() { return { alwaysBlock: ['US_SSN', 'MEMBER_ID', 'LOAN_NUMBER', 'BANK_ACCOUNT', 'ROUTING_NUMBER'] }; },
      policyExceptionReview() { return { total: 1, active: 1, expiringSoon: 0, reviewDue: 0, expired: 0, disabled: 0, reviewWindowDays: 14, items: [] }; },
    },
    coverageModule: { summarize() { return { score: 100, totals: {}, sensors: [], fleet: [], governedDestinations: [], ungovernedDestinations: [], shadowDestinations: [], posture: [] }; } },
    detectorModule: { listDetectors() { return [{ id: 'MEMBER_ID' }]; } },
    customDetectorsModule: { loadCustomDetectors() { return []; } },
    exactMatchModule: { publicSummary() { return { enabled: true, fingerprints: 7, minLength: 6, maxWords: 5, severity: 4, salt: 'cli-salt-decoy' }; } },
    appCatalogModule: { reviewRollup() { return [{ sanctionedStatus: 'unsanctioned', eventCount: 3 }]; } },
    packageInfo: { version: '0.3.0' },
    backupModule: {},
  });

  assert.strictEqual(pack.schemaVersion, 3);
  assert.strictEqual(pack.scope.examinerProfile, 'federal_credit_union');
  assert.strictEqual(pack.ncuaReadiness.profile, 'federal_credit_union');
  assert.strictEqual(pack.ncuaReadiness.panels.exceptions.total, 1);
  assert.strictEqual(pack.ncuaReadiness.panels.memberData.events, 1);
  assert.deepStrictEqual(pack.edm, { enabled: true, fingerprints: 7, minLength: 6, maxWords: 5, severity: 4 });
  const controlMap = require('../server/control-map');
  assert.strictEqual(pack.complianceDisclaimer, controlMap.CONTROL_MAP_DISCLAIMER);
  assert.ok(/not compliance certification/i.test(pack.complianceDisclaimer));
  // controlTests (748 App A "regularly test key controls") rollup.
  assert.strictEqual(pack.controlTests.summary.total, 4);
  const auditTest = pack.controlTests.tests.find((t) => t.id === 'audit_chain_integrity');
  assert.strictEqual(auditTest.result, 'pass');
  assert.ok(auditTest.lastTestedAt, 'audit test carries an honest lastTestedAt');
  const restoreTest = pack.controlTests.tests.find((t) => t.id === 'restore_drill');
  assert.strictEqual(restoreTest.result, 'not_provided');
  assert.strictEqual(restoreTest.lastTestedAt, null);
  assert.ok(/not evidence of a scheduled/i.test(pack.controlTests.disclaimer));
  // AUP clause->control crosswalk rides the examiner pack; no board-adoptable prose.
  assert.ok(Array.isArray(pack.aupCrosswalk) && pack.aupCrosswalk.length >= 5);
  assert.ok(pack.controlMappings.some((c) => c.id === 'ai_acceptable_use'));
  const wire = JSON.stringify(pack);
  assert.ok(!wire.includes('cli-salt-decoy'));
  assert.ok(!wire.includes('99881234'));
});

test('the compliance disclaimer is a non-empty constant absent from v2 default packs', () => {
  const controlMap = require('../server/control-map');
  assert.strictEqual(typeof controlMap.CONTROL_MAP_DISCLAIMER, 'string');
  assert.ok(controlMap.CONTROL_MAP_DISCLAIMER.length > 40);
  assert.ok(/evidence pointers/i.test(controlMap.CONTROL_MAP_DISCLAIMER));
  assert.ok(/not compliance certification/i.test(controlMap.CONTROL_MAP_DISCLAIMER));

  // The disclaimer rides only the examiner-profile (schemaVersion-3) pack; the
  // default schemaVersion-2 pack that consumers pin stays byte-unchanged.
  const pack = packer.buildEvidencePackFromRuntime({
    dbModule: {
      listQueries() { return []; },
      listAudit() { return []; },
      stats() { return { total: 0 }; },
      verifyAuditChain() { return { ok: true, count: 0 }; },
    },
    policyModule: { loadPolicy() { return {}; } },
    coverageModule: { summarize() { return { score: 100, totals: {}, sensors: [], fleet: [], governedDestinations: [], ungovernedDestinations: [], shadowDestinations: [], posture: [] }; } },
    detectorModule: { listDetectors() { return []; } },
    customDetectorsModule: { loadCustomDetectors() { return []; } },
    packageInfo: { version: '0.3.0' },
    backupModule: {},
  });
  assert.strictEqual(pack.schemaVersion, 2);
  assert.strictEqual(pack.complianceDisclaimer, undefined);
  assert.strictEqual(pack.controlTests, undefined);
  assert.strictEqual(pack.aupCrosswalk, undefined);
});

test('renderMarkdown produces a bounded report and never leaks record free text', () => {
  const report = require('../server/evidence-report');
  const pack = {
    schemaVersion: 3,
    generatedAt: '2026-07-09T00:00:00.000Z',
    service: { name: 'RedactWall', version: '0.4.0' },
    scope: { examinerProfile: 'federal_credit_union', rawPromptBodiesIncluded: false },
    complianceDisclaimer: 'These control mappings are product evidence pointers, not compliance certification.',
    controlMappings: [
      { id: 'member_information_safeguards', title: 'Member information safeguards', state: 'covered', controlFamilies: ['NCUA Part 748 Appendix A member-information safeguards evidence'], summary: 'ok' },
    ],
    controlTests: {
      disclaimer: 'point-in-time verification record, not evidence of a scheduled periodic testing program.',
      summary: { total: 4, applicable: 1, passed: 1 },
      tests: [{ id: 'audit_chain_integrity', control: 'tamper_evident_audit', method: 'verifyAuditChain', result: 'pass', lastTestedAt: '2026-07-09T00:00:00.000Z', detail: 'ok' }],
    },
    ncuaReadiness: {
      score: 100,
      state: 'ready',
      panels: { note: 'CONFIDENTIAL-OWNER-jane.doe internal minutes SECRET-NOTE-XYZ' },
    },
    // Records carry potential free text; the renderer must not read them.
    useCases: { records: [{ owner: 'CONFIDENTIAL-OWNER-jane.doe', notes: 'SECRET-NOTE-XYZ' }] },
  };
  const md = report.renderMarkdown(pack);
  assert.ok(md.includes('# RedactWall examiner evidence report'));
  assert.ok(md.includes('Member information safeguards'));
  assert.ok(md.includes('NCUA Part 748 Appendix A'));
  assert.ok(/Control testing/.test(md));
  assert.ok(md.includes('Prompt bodies included:** no'));
  assert.ok(md.includes('not compliance certification'));
  // The renderer reads only bounded fields, so planted record free text is absent.
  assert.ok(!md.includes('CONFIDENTIAL-OWNER-jane.doe'));
  assert.ok(!md.includes('SECRET-NOTE-XYZ'));
});

test('writeEvidencePack --format md writes a rendered sibling report', () => {
  const os = require('os');
  const fs = require('fs');
  const path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-md-'));
  try {
    const file = path.join(dir, 'pack.json');
    const pack = {
      schemaVersion: 3,
      generatedAt: '2026-07-09T00:00:00.000Z',
      service: { name: 'RedactWall', version: '0.4.0' },
      scope: { examinerProfile: 'federal_credit_union', rawPromptBodiesIncluded: false },
      complianceDisclaimer: 'x',
      controlMappings: [],
      controlTests: { tests: [], summary: {}, disclaimer: 'y' },
    };
    const result = packer.writeEvidencePack({ pack, file, force: true, format: 'md' });
    assert.ok(result.mdFile.endsWith('.md'));
    assert.ok(fs.existsSync(result.mdFile));
    assert.ok(fs.readFileSync(result.mdFile, 'utf8').includes('# RedactWall examiner evidence report'));
    // JSON is still written unchanged alongside the md.
    assert.ok(fs.existsSync(file));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
