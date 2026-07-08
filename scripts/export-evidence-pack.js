'use strict';
/**
 * Generate a sanitized examiner evidence pack from the local RedactWall store.
 */
require('../server/env').loadEnv();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const evidence = require('../server/evidence');

const DEFAULT_QUERY_LIMIT = 1000;
const DEFAULT_AUDIT_LIMIT = 1000;
const MAX_LIMIT = 5000;

function parseArgs(argv) {
  const out = { _: [] };
  const booleans = new Set(['force', 'zip', 'scheduled']);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      out._.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (booleans.has(key)) {
      out[key] = true;
      continue;
    }
    out[key] = argv[++i];
  }
  return out;
}

function boundedNumber(value, fallback, max = MAX_LIMIT) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

function loadScheduleConfig(file) {
  if (!file) return {};
  const configPath = path.resolve(file);
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, ''));
  return {
    id: config.id,
    outDir: config.outDir,
    queryLimit: config.queryLimit,
    auditLimit: config.auditLimit,
    generatedBy: config.generatedBy,
    examinerProfile: config.examinerProfile,
    scheduled: config.enabled !== false,
    schedule: {
      id: config.id || path.basename(configPath, path.extname(configPath)),
      enabled: config.enabled !== false,
      cadence: config.cadence,
      nextRunAt: config.nextRunAt,
      retentionDays: config.retentionDays,
    },
  };
}

function stampFor(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

function resolveOutputFile({ outDir, file, generatedAt } = {}) {
  const dir = path.resolve(outDir || path.join(process.cwd(), 'evidence-packs'));
  const stamp = stampFor(generatedAt ? new Date(generatedAt) : new Date());
  return path.resolve(file || path.join(dir, `redactwall-evidence-pack-${stamp}.json`));
}

function verifyBackupEvidence({ backupFile, backupManifestFile, restoreDrillFile, backupModule } = {}) {
  const backup = backupModule || require('./backup-store');
  return {
    backup: backupFile
      ? { ...backup.verifyBackup({ file: backupFile, manifestFile: backupManifestFile }), checkedAt: new Date().toISOString() }
      : null,
    restoreDrill: restoreDrillFile
      ? { ...backup.verifyBackup({ file: restoreDrillFile }), drilledAt: new Date().toISOString() }
      : null,
  };
}

function buildEvidencePackFromRuntime(options = {}) {
  const db = options.dbModule || require('../server/db');
  const policy = options.policyModule || require('../server/policy');
  const coverage = options.coverageModule || require('../server/coverage');
  const detector = options.detectorModule || require('../server/detector');
  const customDetectors = options.customDetectorsModule || require('../server/custom-detectors');
  const exactMatch = options.exactMatchModule || require('../server/exact-match');
  const appCatalog = options.appCatalogModule || require('../server/app-catalog');
  const license = options.licenseModule || require('../server/license');
  // The CLI process starts unlicensed until it reads redactwall.lic; refresh
  // so the entitlement matches what the running control plane enforces.
  if (!options.licenseModule) license.refresh();
  const useCasesEntitled = license.entitled('ncua_readiness');
  const pkg = options.packageInfo || require('../package.json');
  const queryLimit = boundedNumber(options.queryLimit, DEFAULT_QUERY_LIMIT);
  const auditLimit = boundedNumber(options.auditLimit, DEFAULT_AUDIT_LIMIT);
  const activePolicy = policy.loadPolicy();
  const queries = db.listQueries({ limit: queryLimit });
  const summaryQueries = db.listQueries({ all: true });
  const verified = options.backup || options.restoreDrill
    ? { backup: options.backup || null, restoreDrill: options.restoreDrill || null }
    : verifyBackupEvidence({
      backupFile: options.backupFile,
      backupManifestFile: options.backupManifestFile,
      restoreDrillFile: options.restoreDrillFile,
      backupModule: options.backupModule,
    });

  return evidence.buildEvidencePack({
    version: pkg.version,
    generatedAt: options.generatedAt,
    queryLimit,
    auditLimit,
    summaryRowsIncluded: summaryQueries.length,
    summariesUseFullHistory: true,
    report: {
      id: options.reportId,
      generatedBy: options.generatedBy || 'export-evidence-pack',
      periodStart: options.periodStart,
      periodEnd: options.periodEnd,
      scheduled: options.scheduled === true,
      schedule: options.schedule,
    },
    policy: activePolicy,
    stats: db.stats(),
    auditIntegrity: db.verifyAuditChain(),
    coverage: coverage.summarize(summaryQueries, activePolicy),
    detectors: detector.listDetectors({ customDetectors: customDetectors.loadCustomDetectors() }),
    queries,
    lineageQueries: summaryQueries,
    audit: db.listAudit(auditLimit),
    backup: verified.backup,
    restoreDrill: verified.restoreDrill,
    edm: exactMatch.publicSummary(),
    catalog: appCatalog.reviewRollup(),
    useCases: useCasesEntitled && typeof db.listAiUseCases === 'function' ? db.listAiUseCases() : undefined,
    examinerProfile: options.examinerProfile,
    policyExceptionReview: typeof policy.policyExceptionReview === 'function'
      ? policy.policyExceptionReview(activePolicy)
      : undefined,
  });
}

function writeZip({ jsonFile, zipFile, force = false }) {
  const target = path.resolve(zipFile || jsonFile.replace(/\.json$/i, '.zip'));
  if (fs.existsSync(target) && !force) throw new Error(`${target} already exists; pass --force to overwrite`);
  const zip = new AdmZip();
  zip.addLocalFile(jsonFile, '', path.basename(jsonFile));
  zip.writeZip(target);
  return target;
}

function writeEvidencePack(options = {}) {
  const pack = options.pack || buildEvidencePackFromRuntime(options);
  const file = resolveOutputFile({ outDir: options.outDir, file: options.file, generatedAt: pack.generatedAt });
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file) && !options.force) throw new Error(`${file} already exists; pass --force to overwrite`);
  fs.writeFileSync(file, `${JSON.stringify(pack, null, 2)}\n`);
  const result = {
    file,
    bytes: fs.statSync(file).size,
    sha256: sha256File(file),
    pack,
  };
  if (options.zip) {
    result.zipFile = writeZip({ jsonFile: file, zipFile: options.zipFile, force: options.force });
    result.zipBytes = fs.statSync(result.zipFile).size;
    result.zipSha256 = sha256File(result.zipFile);
  }
  return result;
}

function cliOptionsFromArgs(args, schedule = {}) {
  const positional = args._ || [];
  const scheduleMode = !!args.schedule;
  return {
    outDir: args.out || (scheduleMode ? schedule.outDir : positional[0]) || schedule.outDir,
    file: args.file,
    zipFile: args['zip-file'],
    force: args.force,
    zip: args.zip,
    backupFile: args.backup || (scheduleMode ? positional[0] : positional[1]),
    backupManifestFile: args['backup-manifest'],
    restoreDrillFile: args['restore-drill'] || (scheduleMode ? positional[1] : positional[2]),
    queryLimit: args['query-limit'] || schedule.queryLimit,
    auditLimit: args['audit-limit'] || schedule.auditLimit,
    reportId: args['report-id'] || schedule.id,
    generatedBy: args['generated-by'] || schedule.generatedBy,
    examinerProfile: args['examiner-profile'] || schedule.examinerProfile,
    periodStart: args['period-start'],
    periodEnd: args['period-end'],
    scheduled: args.scheduled === true || schedule.scheduled === true,
    schedule: schedule.schedule,
  };
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const loadSchedule = deps.loadScheduleConfig || loadScheduleConfig;
  const writePack = deps.writeEvidencePack || writeEvidencePack;
  const args = parseArgs(argv);
  const schedule = loadSchedule(args.schedule);
  const result = writePack(cliOptionsFromArgs(args, schedule));
  io.log(JSON.stringify({
    file: result.file,
    bytes: result.bytes,
    sha256: result.sha256,
    zipFile: result.zipFile,
    zipBytes: result.zipBytes,
    zipSha256: result.zipSha256,
    schemaVersion: result.pack.schemaVersion,
    examinerProfile: result.pack.scope.examinerProfile || null,
    rawPromptBodiesIncluded: result.pack.scope.rawPromptBodiesIncluded,
    auditDetailsIncluded: result.pack.scope.auditDetailsIncluded,
  }, null, 2));
}

if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });

module.exports = {
  parseArgs,
  boundedNumber,
  loadScheduleConfig,
  buildEvidencePackFromRuntime,
  writeEvidencePack,
  writeZip,
  cliOptionsFromArgs,
  main,
};
