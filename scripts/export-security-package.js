'use strict';
/**
 * Generate a sanitized PromptWall security trust package for vendor-risk review.
 */
require('../server/env').loadEnv();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const securityPackage = require('../server/security-package');

function parseArgs(argv) {
  const out = { _: [] };
  const booleans = new Set(['force', 'zip']);
  for (let i = 0; i < argv.length; i += 1) {
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

function stampFor(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

function resolveOutputFile({ outDir, file, generatedAt } = {}) {
  const dir = path.resolve(outDir || path.join(process.cwd(), 'security-packages'));
  const stamp = stampFor(generatedAt ? new Date(generatedAt) : new Date());
  return path.resolve(file || path.join(dir, `promptwall-security-trust-package-${stamp}.json`));
}

function currentPreflight({ appModule } = {}) {
  const app = appModule || require('../server/app');
  return typeof app.currentPreflight === 'function' ? app.currentPreflight() : null;
}

function buildSecurityPackageFromRuntime(options = {}) {
  const db = options.dbModule || require('../server/db');
  const policy = options.policyModule || require('../server/policy');
  const coverage = options.coverageModule || require('../server/coverage');
  const posture = options.postureModule || require('../server/posture');
  const detectorFeedback = options.detectorFeedbackModule || require('../server/detector-feedback');
  const pkg = options.packageInfo || require('../package.json');
  const activePolicy = policy.loadPolicy();
  const rows = db.listQueries({ all: true });
  const auditIntegrity = db.verifyAuditChain();
  const coverageReport = coverage.summarize(rows, activePolicy);
  return securityPackage.trustPackage({
    generatedAt: options.generatedAt,
    packageInfo: pkg,
    lockfile: options.lockfile,
    lockfilePath: options.lockfilePath,
    policy: activePolicy,
    auditIntegrity,
    preflight: options.preflight || currentPreflight(options),
    coverage: coverageReport,
    posture: posture.summarize({
      rows,
      policy: activePolicy,
      coverageReport,
      auditIntegrity,
      actionStates: db.postureActionStates ? db.postureActionStates(1000) : {},
      detectorFeedbackReport: detectorFeedback.report({
        rows,
        feedback: db.listDetectorFeedback ? db.listDetectorFeedback({ limit: 1000 }) : [],
      }),
    }),
    env: options.env || process.env,
  });
}

function writeZip({ pkg, jsonFile, zipFile, force = false }) {
  const target = path.resolve(zipFile || jsonFile.replace(/\.json$/i, '.zip'));
  if (fs.existsSync(target) && !force) throw new Error(`${target} already exists; pass --force to overwrite`);
  fs.writeFileSync(target, securityPackage.packageArchive(pkg));
  return target;
}

function writeSecurityPackage(options = {}) {
  const pkg = options.package || buildSecurityPackageFromRuntime(options);
  const file = resolveOutputFile({ outDir: options.outDir, file: options.file, generatedAt: pkg.generatedAt });
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file) && !options.force) throw new Error(`${file} already exists; pass --force to overwrite`);
  fs.writeFileSync(file, `${JSON.stringify(pkg, null, 2)}\n`);
  const result = {
    file,
    bytes: fs.statSync(file).size,
    sha256: sha256File(file),
    package: pkg,
  };
  if (options.zip) {
    result.zipFile = writeZip({ pkg, jsonFile: file, zipFile: options.zipFile, force: options.force });
    result.zipBytes = fs.statSync(result.zipFile).size;
    result.zipSha256 = sha256File(result.zipFile);
  }
  return result;
}

function cliOptionsFromArgs(args) {
  return {
    outDir: args.out || (args._ || [])[0],
    file: args.file,
    zipFile: args['zip-file'],
    force: args.force,
    zip: args.zip,
  };
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const writePackage = deps.writeSecurityPackage || writeSecurityPackage;
  const args = parseArgs(argv);
  const result = writePackage(cliOptionsFromArgs(args));
  io.log(JSON.stringify({
    file: result.file,
    bytes: result.bytes,
    sha256: result.sha256,
    zipFile: result.zipFile,
    zipBytes: result.zipBytes,
    zipSha256: result.zipSha256,
    schemaVersion: result.package.schemaVersion,
    rawPromptBodiesIncluded: result.package.privacyContract.rawPromptBodies,
    dependencyComponents: result.package.sbom.summary.components,
    controlCoverage: result.package.summary.controlCoverage,
  }, null, 2));
}

if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });

module.exports = {
  parseArgs,
  buildSecurityPackageFromRuntime,
  writeSecurityPackage,
  writeZip,
  cliOptionsFromArgs,
  main,
};
