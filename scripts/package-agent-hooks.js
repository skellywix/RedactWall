'use strict';
/**
 * Build a prompt-free agent-hooks handoff zip plus an integrity manifest.
 * Mirrors scripts/package-mcp-guard.js: no dev ingest key, no demo PII.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUT_DIR = path.join(ROOT, 'dist', 'agent-hooks');
const PACKAGE_FILES = [
  'package.json',
  'server/env.js',
  'detection-engine/detect.js',
  'sensors/shared/decision.js',
  'sensors/mcp-guard/guard.js',
  'sensors/agent-hooks/hook.js',
  'scripts/install-agent-hooks.js',
  'scripts/check-agent-hooks-install.js',
];

function posixPath(value) { return value.split(path.sep).join('/'); }
function sha256(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }

function runtimeBody(relPath, root = ROOT) {
  let body = fs.readFileSync(path.join(root, relPath));
  if (relPath === 'sensors/mcp-guard/guard.js') {
    body = Buffer.from(body.toString('utf8').replace(/\r?\n\/\/ ---- demo when run directly[\s\S]*$/, '\n'));
  }
  return body;
}

function validateRuntimeFiles(files) {
  const paths = new Set(files.map((f) => f.path));
  for (const required of PACKAGE_FILES) {
    if (!paths.has(required)) throw new Error(`agent-hooks package is missing ${required}`);
  }
  const disallowed = [
    { label: 'development ingest key', pattern: /dev-ingest-key/ },
    { label: 'synthetic SSN demo value', pattern: /524-71-9043/ },
    { label: 'synthetic card demo value', pattern: /4111 1111 1111 1111/ },
    { label: 'environment assignment', pattern: /\b(?:INGEST_API_KEY|SENTINEL_SECRET|SENTINEL_DATA_KEY)\s*=/ },
  ];
  for (const file of files) {
    const text = file.body.toString('utf8');
    for (const rule of disallowed) {
      if (rule.pattern.test(text)) throw new Error(`agent-hooks package contains ${rule.label} in ${file.path}`);
    }
  }
  const hook = files.find((f) => f.path === 'sensors/agent-hooks/hook.js').body.toString('utf8');
  if (!/hook_event_name/.test(hook) || !/decide\(/.test(hook)) {
    throw new Error('agent-hooks package must include the hook dispatch and shared decision logic');
  }
  const installer = files.find((f) => f.path === 'scripts/install-agent-hooks.js').body.toString('utf8');
  if (/x-api-key|INGEST_API_KEY\s*[:=]/.test(installer)) {
    throw new Error('agent-hooks installer must never write the ingest key into settings.json');
  }
}

function packageAgentHooks(opts = {}) {
  const root = opts.root || ROOT;
  const outDir = opts.outDir || DEFAULT_OUT_DIR;
  const now = opts.now || new Date();
  const appVersion = readJson(path.join(root, 'package.json')).version;
  const files = PACKAGE_FILES.map((relPath) => ({ path: posixPath(relPath), body: runtimeBody(relPath, root) }));
  validateRuntimeFiles(files);

  fs.mkdirSync(outDir, { recursive: true });
  const baseName = `promptwall-agent-hooks-v${appVersion}`;
  const zipPath = path.join(outDir, `${baseName}.zip`);
  const manifestPath = path.join(outDir, `${baseName}.manifest.json`);
  const zip = new AdmZip();
  const packagedFiles = files.map((file) => {
    zip.addFile(file.path, file.body);
    return { path: file.path, sizeBytes: file.body.length, sha256: sha256(file.body) };
  });
  zip.writeZip(zipPath);
  const zipBody = fs.readFileSync(zipPath);
  const packageManifest = {
    kind: 'promptwall-agent-hooks-package',
    packageName: path.basename(zipPath),
    appVersion,
    createdAt: now.toISOString(),
    sha256: sha256(zipBody),
    sizeBytes: zipBody.length,
    files: packagedFiles.sort((a, b) => a.path.localeCompare(b.path)),
    checks: {
      explicitIngestKeyRequired: true,
      sharedEngineIncluded: true,
      sharedDecisionIncluded: true,
      installerNeverWritesKey: true,
      developmentIngestKeyAbsent: true,
      promptBodiesAbsent: true,
    },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(packageManifest, null, 2) + '\n');
  return { zipPath, manifestPath, packageManifest };
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  let outDir = DEFAULT_OUT_DIR;
  while (args.length) {
    const arg = args.shift();
    if (arg === '--out') outDir = path.resolve(args.shift() || '');
    else if (arg === '--help' || arg === '-h') return { help: true, outDir };
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else outDir = path.resolve(arg);
  }
  return { outDir };
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const packageFn = deps.packageAgentHooks || packageAgentHooks;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  try {
    const args = parseArgs(argv);
    if (args.help) { io.log('Usage: node scripts/package-agent-hooks.js [--out <directory>]'); return null; }
    const result = packageFn({ outDir: args.outDir });
    io.log(`Wrote ${result.zipPath}`);
    io.log(`Wrote ${result.manifestPath}`);
    io.log(`SHA-256 ${result.packageManifest.sha256}`);
    return result;
  } catch (err) {
    io.error(err.message || err);
    setExitCode(1);
    return null;
  }
}

if (require.main === module) main();

module.exports = { main, packageAgentHooks, parseArgs, runtimeBody, sha256, validateRuntimeFiles };
