'use strict';
/**
 * Build a prompt-free MCP guard handoff zip plus an integrity manifest.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUT_DIR = path.join(ROOT, 'dist', 'mcp-guard');
const PACKAGE_FILES = [
  'package.json',
  'src/env.js',
  'shared/detect.js',
  'mcp-guard/guard.js',
];

function posixPath(value) {
  return value.split(path.sep).join('/');
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function runtimeBody(relPath, root = ROOT) {
  const absPath = path.join(root, relPath);
  let body = fs.readFileSync(absPath);
  if (relPath === 'mcp-guard/guard.js') {
    body = Buffer.from(body.toString('utf8').replace(/\r?\n\/\/ ---- demo when run directly[\s\S]*$/, '\n'));
  }
  return body;
}

function validateRuntimeFiles(files) {
  const paths = new Set(files.map((file) => file.path));
  for (const required of PACKAGE_FILES) {
    if (!paths.has(required)) throw new Error(`MCP guard package is missing ${required}`);
  }

  const disallowed = [
    { label: 'development ingest key', pattern: /dev-ingest-key/ },
    { label: 'synthetic SSN demo value', pattern: /524-71-9043/ },
    { label: 'synthetic card demo value', pattern: /4111 1111 1111 1111/ },
    { label: 'real-looking placeholder key', pattern: /REPLACE_WITH_LONG_RANDOM_INGEST_KEY/ },
    { label: 'environment assignment', pattern: /\b(?:INGEST_API_KEY|SENTINEL_SECRET|SENTINEL_DATA_KEY)\s*=/ },
  ];

  for (const file of files) {
    const text = file.body.toString('utf8');
    for (const rule of disallowed) {
      if (rule.pattern.test(text)) {
        throw new Error(`MCP guard package contains ${rule.label} in ${file.path}`);
      }
    }
  }

  const guard = files.find((file) => file.path === 'mcp-guard/guard.js').body.toString('utf8');
  if (!/process\.env\.INGEST_API_KEY \|\| ''/.test(guard)) {
    throw new Error('MCP guard package must require explicit INGEST_API_KEY for control-plane logging');
  }
  if (/demo when run directly/.test(guard)) {
    throw new Error('MCP guard package must exclude direct-run demo code');
  }
}

function packageMcpGuard(opts = {}) {
  const root = opts.root || ROOT;
  const outDir = opts.outDir || DEFAULT_OUT_DIR;
  const now = opts.now || new Date();
  const appVersion = readJson(path.join(root, 'package.json')).version;
  const files = PACKAGE_FILES.map((relPath) => ({
    path: posixPath(relPath),
    body: runtimeBody(relPath, root),
  }));

  validateRuntimeFiles(files);

  fs.mkdirSync(outDir, { recursive: true });
  const baseName = `promptsentinel-mcp-guard-v${appVersion}`;
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
    kind: 'promptsentinel-mcp-guard-package',
    packageName: path.basename(zipPath),
    appVersion,
    createdAt: now.toISOString(),
    sha256: sha256(zipBody),
    sizeBytes: zipBody.length,
    files: packagedFiles.sort((a, b) => a.path.localeCompare(b.path)),
    checks: {
      explicitIngestKeyRequired: true,
      sharedEngineIncluded: true,
      demoCodeExcluded: true,
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
    if (arg === '--out') {
      outDir = path.resolve(args.shift() || '');
    } else if (arg === '--help' || arg === '-h') {
      return { help: true, outDir };
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      outDir = path.resolve(arg);
    }
  }
  return { outDir };
}

function main() {
  try {
    const args = parseArgs();
    if (args.help) {
      console.log('Usage: node scripts/package-mcp-guard.js [--out <directory>]');
      return;
    }
    const result = packageMcpGuard({ outDir: args.outDir });
    console.log(`Wrote ${result.zipPath}`);
    console.log(`Wrote ${result.manifestPath}`);
    console.log(`SHA-256 ${result.packageManifest.sha256}`);
  } catch (err) {
    console.error(err.message || err);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  packageMcpGuard,
  parseArgs,
  runtimeBody,
  sha256,
  validateRuntimeFiles,
};
