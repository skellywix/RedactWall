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
  'server/env.js',
  'detection-engine/detect.js',
  'sensors/mcp-guard/guard.js',
  'sensors/mcp-guard/sdk.js',
  'sensors/mcp-guard/connectors/microsoft365.js',
  'sensors/mcp-guard/connectors/googledrive.js',
  'scripts/check-mcp-guard-install.js',
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
  if (relPath === 'sensors/mcp-guard/guard.js') {
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

  const guard = files.find((file) => file.path === 'sensors/mcp-guard/guard.js').body.toString('utf8');
  if (!/process\.env\.INGEST_API_KEY \|\| ''/.test(guard)) {
    throw new Error('MCP guard package must require explicit INGEST_API_KEY for control-plane logging');
  }
  if (/demo when run directly/.test(guard)) {
    throw new Error('MCP guard package must exclude direct-run demo code');
  }

  const sdk = files.find((file) => file.path === 'sensors/mcp-guard/sdk.js').body.toString('utf8');
  if (!/sanitizeToolResult/.test(sdk) || !/wrapConnectorTool/.test(sdk) || !/connectorHealthCheck/.test(sdk)) {
    throw new Error('MCP guard package must include connector SDK sanitization and health helpers');
  }

  const microsoft365 = files.find((file) => file.path === 'sensors/mcp-guard/connectors/microsoft365.js').body.toString('utf8');
  if (!/sanitizeDriveItemContent/.test(microsoft365) || !/createDriveItemContentTool/.test(microsoft365) || !/microsoft365ConnectorHealth/.test(microsoft365)) {
    throw new Error('MCP guard package must include Microsoft 365 connector sanitization and health helpers');
  }

  const googledrive = files.find((file) => file.path === 'sensors/mcp-guard/connectors/googledrive.js').body.toString('utf8');
  if (!/sanitizeFileContent/.test(googledrive) || !/createFileContentTool/.test(googledrive) || !/googleDriveConnectorHealth/.test(googledrive)) {
    throw new Error('MCP guard package must include Google Drive connector sanitization and health helpers');
  }

  const installCheck = files.find((file) => file.path === 'scripts/check-mcp-guard-install.js').body.toString('utf8');
  if (!/api\/v1\/heartbeat/.test(installCheck) || !/buildInstallReport/.test(installCheck) || !/INGEST_API_KEY/.test(installCheck)) {
    throw new Error('MCP guard package must include install validation with heartbeat support');
  }
  if (/contentBase64|readFileSync\(filePath|dev-ingest-key|524-71-9043|4111 1111 1111 1111/.test(installCheck)) {
    throw new Error('MCP guard install validation must not read file bodies, package development keys, or carry demo prompt bodies');
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
  const baseName = `promptwall-mcp-guard-v${appVersion}`;
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
    kind: 'promptwall-mcp-guard-package',
    packageName: path.basename(zipPath),
    appVersion,
    createdAt: now.toISOString(),
    sha256: sha256(zipBody),
    sizeBytes: zipBody.length,
    files: packagedFiles.sort((a, b) => a.path.localeCompare(b.path)),
    checks: {
      explicitIngestKeyRequired: true,
      sharedEngineIncluded: true,
      connectorSdkIncluded: true,
      microsoft365ConnectorIncluded: true,
      googleDriveConnectorIncluded: true,
      demoCodeExcluded: true,
      installValidationIncluded: true,
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
