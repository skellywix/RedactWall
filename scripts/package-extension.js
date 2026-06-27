'use strict';
/**
 * Build a Chrome extension zip plus a prompt-free integrity manifest.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUT_DIR = path.join(ROOT, 'dist', 'browser-extension');
const REQUIRED_MANAGED_KEYS = ['serverUrl', 'ingestKey', 'orgId'];
const ENGINE_COPIES = [
  ['detection-engine/detect.js', 'sensors/browser-extension/lib/detect.js'],
  ['detection-engine/adapters.js', 'sensors/browser-extension/lib/adapters.js'],
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

function collectExtensionFiles(extensionDir = path.join(ROOT, 'sensors', 'browser-extension')) {
  const files = [];

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.name === '.DS_Store') continue;
      const absPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(absPath);
        continue;
      }
      if (!entry.isFile()) continue;
      files.push({ absPath, relPath: posixPath(path.relative(extensionDir, absPath)) });
    }
  }

  walk(extensionDir);
  return files;
}

function requirePackageFile(fileSet, relPath) {
  if (!fileSet.has(relPath)) throw new Error(`Extension package is missing ${relPath}`);
}

function validateSyncedEngine(root = ROOT) {
  return ENGINE_COPIES.map(([sourceRel, copyRel]) => {
    const source = fs.readFileSync(path.join(root, sourceRel));
    const copy = fs.readFileSync(path.join(root, copyRel));
    const sourceHash = sha256(source);
    const copyHash = sha256(copy);
    if (sourceHash !== copyHash) {
      throw new Error(`Synced engine copy drifted: ${copyRel} does not match ${sourceRel}`);
    }
    return { source: sourceRel, copy: copyRel, sha256: sourceHash };
  });
}

function validateManifest({ manifest, schema, appVersion, files }) {
  const fileSet = new Set(files.map((f) => f.relPath));
  if (manifest.manifest_version !== 3) throw new Error('Chrome extension manifest_version must be 3');
  if (!manifest.name || !manifest.version || !manifest.description) {
    throw new Error('Chrome extension manifest must include name, version, and description');
  }
  if (manifest.version !== appVersion) {
    throw new Error(`Extension version ${manifest.version} must match app version ${appVersion}`);
  }
  if (manifest.host_permissions && manifest.host_permissions.includes('<all_urls>')) {
    throw new Error('Extension package must not request <all_urls>');
  }

  requirePackageFile(fileSet, 'manifest.json');
  requirePackageFile(fileSet, manifest.background && manifest.background.service_worker);
  requirePackageFile(fileSet, manifest.action && manifest.action.default_popup);
  requirePackageFile(fileSet, manifest.storage && manifest.storage.managed_schema);

  for (const script of manifest.content_scripts || []) {
    for (const js of script.js || []) requirePackageFile(fileSet, js);
    for (const css of script.css || []) requirePackageFile(fileSet, css);
    if (!Array.isArray(script.matches) || !script.matches.length) {
      throw new Error('Every content script must declare match patterns');
    }
  }

  const schemaKeys = new Set(Object.keys((schema && schema.properties) || {}));
  for (const key of REQUIRED_MANAGED_KEYS) {
    if (!schemaKeys.has(key)) throw new Error(`Managed storage schema is missing ${key}`);
  }
}

function validatePackageContents(files) {
  const disallowed = [
    { label: 'development ingest key', pattern: /dev-ingest-key/ },
    { label: 'environment assignment', pattern: /\b(?:INGEST_API_KEY|SENTINEL_SECRET|SENTINEL_DATA_KEY)\s*=/ },
  ];

  for (const file of files) {
    const body = fs.readFileSync(file.absPath);
    const text = body.toString('utf8');
    for (const rule of disallowed) {
      if (rule.pattern.test(text)) {
        throw new Error(`Extension package contains ${rule.label} in ${file.relPath}`);
      }
    }
  }
}

function packageExtension(opts = {}) {
  const root = opts.root || ROOT;
  const extensionDir = opts.extensionDir || path.join(root, 'sensors', 'browser-extension');
  const outDir = opts.outDir || DEFAULT_OUT_DIR;
  const now = opts.now || new Date();
  const manifest = readJson(path.join(extensionDir, 'manifest.json'));
  const schema = readJson(path.join(extensionDir, manifest.storage.managed_schema));
  const appVersion = readJson(path.join(root, 'package.json')).version;
  const files = collectExtensionFiles(extensionDir);

  validateManifest({ manifest, schema, appVersion, files });
  validatePackageContents(files);
  const engineCopies = validateSyncedEngine(root);

  fs.mkdirSync(outDir, { recursive: true });
  const baseName = `promptsentinel-extension-v${manifest.version}`;
  const zipPath = path.join(outDir, `${baseName}.zip`);
  const manifestPath = path.join(outDir, `${baseName}.manifest.json`);
  const zip = new AdmZip();
  const packagedFiles = files.map((file) => {
    const body = fs.readFileSync(file.absPath);
    zip.addFile(file.relPath, body);
    return { path: file.relPath, sizeBytes: body.length, sha256: sha256(body) };
  });

  zip.writeZip(zipPath);
  const zipBody = fs.readFileSync(zipPath);
  const packageManifest = {
    kind: 'promptsentinel-extension-package',
    packageName: path.basename(zipPath),
    extensionVersion: manifest.version,
    appVersion,
    manifestVersion: manifest.manifest_version,
    createdAt: now.toISOString(),
    sha256: sha256(zipBody),
    sizeBytes: zipBody.length,
    files: packagedFiles.sort((a, b) => a.path.localeCompare(b.path)),
    engineCopies,
    checks: {
      manifestV3: true,
      managedStorageSchema: true,
      syncedEngine: true,
      developmentIngestKeyAbsent: true,
      broadHostPermissionsAbsent: true,
    },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(packageManifest, null, 2) + '\n');
  return { zipPath, manifestPath, packageManifest };
}

function parseArgs(argv) {
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
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      console.log('Usage: node scripts/package-extension.js [--out <directory>]');
      return;
    }
    const result = packageExtension({ outDir: args.outDir });
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
  collectExtensionFiles,
  packageExtension,
  parseArgs,
  sha256,
  validateManifest,
  validatePackageContents,
  validateSyncedEngine,
};
