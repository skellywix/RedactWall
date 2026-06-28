'use strict';
/**
 * Build a prompt-free endpoint-agent handoff zip plus an integrity manifest.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUT_DIR = path.join(ROOT, 'dist', 'endpoint-agent');
const PACKAGE_FILES = [
  'package.json',
  'package-lock.json',
  'detection-engine/adapters.js',
  'detection-engine/detect.js',
  'server/env.js',
  'server/policy.js',
  'server/processors.js',
  'sensors/endpoint-agent/agent.js',
  'sensors/endpoint-agent/native-handoff.js',
  'sensors/endpoint-agent/write-handoff.js',
  'sensors/endpoint-agent/collectors/protected-upload.js',
  'scripts/check-endpoint-install.js',
  'scripts/install-desktop-collector.ps1',
  'scripts/install-endpoint-agent.ps1',
  'scripts/run-desktop-collector.ps1',
  'scripts/run-endpoint-agent.ps1',
  'scripts/uninstall-desktop-collector.ps1',
  'scripts/uninstall-endpoint-agent.ps1',
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
  return fs.readFileSync(path.join(root, relPath));
}

function validateRuntimeFiles(files) {
  const paths = new Set(files.map((file) => file.path));
  for (const required of PACKAGE_FILES) {
    if (!paths.has(required)) throw new Error(`Endpoint agent package is missing ${required}`);
  }

  const disallowed = [
    { label: 'development ingest key', pattern: /dev-ingest-key/ },
    { label: 'synthetic SSN demo value', pattern: /524-71-9043/ },
    { label: 'synthetic card demo value', pattern: /4111 1111 1111 1111/ },
    { label: 'demo admin password', pattern: /DemoOnly!2026/ },
    { label: 'real-looking placeholder key', pattern: /REPLACE_WITH_LONG_RANDOM_INGEST_KEY/ },
  ];

  for (const file of files) {
    const text = file.body.toString('utf8');
    for (const rule of disallowed) {
      if (rule.pattern.test(text)) {
        throw new Error(`Endpoint agent package contains ${rule.label} in ${file.path}`);
      }
    }
  }

  const agent = files.find((file) => file.path === 'sensors/endpoint-agent/agent.js').body.toString('utf8');
  if (!/process\.env\.INGEST_API_KEY \|\| ''/.test(agent)) {
    throw new Error('Endpoint agent package must require explicit INGEST_API_KEY for control-plane calls');
  }
  if (/contentBase64|\/api\/v1\/scan-file/.test(agent)) {
    throw new Error('Endpoint agent package must inspect files locally without uploading file bodies');
  }
  if (!/redacted_available/.test(agent) || !/\.promptwall-redacted/.test(agent)) {
    throw new Error('Endpoint agent package must include the local redacted companion handoff');
  }
  if (!/native-handoff/.test(agent) || !/ENDPOINT_AGENT_HANDOFF_SECRET/.test(agent)) {
    throw new Error('Endpoint agent package must include the signed native handoff prototype');
  }

  const handoff = files.find((file) => file.path === 'sensors/endpoint-agent/native-handoff.js').body.toString('utf8');
  if (!/createHmac\('sha256'/.test(handoff) || !/contentBase64/.test(handoff)) {
    throw new Error('Endpoint agent native handoff must be signed and content-free');
  }

  const handoffWriter = files.find((file) => file.path === 'sensors/endpoint-agent/write-handoff.js').body.toString('utf8');
  if (!/writeHandoffFile/.test(handoffWriter) || !/signHandoffEvent/.test(handoffWriter)) {
    throw new Error('Endpoint agent package must include the native handoff writer');
  }
  if (/--secret|contentBase64|readFileSync\(filePath/.test(handoffWriter)) {
    throw new Error('Endpoint agent handoff writer must not take secrets in argv or read file bodies');
  }

  const collector = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/protected-upload.js').body.toString('utf8');
  if (!/collectProtectedUploads/.test(collector) || !/writeHandoffFile/.test(collector) || !/waitForHandoffConsumption/.test(collector)) {
    throw new Error('Endpoint agent package must include the protected-upload desktop collector');
  }
  if (/contentBase64|readFileSync\(filePath/.test(collector)) {
    throw new Error('Endpoint desktop collector must not read file bodies or upload file content');
  }

  const installCheck = files.find((file) => file.path === 'scripts/check-endpoint-install.js').body.toString('utf8');
  if (!/api\/v1\/heartbeat/.test(installCheck) || !/buildInstallReport/.test(installCheck) || !/INGEST_API_KEY/.test(installCheck)) {
    throw new Error('Endpoint agent package must include install validation with heartbeat support');
  }
  if (/contentBase64|readFileSync\(filePath|dev-ingest-key/.test(installCheck)) {
    throw new Error('Endpoint install validation must not read file bodies or package development keys');
  }

  const install = files.find((file) => file.path === 'scripts/install-endpoint-agent.ps1').body.toString('utf8');
  if (!/\[Parameter\(Mandatory = \$true\)\]\s*\r?\n\s*\[string\]\$IngestKey/.test(install)) {
    throw new Error('Endpoint agent installer must require an ingest key parameter');
  }
  if (/"-IngestKey"/.test(install) || /\$IngestKey[\s\S]{0,120}\$taskArgs/.test(install)) {
    throw new Error('Endpoint agent installer must not put the ingest key in scheduled-task arguments');
  }
  if (/"-HandoffSecret"/.test(install) || /\$HandoffSecret[\s\S]{0,120}\$taskArgs/.test(install)) {
    throw new Error('Endpoint agent installer must not put the native handoff secret in scheduled-task arguments');
  }

  const collectorInstall = files.find((file) => file.path === 'scripts/install-desktop-collector.ps1').body.toString('utf8');
  if (!collectorInstall.includes(String.raw`HKEY_CURRENT_USER\Software\Classes\*\shell`) || !collectorInstall.includes('%1') || !/MultiSelectModel/.test(collectorInstall)) {
    throw new Error('Endpoint desktop collector installer must register a per-user file shell action');
  }
  if (!/PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR/.test(collectorInstall) || !/PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET/.test(collectorInstall)) {
    throw new Error('Endpoint desktop collector installer must accept PromptWall handoff env aliases');
  }
  if (/"-HandoffSecret"|INGEST_API_KEY=\$IngestKey/.test(collectorInstall)) {
    throw new Error('Endpoint desktop collector installer must not put secrets in shell commands');
  }

  const runner = files.find((file) => file.path === 'scripts/run-endpoint-agent.ps1').body.toString('utf8');
  if (!/\$env:SENTINEL_ENV_PATH = \$config/.test(runner)) {
    throw new Error('Endpoint agent runner must load local config through SENTINEL_ENV_PATH');
  }

  const collectorRunner = files.find((file) => file.path === 'scripts/run-desktop-collector.ps1').body.toString('utf8');
  if (!/\$env:SENTINEL_ENV_PATH = \$config/.test(collectorRunner) || !/protected-upload\.js/.test(collectorRunner) || !/\[string\[\]\]\$FilePath/.test(collectorRunner)) {
    throw new Error('Endpoint desktop collector runner must load config and invoke the protected-upload collector');
  }
}

function packageEndpointAgent(opts = {}) {
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
  const baseName = `promptwall-endpoint-agent-v${appVersion}`;
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
    kind: 'promptwall-endpoint-agent-package',
    packageName: path.basename(zipPath),
    appVersion,
    createdAt: now.toISOString(),
    sha256: sha256(zipBody),
    sizeBytes: zipBody.length,
    files: packagedFiles.sort((a, b) => a.path.localeCompare(b.path)),
    checks: {
      explicitIngestKeyRequired: true,
      localDetectionEngineIncluded: true,
      endpointRedactionHandoffIncluded: true,
      nativeHandoffPrototypeIncluded: true,
      nativeHandoffWriterIncluded: true,
      protectedUploadCollectorIncluded: true,
      desktopCollectorInstallerIncluded: true,
      installValidationIncluded: true,
      scheduledTaskInstallerIncluded: true,
      localConfigEnvPath: true,
      taskArgsDoNotExposeIngestKey: true,
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
      console.log('Usage: node scripts/package-endpoint-agent.js [--out <directory>]');
      return;
    }
    const result = packageEndpointAgent({ outDir: args.outDir });
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
  packageEndpointAgent,
  parseArgs,
  runtimeBody,
  sha256,
  validateRuntimeFiles,
};
