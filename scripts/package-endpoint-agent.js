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
  'server/custom-detectors.js',
  'server/exact-match.js',
  'server/env.js',
  'server/policy.js',
  'server/processors.js',
  'sensors/endpoint-agent/agent.js',
  'sensors/endpoint-agent/file-flow-profiles.js',
  'sensors/endpoint-agent/ocr.js',
  'sensors/endpoint-agent/native-handoff.js',
  'sensors/endpoint-agent/native-messaging-host.js',
  'sensors/endpoint-agent/write-handoff.js',
  'sensors/endpoint-agent/collectors/ai-tool-inventory.js',
  'sensors/endpoint-agent/collectors/mcp-inventory.js',
  'sensors/endpoint-agent/collectors/clipboard-guard.js',
  'sensors/endpoint-agent/collectors/desktop-app-flow.js',
  'sensors/endpoint-agent/collectors/git-push-guard.js',
  'sensors/endpoint-agent/collectors/protected-upload.js',
  'sensors/endpoint-agent/fixtures/ocr-sample.png',
  'scripts/check-endpoint-install.js',
  'scripts/install-clipboard-guard.ps1',
  'scripts/install-desktop-collector.ps1',
  'scripts/install-endpoint-agent.ps1',
  'scripts/install-file-intent-host.ps1',
  'scripts/install-git-push-guard.ps1',
  'scripts/run-clipboard-guard.ps1',
  'scripts/run-desktop-collector.ps1',
  'scripts/run-endpoint-agent.ps1',
  'scripts/uninstall-clipboard-guard.ps1',
  'scripts/uninstall-desktop-collector.ps1',
  'scripts/uninstall-endpoint-agent.ps1',
  'scripts/uninstall-file-intent-host.ps1',
  'scripts/uninstall-git-push-guard.ps1',
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
  if (!/file-flow-profiles/.test(agent) || !/startWatchedRoot/.test(agent)) {
    throw new Error('Endpoint agent package must include named file-flow watcher profiles');
  }
  if (!/\.\/ocr/.test(agent) || !/extractEndpointFile/.test(agent)) {
    throw new Error('Endpoint agent package must route image files through endpoint-local OCR');
  }

  const fileFlowProfiles = files.find((file) => file.path === 'sensors/endpoint-agent/file-flow-profiles.js').body.toString('utf8');
  if (!/publicProfileChecks/.test(fileFlowProfiles) || !/MAX_FILE_FLOW_PROFILES/.test(fileFlowProfiles)) {
    throw new Error('Endpoint agent package must include file-flow profile validation');
  }
  if (/contentBase64|fetch\(|https?:\/\/|readFileSync|writeFileSync|console\./.test(fileFlowProfiles)) {
    throw new Error('Endpoint file-flow profile validation must not upload, persist, or log local path data');
  }

  const ocr = files.find((file) => file.path === 'sensors/endpoint-agent/ocr.js').body.toString('utf8');
  if (!/extractImageFile/.test(ocr) || !/execFile/.test(ocr) || !/ENDPOINT_AGENT_OCR_COMMAND/.test(ocr)) {
    throw new Error('Endpoint agent package must include the endpoint-local OCR bridge');
  }
  if (/contentBase64|fetch\(|https?:\/\/|shell:\s*true|readFileSync/.test(ocr)) {
    throw new Error('Endpoint OCR bridge must stay local and must not upload, shell, or read unrelated file bodies');
  }

  const appFlow = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/desktop-app-flow.js').body.toString('utf8');
  if (!/publicAppFlowChecks/.test(appFlow) || !/desktopAppFlowProfiles/.test(appFlow)) {
    throw new Error('Endpoint agent package must include the per-app guarded folder collector');
  }
  if (/contentBase64|fetch\(|https?:\/\/|readFileSync|writeFileSync|console\./.test(appFlow)) {
    throw new Error('Endpoint app file-flow collector must not upload, persist, or log local path data');
  }

  const aiToolInventory = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/ai-tool-inventory.js').body.toString('utf8');
  if (!/collectAiToolInventory/.test(aiToolInventory) || !/parseApprovedTools/.test(aiToolInventory)) {
    throw new Error('Endpoint agent package must include sanitized AI tool inventory');
  }
  if (/contentBase64|fetch\(|https?:\/\/|readFileSync|writeFileSync|console\.log\([^)]*process|console\.error\([^)]*process/.test(aiToolInventory)) {
    throw new Error('Endpoint AI tool inventory must not upload, persist, or log local process or path data');
  }

  const mcpInventory = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/mcp-inventory.js').body.toString('utf8');
  if (!/collectMcpInventorySync/.test(mcpInventory) || !/serverMetadata/.test(mcpInventory)) {
    throw new Error('Endpoint agent package must include sanitized MCP server inventory');
  }
  // The MCP collector reads config files (readFileSync is expected) but must
  // never upload, persist, or log their contents.
  if (/contentBase64|fetch\(|https?:\/\/|writeFileSync|console\.log|console\.error/.test(mcpInventory)) {
    throw new Error('Endpoint MCP inventory must not upload, persist, or log MCP config data');
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

  const intentHost = files.find((file) => file.path === 'sensors/endpoint-agent/native-messaging-host.js').body.toString('utf8');
  if (!/upload_intent/.test(intentHost) || !/resolveIntentFile/.test(intentHost) || !/writeHandoffFile/.test(intentHost)) {
    throw new Error('Endpoint agent package must include the browser file-intent native messaging host');
  }
  if (/contentBase64|readFileSync\(|fetch\(|https?:\/\//.test(intentHost)) {
    throw new Error('Endpoint file-intent host must stay local and never read file bodies or call out');
  }

  const intentInstall = files.find((file) => file.path === 'scripts/install-file-intent-host.ps1').body.toString('utf8');
  if (!/NativeMessagingHosts/.test(intentInstall) || !/allowed_origins/.test(intentInstall) || !/\[a-p\]\{32\}/.test(intentInstall)) {
    throw new Error('Endpoint file-intent host installer must register a per-user host manifest bound to one extension id');
  }
  if (/"-IngestKey"|"-HandoffSecret"|INGEST_API_KEY|ENDPOINT_AGENT_HANDOFF_SECRET/.test(intentInstall)) {
    throw new Error('Endpoint file-intent host installer must not put secrets in launchers, manifests, or the registry');
  }

  const intentUninstall = files.find((file) => file.path === 'scripts/uninstall-file-intent-host.ps1').body.toString('utf8');
  if (!/NativeMessagingHosts/.test(intentUninstall) || !/Remove-Item/.test(intentUninstall)) {
    throw new Error('Endpoint file-intent host uninstaller must remove the per-user host registration');
  }

  const collector = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/protected-upload.js').body.toString('utf8');
  if (!/collectProtectedUploads/.test(collector) || !/writeHandoffFile/.test(collector) || !/waitForHandoffConsumption/.test(collector)) {
    throw new Error('Endpoint agent package must include the protected-upload desktop collector');
  }
  if (/contentBase64|readFileSync\(filePath/.test(collector)) {
    throw new Error('Endpoint desktop collector must not read file bodies or upload file content');
  }

  const clipboardCollector = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/clipboard-guard.js').body.toString('utf8');
  if (!/collectClipboard/.test(clipboardCollector) || !/clientPreRedacted/.test(clipboardCollector) || !/Set-Clipboard/.test(clipboardCollector)) {
    throw new Error('Endpoint agent package must include the clipboard guard collector');
  }
  if (/contentBase64|writeFileSync|readFileSync|console\.log\([^)]*raw|console\.error\([^)]*raw/.test(clipboardCollector)) {
    throw new Error('Endpoint clipboard guard must not upload, persist, or log raw clipboard content');
  }

  const gitPushGuard = files.find((file) => file.path === 'sensors/endpoint-agent/collectors/git-push-guard.js').body.toString('utf8');
  if (!/collectGitPush/.test(gitPushGuard) || !/clientPreRedacted/.test(gitPushGuard) || !/git_push/.test(gitPushGuard)) {
    throw new Error('Endpoint agent package must include the local git push guard collector');
  }
  if (/contentBase64|writeFileSync|readFileSync|shell:\s*true|console\.log\([^)]*diff|console\.error\([^)]*diff/.test(gitPushGuard)) {
    throw new Error('Endpoint git push guard must not upload, persist, shell, or log raw git diff content');
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
  if (!/InstallClipboardGuard/.test(install) || !/install-clipboard-guard\.ps1/.test(install)) {
    throw new Error('Endpoint agent installer must be able to install the clipboard guard shortcut');
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

  const gitPushInstall = files.find((file) => file.path === 'scripts/install-git-push-guard.ps1').body.toString('utf8');
  if (!/git-push-guard\.js/.test(gitPushInstall) || !/PROMPTWALL_ENV_PATH/.test(gitPushInstall) || !/PromptWall Git Push Guard/.test(gitPushInstall)) {
    throw new Error('Endpoint git push guard installer must write a managed pre-push hook');
  }
  if (/"-IngestKey"|"-HandoffSecret"|INGEST_API_KEY|ENDPOINT_AGENT_HANDOFF_SECRET|contentBase64/.test(gitPushInstall)) {
    throw new Error('Endpoint git push guard installer must not put secrets or prompt content in hooks');
  }

  const gitPushUninstall = files.find((file) => file.path === 'scripts/uninstall-git-push-guard.ps1').body.toString('utf8');
  if (!/pre-push/.test(gitPushUninstall) || !/PromptWall Git Push Guard/.test(gitPushUninstall) || !/Remove-Item/.test(gitPushUninstall)) {
    throw new Error('Endpoint git push guard uninstaller must remove only managed hooks by default');
  }

  const clipboardInstall = files.find((file) => file.path === 'scripts/install-clipboard-guard.ps1').body.toString('utf8');
  if (!/WScript\.Shell/.test(clipboardInstall) || !/run-clipboard-guard\.ps1/.test(clipboardInstall) || !/Clipboard Guard/.test(clipboardInstall)) {
    throw new Error('Endpoint clipboard guard installer must create a per-user shortcut');
  }
  if (!/Assert-SafeShortcutName/.test(clipboardInstall) || !/Assert-SafeShortcutArgument/.test(clipboardInstall)) {
    throw new Error('Endpoint clipboard guard installer must validate shortcut labels and arguments');
  }
  if (/"-IngestKey"|"-HandoffSecret"|INGEST_API_KEY|ENDPOINT_AGENT_HANDOFF_SECRET/.test(clipboardInstall)) {
    throw new Error('Endpoint clipboard guard installer must not put secrets in shortcuts');
  }

  const runner = files.find((file) => file.path === 'scripts/run-endpoint-agent.ps1').body.toString('utf8');
  if (!/\$env:PROMPTWALL_ENV_PATH = \$config/.test(runner) || /\$env:SENTINEL_ENV_PATH = \$config/.test(runner)) {
    throw new Error('Endpoint agent runner must load local config through PROMPTWALL_ENV_PATH');
  }

  const clipboardRunner = files.find((file) => file.path === 'scripts/run-clipboard-guard.ps1').body.toString('utf8');
  if (!/\$env:PROMPTWALL_ENV_PATH = \$config/.test(clipboardRunner) || /\$env:SENTINEL_ENV_PATH = \$config/.test(clipboardRunner) || !/clipboard-guard\.js/.test(clipboardRunner) || !/--clear-on-block/.test(clipboardRunner)) {
    throw new Error('Endpoint clipboard guard runner must load config and invoke the clipboard guard collector');
  }
  if (/contentBase64|Get-Clipboard|Set-Clipboard/.test(clipboardRunner)) {
    throw new Error('Endpoint clipboard guard runner must delegate clipboard access to the collector');
  }

  const collectorRunner = files.find((file) => file.path === 'scripts/run-desktop-collector.ps1').body.toString('utf8');
  if (!/\$env:PROMPTWALL_ENV_PATH = \$config/.test(collectorRunner) || /\$env:SENTINEL_ENV_PATH = \$config/.test(collectorRunner) || !/protected-upload\.js/.test(collectorRunner) || !/\[string\[\]\]\$FilePath/.test(collectorRunner)) {
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
      endpointFileFlowProfilesIncluded: true,
      endpointOcrIncluded: true,
      aiToolInventoryIncluded: true,
      nativeHandoffPrototypeIncluded: true,
      nativeHandoffWriterIncluded: true,
      fileIntentHostIncluded: true,
      fileIntentHostInstallerIncluded: true,
      protectedUploadCollectorIncluded: true,
      clipboardGuardIncluded: true,
      gitPushGuardIncluded: true,
      gitPushGuardInstallerIncluded: true,
      clipboardGuardRunnerIncluded: true,
      clipboardGuardInstallerIncluded: true,
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

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const packageFn = deps.packageEndpointAgent || packageEndpointAgent;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  try {
    const args = parseArgs(argv);
    if (args.help) {
      io.log('Usage: node scripts/package-endpoint-agent.js [--out <directory>]');
      return null;
    }
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

module.exports = {
  main,
  packageEndpointAgent,
  parseArgs,
  runtimeBody,
  sha256,
  validateRuntimeFiles,
};
