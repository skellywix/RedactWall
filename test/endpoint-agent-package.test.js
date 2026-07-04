'use strict';
/** Endpoint agent package must be pilot-ready and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AdmZip = require('adm-zip');

const {
  main,
  packageEndpointAgent,
  parseArgs,
  sha256,
  validateRuntimeFiles,
} = require('../scripts/package-endpoint-agent');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-endpoint-agent-package-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function minimalFiles(agentBody) {
  return [
    { path: 'package.json', body: Buffer.from('{"version":"0.0.0"}') },
    { path: 'package-lock.json', body: Buffer.from('{}') },
    { path: 'detection-engine/adapters.js', body: Buffer.from('module.exports = {};') },
    { path: 'detection-engine/detect.js', body: Buffer.from('module.exports = {};') },
    { path: 'server/custom-detectors.js', body: Buffer.from('module.exports = {};') },
    { path: 'server/env.js', body: Buffer.from('module.exports = {};') },
    { path: 'server/policy.js', body: Buffer.from('module.exports = {};') },
    { path: 'server/processors.js', body: Buffer.from('module.exports = {};') },
    { path: 'sensors/endpoint-agent/agent.js', body: Buffer.from(agentBody) },
    {
      path: 'sensors/endpoint-agent/file-flow-profiles.js',
      body: Buffer.from('const MAX_FILE_FLOW_PROFILES = 8;\nfunction publicProfileChecks() {}\nmodule.exports = { publicProfileChecks, MAX_FILE_FLOW_PROFILES };\n'),
    },
    {
      path: 'sensors/endpoint-agent/ocr.js',
      body: Buffer.from('const { execFile } = require("child_process");\nconst env = "ENDPOINT_AGENT_OCR_COMMAND";\nfunction extractImageFile() {}\nmodule.exports = { extractImageFile };\n'),
    },
    {
      path: 'sensors/endpoint-agent/native-handoff.js',
      body: Buffer.from("require('crypto').createHmac('sha256', 'secret'); const blocked = 'contentBase64';"),
    },
    {
      path: 'sensors/endpoint-agent/write-handoff.js',
      body: Buffer.from('function writeHandoffFile() { return signHandoffEvent(); }\nfunction signHandoffEvent() {}\n'),
    },
    {
      path: 'sensors/endpoint-agent/collectors/ai-tool-inventory.js',
      body: Buffer.from('function collectAiToolInventory() {}\nfunction parseApprovedTools() {}\nmodule.exports = { collectAiToolInventory, parseApprovedTools };\n'),
    },
    {
      path: 'sensors/endpoint-agent/collectors/clipboard-guard.js',
      body: Buffer.from('async function collectClipboard() { return { clientPreRedacted: true, cleared: true }; }\nconst cmd = "Set-Clipboard";\n'),
    },
    {
      path: 'sensors/endpoint-agent/collectors/git-push-guard.js',
      body: Buffer.from('async function collectGitPush() { return { clientPreRedacted: true, channel: "git_push" }; }\n'),
    },
    {
      path: 'sensors/endpoint-agent/collectors/protected-upload.js',
      body: Buffer.from('async function collectProtectedUploads() { return writeHandoffFile(); }\nfunction writeHandoffFile() {}\nfunction waitForHandoffConsumption() {}\n'),
    },
    {
      path: 'scripts/check-endpoint-install.js',
      body: Buffer.from("const api = '/api/v1/heartbeat';\nfunction buildInstallReport() {}\nconst key = 'INGEST_API_KEY';\n"),
    },
    {
      path: 'scripts/install-clipboard-guard.ps1',
      body: Buffer.from('WScript.Shell\nrun-clipboard-guard.ps1\nPromptWall Clipboard Guard\nAssert-SafeShortcutName\nAssert-SafeShortcutArgument\n'),
    },
    {
      path: 'scripts/install-desktop-collector.ps1',
      body: Buffer.from('HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\n"%1"\nMultiSelectModel\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET\n'),
    },
    {
      path: 'scripts/install-endpoint-agent.ps1',
      body: Buffer.from('$taskArgs = "-File runner.ps1"\n[Parameter(Mandatory = $true)]\n[string]$IngestKey\nInstallClipboardGuard\ninstall-clipboard-guard.ps1\n'),
    },
    {
      path: 'scripts/install-git-push-guard.ps1',
      body: Buffer.from('PromptWall Git Push Guard\ngit-push-guard.js\nPROMPTWALL_ENV_PATH\n'),
    },
    {
      path: 'scripts/run-clipboard-guard.ps1',
      body: Buffer.from('$env:PROMPTWALL_ENV_PATH = $config\nclipboard-guard.js\n--clear-on-block\n'),
    },
    {
      path: 'scripts/run-desktop-collector.ps1',
      body: Buffer.from('[string[]]$FilePath\n$env:PROMPTWALL_ENV_PATH = $config\nprotected-upload.js\n'),
    },
    {
      path: 'scripts/run-endpoint-agent.ps1',
      body: Buffer.from('$env:PROMPTWALL_ENV_PATH = $config\n'),
    },
    { path: 'scripts/uninstall-desktop-collector.ps1', body: Buffer.from('Remove-Item\n') },
    { path: 'scripts/uninstall-clipboard-guard.ps1', body: Buffer.from('Remove-Item\n') },
    { path: 'scripts/uninstall-endpoint-agent.ps1', body: Buffer.from('Unregister-ScheduledTask\n') },
    { path: 'scripts/uninstall-git-push-guard.ps1', body: Buffer.from('pre-push\nPromptWall Git Push Guard\nRemove-Item\n') },
  ];
}

const validAgentBody = [
  "const KEY = process.env.INGEST_API_KEY || '';",
  "const outcome = 'redacted_available';",
  "const dir = '.promptwall-redacted';",
  "require('./native-handoff');",
  "const handoff = 'ENDPOINT_AGENT_HANDOFF_SECRET';",
  "require('./file-flow-profiles');",
  'function startWatchedRoot() {}',
  "const ocr = require('./ocr');",
  'function extractEndpointFile() {}',
].join('\n');

function replaceBody(files, relPath, body) {
  return files.map((file) => (
    file.path === relPath ? { ...file, body: Buffer.from(body) } : file
  ));
}

function withoutFile(files, relPath) {
  return files.filter((file) => file.path !== relPath);
}

test('package script writes a prompt-free endpoint agent zip and integrity manifest', (t) => {
  const outDir = tempDir(t);
  const result = packageEndpointAgent({ outDir, now: new Date('2026-06-26T12:00:00.000Z') });
  assert.ok(fs.existsSync(result.zipPath));
  assert.ok(fs.existsSync(result.manifestPath));

  const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  const zipBody = fs.readFileSync(result.zipPath);
  assert.strictEqual(manifest.kind, 'promptwall-endpoint-agent-package');
  assert.strictEqual(manifest.sha256, sha256(zipBody));
  assert.strictEqual(manifest.appVersion, JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version);
  assert.strictEqual(manifest.checks.explicitIngestKeyRequired, true);
  assert.strictEqual(manifest.checks.localDetectionEngineIncluded, true);
  assert.strictEqual(manifest.checks.endpointRedactionHandoffIncluded, true);
  assert.strictEqual(manifest.checks.endpointFileFlowProfilesIncluded, true);
  assert.strictEqual(manifest.checks.endpointOcrIncluded, true);
  assert.strictEqual(manifest.checks.aiToolInventoryIncluded, true);
  assert.strictEqual(manifest.checks.nativeHandoffPrototypeIncluded, true);
  assert.strictEqual(manifest.checks.nativeHandoffWriterIncluded, true);
  assert.strictEqual(manifest.checks.protectedUploadCollectorIncluded, true);
  assert.strictEqual(manifest.checks.clipboardGuardIncluded, true);
  assert.strictEqual(manifest.checks.gitPushGuardIncluded, true);
  assert.strictEqual(manifest.checks.gitPushGuardInstallerIncluded, true);
  assert.strictEqual(manifest.checks.clipboardGuardRunnerIncluded, true);
  assert.strictEqual(manifest.checks.clipboardGuardInstallerIncluded, true);
  assert.strictEqual(manifest.checks.desktopCollectorInstallerIncluded, true);
  assert.strictEqual(manifest.checks.installValidationIncluded, true);
  assert.strictEqual(manifest.checks.scheduledTaskInstallerIncluded, true);
  assert.strictEqual(manifest.checks.localConfigEnvPath, true);
  assert.strictEqual(manifest.checks.taskArgsDoNotExposeIngestKey, true);
  assert.strictEqual(manifest.checks.developmentIngestKeyAbsent, true);
  assert.strictEqual(manifest.checks.promptBodiesAbsent, true);

  const zip = new AdmZip(result.zipPath);
  const entries = zip.getEntries().map((entry) => entry.entryName).sort();
  for (const required of [
    'package.json',
    'package-lock.json',
    'detection-engine/adapters.js',
    'detection-engine/detect.js',
    'server/custom-detectors.js',
    'server/env.js',
    'server/policy.js',
    'server/processors.js',
    'sensors/endpoint-agent/agent.js',
    'sensors/endpoint-agent/file-flow-profiles.js',
    'sensors/endpoint-agent/ocr.js',
    'sensors/endpoint-agent/native-handoff.js',
    'sensors/endpoint-agent/write-handoff.js',
    'sensors/endpoint-agent/collectors/ai-tool-inventory.js',
    'sensors/endpoint-agent/collectors/clipboard-guard.js',
    'sensors/endpoint-agent/collectors/git-push-guard.js',
    'sensors/endpoint-agent/collectors/protected-upload.js',
    'scripts/check-endpoint-install.js',
    'scripts/install-clipboard-guard.ps1',
    'scripts/install-desktop-collector.ps1',
    'scripts/install-endpoint-agent.ps1',
    'scripts/install-git-push-guard.ps1',
    'scripts/run-clipboard-guard.ps1',
    'scripts/run-desktop-collector.ps1',
    'scripts/run-endpoint-agent.ps1',
    'scripts/uninstall-clipboard-guard.ps1',
    'scripts/uninstall-desktop-collector.ps1',
    'scripts/uninstall-endpoint-agent.ps1',
    'scripts/uninstall-git-push-guard.ps1',
  ]) {
    assert.ok(entries.includes(required), required);
    assert.ok(manifest.files.some((file) => file.path === required), required);
  }

  const agent = zip.readAsText('sensors/endpoint-agent/agent.js');
  assert.match(agent, /process\.env\.INGEST_API_KEY \|\| ''/);
  assert.match(agent, /redacted_available/);
  assert.match(agent, /\.promptwall-redacted/);
  assert.match(agent, /ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.match(agent, /file-flow-profiles/);
  assert.match(agent, /startWatchedRoot/);
  assert.match(agent, /extractEndpointFile/);
  assert.match(zip.readAsText('sensors/endpoint-agent/file-flow-profiles.js'), /publicProfileChecks/);
  assert.match(zip.readAsText('sensors/endpoint-agent/ocr.js'), /ENDPOINT_AGENT_OCR_COMMAND/);
  assert.match(zip.readAsText('sensors/endpoint-agent/ocr.js'), /extractImageFile/);
  assert.match(zip.readAsText('sensors/endpoint-agent/native-handoff.js'), /createHmac\('sha256'/);
  assert.match(zip.readAsText('sensors/endpoint-agent/write-handoff.js'), /writeHandoffFile/);
  assert.match(zip.readAsText('sensors/endpoint-agent/collectors/ai-tool-inventory.js'), /collectAiToolInventory/);
  assert.match(zip.readAsText('sensors/endpoint-agent/collectors/clipboard-guard.js'), /collectClipboard/);
  assert.match(zip.readAsText('sensors/endpoint-agent/collectors/git-push-guard.js'), /collectGitPush/);
  assert.match(zip.readAsText('sensors/endpoint-agent/collectors/protected-upload.js'), /collectProtectedUploads/);
  assert.match(zip.readAsText('scripts/check-endpoint-install.js'), /\/api\/v1\/heartbeat/);
  assert.match(zip.readAsText('scripts/install-clipboard-guard.ps1'), /PromptWall Clipboard Guard/);
  assert.match(zip.readAsText('scripts/install-git-push-guard.ps1'), /PromptWall Git Push Guard/);
  assert.match(zip.readAsText('scripts/run-clipboard-guard.ps1'), /clipboard-guard\.js/);
  assert.match(zip.readAsText('scripts/install-desktop-collector.ps1'), /HKEY_CURRENT_USER\\Software\\Classes\\\*\\shell/);
  assert.match(zip.readAsText('scripts/run-desktop-collector.ps1'), /protected-upload\.js/);
  assert.doesNotMatch(agent, /dev-ingest-key|524-71-9043|4111 1111 1111 1111/);
  assert.doesNotMatch(JSON.stringify(manifest), /prompt\s*:/i);
  assert.doesNotMatch(JSON.stringify(manifest), /524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY/);
});

test('package validation refuses prompt bodies or development keys', () => {
  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';\nconst outcome = 'redacted_available';\nconst dir = '.promptwall-redacted';")),
    /development ingest key/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst outcome = 'redacted_available';\nconst dir = '.promptwall-redacted';\nconst sample = '524-71-9043';")),
    /synthetic SSN demo value/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst outcome = 'redacted_available';\nconst dir = '.promptwall-redacted';\nconst path = '/api/v1/scan-file';\nconst contentBase64 = 'abc';")),
    /without uploading file bodies/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';")),
    /redacted companion handoff/
  );
});

test('package validation covers endpoint runtime and installer guardrails', () => {
  const validFiles = minimalFiles(validAgentBody);
  assert.doesNotThrow(() => validateRuntimeFiles(validFiles));

  const cases = [
    {
      name: 'missing package member',
      files: withoutFile(validFiles, 'scripts/run-endpoint-agent.ps1'),
      message: /missing scripts\/run-endpoint-agent\.ps1/,
    },
    {
      name: 'agent missing explicit key',
      files: minimalFiles("const KEY = process.env.INGEST_API_KEY || 'fallback';\nredacted_available\n.promptwall-redacted\nnative-handoff\nENDPOINT_AGENT_HANDOFF_SECRET\n./ocr\nextractEndpointFile"),
      message: /explicit INGEST_API_KEY/,
    },
    {
      name: 'agent missing native handoff',
      files: minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nredacted_available\n.promptwall-redacted\n./ocr\nextractEndpointFile"),
      message: /signed native handoff/,
    },
    {
      name: 'agent missing file-flow profile watcher',
      files: minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nredacted_available\n.promptwall-redacted\nnative-handoff\nENDPOINT_AGENT_HANDOFF_SECRET\n./ocr\nextractEndpointFile"),
      message: /file-flow watcher profiles/,
    },
    {
      name: 'file-flow profile parser missing public checks',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/file-flow-profiles.js', 'const MAX_FILE_FLOW_PROFILES = 8;'),
      message: /file-flow profile validation/,
    },
    {
      name: 'file-flow profile parser leaks path data',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/file-flow-profiles.js', 'const MAX_FILE_FLOW_PROFILES = 8;\nfunction publicProfileChecks() {}\nconsole.log(process.env.USERPROFILE);'),
      message: /must not upload, persist, or log local path data/,
    },
    {
      name: 'agent missing OCR bridge',
      files: minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nredacted_available\n.promptwall-redacted\nnative-handoff\nENDPOINT_AGENT_HANDOFF_SECRET\nfile-flow-profiles\nstartWatchedRoot"),
      message: /endpoint-local OCR/,
    },
    {
      name: 'OCR bridge missing runtime pieces',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/ocr.js', 'function extractImageFile() {}'),
      message: /endpoint-local OCR bridge/,
    },
    {
      name: 'OCR bridge shells or uploads',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/ocr.js', "function extractImageFile() {}\nconst execFile = 1;\nconst c = 'ENDPOINT_AGENT_OCR_COMMAND';\nfetch('https://example.test');"),
      message: /OCR bridge must stay local/,
    },
    {
      name: 'AI tool inventory missing parser',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/ai-tool-inventory.js', 'function collectAiToolInventory() {}'),
      message: /sanitized AI tool inventory/,
    },
    {
      name: 'AI tool inventory leaks process data',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/ai-tool-inventory.js', 'function collectAiToolInventory() {}\nfunction parseApprovedTools() {}\nfetch("https://example.test");'),
      message: /must not upload, persist, or log/,
    },
    {
      name: 'native handoff missing HMAC',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/native-handoff.js', "const payload = 'contentBase64';"),
      message: /native handoff must be signed/,
    },
    {
      name: 'handoff writer missing signer',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/write-handoff.js', 'function writeHandoffFile() {}'),
      message: /native handoff writer/,
    },
    {
      name: 'handoff writer exposes secret arg',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/write-handoff.js', 'function writeHandoffFile() { return signHandoffEvent(); }\nfunction signHandoffEvent() {}\nconst arg = "--secret";'),
      message: /must not take secrets/,
    },
    {
      name: 'protected upload missing consumption wait',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/protected-upload.js', 'function collectProtectedUploads() {}\nfunction writeHandoffFile() {}'),
      message: /protected-upload desktop collector/,
    },
    {
      name: 'protected upload reads bodies',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/protected-upload.js', 'function collectProtectedUploads() { return writeHandoffFile(); }\nfunction writeHandoffFile() {}\nfunction waitForHandoffConsumption() {}\nreadFileSync(filePath);'),
      message: /must not read file bodies/,
    },
    {
      name: 'clipboard collector missing clear path',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/clipboard-guard.js', 'function collectClipboard() {}\nclientPreRedacted'),
      message: /clipboard guard collector/,
    },
    {
      name: 'clipboard collector persists raw content',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/clipboard-guard.js', 'function collectClipboard() {}\nclientPreRedacted\nSet-Clipboard\nwriteFileSync(raw);'),
      message: /must not upload, persist, or log raw/,
    },
    {
      name: 'git push guard missing sanitized evidence path',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/git-push-guard.js', 'function collectGitPush() {}'),
      message: /local git push guard collector/,
    },
    {
      name: 'git push guard persists raw diff',
      files: replaceBody(validFiles, 'sensors/endpoint-agent/collectors/git-push-guard.js', 'function collectGitPush() {}\nclientPreRedacted\ngit_push\nwriteFileSync(diff);'),
      message: /must not upload, persist, shell, or log raw git diff content/,
    },
    {
      name: 'git push guard installer missing managed hook',
      files: replaceBody(validFiles, 'scripts/install-git-push-guard.ps1', 'PROMPTWALL_ENV_PATH'),
      message: /managed pre-push hook/,
    },
    {
      name: 'git push guard installer exposes secret',
      files: replaceBody(validFiles, 'scripts/install-git-push-guard.ps1', 'PromptWall Git Push Guard\ngit-push-guard.js\nPROMPTWALL_ENV_PATH\nINGEST_API_KEY'),
      message: /must not put secrets or prompt content in hooks/,
    },
    {
      name: 'git push guard uninstaller can remove arbitrary hooks',
      files: replaceBody(validFiles, 'scripts/uninstall-git-push-guard.ps1', 'Remove-Item'),
      message: /remove only managed hooks/,
    },
    {
      name: 'install validation missing heartbeat',
      files: replaceBody(validFiles, 'scripts/check-endpoint-install.js', "function buildInstallReport() {}\nconst key = 'INGEST_API_KEY';"),
      message: /install validation with heartbeat/,
    },
    {
      name: 'install validation reads file bodies',
      files: replaceBody(validFiles, 'scripts/check-endpoint-install.js', "const api = '/api/v1/heartbeat';\nfunction buildInstallReport() {}\nconst key = 'INGEST_API_KEY';\nconst bad = 'contentBase64';"),
      message: /must not read file bodies or package development keys/,
    },
    {
      name: 'endpoint installer missing mandatory ingest key',
      files: replaceBody(validFiles, 'scripts/install-endpoint-agent.ps1', '$taskArgs = "-File runner.ps1"'),
      message: /must require an ingest key/,
    },
    {
      name: 'endpoint installer exposes ingest key in task args',
      files: replaceBody(validFiles, 'scripts/install-endpoint-agent.ps1', '[Parameter(Mandatory = $true)]\n[string]$IngestKey\n$taskArgs = "-IngestKey $IngestKey"\nInstallClipboardGuard\ninstall-clipboard-guard.ps1'),
      message: /must not put the ingest key/,
    },
    {
      name: 'endpoint installer exposes handoff secret in task args',
      files: replaceBody(validFiles, 'scripts/install-endpoint-agent.ps1', '$taskArgs = \'"-HandoffSecret" $HandoffSecret\'\n[Parameter(Mandatory = $true)]\n[string]$IngestKey\nInstallClipboardGuard\ninstall-clipboard-guard.ps1'),
      message: /must not put the native handoff secret/,
    },
    {
      name: 'endpoint installer cannot install clipboard guard',
      files: replaceBody(validFiles, 'scripts/install-endpoint-agent.ps1', '$taskArgs = "-File runner.ps1"\n[Parameter(Mandatory = $true)]\n[string]$IngestKey'),
      message: /must be able to install the clipboard guard/,
    },
    {
      name: 'desktop collector installer missing shell action',
      files: replaceBody(validFiles, 'scripts/install-desktop-collector.ps1', 'PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET'),
      message: /register a per-user file shell action/,
    },
    {
      name: 'desktop collector installer missing env aliases',
      files: replaceBody(validFiles, 'scripts/install-desktop-collector.ps1', 'HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\n"%1"\nMultiSelectModel'),
      message: /accept PromptWall handoff env aliases/,
    },
    {
      name: 'desktop collector installer exposes secrets',
      files: replaceBody(validFiles, 'scripts/install-desktop-collector.ps1', 'HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\n"%1"\nMultiSelectModel\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET\n"-HandoffSecret"'),
      message: /must not put secrets in shell commands/,
    },
    {
      name: 'clipboard installer missing shortcut',
      files: replaceBody(validFiles, 'scripts/install-clipboard-guard.ps1', 'Assert-SafeShortcutName\nAssert-SafeShortcutArgument'),
      message: /create a per-user shortcut/,
    },
    {
      name: 'clipboard installer missing validation',
      files: replaceBody(validFiles, 'scripts/install-clipboard-guard.ps1', 'WScript.Shell\nrun-clipboard-guard.ps1\nPromptWall Clipboard Guard'),
      message: /validate shortcut labels and arguments/,
    },
    {
      name: 'clipboard installer exposes secrets',
      files: replaceBody(validFiles, 'scripts/install-clipboard-guard.ps1', 'WScript.Shell\nrun-clipboard-guard.ps1\nPromptWall Clipboard Guard\nAssert-SafeShortcutName\nAssert-SafeShortcutArgument\nINGEST_API_KEY'),
      message: /must not put secrets in shortcuts/,
    },
    {
      name: 'endpoint runner missing PromptWall env path',
      files: replaceBody(validFiles, 'scripts/run-endpoint-agent.ps1', '$env:SENTINEL_ENV_PATH = $config'),
      message: /runner must load local config/,
    },
    {
      name: 'clipboard runner missing invocation',
      files: replaceBody(validFiles, 'scripts/run-clipboard-guard.ps1', '$env:PROMPTWALL_ENV_PATH = $config'),
      message: /clipboard guard runner/,
    },
    {
      name: 'clipboard runner touches clipboard directly',
      files: replaceBody(validFiles, 'scripts/run-clipboard-guard.ps1', '$env:PROMPTWALL_ENV_PATH = $config\nclipboard-guard.js\n--clear-on-block\nGet-Clipboard'),
      message: /must delegate clipboard access/,
    },
    {
      name: 'desktop runner missing file array',
      files: replaceBody(validFiles, 'scripts/run-desktop-collector.ps1', '$env:PROMPTWALL_ENV_PATH = $config\nprotected-upload.js'),
      message: /desktop collector runner/,
    },
  ];

  for (const item of cases) {
    assert.throws(() => validateRuntimeFiles(item.files), item.message, item.name);
  }
});

test('package CLI main writes status, help, and errors through injected console', () => {
  const logs = [];
  const errors = [];
  const exitCodes = [];
  const io = {
    log: (line) => logs.push(String(line)),
    error: (line) => errors.push(String(line)),
  };
  const result = main(['--out', 'dist/custom-endpoint'], {
    console: io,
    setExitCode: (code) => exitCodes.push(code),
    packageEndpointAgent: ({ outDir }) => ({
      zipPath: path.join(outDir, 'endpoint.zip'),
      manifestPath: path.join(outDir, 'endpoint.manifest.json'),
      packageManifest: { sha256: 'abc123' },
    }),
  });
  assert.match(result.zipPath, /custom-endpoint[\\/]endpoint\.zip$/);
  assert.ok(logs.some((line) => /SHA-256 abc123/.test(line)));
  assert.deepStrictEqual(exitCodes, []);

  logs.length = 0;
  assert.strictEqual(main(['--help'], { console: io, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.match(logs.join('\n'), /Usage: node scripts\/package-endpoint-agent\.js/);

  assert.strictEqual(main(['--bad'], { console: io, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.ok(errors.some((line) => /Unknown option: --bad/.test(line)));
  assert.ok(exitCodes.includes(1));
});

test('packaged endpoint agent runs a package-to-install pilot smoke', async (t) => {
  const outDir = tempDir(t, 'ps-endpoint-agent-pilot-package-');
  const installRoot = tempDir(t, 'ps-endpoint-agent-pilot-install-');
  const watchDir = path.join(installRoot, 'watch');
  const configDir = path.join(installRoot, 'config');
  const configPath = path.join(configDir, 'endpoint-agent.env');
  const packageHandoffDir = path.join(installRoot, 'configured-native-handoff');
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(configPath, [
    'PROMPTWALL_URL=http://promptwall.package.test',
    'INGEST_API_KEY=pilot-ingest-key-000000000000000000000000000001',
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    `ENDPOINT_AGENT_HANDOFF_SECRET=native-handoff-secret-000000000000000001`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${packageHandoffDir}`,
    'SENTINEL_REQUEST_TIMEOUT_MS=250',
  ].join('\n') + '\n');

  const packaged = packageEndpointAgent({ outDir, now: new Date('2026-06-26T13:00:00.000Z') });
  const zip = new AdmZip(packaged.zipPath);
  zip.extractAllTo(installRoot, true);

  const installScript = fs.readFileSync(path.join(installRoot, 'scripts', 'install-endpoint-agent.ps1'), 'utf8');
  const clipboardInstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'install-clipboard-guard.ps1'), 'utf8');
  const clipboardRunnerScript = fs.readFileSync(path.join(installRoot, 'scripts', 'run-clipboard-guard.ps1'), 'utf8');
  const desktopInstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'install-desktop-collector.ps1'), 'utf8');
  const desktopRunnerScript = fs.readFileSync(path.join(installRoot, 'scripts', 'run-desktop-collector.ps1'), 'utf8');
  const gitPushInstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'install-git-push-guard.ps1'), 'utf8');
  const gitPushUninstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'uninstall-git-push-guard.ps1'), 'utf8');
  const runnerScript = fs.readFileSync(path.join(installRoot, 'scripts', 'run-endpoint-agent.ps1'), 'utf8');
  const uninstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'uninstall-endpoint-agent.ps1'), 'utf8');
  assert.match(installScript, /Register-ScheduledTask/);
  assert.match(installScript, /\[Alias\("SentinelUrl"\)\]/);
  assert.match(installScript, /PROMPTWALL_URL=\$PromptWallUrl/);
  assert.match(installScript, /INGEST_API_KEY=\$IngestKey/);
  assert.match(installScript, /InstallDesktopCollector/);
  assert.match(installScript, /InstallClipboardGuard/);
  assert.match(installScript, /install-clipboard-guard\.ps1/);
  assert.doesNotMatch(installScript, /"-IngestKey"/);
  assert.ok(desktopInstallScript.includes(String.raw`HKEY_CURRENT_USER\Software\Classes\*\shell`));
  assert.ok(desktopInstallScript.includes('%1'));
  assert.match(desktopInstallScript, /MultiSelectModel/);
  assert.match(desktopInstallScript, /PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.doesNotMatch(desktopInstallScript, /"-HandoffSecret"/);
  assert.match(clipboardInstallScript, /WScript\.Shell/);
  assert.match(clipboardInstallScript, /run-clipboard-guard\.ps1/);
  assert.match(clipboardInstallScript, /PromptWall Clipboard Guard/);
  assert.doesNotMatch(clipboardInstallScript, /INGEST_API_KEY|ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.match(clipboardRunnerScript, /clipboard-guard\.js/);
  assert.match(clipboardRunnerScript, /\$env:PROMPTWALL_ENV_PATH = \$config/);
  assert.match(clipboardRunnerScript, /--clear-on-block/);
  assert.doesNotMatch(clipboardRunnerScript, /\$env:SENTINEL_ENV_PATH = \$config/);
  assert.doesNotMatch(clipboardRunnerScript, /Get-Clipboard|Set-Clipboard|contentBase64/);
  assert.match(desktopRunnerScript, /protected-upload\.js/);
  assert.match(desktopRunnerScript, /\[string\[\]\]\$FilePath/);
  assert.match(desktopRunnerScript, /\$env:PROMPTWALL_ENV_PATH = \$config/);
  assert.match(gitPushInstallScript, /git-push-guard\.js/);
  assert.match(gitPushInstallScript, /PROMPTWALL_ENV_PATH/);
  assert.match(gitPushInstallScript, /PromptWall Git Push Guard/);
  assert.doesNotMatch(gitPushInstallScript, /INGEST_API_KEY|ENDPOINT_AGENT_HANDOFF_SECRET|contentBase64/);
  assert.match(gitPushUninstallScript, /PromptWall Git Push Guard/);
  assert.match(gitPushUninstallScript, /Remove-Item/);
  assert.match(runnerScript, /\$env:PROMPTWALL_ENV_PATH = \$config/);
  assert.doesNotMatch(desktopRunnerScript, /\$env:SENTINEL_ENV_PATH = \$config/);
  assert.doesNotMatch(runnerScript, /\$env:SENTINEL_ENV_PATH = \$config/);
  assert.match(uninstallScript, /Unregister-ScheduledTask/);
  assert.match(uninstallScript, /RemoveDesktopCollector/);
  assert.match(uninstallScript, /endpoint-agent\.env/);

  const previousEnv = {};
  for (const key of ['SENTINEL_ENV_PATH', 'PROMPTWALL_ENV_PATH', 'SENTINEL_URL', 'PROMPTWALL_URL', 'INGEST_API_KEY', 'ENDPOINT_AGENT_WATCH_DIR', 'SENTINEL_REQUEST_TIMEOUT_MS']) {
    previousEnv[key] = process.env[key];
    delete process.env[key];
  }
  process.env.PROMPTWALL_ENV_PATH = configPath;
  t.after(() => {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  const agentPath = require.resolve(path.join(installRoot, 'sensors', 'endpoint-agent', 'agent.js'));
  const writerPath = require.resolve(path.join(installRoot, 'sensors', 'endpoint-agent', 'write-handoff.js'));
  const clipboardPath = require.resolve(path.join(installRoot, 'sensors', 'endpoint-agent', 'collectors', 'clipboard-guard.js'));
  const collectorPath = require.resolve(path.join(installRoot, 'sensors', 'endpoint-agent', 'collectors', 'protected-upload.js'));
  delete require.cache[agentPath];
  delete require.cache[writerPath];
  delete require.cache[clipboardPath];
  delete require.cache[collectorPath];
  const agent = require(agentPath);
  const handoffWriter = require(writerPath);
  const clipboardCollector = require(clipboardPath);
  const desktopCollector = require(collectorPath);
  t.after(() => {
    delete require.cache[agentPath];
    delete require.cache[writerPath];
    delete require.cache[clipboardPath];
    delete require.cache[collectorPath];
  });
  assert.strictEqual(agent.configuredKey({}), 'pilot-ingest-key-000000000000000000000000000001');

  fs.mkdirSync(watchDir, { recursive: true });
  const filename = 'member-524-71-9043.txt';
  fs.writeFileSync(path.join(watchDir, filename), 'Loan file. SSN 524-71-9043. Card 4111 1111 1111 1111.');

  const requests = [];
  const fetchImpl = async (url, opts = {}) => {
    requests.push({ url, method: opts.method || 'GET', body: opts.body || '' });
    assert.strictEqual(opts.headers['x-api-key'], 'pilot-ingest-key-000000000000000000000000000001');
    if (url === 'http://promptwall.package.test/api/v1/policy') {
      return {
        ok: true,
        json: async () => ({
          enforcementMode: 'redact',
          blockMinSeverity: 2,
          blockRiskScore: 20,
          alwaysBlock: ['US_SSN', 'CREDIT_CARD'],
          ignore: [],
          disabledDetectors: [],
          desktopCollectorDestination: 'Copilot Desktop',
          scanner: {
            ignoreDirectories: [],
            ignoreFilenames: [],
            ignoreExtensions: ['.tmp'],
            maxFileBytes: 4096,
          },
        }),
      };
    }
    if (url === 'http://promptwall.package.test/api/v1/gate') {
      const body = JSON.parse(opts.body);
      if (body.channel === 'clipboard') {
        assert.strictEqual(body.source, 'endpoint_agent');
        assert.strictEqual(body.clientOutcome, 'action_blocked');
        assert.strictEqual(body.clientPreRedacted, true);
        assert.match(body.prompt, /^\[clipboard blocked locally\]/);
        assert.ok(body.clientFindings.some((finding) => finding.type === 'US_SSN'));
        assert.ok(body.clientFindings.some((finding) => finding.type === 'CREDIT_CARD'));
        assert.ok(!JSON.stringify(body).includes('524-71-9043'));
        assert.ok(!JSON.stringify(body).includes('4111 1111 1111 1111'));
        return {
          ok: true,
          json: async () => ({
            id: 'q_packaged_clipboard',
            decision: 'block',
            mode: 'browser_action_block',
            status: 'action_blocked',
          }),
        };
      }
      assert.strictEqual(body.clientOutcome, 'redacted_available');
      assert.strictEqual(body.clientPreRedacted, true);
      assert.strictEqual(body.source, 'endpoint_agent');
      assert.strictEqual(body.channel, 'file_upload');
      const isNativeHandoff = /evt_packaged_native/.test(body.note || '');
      assert.match(body.prompt, /\[\[US_SSN_1\]\]/);
      if (isNativeHandoff) {
        assert.strictEqual(body.destination, 'Desktop AI');
        assert.strictEqual(body.user, 'native-user@example.test');
        assert.match(body.note, /native handoff evt_packaged_native/);
      } else {
        assert.match(body.prompt, /\[\[CREDIT_CARD_1\]\]/);
        assert.ok(body.clientFindings.some((finding) => finding.type === 'CREDIT_CARD'));
      }
      assert.match(body.note, /\.promptwall-redacted/);
      assert.ok(body.clientFindings.some((finding) => finding.type === 'US_SSN'));
      assert.ok(!JSON.stringify(body).includes('524-71-9043'));
      assert.ok(!JSON.stringify(body).includes('4111 1111 1111 1111'));
      assert.strictEqual(body.contentBase64, undefined);
      return {
        ok: true,
        json: async () => ({
          id: 'q_packaged_pilot',
          decision: 'redact',
          mode: 'redact',
          status: 'redacted',
          tokenizedPrompt: body.prompt,
          findings: body.clientFindings,
          categories: [],
          riskScore: body.clientRiskScore,
        }),
      };
    }
    throw new Error('unexpected packaged endpoint request: ' + url);
  };

  const scanner = await agent.refreshPolicy({ fetchImpl });
  assert.strictEqual(scanner.maxFileBytes, 4096);
  assert.ok(scanner.ignoreExtensions.has('.tmp'));

  const result = await agent.scanFile(filename, { user: 'pilot-user', fetchImpl });
  assert.strictEqual(result.decision, 'redact');
  assert.strictEqual(result.status, 'redacted');
  assert.ok(result.redactionHandoff);
  assert.match(result.redactionHandoff.relativePath, /^\.promptwall-redacted[\\/]/);
  assert.ok(!result.redactionHandoff.relativePath.includes('524-71-9043'));

  const companion = fs.readFileSync(result.redactionHandoff.path, 'utf8');
  assert.match(companion, /\[\[US_SSN_1\]\]/);
  assert.match(companion, /\[\[CREDIT_CARD_1\]\]/);
  assert.match(companion, /Original file: \[sensitive filename\]/);
  assert.ok(!companion.includes('524-71-9043'));
  assert.ok(!companion.includes('4111 1111 1111 1111'));
  assert.ok(requests.some((request) => request.url.endsWith('/api/v1/policy')));
  assert.ok(requests.some((request) => request.url.endsWith('/api/v1/gate')));

  const sourceDir = path.join(installRoot, 'native-source');
  const handoffDir = path.join(installRoot, 'native-handoff');
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(handoffDir, { recursive: true });
  const nativeFile = path.join(sourceDir, 'member-524-71-9043.txt');
  fs.writeFileSync(nativeFile, 'Native file flow SSN 524-71-9043 and card 4111 1111 1111 1111.');
  const nativeSecret = 'native-handoff-secret-000000000000000001';
  const collectorResult = await desktopCollector.collectProtectedUploads({
    files: [nativeFile],
    envPath: configPath,
    id: 'evt_packaged_collector',
    now: new Date('2026-06-26T13:00:30.000Z'),
    destination: 'Desktop AI',
    user: 'native-user@example.test',
    nonce: 'collector-nonce',
  });
  assert.strictEqual(collectorResult.status, 'written');
  assert.ok(!JSON.stringify(collectorResult).includes('524-71-9043'));
  const collectorEventPath = path.join(packageHandoffDir, 'evt_packaged_collector.json');
  assert.ok(fs.existsSync(collectorEventPath));
  assert.ok(!fs.readFileSync(collectorEventPath, 'utf8').includes('Native file flow SSN'));

  const collectorNativeResult = await agent.processNativeHandoffFile(collectorEventPath, {
    secret: nativeSecret,
    now: new Date('2026-06-26T13:01:00.000Z'),
    policy: {
      enforcementMode: 'redact',
      blockMinSeverity: 2,
      blockRiskScore: 20,
      alwaysBlock: ['US_SSN', 'CREDIT_CARD'],
      ignore: [],
      disabledDetectors: [],
    },
    fetchImpl,
  });
  assert.strictEqual(collectorNativeResult.status, 'processed');
  assert.strictEqual(collectorNativeResult.result.decision, 'redact');
  assert.strictEqual(fs.existsSync(collectorEventPath), false);

  const nativeEvent = handoffWriter.writeHandoffFile({
    filePath: nativeFile,
    dir: handoffDir,
    secret: nativeSecret,
    id: 'evt_packaged_native',
    now: new Date('2026-06-26T13:01:00.000Z'),
    destination: 'Desktop AI',
    user: 'native-user@example.test',
    nonce: 'native-nonce',
  });
  assert.ok(fs.existsSync(nativeEvent.path));
  assert.ok(!fs.readFileSync(nativeEvent.path, 'utf8').includes('Native file flow SSN'));

  const nativeResult = await agent.processNativeHandoffFile(nativeEvent.path, {
    secret: nativeSecret,
    now: new Date('2026-06-26T13:02:00.000Z'),
    policy: {
      enforcementMode: 'redact',
      blockMinSeverity: 2,
      blockRiskScore: 20,
      alwaysBlock: ['US_SSN', 'CREDIT_CARD'],
      ignore: [],
      disabledDetectors: [],
    },
    fetchImpl,
  });

  assert.strictEqual(nativeResult.status, 'processed');
  assert.strictEqual(nativeResult.result.decision, 'redact');
  assert.strictEqual(fs.existsSync(nativeEvent.path), false);

  let clipboardCleared = 0;
  const clipboardResult = await clipboardCollector.collectClipboard({
    readClipboard: async () => 'Clipboard SSN 524-71-9043 and card 4111 1111 1111 1111.',
    clearClipboard: async () => { clipboardCleared += 1; },
    clearOnBlock: true,
    policy: {
      enforcementMode: 'block',
      blockMinSeverity: 2,
      blockRiskScore: 20,
      alwaysBlock: ['US_SSN', 'CREDIT_CARD'],
      ignore: [],
      disabledDetectors: [],
    },
    fetchImpl,
  });
  assert.strictEqual(clipboardCleared, 1);
  assert.strictEqual(clipboardResult.status, 'blocked');
  assert.strictEqual(clipboardResult.cleared, true);
  assert.ok(clipboardResult.recorded);
  assert.ok(requests.some((request) => {
    if (!request.url.endsWith('/api/v1/gate')) return false;
    const body = JSON.parse(request.body);
    return body.channel === 'clipboard' && body.clientOutcome === 'action_blocked';
  }));
  assert.ok(!JSON.stringify(requests).includes('524-71-9043'));
  assert.ok(!JSON.stringify(requests).includes('4111 1111 1111 1111'));
});

test('package args support explicit output directories', () => {
  const parsed = parseArgs(['--out', 'dist/custom-endpoint']);
  assert.match(parsed.outDir, /dist[\\/]custom-endpoint$/);
  assert.match(parseArgs(['dist/positional-endpoint']).outDir, /dist[\\/]positional-endpoint$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
});
