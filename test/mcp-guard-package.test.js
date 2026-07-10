'use strict';
/** MCP guard package must be pilot-ready and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const AdmZip = require('adm-zip');

const {
  main,
  packageMcpGuard,
  parseArgs,
  sha256,
  validateRuntimeFiles,
} = require('../scripts/package-mcp-guard');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-mcp-guard-package-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function minimalMcpFiles(guardBody = "const KEY = process.env.INGEST_API_KEY || '';") {
  return [
    { path: 'package.json', body: Buffer.from('{}') },
    { path: 'server/env.js', body: Buffer.from('module.exports = {};') },
    { path: 'server/file-mutation-lock.js', body: Buffer.from('module.exports = {};') },
    { path: 'server/private-path.js', body: Buffer.from('module.exports = {};') },
    { path: 'detection-engine/detect.js', body: Buffer.from('module.exports = {};') },
    { path: 'sensors/shared/decision.js', body: Buffer.from('function mandatoryAlwaysBlock(v) { return v || []; }\nmodule.exports = { mandatoryAlwaysBlock };') },
    { path: 'sensors/shared/bounded-response.js', body: Buffer.from('function readBoundedJson() {}\nfunction readBoundedText() {}\nmodule.exports = { readBoundedJson, readBoundedText };') },
    { path: 'sensors/shared/opaque-content.js', body: Buffer.from('function carriesEncodedSensitiveText() {}\nfunction carriesNumericContent() {}\nmodule.exports = { carriesEncodedSensitiveText, carriesNumericContent };') },
    { path: 'sensors/shared/signed-policy.js', body: Buffer.from('module.exports = {};') },
    { path: 'sensors/shared/server-url.js', body: Buffer.from('function secureServerUrl() {}\nmodule.exports = { secureServerUrl };') },
    { path: 'sensors/mcp-guard/guard.js', body: Buffer.from(guardBody) },
    { path: 'sensors/mcp-guard/sdk.js', body: Buffer.from('function sanitizeToolResult() {}\nfunction wrapConnectorTool() {}\nfunction executeConnectorTool() {}\nfunction guardToolRequest() {}\nfunction connectorHealthCheck() {}\nfunction carriesUnscannableToolResult() {}\nfunction blockUnscannableToolResult() {}\nfunction blockUninspectableToolResult() {}\nmodule.exports = { sanitizeToolResult, wrapConnectorTool, executeConnectorTool, connectorHealthCheck };') },
    { path: 'sensors/mcp-guard/connector-registry.js', body: Buffer.from('const CONNECTOR_PROFILES = [];\nfunction connectorRegistryStatus() {}\nfunction connectorRegistryChecks() {}\nmodule.exports = { CONNECTOR_PROFILES, connectorRegistryStatus, connectorRegistryChecks };') },
    { path: 'sensors/mcp-guard/connectors/microsoft365.js', body: Buffer.from('function executeConnectorTool() {}\nfunction sanitizeDriveItemContent() {}\nfunction createDriveItemContentTool() {}\nfunction microsoft365ConnectorHealth() {}\nmodule.exports = { sanitizeDriveItemContent, createDriveItemContentTool, microsoft365ConnectorHealth };') },
    { path: 'sensors/mcp-guard/connectors/google-drive.js', body: Buffer.from('function executeConnectorTool() {}\nfunction sanitizeDriveFileContent() {}\nfunction createDriveFileContentTool() {}\nfunction googleDriveConnectorHealth() {}\nmodule.exports = { sanitizeDriveFileContent, createDriveFileContentTool, googleDriveConnectorHealth };') },
    { path: 'sensors/mcp-guard/connectors/slack.js', body: Buffer.from('function executeConnectorTool() {}\nfunction sanitizeConversationHistory() {}\nfunction createSlackConversationHistoryTool() {}\nfunction sanitizeSlackFileContent() {}\nfunction slackConnectorHealth() {}\nmodule.exports = { sanitizeConversationHistory, createSlackConversationHistoryTool, sanitizeSlackFileContent, slackConnectorHealth };') },
    { path: 'sensors/mcp-guard/connectors/teams.js', body: Buffer.from('function executeConnectorTool() {}\nfunction sanitizeTeamsChannelMessages() {}\nfunction createTeamsChannelMessagesTool() {}\nfunction sanitizeTeamsChatMessages() {}\nfunction teamsConnectorHealth() {}\nmodule.exports = { sanitizeTeamsChannelMessages, createTeamsChannelMessagesTool, sanitizeTeamsChatMessages, teamsConnectorHealth };') },
    { path: 'sensors/mcp-guard/connectors/atlassian.js', body: Buffer.from('function executeConnectorTool() {}\nfunction sanitizeJiraIssue() {}\nfunction createJiraIssueTool() {}\nfunction sanitizeConfluencePage() {}\nfunction atlassianConnectorHealth() {}\nmodule.exports = { sanitizeJiraIssue, createJiraIssueTool, sanitizeConfluencePage, atlassianConnectorHealth };') },
    { path: 'sensors/mcp-guard/connectors/database-readonly.js', body: Buffer.from('function executeConnectorTool() {}\nfunction sanitizeDatabaseRows() {}\nfunction createDatabaseReadonlyQueryTool() {}\nfunction sanitizeDatabaseSchema() {}\nfunction databaseReadonlyConnectorHealth() {}\nmodule.exports = { sanitizeDatabaseRows, createDatabaseReadonlyQueryTool, sanitizeDatabaseSchema, databaseReadonlyConnectorHealth };') },
    { path: 'sensors/mcp-guard/connectors/database-readonly-worker.js', body: Buffer.from('module.exports = {};') },
    { path: 'scripts/check-mcp-guard-install.js', body: Buffer.from("const api = '/api/v1/heartbeat';\nfunction buildInstallReport() {}\nfunction connectorRegistryStatus() {}\nconst key = 'INGEST_API_KEY';") },
  ];
}

function replaceBody(files, relPath, body) {
  return files.map((file) => (
    file.path === relPath ? { ...file, body: Buffer.from(body) } : file
  ));
}

function withoutFile(files, relPath) {
  return files.filter((file) => file.path !== relPath);
}

test('package script writes a prompt-free MCP guard zip and integrity manifest', (t) => {
  const outDir = tempDir(t);
  const result = packageMcpGuard({ outDir, now: new Date('2026-06-26T12:00:00.000Z') });
  assert.ok(fs.existsSync(result.zipPath));
  assert.ok(fs.existsSync(result.manifestPath));

  const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  const zipBody = fs.readFileSync(result.zipPath);
  assert.strictEqual(manifest.kind, 'redactwall-mcp-guard-package');
  assert.strictEqual(manifest.sha256, sha256(zipBody));
  assert.strictEqual(manifest.appVersion, JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version);
  assert.strictEqual(manifest.checks.explicitIngestKeyRequired, true);
  assert.strictEqual(manifest.checks.sharedEngineIncluded, true);
  assert.strictEqual(manifest.checks.boundedResponseReaderIncluded, true);
  assert.strictEqual(manifest.checks.connectorSdkIncluded, true);
  assert.strictEqual(manifest.checks.connectorRegistryIncluded, true);
  assert.strictEqual(manifest.checks.microsoft365ConnectorIncluded, true);
  assert.strictEqual(manifest.checks.googleDriveConnectorIncluded, true);
  assert.strictEqual(manifest.checks.slackConnectorIncluded, true);
  assert.strictEqual(manifest.checks.teamsConnectorIncluded, true);
  assert.strictEqual(manifest.checks.atlassianConnectorIncluded, true);
  assert.strictEqual(manifest.checks.databaseReadonlyConnectorIncluded, true);
  assert.strictEqual(manifest.checks.databaseQueryWorkerIncluded, true);
  assert.strictEqual(manifest.checks.demoCodeExcluded, true);
  assert.strictEqual(manifest.checks.installValidationIncluded, true);
  assert.strictEqual(manifest.checks.developmentIngestKeyAbsent, true);
  assert.strictEqual(manifest.checks.promptBodiesAbsent, true);

  const zip = new AdmZip(result.zipPath);
  const entries = zip.getEntries().map((entry) => entry.entryName).sort();
  for (const required of ['package.json', 'sensors/mcp-guard/guard.js', 'sensors/mcp-guard/sdk.js', 'sensors/mcp-guard/connector-registry.js', 'sensors/mcp-guard/connectors/microsoft365.js', 'sensors/mcp-guard/connectors/google-drive.js', 'sensors/mcp-guard/connectors/slack.js', 'sensors/mcp-guard/connectors/teams.js', 'sensors/mcp-guard/connectors/atlassian.js', 'sensors/mcp-guard/connectors/database-readonly.js', 'sensors/shared/decision.js', 'sensors/shared/opaque-content.js', 'detection-engine/detect.js', 'server/env.js', 'server/file-mutation-lock.js', 'server/private-path.js', 'scripts/check-mcp-guard-install.js']) {
    assert.ok(entries.includes(required), required);
    assert.ok(manifest.files.some((file) => file.path === required), required);
  }

  const guard = zip.readAsText('sensors/mcp-guard/guard.js');
  assert.match(guard, /process\.env\.INGEST_API_KEY \|\| ''/);
  assert.doesNotMatch(guard, /demo when run directly|dev-ingest-key|524-71-9043|4111 1111 1111 1111/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /sanitizeToolResult/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /connectorHealthCheck/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /carriesUnscannableToolResult/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /blockUnscannableToolResult/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /blockUninspectableToolResult/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /guardToolRequest/);
  assert.match(zip.readAsText('sensors/mcp-guard/sdk.js'), /executeConnectorTool/);
  assert.match(zip.readAsText('sensors/mcp-guard/connector-registry.js'), /connectorRegistryStatus/);
  assert.match(zip.readAsText('sensors/mcp-guard/connector-registry.js'), /google_drive/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/microsoft365.js'), /sanitizeDriveItemContent/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/microsoft365.js'), /microsoft365ConnectorHealth/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/google-drive.js'), /sanitizeDriveFileContent/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/google-drive.js'), /googleDriveConnectorHealth/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/slack.js'), /sanitizeConversationHistory/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/slack.js'), /slackConnectorHealth/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/teams.js'), /sanitizeTeamsChannelMessages/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/teams.js'), /teamsConnectorHealth/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/atlassian.js'), /sanitizeJiraIssue/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/atlassian.js'), /atlassianConnectorHealth/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/database-readonly.js'), /sanitizeDatabaseRows/);
  assert.match(zip.readAsText('sensors/mcp-guard/connectors/database-readonly.js'), /databaseReadonlyConnectorHealth/);
  for (const connector of ['microsoft365', 'google-drive', 'slack', 'teams', 'atlassian', 'database-readonly']) {
    assert.match(zip.readAsText(`sensors/mcp-guard/connectors/${connector}.js`), /executeConnectorTool/);
  }
  assert.match(zip.readAsText('scripts/check-mcp-guard-install.js'), /\/api\/v1\/heartbeat/);
  assert.doesNotMatch(JSON.stringify(manifest), /prompt\s*:/i);
  assert.doesNotMatch(JSON.stringify(manifest), /524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY/);
});

test('packaged MCP SDK clean-unpack smoke delivers its inspected snapshot', (t) => {
  const outDir = tempDir(t);
  const unpackDir = tempDir(t, 'ps-mcp-guard-unpack-');
  const result = packageMcpGuard({ outDir, now: new Date('2026-06-26T12:00:00.000Z') });
  new AdmZip(result.zipPath).extractAllTo(unpackDir, true);

  const smoke = spawnSync(process.execPath, ['-e', [
    "const assert = require('node:assert/strict');",
    "const { sanitizeToolResult, wrapConnectorTool } = require('./sensors/mcp-guard/sdk');",
    '(async () => {',
    '  let calls = 0;',
    '  const raw = { toJSON() {',
    '    calls += 1;',
    "    return calls === 1 ? { content: [{ type: 'text', text: 'Public schedule.' }] }",
    "      : { content: [{ type: 'text', text: 'Member SSN 524-71-9043.' }] };",
    '  } };',
    "  const safe = await sanitizeToolResult(raw, { connector: 'records', tool: 'fetch' },",
    '    { key: \'\', policy: { ignore: [], disabledDetectors: [] } });',
    '  assert.equal(calls, 1);',
    "  assert.deepEqual(safe.result, { content: [{ type: 'text', text: 'Public schedule.' }] });",
    "  assert.doesNotMatch(JSON.stringify(safe.result), /524-71-9043/);",
    '  const hostile = {};',
    "  Object.defineProperty(hostile, 'structuredContent', { enumerable: true,",
    "    get() { throw new Error('hostile result context 524-71-9043'); } });",
    "  const wrapped = wrapConnectorTool(async () => hostile, { connector: 'records', tool: 'fetch' },",
    '    { key: \'\', policy: { ignore: [], disabledDetectors: [] } });',
    '  const blocked = await wrapped({});',
    "  assert.deepEqual(blocked, { content: [{ type: 'text',",
    "    text: '[BLOCKED: MCP tool result could not be safely inspected]' }] });",
    "  assert.doesNotMatch(JSON.stringify(blocked), /524-71-9043/);",
    "  process.stdout.write('snapshot-ok');",
    '})().catch((error) => { console.error(error); process.exitCode = 1; });',
  ].join('\n')], {
    cwd: unpackDir,
    encoding: 'utf8',
    env: {
      ...process.env,
      INGEST_API_KEY: '',
      REDACTWALL_URL: 'http://127.0.0.1:4000',
      REDACTWALL_ALLOW_INSECURE_SERVER: '0',
    },
  });

  assert.strictEqual(smoke.status, 0, smoke.stderr || smoke.stdout);
  assert.strictEqual(smoke.stdout, 'snapshot-ok');
});

test('package validation refuses prompt bodies or development keys', () => {
  assert.throws(
    () => validateRuntimeFiles(minimalMcpFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst sample = '524-71-9043';")),
    /synthetic SSN demo value/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalMcpFiles("const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';")),
    /development ingest key/
  );
});

test('package validation covers MCP runtime and install-check guardrails', () => {
  const validFiles = minimalMcpFiles();
  assert.doesNotThrow(() => validateRuntimeFiles(validFiles));

  const cases = [
    {
      name: 'missing required package member',
      files: withoutFile(validFiles, 'sensors/mcp-guard/sdk.js'),
      message: /missing sensors\/mcp-guard\/sdk\.js/,
    },
    {
      name: 'guard missing explicit key',
      files: minimalMcpFiles("const KEY = process.env.INGEST_API_KEY || 'fallback';"),
      message: /explicit INGEST_API_KEY/,
    },
    {
      name: 'guard demo code included',
      files: minimalMcpFiles("const KEY = process.env.INGEST_API_KEY || '';\n// ---- demo when run directly"),
      message: /exclude direct-run demo code/,
    },
    {
      name: 'sdk missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/sdk.js', 'function sanitizeToolResult() {}\nfunction wrapConnectorTool() {}'),
      message: /connector SDK sanitization/,
    },
    {
      name: 'sdk missing binary fail-closed guard',
      files: replaceBody(validFiles, 'sensors/mcp-guard/sdk.js', 'function sanitizeToolResult() {}\nfunction wrapConnectorTool() {}\nfunction connectorHealthCheck() {}'),
      message: /binary fail-closed guard/,
    },
    {
      name: 'sdk missing request-policy preflight',
      files: replaceBody(validFiles, 'sensors/mcp-guard/sdk.js', 'function sanitizeToolResult() {}\nfunction wrapConnectorTool() {}\nfunction connectorHealthCheck() {}\nfunction carriesUnscannableToolResult() {}\nfunction blockUnscannableToolResult() {}\nfunction blockUninspectableToolResult() {}'),
      message: /request-policy preflight/,
    },
    {
      name: 'sdk missing inspection fail-closed guard',
      files: replaceBody(validFiles, 'sensors/mcp-guard/sdk.js', 'function sanitizeToolResult() {}\nfunction wrapConnectorTool() {}\nfunction executeConnectorTool() {}\nfunction guardToolRequest() {}\nfunction connectorHealthCheck() {}\nfunction carriesUnscannableToolResult() {}\nfunction blockUnscannableToolResult() {}'),
      message: /inspection fail-closed guard/,
    },
    {
      name: 'first-party connector missing request-policy preflight',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/microsoft365.js', 'function sanitizeDriveItemContent() {}\nfunction createDriveItemContentTool() {}\nfunction microsoft365ConnectorHealth() {}'),
      message: /Microsoft 365 connector request-policy preflight/,
    },
    {
      name: 'connector registry missing checks',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connector-registry.js', 'const CONNECTOR_PROFILES = [];\nfunction connectorRegistryStatus() {}'),
      message: /connector registry profiles/,
    },
    {
      name: 'microsoft connector missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/microsoft365.js', 'function sanitizeDriveItemContent() {}\nfunction createDriveItemContentTool() {}'),
      message: /Microsoft 365 connector/,
    },
    {
      name: 'google drive connector missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/google-drive.js', 'function sanitizeDriveFileContent() {}\nfunction createDriveFileContentTool() {}'),
      message: /Google Drive connector/,
    },
    {
      name: 'slack connector missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/slack.js', 'function sanitizeConversationHistory() {}\nfunction createSlackConversationHistoryTool() {}\nfunction sanitizeSlackFileContent() {}'),
      message: /Slack connector/,
    },
    {
      name: 'teams connector missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/teams.js', 'function sanitizeTeamsChannelMessages() {}\nfunction createTeamsChannelMessagesTool() {}\nfunction sanitizeTeamsChatMessages() {}'),
      message: /Microsoft Teams connector/,
    },
    {
      name: 'atlassian connector missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/atlassian.js', 'function sanitizeJiraIssue() {}\nfunction createJiraIssueTool() {}\nfunction sanitizeConfluencePage() {}'),
      message: /Atlassian connector/,
    },
    {
      name: 'database connector missing health helper',
      files: replaceBody(validFiles, 'sensors/mcp-guard/connectors/database-readonly.js', 'function sanitizeDatabaseRows() {}\nfunction createDatabaseReadonlyQueryTool() {}\nfunction sanitizeDatabaseSchema() {}'),
      message: /database read-only connector/,
    },
    {
      name: 'install check missing heartbeat support',
      files: replaceBody(validFiles, 'scripts/check-mcp-guard-install.js', "function buildInstallReport() {}\nconst key = 'INGEST_API_KEY';"),
      message: /install validation with heartbeat/,
    },
    {
      name: 'install check reads file bodies',
      files: replaceBody(validFiles, 'scripts/check-mcp-guard-install.js', "const api = '/api/v1/heartbeat';\nfunction buildInstallReport() {}\nfunction connectorRegistryStatus() {}\nconst key = 'INGEST_API_KEY';\nconst bad = 'contentBase64';"),
      message: /must not read file bodies/,
    },
  ];

  for (const item of cases) {
    assert.throws(() => validateRuntimeFiles(item.files), item.message, item.name);
  }
});

test('package args support explicit output directories', () => {
  const parsed = parseArgs(['--out', 'dist/custom-mcp']);
  assert.match(parsed.outDir, /dist[\\/]custom-mcp$/);
  assert.match(parseArgs(['dist/positional-mcp']).outDir, /dist[\\/]positional-mcp$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
});

test('package CLI main writes status, help, and errors through injected console', () => {
  const logs = [];
  const errors = [];
  const exitCodes = [];
  const io = {
    log: (line) => logs.push(String(line)),
    error: (line) => errors.push(String(line)),
  };
  const result = main(['--out', 'dist/custom-mcp'], {
    console: io,
    setExitCode: (code) => exitCodes.push(code),
    packageMcpGuard: ({ outDir }) => ({
      zipPath: path.join(outDir, 'mcp.zip'),
      manifestPath: path.join(outDir, 'mcp.manifest.json'),
      packageManifest: { sha256: 'mcp-sha' },
    }),
  });
  assert.match(result.zipPath, /custom-mcp[\\/]mcp\.zip$/);
  assert.ok(logs.some((line) => /SHA-256 mcp-sha/.test(line)));
  assert.deepStrictEqual(exitCodes, []);

  logs.length = 0;
  assert.strictEqual(main(['--help'], { console: io, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.match(logs.join('\n'), /Usage: node scripts\/package-mcp-guard\.js/);

  assert.strictEqual(main(['--bad'], { console: io, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.ok(errors.some((line) => /Unknown option: --bad/.test(line)));
  assert.ok(exitCodes.includes(1));
});

test('MCP guard rejects an insecure control plane without echoing its configured URL', () => {
  const secretUrl = 'http://operator:super-secret@remote-plane.example.test/private';
  const child = spawnSync(process.execPath, ['-e', "require('./sensors/mcp-guard/guard')"], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      REDACTWALL_URL: secretUrl,
      REDACTWALL_ALLOW_INSECURE_SERVER: '0',
    },
  });
  assert.notStrictEqual(child.status, 0);
  assert.match(child.stderr, /refusing insecure control-plane URL/);
  assert.ok(!child.stderr.includes(secretUrl));
  assert.ok(!child.stderr.includes('super-secret'));
});
