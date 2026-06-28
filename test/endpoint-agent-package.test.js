'use strict';
/** Endpoint agent package must be pilot-ready and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AdmZip = require('adm-zip');

const {
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
      path: 'sensors/endpoint-agent/native-handoff.js',
      body: Buffer.from("require('crypto').createHmac('sha256', 'secret'); const blocked = 'contentBase64';"),
    },
    {
      path: 'sensors/endpoint-agent/write-handoff.js',
      body: Buffer.from('function writeHandoffFile() { return signHandoffEvent(); }\nfunction signHandoffEvent() {}\n'),
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
      path: 'scripts/install-desktop-collector.ps1',
      body: Buffer.from('HKEY_CURRENT_USER\\Software\\Classes\\*\\shell\n"%1"\nMultiSelectModel\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR\nPROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET\n'),
    },
    {
      path: 'scripts/install-endpoint-agent.ps1',
      body: Buffer.from('[Parameter(Mandatory = $true)]\n[string]$IngestKey\n$taskArgs = "-File runner.ps1"\n'),
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
    { path: 'scripts/uninstall-endpoint-agent.ps1', body: Buffer.from('Unregister-ScheduledTask\n') },
  ];
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
  assert.strictEqual(manifest.checks.nativeHandoffPrototypeIncluded, true);
  assert.strictEqual(manifest.checks.nativeHandoffWriterIncluded, true);
  assert.strictEqual(manifest.checks.protectedUploadCollectorIncluded, true);
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
  ]) {
    assert.ok(entries.includes(required), required);
    assert.ok(manifest.files.some((file) => file.path === required), required);
  }

  const agent = zip.readAsText('sensors/endpoint-agent/agent.js');
  assert.match(agent, /process\.env\.INGEST_API_KEY \|\| ''/);
  assert.match(agent, /redacted_available/);
  assert.match(agent, /\.promptwall-redacted/);
  assert.match(agent, /ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.match(zip.readAsText('sensors/endpoint-agent/native-handoff.js'), /createHmac\('sha256'/);
  assert.match(zip.readAsText('sensors/endpoint-agent/write-handoff.js'), /writeHandoffFile/);
  assert.match(zip.readAsText('sensors/endpoint-agent/collectors/protected-upload.js'), /collectProtectedUploads/);
  assert.match(zip.readAsText('scripts/check-endpoint-install.js'), /\/api\/v1\/heartbeat/);
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
  const desktopInstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'install-desktop-collector.ps1'), 'utf8');
  const desktopRunnerScript = fs.readFileSync(path.join(installRoot, 'scripts', 'run-desktop-collector.ps1'), 'utf8');
  const runnerScript = fs.readFileSync(path.join(installRoot, 'scripts', 'run-endpoint-agent.ps1'), 'utf8');
  const uninstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'uninstall-endpoint-agent.ps1'), 'utf8');
  assert.match(installScript, /Register-ScheduledTask/);
  assert.match(installScript, /\[Alias\("SentinelUrl"\)\]/);
  assert.match(installScript, /PROMPTWALL_URL=\$PromptWallUrl/);
  assert.match(installScript, /INGEST_API_KEY=\$IngestKey/);
  assert.match(installScript, /InstallDesktopCollector/);
  assert.doesNotMatch(installScript, /"-IngestKey"/);
  assert.ok(desktopInstallScript.includes(String.raw`HKEY_CURRENT_USER\Software\Classes\*\shell`));
  assert.ok(desktopInstallScript.includes('%1'));
  assert.match(desktopInstallScript, /MultiSelectModel/);
  assert.match(desktopInstallScript, /PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.doesNotMatch(desktopInstallScript, /"-HandoffSecret"/);
  assert.match(desktopRunnerScript, /protected-upload\.js/);
  assert.match(desktopRunnerScript, /\[string\[\]\]\$FilePath/);
  assert.match(desktopRunnerScript, /\$env:PROMPTWALL_ENV_PATH = \$config/);
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
  const collectorPath = require.resolve(path.join(installRoot, 'sensors', 'endpoint-agent', 'collectors', 'protected-upload.js'));
  delete require.cache[agentPath];
  delete require.cache[writerPath];
  delete require.cache[collectorPath];
  const agent = require(agentPath);
  const handoffWriter = require(writerPath);
  const desktopCollector = require(collectorPath);
  t.after(() => {
    delete require.cache[agentPath];
    delete require.cache[writerPath];
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
  assert.ok(!JSON.stringify(requests).includes('524-71-9043'));
  assert.ok(!JSON.stringify(requests).includes('4111 1111 1111 1111'));
});

test('package args support explicit output directories', () => {
  const parsed = parseArgs(['--out', 'dist/custom-endpoint']);
  assert.match(parsed.outDir, /dist[\\/]custom-endpoint$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
});
