'use strict';
/** Endpoint file sensor must inspect locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  scanFile,
  processNativeHandoffFile,
  refreshPolicy,
  fetchPolicy,
  sensorPolicy,
  scannerConfig,
  ignoredByScanner,
  postJson,
  defaultWatchDir,
  configuredKey,
  nativeHandoff,
} = require('../sensors/endpoint-agent/agent');
const pkg = require('../package.json');

test('watch directory prefers CLI argument, then endpoint env, then temp default', () => {
  assert.strictEqual(defaultWatchDir(['node', 'agent.js', 'C:\\Watch'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'C:\\Watch');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'D:\\FromEnv');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR: 'E:\\PromptWallWatch' }), 'E:\\PromptWallWatch');
  assert.match(defaultWatchDir(['node', 'agent.js'], {}), /promptwall-watch$/);
});

test('analyzes supported files locally and reports sanitized findings to gate', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  const raw = 'Loan file. SSN 524-71-9043. Card 4111 1111 1111 1111.';
  fs.writeFileSync(path.join(dir, filename), raw);

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    report: async (req) => {
      reportRequest = req;
      return { decision: 'block', mode: 'block', status: 'pending', id: 'q_test', findings: req.clientFindings, categories: [], riskScore: req.clientRiskScore };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(reportRequest.source, 'endpoint_agent');
  assert.strictEqual(reportRequest.channel, 'file_upload');
  assert.strictEqual(reportRequest.clientPreRedacted, true);
  assert.ok(reportRequest.clientFindings.some((f) => f.type === 'US_SSN'));
  assert.ok(reportRequest.clientFindings.some((f) => f.type === 'CREDIT_CARD'));
  assert.deepStrictEqual(reportRequest.sensor, { name: 'endpoint_agent', version: pkg.version, platform: process.platform });
  assert.strictEqual(reportRequest.contentBase64, undefined);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
  assert.ok(!JSON.stringify(reportRequest).includes('4111 1111 1111 1111'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('redact policy writes a sanitized companion file for structured findings', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'member-524-71-9043.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'redact', mode: 'redact', status: 'redacted', id: 'q_redacted' };
    },
  });

  assert.strictEqual(res.decision, 'redact');
  assert.strictEqual(reportRequest.clientOutcome, 'redacted_available');
  assert.match(reportRequest.prompt, /\[\[US_SSN_1\]\]/);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
  assert.ok(res.redactionHandoff);
  assert.match(res.redactionHandoff.relativePath, /^\.promptwall-redacted[\\/]/);
  assert.ok(!res.redactionHandoff.relativePath.includes('524-71-9043'));
  assert.strictEqual(ignoredByScanner(res.redactionHandoff.relativePath, scannerConfig({
    ignoreDirectories: [],
    ignoreFilenames: [],
    ignoreExtensions: [],
    maxFileBytes: 4096,
  })), true);
  const companion = fs.readFileSync(res.redactionHandoff.path, 'utf8');
  assert.match(companion, /\[\[US_SSN_1\]\]/);
  assert.match(companion, /Original file: \[sensitive filename\]/);
  assert.ok(!companion.includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('removes redacted companion files when control-plane recording fails', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');

  const requests = [];
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => { requests.push(req); return null; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  assert.strictEqual(requests[0].clientOutcome, 'redacted_available');
  const handoffDir = path.join(dir, '.promptwall-redacted');
  assert.deepStrictEqual(fs.existsSync(handoffDir) ? fs.readdirSync(handoffDir) : [], []);
  assert.ok(!JSON.stringify(requests).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('falls back to approval when redacted companion creation fails', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');
  fs.writeFileSync(path.join(dir, '.promptwall-redacted'), 'not a directory');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'block', mode: 'redact', status: 'pending', id: 'q_pending' };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(reportRequest.clientOutcome, 'awaiting_approval');
  assert.match(reportRequest.note, /redacted companion unavailable/);
  assert.strictEqual(res.redactionHandoff, undefined);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('sanitizes sensitive filenames before reporting local file evidence', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'member-524-71-9043.txt';
  fs.writeFileSync(path.join(dir, filename), 'Clean file body for a summary.');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    report: async (req) => {
      reportRequest = req;
      return { decision: 'allow', status: 'allowed', id: 'q_clean' };
    },
  });

  assert.strictEqual(res.decision, 'allow');
  assert.match(reportRequest.prompt, /\[sensitive filename\]/);
  assert.match(reportRequest.note, /\[sensitive filename\]/);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('does not upload unsupported file bytes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'driver-license.png';
  const raw = 'pretend binary with SSN 524-71-9043';
  fs.writeFileSync(path.join(dir, filename), raw);

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    report: async (req) => { reportRequest = req; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.supported, false);
  assert.strictEqual(reportRequest.clientOutcome, 'file_unsupported');
  assert.strictEqual(reportRequest.contentBase64, undefined);
  assert.deepStrictEqual(reportRequest.sensor, { name: 'endpoint_agent', version: pkg.version, platform: process.platform });
  assert.ok(!reportRequest.prompt.includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('blocks configured endpoint destinations before local file inspection', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'member-524-71-9043.txt';
  fs.writeFileSync(path.join(dir, filename), 'SSN 524-71-9043 should never be inspected for a blocked destination.');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    destination: 'Desktop AI',
    policy: { blockedDestinations: ['desktop-ai'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'block', status: 'destination_blocked', id: 'q_destination_blocked' };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'destination_blocked');
  assert.strictEqual(res.inspected, false);
  assert.strictEqual(reportRequest.clientOutcome, 'destination_blocked');
  assert.strictEqual(reportRequest.prompt, '[destination blocked] desktop-ai');
  assert.strictEqual(reportRequest.contentBase64, undefined);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('blocks configured file-upload destinations without inspecting endpoint files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'member-524-71-9043.txt';
  fs.writeFileSync(path.join(dir, filename), 'SSN 524-71-9043 should never be inspected for a file-upload policy block.');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    destination: 'Desktop AI',
    policy: { blockedFileUploadDestinations: ['desktop-ai'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'block', status: 'file_upload_blocked', id: 'q_file_upload_blocked' };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'file_upload_blocked');
  assert.strictEqual(res.inspected, false);
  assert.strictEqual(reportRequest.clientOutcome, 'file_upload_blocked');
  assert.strictEqual(reportRequest.prompt, '[file upload blocked] desktop-ai');
  assert.strictEqual(reportRequest.contentBase64, undefined);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('blocks supported files locally when control-plane logging is unavailable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  const raw = 'Loan file that must not pass during outage. SSN 524-71-9043.';
  fs.writeFileSync(path.join(dir, filename), raw);

  const requests = [];
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    report: async (req) => { requests.push(req); return null; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  assert.strictEqual(res.supported, true);
  assert.strictEqual(requests[0].clientPreRedacted, true);
  assert.ok(requests[0].clientFindings.some((f) => f.type === 'US_SSN'));
  assert.strictEqual(requests[1].clientOutcome, 'scan_unavailable');
  assert.match(requests[1].prompt, /^\[file blocked unscanned\] loan\.txt$/);
  assert.ok(!JSON.stringify(requests).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('blocks supported files locally without an ingest key or network call', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Loan file that must not pass. SSN 524-71-9043.');

  let calls = 0;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    key: '',
    fetchImpl: async () => {
      calls += 1;
      return { ok: true, json: async () => ({ decision: 'allow' }) };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  assert.strictEqual(res.supported, true);
  assert.strictEqual(calls, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('postJson times out stalled control-plane requests', async () => {
  const started = Date.now();
  const res = await postJson('/api/v1/gate', { prompt: '[file inspected locally] loan.txt' }, {
    server: 'http://sentinel.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'http://sentinel.test/api/v1/gate');
      assert.strictEqual(opts.headers['x-api-key'], 'unit-key');
      opts.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    }),
  });

  assert.strictEqual(res, null);
  assert.ok(Date.now() - started < 1000);
});

test('does not contact the control plane without an ingest key', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: true, json: async () => ({}) };
  };

  assert.strictEqual(configuredKey({ key: '  unit-key  ' }), 'unit-key');
  assert.strictEqual(await fetchPolicy({ key: '', fetchImpl }), null);
  assert.strictEqual(await postJson('/api/v1/gate', { prompt: 'blocked locally' }, { key: '', fetchImpl }), null);
  assert.strictEqual(calls, 0);
});

test('refreshes scanner policy from the control plane', async () => {
  let request;
  const scanner = await refreshPolicy({
    server: 'http://sentinel.test',
    key: 'policy-key',
    fetchImpl: async (url, opts) => {
      request = { url, headers: opts.headers };
      return {
        ok: true,
        json: async () => ({
          scanner: {
            ignoreDirectories: ['Secrets'],
            ignoreFilenames: ['skip-me.txt'],
            ignoreExtensions: ['blocked'],
            maxFileBytes: 4096,
          },
        }),
      };
    },
  });

  assert.strictEqual(request.url, 'http://sentinel.test/api/v1/policy');
  assert.strictEqual(request.headers['x-api-key'], 'policy-key');
  assert.ok(scanner.ignoreDirectories.has('secrets'));
  assert.ok(scanner.ignoreFilenames.has('skip-me.txt'));
  assert.ok(scanner.ignoreExtensions.has('.blocked'));
  assert.strictEqual(scanner.maxFileBytes, 4096);
  assert.strictEqual(scannerConfig({ maxFileBytes: 4096.7 }).maxFileBytes, 4097);
});

test('sensor policy keeps the desktop collector destination label', () => {
  const pol = sensorPolicy({ desktopCollectorDestination: 'Copilot Desktop' });
  assert.strictEqual(pol.desktopCollectorDestination, 'Copilot Desktop');
  assert.strictEqual(sensorPolicy({ desktopCollectorDestination: '   ' }).desktopCollectorDestination, 'Desktop AI');
});

test('policy refresh times out and keeps the current scanner config', async () => {
  const started = Date.now();
  const scanner = await refreshPolicy({
    server: 'http://sentinel.test',
    key: 'policy-key',
    timeoutMs: 10,
    silent: true,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'http://sentinel.test/api/v1/policy');
      opts.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    }),
  });

  assert.ok(scanner.ignoreFilenames instanceof Set);
  assert.ok(Date.now() - started < 1000);
});

test('scanner policy controls endpoint ignores and size blocking', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const ignored = 'notes.blocked';
  fs.writeFileSync(path.join(dir, ignored), 'SSN 524-71-9043');

  const scanner = scannerConfig({
    ignoreExtensions: ['.blocked'],
    ignoreFilenames: [],
    ignoreDirectories: [],
    maxFileBytes: 8,
  });

  assert.strictEqual(ignoredByScanner(ignored, scanner), true);
  assert.strictEqual(ignoredByScanner('.promptsentinel-redacted/loan.promptsentinel-redacted.txt', scanner), true);
  let reportCalled = false;
  const ignoredRes = await scanFile(ignored, {
    watchDir: dir,
    scanner,
    report: async () => { reportCalled = true; },
  });
  assert.strictEqual(ignoredRes, undefined);
  assert.strictEqual(reportCalled, false);

  const large = 'large.txt';
  fs.writeFileSync(path.join(dir, large), 'larger than eight bytes');
  let reportRequest;
  const blocked = await scanFile(large, {
    watchDir: dir,
    scanner,
    user: 'unit-user',
    report: async (req) => { reportRequest = req; },
  });

  assert.strictEqual(blocked.decision, 'block');
  assert.strictEqual(blocked.status, 'file_too_large');
  assert.strictEqual(reportRequest.clientOutcome, 'file_too_large');
  assert.ok(!reportRequest.prompt.includes('larger than eight bytes'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('processes signed native file-flow handoff events without raw payloads', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-'));
  const sourceDir = path.join(dir, 'source');
  const handoffDir = path.join(dir, 'handoff');
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(handoffDir, { recursive: true });
  const filePath = path.join(sourceDir, 'member-524-71-9043.txt');
  fs.writeFileSync(filePath, 'Loan file. SSN 524-71-9043.');
  const handoffPath = path.join(handoffDir, 'evt.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_native_unit',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-1',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));

  let reportRequest;
  const res = await processNativeHandoffFile(handoffPath, {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
    policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'redact', mode: 'redact', status: 'redacted', id: 'q_native_redacted' };
    },
  });

  assert.strictEqual(res.status, 'processed');
  assert.strictEqual(res.event.id, 'evt_native_unit');
  assert.strictEqual(res.result.decision, 'redact');
  assert.strictEqual(reportRequest.user, 'native-user@example.test');
  assert.strictEqual(reportRequest.destination, 'Desktop AI');
  assert.match(reportRequest.note, /native handoff evt_native_unit/);
  assert.strictEqual(reportRequest.clientOutcome, 'redacted_available');
  assert.match(reportRequest.prompt, /\[\[US_SSN_1\]\]/);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
  assert.strictEqual(fs.existsSync(handoffPath), false);
  assert.match(res.result.redactionHandoff.relativePath, /^\.promptwall-redacted[\\/]/);
  const companion = fs.readFileSync(res.result.redactionHandoff.path, 'utf8');
  assert.match(companion, /\[\[US_SSN_1\]\]/);
  assert.ok(!companion.includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('rejects invalid native handoff events without scanning files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-bad-'));
  const handoffPath = path.join(dir, 'bad.json');
  fs.writeFileSync(handoffPath, JSON.stringify({ version: nativeHandoff.EVENT_VERSION, signature: '0'.repeat(64) }));

  let reportCalled = false;
  const res = await processNativeHandoffFile(handoffPath, {
    secret: 'native-handoff-secret-000000000000000001',
    removeRejected: true,
    silent: true,
    report: async () => { reportCalled = true; },
  });

  assert.strictEqual(res.status, 'rejected');
  assert.match(res.reason, /filePath|signature|createdAt|operation/);
  assert.strictEqual(reportCalled, false);
  assert.strictEqual(fs.existsSync(handoffPath), false);

  fs.rmSync(dir, { recursive: true, force: true });
});
