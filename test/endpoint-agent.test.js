'use strict';
/** Endpoint file sensor must inspect locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  scanFile,
  scanAbsoluteFile,
  processNativeHandoffFile,
  processNativeHandoffFileSafe,
  processHandoffDirectory,
  refreshPolicy,
  fetchPolicy,
  sensorPolicy,
  scannerConfig,
  ignoredByScanner,
  postJson,
  start,
  defaultWatchDir,
  configuredKey,
  handoffSecretReady,
  nativeHandoff,
  fileFlowProfiles,
  startWatchedRoot,
} = require('../sensors/endpoint-agent/agent');
const pkg = require('../package.json');
const D = require('../detection-engine/detect');

test('watch directory prefers CLI argument, then endpoint env, then temp default', () => {
  assert.strictEqual(defaultWatchDir(['node', 'agent.js', 'C:\\Watch'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'C:\\Watch');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'D:\\FromEnv');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { REDACTWALL_ENDPOINT_AGENT_WATCH_DIR: 'E:\\RedactWallWatch' }), 'E:\\RedactWallWatch');
  assert.match(defaultWatchDir(['node', 'agent.js'], {}), /redactwall-watch$/);
});

test('endpoint agent start wires refresh, file watch, scans, and native handoff watcher', async () => {
  const logs = [];
  const scans = [];
  const handoffs = [];
  let unrefCalled = false;
  let watchCallback;
  let intervalCallback;
  const started = start({
    console: { log: (...args) => logs.push(args.join(' ')) },
    watchDir: 'C:\\RedactWall\\watch',
    handoffDir: 'C:\\RedactWall\\handoff',
    handoffSecret: 'native-handoff-secret-000000000000000001',
    server: 'https://redactwall.example',
    key: 'ingest-key-configured',
    refreshPolicy: async () => {},
    scanFile: (filename, opts) => scans.push({ filename, opts }),
    readdirSync: () => ['existing.txt'],
    setInterval: (fn, ms) => {
      intervalCallback = fn;
      assert.strictEqual(ms, 15 * 60 * 1000);
      return { unref: () => { unrefCalled = true; } };
    },
    setTimeout: (fn, ms) => {
      assert.strictEqual(ms, 200);
      fn();
      return null;
    },
    watch: (dir, cb) => {
      assert.strictEqual(dir, 'C:\\RedactWall\\watch');
      watchCallback = cb;
      return { close() {} };
    },
    processHandoffDirectory: (dir, opts) => {
      handoffs.push({ dir, opts });
      return { close() {} };
    },
  });

  await started.initialRefresh;
  intervalCallback();
  watchCallback('rename', 'new.txt');
  watchCallback('change', 'ignored.txt');

  assert.ok(unrefCalled);
  assert.deepStrictEqual(scans, [
    { filename: 'existing.txt', opts: { watchDir: 'C:\\RedactWall\\watch', settleMs: 150 } },
    { filename: 'new.txt', opts: { watchDir: 'C:\\RedactWall\\watch', settleMs: 150 } },
  ]);
  assert.deepStrictEqual(handoffs, [{
    dir: 'C:\\RedactWall\\handoff',
    opts: { secret: 'native-handoff-secret-000000000000000001' },
  }]);
  assert.ok(logs.some((line) => line.includes('RedactWall endpoint agent')));
  assert.ok(logs.some((line) => line.includes('file-flow profiles: disabled')));
  assert.ok(logs.some((line) => line.includes('ingest  : configured')));
});

test('file-flow profiles scan named roots with destination context and public checks hide paths', () => {
  const raw = JSON.stringify([
    { id: 'Lending Files', dir: 'C:\\Sensitive\\LendingFlow', destination: 'Copilot Desktop', user: 'lending@example.test' },
  ]);
  const profiles = fileFlowProfiles.normalizeFileFlowProfiles(raw);
  assert.strictEqual(profiles.length, 1);
  assert.strictEqual(profiles[0].id, 'lending_files');
  assert.strictEqual(profiles[0].destination, 'Copilot Desktop');
  assert.strictEqual(profiles[0].user, 'lending@example.test');

  const scans = [];
  let watchCallback;
  startWatchedRoot(profiles[0], {
    readdirSync: () => ['queued.pdf'],
    scanFile: (filename, opts) => scans.push({ filename, opts }),
    setTimeout: (fn, ms) => {
      assert.strictEqual(ms, 200);
      fn();
      return null;
    },
    watch: (dir, cb) => {
      assert.strictEqual(dir, profiles[0].dir);
      watchCallback = cb;
      return { close() {} };
    },
  });
  watchCallback('rename', 'new.docx');
  watchCallback('change', 'ignored.docx');

  assert.deepStrictEqual(scans.map((scan) => scan.filename), ['queued.pdf', 'new.docx']);
  assert.deepStrictEqual(scans[0].opts, {
    settleMs: 150,
    watchDir: profiles[0].dir,
    destination: 'Copilot Desktop',
    user: 'lending@example.test',
  });

  const checks = fileFlowProfiles.publicProfileChecks(profiles, (dir) => dir === profiles[0].dir);
  assert.deepStrictEqual(checks, [
    { id: 'endpoint_file_flow_profiles', ok: true, detail: 'configured:1' },
    { id: 'endpoint_file_flow_profile_lending_files', ok: true, detail: 'configured directory' },
  ]);
  assert.ok(!JSON.stringify(checks).includes('Sensitive'));
  assert.throws(() => fileFlowProfiles.normalizeFileFlowProfiles('[{"id":"bad"}]'), /directory is required/);
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
  assert.match(res.redactionHandoff.relativePath, /^\.redactwall-redacted[\\/]/);
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
  const handoffDir = path.join(dir, '.redactwall-redacted');
  assert.deepStrictEqual(fs.existsSync(handoffDir) ? fs.readdirSync(handoffDir) : [], []);
  assert.ok(!JSON.stringify(requests).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('redacted companion names fall back after deterministic suffix exhaustion', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-companion-'));
  const handoffDir = path.join(dir, '.redactwall-redacted');
  fs.mkdirSync(handoffDir, { recursive: true });
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');
  for (let i = 0; i < 100; i += 1) {
    const suffix = i ? `-${i + 1}` : '';
    fs.writeFileSync(path.join(handoffDir, `loan.redactwall-redacted${suffix}.txt`), 'occupied');
  }

  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async () => ({ decision: 'redact', mode: 'redact', status: 'redacted', id: 'q_redacted_random' }),
  });

  assert.strictEqual(res.decision, 'redact');
  assert.match(path.basename(res.redactionHandoff.path), /^loan\.redactwall-redacted-[0-9a-f]{8}\.txt$/);
  assert.ok(!fs.readFileSync(res.redactionHandoff.path, 'utf8').includes('524-71-9043'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('redaction handoff self-check falls back to approval if tokenization leaves raw values', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-raw-handoff-'));
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');
  const originalTokenize = D.tokenize;
  let reportRequest;
  try {
    D.tokenize = () => ({
      text: 'unsafe 524-71-9043',
      tokens: 1,
      map: { US_SSN_1: '524-71-9043' },
    });
    const res = await scanFile(filename, {
      watchDir: dir,
      user: 'unit-user',
      policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
      report: async (req) => {
        reportRequest = req;
        return { decision: 'block', mode: 'redact', status: 'pending', id: 'q_raw_handoff' };
      },
    });

    assert.strictEqual(res.decision, 'block');
    assert.strictEqual(reportRequest.clientOutcome, 'awaiting_approval');
    assert.match(reportRequest.note, /redacted companion unavailable/);
    assert.ok(!JSON.stringify(reportRequest).includes('unsafe 524-71-9043'));
  } finally {
    D.tokenize = originalTokenize;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('falls back to approval when redacted companion creation fails', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');
  fs.writeFileSync(path.join(dir, '.redactwall-redacted'), 'not a directory');

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
  const filename = 'driver-license.bin';
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

test('blocks image files locally as ocr_required without uploading bytes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'driver-license.png';
  const raw = 'pretend image bytes with SSN 524-71-9043';
  fs.writeFileSync(path.join(dir, filename), raw);

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    report: async (req) => { reportRequest = req; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'ocr_required');
  assert.strictEqual(res.supported, true);
  assert.strictEqual(res.inspected, false);
  assert.strictEqual(res.ocrRequired, true);
  assert.strictEqual(reportRequest.clientOutcome, 'ocr_required');
  assert.strictEqual(reportRequest.contentBase64, undefined);
  assert.deepStrictEqual(reportRequest.sensor, { name: 'endpoint_agent', version: pkg.version, platform: process.platform });
  assert.ok(!reportRequest.prompt.includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('uses configured endpoint-local OCR for image files without uploading bytes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan-scan.png';
  const raw = 'pretend image bytes with SSN 524-71-9043';
  fs.writeFileSync(path.join(dir, filename), raw);

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    ocr: { extractImageText: async () => 'OCR text. SSN 524-71-9043.' },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'block', mode: 'block', status: 'pending', id: 'q_ocr', findings: req.clientFindings, categories: [], riskScore: req.clientRiskScore };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'pending');
  assert.strictEqual(res.inspectedLocally, true);
  assert.ok(res.localAnalysis.findings.some((finding) => finding.type === 'US_SSN'));
  assert.strictEqual(reportRequest.source, 'endpoint_agent');
  assert.strictEqual(reportRequest.channel, 'file_upload');
  assert.strictEqual(reportRequest.clientPreRedacted, true);
  assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'US_SSN'));
  assert.strictEqual(reportRequest.contentBase64, undefined);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
  assert.ok(!JSON.stringify(reportRequest).includes(raw));

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
    server: 'http://redactwall.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'http://redactwall.test/api/v1/gate');
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
  assert.deepStrictEqual(await postJson('/api/v1/gate', { prompt: 'safe' }, {
    server: 'http://redactwall.test',
    key: 'unit-key',
    fetchImpl: async () => ({ ok: true, json: async () => ({ decision: 'allow', id: 'q_ok' }) }),
  }), { decision: 'allow', id: 'q_ok' });
  assert.strictEqual(calls, 0);
});

test('endpoint helper paths fail closed without leaking local content', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-helper-'));
  const filename = 'safe.txt';
  fs.writeFileSync(path.join(dir, filename), 'Public branch schedule.');
  const requests = [];

  assert.strictEqual(handoffSecretReady('short'), false);
  assert.strictEqual(handoffSecretReady('native-handoff-secret-000000000000000001'), true);
  assert.strictEqual(await scanFile('../outside.txt', { watchDir: dir }), undefined);
  assert.strictEqual(await postJson('/api/v1/gate', { prompt: 'safe' }, {
    server: 'http://redactwall.test',
    key: 'unit-key',
    fetchImpl: async () => ({ ok: false, json: async () => ({ error: 'denied' }) }),
  }), null);

  const res = await scanAbsoluteFile(path.join(dir, filename), {
    report: async (req) => {
      requests.push(req);
      return null;
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  assert.strictEqual(res.inspectedLocally, true);
  assert.strictEqual(requests[0].clientOutcome, 'allowed');
  assert.ok(!JSON.stringify(requests).includes('Public branch schedule.'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('refreshes scanner policy from the control plane', async () => {
  let request;
  const scanner = await refreshPolicy({
    server: 'http://redactwall.test',
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

  assert.strictEqual(request.url, 'http://redactwall.test/api/v1/policy');
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

test('sensor policy preserves reviewed AI destination controls', () => {
  const pol = sensorPolicy({
    governedDestinations: ['ChatGPT.com'],
    allowedDestinations: ['Claude.ai'],
    blockedFileUploadDestinations: ['NotebookLM.Google.com'],
    blockUnapprovedAiDestinations: false,
  });

  assert.deepStrictEqual(pol.governedDestinations, ['chatgpt.com']);
  assert.deepStrictEqual(pol.allowedDestinations, ['claude.ai']);
  assert.deepStrictEqual(pol.blockedFileUploadDestinations, ['notebooklm.google.com']);
  assert.strictEqual(pol.blockUnapprovedAiDestinations, false);
});

test('policy refresh times out and keeps the current scanner config', async () => {
  const started = Date.now();
  const scanner = await refreshPolicy({
    server: 'http://redactwall.test',
    key: 'policy-key',
    timeoutMs: 10,
    silent: true,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'http://redactwall.test/api/v1/policy');
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
  assert.strictEqual(ignoredByScanner('.redactwall-redacted/loan.redactwall-redacted.txt', scanner), true);
  assert.strictEqual(ignoredByScanner('.promptwall-redacted/loan.promptwall-redacted.txt', scanner), true);
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
  assert.match(res.result.redactionHandoff.relativePath, /^\.redactwall-redacted[\\/]/);
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

test('native handoff cleanup failures are logged without throwing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-cleanup-'));
  const handoffPath = path.join(dir, 'bad.json');
  fs.writeFileSync(handoffPath, JSON.stringify({ version: nativeHandoff.EVENT_VERSION, signature: '0'.repeat(64) }));
  const originalRmSync = fs.rmSync;
  const originalError = console.error;
  const errors = [];
  try {
    fs.rmSync = (target, opts) => {
      if (target === handoffPath && opts && opts.force) throw new Error('cleanup denied');
      return originalRmSync(target, opts);
    };
    console.error = (...args) => errors.push(args.join(' '));
    const res = await processNativeHandoffFile(handoffPath, {
      secret: 'native-handoff-secret-000000000000000001',
      removeRejected: true,
    });
    assert.strictEqual(res.status, 'rejected');
    assert.ok(errors.some((line) => /native handoff cleanup failed/.test(line)));
  } finally {
    console.error = originalError;
    fs.rmSync = originalRmSync;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('native handoff safe wrapper logs unexpected async failures', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-safe-'));
  const sourceDir = path.join(dir, 'source');
  fs.mkdirSync(sourceDir, { recursive: true });
  const filePath = path.join(sourceDir, 'member.txt');
  fs.writeFileSync(filePath, 'Loan file. SSN 524-71-9043.');
  const handoffPath = path.join(dir, 'evt.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_native_safe',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-safe',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));
  const originalError = console.error;
  const errors = [];
  try {
    console.error = (...args) => errors.push(args.join(' '));
    processNativeHandoffFileSafe(handoffPath, {
      secret,
      now: new Date('2026-06-26T15:01:00.000Z'),
      report: async () => { throw new Error('control plane unavailable'); },
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
  } finally {
    console.error = originalError;
  }

  assert.ok(errors.some((line) => /native handoff failed: control plane unavailable/.test(line)));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('native handoff directory watcher processes existing and new event files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-watch-'));
  assert.strictEqual(processHandoffDirectory(dir, { secret: 'short' }), undefined);
  fs.writeFileSync(path.join(dir, 'existing.json'), JSON.stringify({ version: nativeHandoff.EVENT_VERSION }));

  const watcher = processHandoffDirectory(dir, {
    secret: 'native-handoff-secret-000000000000000001',
    removeRejected: true,
    silent: true,
  });
  assert.ok(watcher && typeof watcher.close === 'function');
  fs.writeFileSync(path.join(dir, 'new.json'), JSON.stringify({ version: nativeHandoff.EVENT_VERSION }));
  await new Promise((resolve) => setTimeout(resolve, 260));
  watcher.close();

  assert.strictEqual(fs.existsSync(path.join(dir, 'existing.json')), false);
  assert.strictEqual(fs.existsSync(path.join(dir, 'new.json')), false);
  fs.rmSync(dir, { recursive: true, force: true });
});
