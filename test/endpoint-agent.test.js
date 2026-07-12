'use strict';
/** Endpoint file sensor must inspect locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
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
  report,
  sendHeartbeat,
  start,
  defaultWatchDir,
  configuredKey,
  handoffSecretReady,
  nativeHandoff,
  fileFlowProfiles,
  startWatchedRoot,
  watchScheduler,
  _setTrustedPolicyForTest,
  _internal,
} = require('../sensors/endpoint-agent/agent');
const pkg = require('../package.json');
const D = require('../detection-engine/detect');
const { gateSchema } = require('../server/validation');
const { assertPrivatePath } = require('../server/private-path');

test.beforeEach(() => _setTrustedPolicyForTest({}));

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const POLICY_TEST_KEYS = crypto.generateKeyPairSync('ed25519');
const POLICY_TEST_PUBLIC_KEY = POLICY_TEST_KEYS.publicKey.export({ type: 'spki', format: 'pem' }).toString();
function signedPolicyBundle(policy, now = Date.now()) {
  const header = {
    version: 1,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 15 * 60 * 1000).toISOString(),
    policy,
  };
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  const input = JSON.stringify({ version: 1, issuedAt: header.issuedAt, expiresAt: header.expiresAt, policyHash });
  return { ...header, signature: crypto.sign(null, Buffer.from(input), POLICY_TEST_KEYS.privateKey).toString('base64') };
}

test('watch directory prefers CLI argument, then endpoint env, then temp default', () => {
  assert.strictEqual(defaultWatchDir(['node', 'agent.js', 'C:\\Watch'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'C:\\Watch');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'D:\\FromEnv');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { REDACTWALL_ENDPOINT_AGENT_WATCH_DIR: 'E:\\RedactWallWatch' }), 'E:\\RedactWallWatch');
  assert.match(defaultWatchDir(['node', 'agent.js'], {}), /redactwall-watch$/);
});

test('endpoint sensor policy carries EDM and cannot disable active hard stops', () => {
  const value = '550e8400-e29b-41d4-a716-446655440000';
  const salt = 'endpoint-unit-salt-0123456789abcdef';
  const exactMatch = {
    formatVersion: 2,
    algorithm: 'sha256',
    valuePolicy: 'offline-random-id-v1',
    salt,
    minLen: 20,
    maxWords: 1,
    fingerprints: [D.edmFingerprint(value, salt)],
  };
  const policy = sensorPolicy({
    alwaysBlock: ['US_SSN', 'EXACT_MATCH'],
    disabledDetectors: ['US_SSN', 'EXACT_MATCH', 'EMAIL_ADDRESS'],
    exactMatch,
  });

  assert.deepStrictEqual(policy.disabledDetectors, ['EMAIL_ADDRESS']);
  assert.strictEqual(policy.exactMatch, exactMatch);
  assert.ok(policy.alwaysBlock.includes('CREDIT_CARD'), 'remote policy cannot remove mandatory endpoint hard stops');
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
      assert.strictEqual(ms, 5 * 60 * 1000);
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
  watchCallback('change', 'changed.txt');

  assert.ok(unrefCalled);
  assert.deepStrictEqual(scans, [
    { filename: 'existing.txt', opts: { watchDir: 'C:\\RedactWall\\watch', settleMs: 150 } },
    { filename: 'new.txt', opts: { watchDir: 'C:\\RedactWall\\watch', settleMs: 150 } },
    { filename: 'changed.txt', opts: { watchDir: 'C:\\RedactWall\\watch', settleMs: 150 } },
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
  watchCallback('change', 'changed.docx');

  assert.deepStrictEqual(scans.map((scan) => scan.filename), ['queued.pdf', 'new.docx', 'changed.docx']);
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

test('file watcher rescans an existing file after a change event and blocks newly written PII', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-change-watch-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = 'existing.log';
  fs.writeFileSync(path.join(dir, filename), 'public branch hours');
  let callback;
  let timerCallback;
  let reportRequest;
  startWatchedRoot({ id: 'change_watch', dir, destination: 'Desktop AI' }, {
    readdirSync: () => [],
    watch: (_dir, handler) => {
      callback = handler;
      return { close() {} };
    },
    setTimeout: (handler) => {
      timerCallback = handler;
      return 1;
    },
    clearTimeout: () => {},
    scanFile: (name, options) => scanFile(name, {
      ...options,
      report: async (request) => {
        reportRequest = request;
        return { decision: 'block', status: 'pending', mode: 'block', id: 'q_changed_file' };
      },
    }),
  });

  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043');
  callback('change', filename);
  const result = await timerCallback();
  assert.strictEqual(result.decision, 'block');
  assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'US_SSN'));
  assert.doesNotMatch(JSON.stringify(reportRequest), /524-71-9043/);
});

test('watch scheduler debounces repeated rename and change events for one path', () => {
  const callbacks = [];
  const cleared = [];
  const scans = [];
  const schedule = watchScheduler((filename) => scans.push(filename), {
    setTimeout: (callback) => { callbacks.push(callback); return callbacks.length; },
    clearTimeout: (timer) => cleared.push(timer),
    delayMs: 25,
  });
  schedule('rename', 'member.txt');
  schedule('change', 'member.txt');
  assert.deepStrictEqual(cleared, [1]);
  callbacks[1]();
  assert.deepStrictEqual(scans, ['member.txt']);
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

test('default scanner inspects sensitive log and temporary files instead of silently authorizing them', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-default-text-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  for (const filename of ['member.log', 'member.tmp']) {
    fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043');
    let reportRequest;
    const result = await scanFile(filename, {
      watchDir: dir,
      user: 'unit-user',
      report: async (request) => {
        reportRequest = request;
        return { decision: 'block', mode: 'block', status: 'pending', id: 'q_default_text' };
      },
    });
    assert.strictEqual(result.decision, 'block', filename);
    if (filename.endsWith('.log')) {
      assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'US_SSN'), filename);
    } else {
      assert.strictEqual(reportRequest.clientOutcome, 'file_unsupported');
    }
    assert.doesNotMatch(JSON.stringify(reportRequest), /524-71-9043/);
  }
});

test('endpoint file scan blocks encoded SSNs and never records opaque Base64 as allowed', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-encoded-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cases = [
    { name: 'base64.txt', body: Buffer.from('SSN 524-71-9043').toString('base64'), opaque: false },
    { name: 'hex.txt', body: Buffer.from('SSN 524-71-9043').toString('hex'), opaque: false },
    { name: 'binary.txt', body: Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64'), opaque: true },
  ];

  for (const item of cases) {
    fs.writeFileSync(path.join(dir, item.name), item.body);
    let reportRequest;
    const result = await scanFile(item.name, {
      watchDir: dir,
      policy: { enforcementMode: 'warn', alwaysBlock: [], ignore: [], disabledDetectors: [] },
      report: async (record) => {
        reportRequest = record;
        return { decision: 'block', status: 'blocked_unscannable', id: 'q_endpoint_encoded' };
      },
    });

    assert.strictEqual(result.decision, 'block');
    assert.notStrictEqual(reportRequest.clientOutcome, 'allowed');
    assert.ok(!JSON.stringify(reportRequest).includes(item.body));
    if (item.opaque) {
      assert.strictEqual(reportRequest.clientOutcome, 'action_blocked');
      assert.strictEqual(reportRequest.clientPreRedacted, undefined);
    } else {
      assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'US_SSN'));
    }
  }
});

test('endpoint local scan enforces a supplied exact-match dataset', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-edm-'));
  const filename = 'order.txt';
  const value = '550e8400-e29b-41d4-a716-446655440000';
  fs.writeFileSync(path.join(dir, filename), `opaque record ${value}`);
  const salt = 'endpoint-scan-salt-0123456789abcdef';
  const exactMatch = {
    formatVersion: 2,
    algorithm: 'sha256',
    valuePolicy: 'offline-random-id-v1',
    salt,
    minLen: 20,
    maxWords: 1,
    fingerprints: [D.edmFingerprint(value, salt)],
  };
  let reportRequest;
  try {
    const result = await scanFile(filename, {
      watchDir: dir,
      policy: {
        enforcementMode: 'block',
        alwaysBlock: ['EXACT_MATCH'],
        disabledDetectors: ['EXACT_MATCH'],
        exactMatch,
      },
      report: async (request) => {
        reportRequest = request;
        return { id: 'q-edm', decision: 'block', status: 'pending' };
      },
    });

    assert.strictEqual(result.decision, 'block');
    assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'EXACT_MATCH'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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
    ocr: {
      extractImageText: async (snapshot) => {
        assertPrivatePath(path.dirname(snapshot), { directory: true, label: 'OCR temporary directory' });
        assertPrivatePath(snapshot, { directory: false, label: 'OCR temporary snapshot' });
        return 'OCR text. SSN 524-71-9043.';
      },
    },
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

test('endpoint OCR secures an empty snapshot before writing raw image bytes', async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-ocr-private-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const raw = Buffer.from('synthetic screenshot bytes with SSN 524-71-9043');
  const events = [];
  let fileSecured = false;
  const fsImpl = {
    ...fs,
    writeFileSync(...args) {
      events.push(`write:${Buffer.byteLength(args[1])}`);
      assert.strictEqual(fileSecured, true, 'raw bytes cannot be written before file privacy is established');
      return fs.writeFileSync(...args);
    },
  };

  const result = await _internal.extractEndpointOcrSnapshot('capture.png', raw, {}, {
    fs: fsImpl,
    tmpdir: tempRoot,
    securePrivatePath(target, options) {
      if (options.directory) {
        events.push('secure-directory');
        fs.chmodSync(target, 0o700);
      } else {
        events.push(`secure-file:${fs.statSync(target).size}`);
        assert.strictEqual(fs.statSync(target).size, 0, 'the snapshot must still be empty while its ACL is secured');
        fs.chmodSync(target, 0o600);
        fileSecured = true;
      }
    },
    async extractImageFile(_name, snapshot) {
      events.push('ocr');
      assert.deepStrictEqual(fs.readFileSync(snapshot), raw);
      return { extractionOk: true, text: 'synthetic OCR result' };
    },
  });

  assert.strictEqual(result.extractionOk, true);
  assert.deepStrictEqual(events, [
    'secure-directory',
    'secure-file:0',
    `write:${raw.length}`,
    'ocr',
  ]);
  assert.deepStrictEqual(fs.readdirSync(tempRoot), [], 'OCR cleanup removes the private snapshot directory');
});

test('endpoint OCR writes no raw bytes when private file setup fails', async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-ocr-private-fail-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  let rawWrites = 0;
  const fsImpl = {
    ...fs,
    writeFileSync(...args) {
      rawWrites += 1;
      return fs.writeFileSync(...args);
    },
  };

  await assert.rejects(() => _internal.extractEndpointOcrSnapshot(
    'capture.png',
    Buffer.from('raw screenshot bytes'),
    {},
    {
      fs: fsImpl,
      tmpdir: tempRoot,
      securePrivatePath(target, options) {
        if (options.directory) fs.chmodSync(target, 0o700);
        else throw new Error('synthetic Windows DACL failure');
      },
      extractImageFile: async () => { throw new Error('OCR must not run'); },
    },
  ), /synthetic Windows DACL failure/);
  assert.strictEqual(rawWrites, 0);
  assert.deepStrictEqual(fs.readdirSync(tempRoot), []);
});

test('blank endpoint OCR fails closed instead of recording an image as clean', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'blank-ocr.png';
  fs.writeFileSync(path.join(dir, filename), 'synthetic image bytes');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    ocr: { env: {}, extractImageText: async () => '' },
    report: async (req) => { reportRequest = req; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'ocr_required');
  assert.strictEqual(res.inspected, false);
  assert.strictEqual(reportRequest.clientOutcome, 'ocr_required');
  assert.notStrictEqual(reportRequest.clientOutcome, 'allowed');
  assert.strictEqual(reportRequest.contentBase64, undefined);
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
    server: 'https://redactwall.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'https://redactwall.test/api/v1/gate');
      assert.strictEqual(opts.headers['x-api-key'], 'unit-key');
      assert.strictEqual(opts.redirect, 'error');
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

test('postJson bounds stalled and oversized control-plane response bodies', async () => {
  let cancelled = 0;
  const stalled = new Response(new ReadableStream({
    cancel() { cancelled += 1; },
  }), { status: 200, headers: { 'content-type': 'application/json' } });

  const stalledResult = await postJson('/api/v1/gate', { prompt: 'safe' }, {
    server: 'https://redactwall.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async () => stalled,
  });
  assert.strictEqual(stalledResult, null);
  assert.strictEqual(cancelled, 1);

  const oversizedResult = await postJson('/api/v1/gate', { prompt: 'safe' }, {
    server: 'https://redactwall.test',
    key: 'unit-key',
    maxResponseBytes: 1024,
    fetchImpl: async () => jsonResponse(200, { padding: 'x'.repeat(2048) }),
  });
  assert.strictEqual(oversizedResult, null);
});

test('endpoint gate and heartbeat tenant context honors scope, aliases, and standalone mode', async () => {
  assert.deepStrictEqual(
    _internal.withEndpointTenantContext({ prompt: 'safe', orgId: 'Caller_Scope' }, {
      orgId: 'opts-scope',
      env: { REDACTWALL_TENANT_ID: 'env-scope' },
    }),
    { prompt: 'safe', orgId: 'caller_scope' },
    'an explicit valid body scope is normalized but never replaced',
  );
  assert.deepStrictEqual(
    _internal.withEndpointTenantContext({ prompt: 'safe' }, {
      orgId: 'Opts-Scope',
      env: { REDACTWALL_TENANT_ID: 'env-scope' },
    }),
    { prompt: 'safe', orgId: 'opts-scope' },
  );
  assert.deepStrictEqual(
    _internal.withEndpointTenantContext({ prompt: 'safe' }, { env: {} }),
    { prompt: 'safe' },
    'standalone mode does not invent a tenant',
  );

  let gateBody;
  await report({ prompt: 'safe', source: 'endpoint_agent', channel: 'file_upload' }, {
    server: 'https://redactwall.test',
    key: 'unit-key',
    env: { REDACTWALL_TENANT_ID: 'RedactWall-CU' },
    fetchImpl: async (url, opts) => {
      gateBody = JSON.parse(opts.body);
      return jsonResponse(200, { id: 'q_tenant', decision: 'allow', status: 'allowed' });
    },
  });
  assert.strictEqual(gateBody.orgId, 'redactwall-cu');

  let heartbeatBody;
  await sendHeartbeat({
    server: 'https://redactwall.test',
    key: 'unit-key',
    env: { PROMPTWALL_TENANT_ID: 'Legacy_CU' },
    fetchImpl: async (url, opts) => {
      heartbeatBody = JSON.parse(opts.body);
      return jsonResponse(200, { companions: {} });
    },
  });
  assert.strictEqual(heartbeatBody.orgId, 'legacy_cu');

  let standaloneBody;
  await report({ prompt: 'safe' }, {
    server: 'https://redactwall.test',
    key: 'unit-key',
    env: {},
    fetchImpl: async (url, opts) => {
      standaloneBody = JSON.parse(opts.body);
      return jsonResponse(200, { id: 'q_standalone', decision: 'allow', status: 'allowed' });
    },
  });
  assert.strictEqual(Object.hasOwn(standaloneBody, 'orgId'), false);

  let calls = 0;
  await assert.rejects(
    report({ prompt: 'safe' }, {
      server: 'https://redactwall.test',
      key: 'unit-key',
      env: { REDACTWALL_TENANT_ID: 'invalid tenant value' },
      fetchImpl: async () => { calls += 1; },
    }),
    (error) => error && error.code === 'REDACTWALL_TENANT_CONTEXT_INVALID',
  );
  assert.strictEqual(calls, 0, 'invalid tenant configuration fails locally before any credentialed fetch');
  await assert.rejects(
    report({ prompt: 'safe' }, {
      server: 'https://redactwall.test',
      key: 'unit-key',
      env: { PROMPTWALL_TENANT_ID: '123-45-6789' },
      fetchImpl: async () => { calls += 1; },
    }),
    (error) => error && error.code === 'REDACTWALL_TENANT_CONTEXT_INVALID',
  );
  assert.strictEqual(calls, 0, 'regulated legacy tenant aliases fail locally without echo or fetch');
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
    server: 'https://redactwall.test',
    key: 'unit-key',
    fetchImpl: async () => jsonResponse(200, { decision: 'allow', id: 'q_ok' }),
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
    server: 'https://redactwall.test',
    key: 'unit-key',
    fetchImpl: async () => jsonResponse(403, { error: 'denied' }),
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

test('refreshes scanner policy from the control plane', async (t) => {
  let request;
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-endpoint-policy-'));
  t.after(() => fs.rmSync(cacheDir, { recursive: true, force: true }));
  const policy = {
    scanner: {
      ignoreDirectories: ['Secrets'],
      ignoreFilenames: ['skip-me.txt'],
      ignoreExtensions: ['blocked'],
      maxFileBytes: 4096,
    },
  };
  const scanner = await refreshPolicy({
    server: 'https://redactwall.test',
    key: 'policy-key',
    policyPublicKey: POLICY_TEST_PUBLIC_KEY,
    policyCachePath: path.join(cacheDir, 'bundle.json'),
    fetchImpl: async (url, opts) => {
      request = { url, headers: opts.headers };
      assert.strictEqual(opts.redirect, 'error');
      return jsonResponse(200, signedPolicyBundle(policy));
    },
  });

  assert.strictEqual(request.url, 'https://redactwall.test/api/v1/policy/bundle');
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
    server: 'https://redactwall.test',
    key: 'policy-key',
    timeoutMs: 10,
    silent: true,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'https://redactwall.test/api/v1/policy/bundle');
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

test('destination and upload blocks take precedence over scanner ignore exceptions', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-ignore-policy-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = 'ignored.blocked';
  fs.writeFileSync(path.join(dir, filename), 'public data');
  const scanner = scannerConfig({
    ignoreExtensions: ['.blocked'], ignoreFilenames: [], ignoreDirectories: [], maxFileBytes: 1024,
  });
  let reportRequest;
  const result = await scanFile(filename, {
    watchDir: dir,
    destination: 'desktop-ai',
    scanner,
    policy: { blockedFileUploadDestinations: ['desktop-ai'] },
    report: async (request) => {
      reportRequest = request;
      return { decision: 'block', status: 'file_upload_blocked', id: 'q_ignore_block' };
    },
  });
  assert.strictEqual(result.decision, 'block');
  assert.strictEqual(reportRequest.clientOutcome, 'file_upload_blocked');
});

test('fd-bound endpoint reads block growth after the trusted handle is opened', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-grow-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = 'growing.txt';
  const full = path.join(dir, filename);
  fs.writeFileSync(full, 'safe');
  let reportRequest;

  const result = await scanFile(filename, {
    watchDir: dir,
    scanner: scannerConfig({ ignoreDirectories: [], ignoreFilenames: [], ignoreExtensions: [], maxFileBytes: 8 }),
    onFileOpened: () => fs.appendFileSync(full, ' sensitive bytes that exceed the bound'),
    report: async (request) => { reportRequest = request; },
  });

  assert.strictEqual(result.status, 'file_too_large');
  assert.strictEqual(reportRequest.clientOutcome, 'file_too_large');
  assert.ok(!JSON.stringify(reportRequest).includes('sensitive bytes'));
});

test('fd-bound endpoint reads reject a large path replacement after open', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-replace-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = 'replaced.txt';
  const full = path.join(dir, filename);
  const replacement = path.join(dir, 'replacement.tmp');
  fs.writeFileSync(full, 'safe');
  fs.writeFileSync(replacement, 'replacement contains sensitive bytes and exceeds the bound');
  let reportRequest;

  const result = await scanFile(filename, {
    watchDir: dir,
    scanner: scannerConfig({ ignoreDirectories: [], ignoreFilenames: [], ignoreExtensions: [], maxFileBytes: 8 }),
    onFileOpened: () => {
      fs.renameSync(full, path.join(dir, 'opened.txt'));
      fs.renameSync(replacement, full);
    },
    report: async (request) => { reportRequest = request; },
  });

  assert.strictEqual(result.status, 'file_changed_during_inspection');
  assert.strictEqual(reportRequest.clientOutcome, 'scan_unavailable');
  assert.strictEqual(gateSchema.safeParse(reportRequest).success, true);
  assert.ok(!JSON.stringify(reportRequest).includes('sensitive bytes'));
});

test('endpoint scans reject distinct BigInt file identities that collide as Numbers', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-bigint-identity-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const full = path.join(dir, 'visible.txt');
  const redirected = path.join(dir, 'redirected.txt');
  fs.writeFileSync(full, 'Public branch schedule.');
  fs.writeFileSync(redirected, 'Synthetic SSN 524-71-9043.');
  const pathId = 10414574140023031n;
  const handleId = 10414574140023032n;
  assert.strictEqual(Number(pathId), Number(handleId));
  assert.strictEqual(_internal.sameFileIdentity({ dev: 0n, ino: pathId }, { dev: 0n, ino: pathId }), false);
  assert.strictEqual(_internal.sameFileIdentity({ dev: 1n, ino: 0n }, { dev: 1n, ino: 0n }), false);
  assert.strictEqual(
    _internal.sameFileIdentity({ dev: 1, ino: Number(pathId) }, { dev: 1, ino: Number(handleId) }),
    false,
  );
  const safeNumberStat = { dev: 1, ino: 2, size: 3, mtimeMs: 4.5, ctimeMs: 5.5 };
  assert.strictEqual(_internal.sameFileSnapshot(safeNumberStat, { ...safeNumberStat }), true);

  const originals = {
    openSync: fs.openSync,
    statSync: fs.statSync,
    lstatSync: fs.lstatSync,
    fstatSync: fs.fstatSync,
  };
  const withIdentity = (stat, id) => {
    const exact = typeof stat.dev === 'bigint';
    const changed = Object.create(stat);
    Object.defineProperties(changed, {
      dev: { value: exact ? 1n : 1 },
      ino: { value: exact ? id : Number(id) },
      nlink: { value: exact ? 1n : 1 },
    });
    return changed;
  };
  const callStat = (method, target, options) => options === undefined
    ? method(target) : method(target, options);
  let reportRequest;
  try {
    fs.openSync = (target, ...args) => originals.openSync(
      path.resolve(String(target)) === full ? redirected : target,
      ...args,
    );
    fs.statSync = (target, options) => withIdentity(
      callStat(originals.statSync, target, options),
      path.resolve(String(target)) === full ? pathId : handleId,
    );
    fs.lstatSync = (target, options) => withIdentity(
      callStat(originals.lstatSync, target, options),
      path.resolve(String(target)) === full ? pathId : handleId,
    );
    fs.fstatSync = (fd, options) => withIdentity(callStat(originals.fstatSync, fd, options), handleId);

    const result = await scanFile(path.basename(full), {
      watchDir: dir,
      scanner: scannerConfig({ ignoreDirectories: [], ignoreFilenames: [], ignoreExtensions: [], maxFileBytes: 1024 }),
      report: async (request) => {
        reportRequest = request;
        return { decision: 'block', status: 'pending', id: 'q_bigint_identity' };
      },
    });

    assert.strictEqual(result.status, 'unsafe_file_reference');
    assert.strictEqual(reportRequest.clientOutcome, 'scan_unavailable');
    assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
  } finally {
    Object.assign(fs, originals);
  }
});

test('endpoint reads reject multiply linked files', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-hardlink-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const full = path.join(dir, 'visible.txt');
  fs.writeFileSync(full, 'Public branch schedule.');
  fs.linkSync(full, path.join(dir, 'alias.txt'));

  assert.deepStrictEqual(
    await _internal.readStableFileSnapshot(full, dir, 1024),
    { error: 'unsafe_file_reference' },
  );
});

test('endpoint reads reject in-place changes during the final path snapshot', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-final-path-race-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const full = path.join(dir, 'visible.txt');
  fs.writeFileSync(full, 'Public branch schedule.');
  const originalStatSync = fs.statSync;
  let targetStats = 0;
  try {
    fs.statSync = function mutateDuringFinalPathStat(target, options) {
      if (path.resolve(String(target)) === full) {
        targetStats += 1;
        if (targetStats === 2) fs.appendFileSync(full, ' Synthetic SSN 524-71-9043.');
      }
      return originalStatSync.call(fs, target, options);
    };
    assert.deepStrictEqual(
      await _internal.readStableFileSnapshot(full, dir, 1024),
      { error: 'file_changed_during_inspection' },
    );
    assert.strictEqual(targetStats, 2, 'the mutation occurred during the final path stat');
  } finally {
    fs.statSync = originalStatSync;
  }
});

test('endpoint scans reject linked paths that escape a watched root', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-link-root-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const root = path.join(dir, 'watch');
  const outside = path.join(dir, 'outside');
  fs.mkdirSync(root);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, 'member.txt'), 'SSN 524-71-9043');
  const linked = path.join(root, 'linked');
  fs.symlinkSync(outside, linked, process.platform === 'win32' ? 'junction' : 'dir');
  let reportRequest;

  const result = await scanFile(path.join('linked', 'member.txt'), {
    watchDir: root,
    report: async (request) => { reportRequest = request; },
  });

  assert.strictEqual(result.status, 'unsafe_file_reference');
  assert.strictEqual(reportRequest.clientOutcome, 'scan_unavailable');
  assert.strictEqual(gateSchema.safeParse(reportRequest).success, true);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
});

test('invalid endpoint control-plane URLs never echo credentials or query secrets', () => {
  const raw = 'https://endpoint-user:endpoint-pass@example.invalid/control?token=endpoint-secret';
  const child = spawnSync(process.execPath, ['sensors/endpoint-agent/agent.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, REDACTWALL_URL: raw },
    encoding: 'utf8',
  });
  assert.strictEqual(child.status, 1);
  assert.match(child.stderr, /refusing insecure or invalid control-plane URL/);
  for (const secret of [raw, 'endpoint-user', 'endpoint-pass', 'endpoint-secret']) {
    assert.ok(!child.stderr.includes(secret));
  }
});

test('processes signed native file-flow handoff events without raw payloads', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-'));
  const sourceDir = path.join(dir, 'source');
  const handoffDir = path.join(dir, 'handoff');
  fs.mkdirSync(sourceDir, { recursive: true });
  nativeHandoff.ensurePrivateDirectory(handoffDir);
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
  assert.strictEqual(reportRequest.idempotency.scope, 'native_handoff_v1');
  assert.match(reportRequest.idempotency.key, /^[0-9a-f]{64}$/);
  assert.match(reportRequest.prompt, /\[\[US_SSN_1\]\]/);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));
  assert.strictEqual(fs.existsSync(handoffPath), false);
  assert.match(res.result.redactionHandoff.relativePath, /^\.redactwall-redacted[\\/]/);
  const companion = fs.readFileSync(res.result.redactionHandoff.path, 'utf8');
  assert.match(companion, /\[\[US_SSN_1\]\]/);
  assert.ok(!companion.includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('native ingest identity is stable across restart input and distinct across signed events', () => {
  const secret = 'native-handoff-secret-000000000000000001';
  const base = {
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_ingest_identity',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: 'C:\\Synthetic\\evidence.txt',
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-ingest-identity',
  };
  const signed = nativeHandoff.signHandoffEvent(base, secret);
  const afterRestart = nativeHandoff.validateHandoffEvent(JSON.parse(JSON.stringify(signed)), {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  const first = nativeHandoff.ingestIdempotency(afterRestart, { secret });
  const second = nativeHandoff.ingestIdempotency(afterRestart, { secret });
  const unrelated = nativeHandoff.ingestIdempotency(
    nativeHandoff.signHandoffEvent({ ...base, id: 'evt_ingest_identity_2', nonce: 'nonce-ingest-identity-2' }, secret),
    { secret },
  );
  assert.deepStrictEqual(first, second);
  assert.notStrictEqual(first.key, unrelated.key);
  assert.strictEqual(JSON.stringify(first).includes(base.filePath), false);
  assert.strictEqual(JSON.stringify(first).includes(base.id), false);
  assert.strictEqual(JSON.stringify(first).includes(base.nonce), false);
});

test('native handoff claims stop duplicate watcher and restart replay before reporting', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-replay-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const source = path.join(dir, 'source.txt');
  const handoffDir = path.join(dir, 'handoff');
  nativeHandoff.ensurePrivateDirectory(handoffDir);
  fs.writeFileSync(source, 'Public branch schedule.');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_replay_unit',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-replay-unit',
  }, secret);
  const first = path.join(handoffDir, 'first.json');
  const duplicate = path.join(handoffDir, 'duplicate.json');
  fs.writeFileSync(first, JSON.stringify(event));
  fs.writeFileSync(duplicate, JSON.stringify(event));
  let reports = 0;
  const opts = {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
    report: async () => {
      reports += 1;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return { decision: 'allow', status: 'allowed', id: 'q_native_once' };
    },
  };

  const concurrent = await Promise.all([
    processNativeHandoffFile(first, opts),
    processNativeHandoffFile(duplicate, opts),
  ]);
  assert.deepStrictEqual(concurrent.map((item) => item.status).sort(), ['processed', 'replayed']);
  assert.strictEqual(reports, 1);

  const afterRestart = path.join(handoffDir, 'after-restart.json');
  fs.writeFileSync(afterRestart, JSON.stringify(event));
  const replay = await processNativeHandoffFile(afterRestart, opts);
  assert.strictEqual(replay.status, 'replayed');
  assert.strictEqual(reports, 1);
  const claims = fs.readdirSync(path.join(handoffDir, nativeHandoff.CONSUMED_DIR_NAME));
  assert.strictEqual(claims.length, 1);
  assert.match(claims[0], /^[0-9a-f]{64}\.claim$/);
});

test('native handoff cleanup preserves a filename replacement published during processing', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-cleanup-replacement-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const source = path.join(dir, 'source.txt');
  const handoffDir = path.join(dir, 'handoff');
  nativeHandoff.ensurePrivateDirectory(handoffDir);
  fs.writeFileSync(source, 'Public branch schedule.');
  const secret = 'native-handoff-secret-000000000000000001';
  const base = {
    version: nativeHandoff.EVENT_VERSION,
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
  };
  const accepted = nativeHandoff.signHandoffEvent({
    ...base,
    id: 'evt_cleanup_accepted',
    nonce: 'nonce-cleanup-accepted',
  }, secret);
  const replacement = nativeHandoff.signHandoffEvent({
    ...base,
    id: 'evt_cleanup_replacement',
    nonce: 'nonce-cleanup-replacement',
  }, secret);
  const handoffPath = path.join(handoffDir, 'event.json');
  const movedAccepted = path.join(handoffDir, 'accepted-moved-aside.json');
  const replacementBody = JSON.stringify(replacement);
  fs.writeFileSync(handoffPath, JSON.stringify(accepted), { mode: 0o600 });

  const result = await processNativeHandoffFile(handoffPath, {
    secret,
    silent: true,
    now: new Date('2026-06-26T15:01:00.000Z'),
    report: async () => {
      fs.renameSync(handoffPath, movedAccepted);
      fs.writeFileSync(handoffPath, replacementBody, { flag: 'wx', mode: 0o600 });
      return { decision: 'allow', status: 'allowed', id: 'q_native_cleanup_replacement' };
    },
  });

  assert.strictEqual(result.status, 'processed');
  assert.strictEqual(fs.readFileSync(handoffPath, 'utf8'), replacementBody);
  assert.strictEqual(fs.existsSync(movedAccepted), true);
});

test('native handoff cleanup preserves same-inode rewritten event bytes with restored metadata', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-cleanup-digest-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'source.txt');
  fs.writeFileSync(source, 'ordinary public text');
  const handoffPath = path.join(dir, 'handoff.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const signed = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_cleanup_digest',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-cleanup-digest',
  }, secret);
  const acceptedBody = JSON.stringify(signed);
  const replacementBody = acceptedBody.replace('Desktop AI', 'Desktop XX');
  assert.strictEqual(Buffer.byteLength(replacementBody), Buffer.byteLength(acceptedBody));
  fs.writeFileSync(handoffPath, acceptedBody, { mode: 0o600 });
  const fixedTime = new Date('2026-06-26T15:00:30.000Z');
  fs.utimesSync(handoffPath, fixedTime, fixedTime);
  const acceptedStat = fs.lstatSync(handoffPath, { bigint: true });

  const result = await processNativeHandoffFile(handoffPath, {
    secret,
    silent: true,
    now: new Date('2026-06-26T15:01:00.000Z'),
    report: async () => {
      fs.writeFileSync(handoffPath, replacementBody, { mode: 0o600 });
      fs.utimesSync(handoffPath, fixedTime, fixedTime);
      const replacementStat = fs.lstatSync(handoffPath, { bigint: true });
      assert.strictEqual(replacementStat.dev, acceptedStat.dev);
      assert.strictEqual(replacementStat.ino, acceptedStat.ino);
      assert.strictEqual(replacementStat.size, acceptedStat.size);
      assert.strictEqual(replacementStat.mtimeNs, acceptedStat.mtimeNs);
      return { decision: 'allow', status: 'allowed', id: 'q_native_cleanup_digest' };
    },
  });

  assert.strictEqual(result.status, 'processed');
  assert.strictEqual(fs.readFileSync(handoffPath, 'utf8'), replacementBody);
  const preservedStat = fs.lstatSync(handoffPath, { bigint: true });
  assert.strictEqual(preservedStat.dev, acceptedStat.dev);
  assert.strictEqual(preservedStat.ino, acceptedStat.ino);
});

test('rejected native handoff cleanup preserves same-inode rewritten bytes with restored metadata', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-rejected-digest-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'source.txt');
  fs.writeFileSync(source, 'ordinary public text');
  const handoffPath = path.join(dir, 'handoff.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const invalid = {
    ...nativeHandoff.signHandoffEvent({
      version: nativeHandoff.EVENT_VERSION,
      id: 'evt_rejected_cleanup_digest',
      createdAt: '2026-06-26T15:00:00.000Z',
      operation: 'upload',
      filePath: source,
      destination: { app: 'Desktop AI' },
      user: 'native-user@example.test',
      nonce: 'nonce-rejected-cleanup-digest',
    }, secret),
    signature: '0'.repeat(64),
  };
  const acceptedBody = JSON.stringify(invalid);
  const replacementBody = acceptedBody.replace('Desktop AI', 'Desktop XX');
  assert.strictEqual(Buffer.byteLength(replacementBody), Buffer.byteLength(acceptedBody));
  fs.writeFileSync(handoffPath, acceptedBody, { mode: 0o600 });
  const fixedTime = new Date('2026-06-26T15:00:30.000Z');
  fs.utimesSync(handoffPath, fixedTime, fixedTime);
  const acceptedStat = fs.lstatSync(handoffPath, { bigint: true });
  const originalRename = fs.renameSync;
  let rewritten = false;
  fs.renameSync = (sourcePath, destinationPath) => {
    if (!rewritten && path.resolve(String(sourcePath)) === handoffPath
        && String(destinationPath).includes('.processed.')) {
      fs.writeFileSync(handoffPath, replacementBody, { mode: 0o600 });
      fs.utimesSync(handoffPath, fixedTime, fixedTime);
      const replacementStat = fs.lstatSync(handoffPath, { bigint: true });
      assert.strictEqual(replacementStat.dev, acceptedStat.dev);
      assert.strictEqual(replacementStat.ino, acceptedStat.ino);
      assert.strictEqual(replacementStat.size, acceptedStat.size);
      assert.strictEqual(replacementStat.mtimeNs, acceptedStat.mtimeNs);
      rewritten = true;
    }
    return originalRename(sourcePath, destinationPath);
  };

  let result;
  try {
    result = await processNativeHandoffFile(handoffPath, {
      secret,
      removeRejected: true,
      silent: true,
      now: new Date('2026-06-26T15:01:00.000Z'),
    });
  } finally {
    fs.renameSync = originalRename;
  }

  assert.strictEqual(result.status, 'rejected');
  assert.strictEqual(rewritten, true);
  assert.strictEqual(fs.readFileSync(handoffPath, 'utf8'), replacementBody);
  const preservedStat = fs.lstatSync(handoffPath, { bigint: true });
  assert.strictEqual(preservedStat.dev, acceptedStat.dev);
  assert.strictEqual(preservedStat.ino, acceptedStat.ino);
});

test('replayed native handoff cleanup preserves same-inode rewritten bytes with restored metadata', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-replayed-digest-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'source.txt');
  fs.writeFileSync(source, 'ordinary public text');
  const handoffPath = path.join(dir, 'handoff.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const signed = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_replayed_cleanup_digest',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-replayed-cleanup-digest',
  }, secret);
  const acceptedBody = JSON.stringify(signed);
  const replacementBody = acceptedBody.replace('Desktop AI', 'Desktop XX');
  assert.strictEqual(Buffer.byteLength(replacementBody), Buffer.byteLength(acceptedBody));
  fs.writeFileSync(handoffPath, acceptedBody, { mode: 0o600 });
  const common = {
    secret,
    silent: true,
    now: new Date('2026-06-26T15:01:00.000Z'),
  };
  const first = await processNativeHandoffFile(handoffPath, {
    ...common,
    keepHandoffFile: true,
    report: async () => ({ decision: 'allow', status: 'allowed', id: 'q_native_replayed_digest' }),
  });
  assert.strictEqual(first.status, 'processed');
  const fixedTime = new Date('2026-06-26T15:00:30.000Z');
  fs.utimesSync(handoffPath, fixedTime, fixedTime);
  const acceptedStat = fs.lstatSync(handoffPath, { bigint: true });
  const originalRename = fs.renameSync;
  let rewritten = false;
  fs.renameSync = (sourcePath, destinationPath) => {
    if (!rewritten && path.resolve(String(sourcePath)) === handoffPath
        && String(destinationPath).includes('.processed.')) {
      fs.writeFileSync(handoffPath, replacementBody, { mode: 0o600 });
      fs.utimesSync(handoffPath, fixedTime, fixedTime);
      const replacementStat = fs.lstatSync(handoffPath, { bigint: true });
      assert.strictEqual(replacementStat.dev, acceptedStat.dev);
      assert.strictEqual(replacementStat.ino, acceptedStat.ino);
      assert.strictEqual(replacementStat.size, acceptedStat.size);
      assert.strictEqual(replacementStat.mtimeNs, acceptedStat.mtimeNs);
      rewritten = true;
    }
    return originalRename(sourcePath, destinationPath);
  };

  let replay;
  try {
    replay = await processNativeHandoffFile(handoffPath, {
      ...common,
      report: async () => { throw new Error('replayed handoff must not report again'); },
    });
  } finally {
    fs.renameSync = originalRename;
  }

  assert.strictEqual(replay.status, 'replayed');
  assert.strictEqual(rewritten, true);
  assert.strictEqual(fs.readFileSync(handoffPath, 'utf8'), replacementBody);
  const preservedStat = fs.lstatSync(handoffPath, { bigint: true });
  assert.strictEqual(preservedStat.dev, acceptedStat.dev);
  assert.strictEqual(preservedStat.ino, acceptedStat.ino);
});

test('native handoff missing target records a terminal fail-closed result', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-missing-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'removed-member-524-71-9043.txt');
  fs.writeFileSync(source, 'temporary synthetic file');
  const handoffPath = path.join(dir, 'missing.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_missing_target',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-missing-target',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));
  fs.rmSync(source);
  const reports = [];

  const result = await processNativeHandoffFile(handoffPath, {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (request) => {
      reports.push(request);
      return { id: 'q_missing_target', decision: 'block', status: 'file_blocked_unscanned' };
    },
  });

  assert.strictEqual(result.status, 'processed');
  assert.strictEqual(result.result.decision, 'block');
  assert.strictEqual(result.result.status, 'file_missing_or_unreadable');
  assert.strictEqual(reports.length, 1);
  assert.strictEqual(reports[0].clientOutcome, 'scan_unavailable');
  assert.ok(!JSON.stringify(reports[0]).includes('524-71-9043'));
  assert.strictEqual(result.terminal.state, 'terminal');
  assert.strictEqual(result.terminal.decision, 'block');
  assert.strictEqual(result.terminal.recorded, true);
  assert.strictEqual(fs.existsSync(handoffPath), false);
});

test('native handoff without durable audit evidence remains queued for retry', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-audit-retry-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'removed.txt');
  fs.writeFileSync(source, 'temporary synthetic file');
  const handoffPath = path.join(dir, 'audit-retry.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_audit_retry',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-audit-retry',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));
  fs.rmSync(source);
  const common = {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
  };

  await assert.rejects(
    () => processNativeHandoffFile(handoffPath, { ...common, report: async () => null }),
    (error) => error && error.code === 'REDACTWALL_HANDOFF_AUDIT_UNAVAILABLE',
  );
  assert.strictEqual(fs.existsSync(handoffPath), true);
  assert.strictEqual(nativeHandoff.readHandoffClaim(event, handoffPath, common).state, 'claimed');

  const resumed = await processNativeHandoffFile(handoffPath, {
    ...common,
    report: async () => ({ id: 'q_audit_retry', decision: 'block', status: 'file_blocked_unscanned' }),
  });
  assert.strictEqual(resumed.status, 'processed');
  assert.strictEqual(resumed.terminal.recorded, true);
  assert.strictEqual(fs.existsSync(handoffPath), false);
});

test('native handoff safe processing retries audit-unavailable work without restart', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-auto-retry-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'source.txt');
  fs.writeFileSync(source, 'ordinary public text');
  const handoffPath = path.join(dir, 'retry.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_auto_retry',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-auto-retry',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));
  let reports = 0;

  const first = await processNativeHandoffFileSafe(handoffPath, {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    handoffAuditRetryMs: 10,
    silent: true,
    report: async () => {
      reports += 1;
      return reports <= 2 ? null : { id: 'q_auto_retry', decision: 'allow', status: 'allowed' };
    },
  });
  assert.strictEqual(first.status, 'retry_scheduled');

  const deadline = Date.now() + 10000;
  while (fs.existsSync(handoffPath) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.strictEqual(fs.existsSync(handoffPath), false, 'retry should finish and remove the queued event');
  assert.strictEqual(reports, 3);
  const claim = nativeHandoff.readHandoffClaim(event, handoffPath, { secret });
  assert.strictEqual(claim.state, 'terminal');
  assert.strictEqual(claim.recorded, true);
});

test('an accepted native handoff can finish after its initial freshness window', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-stale-retry-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'source.txt');
  fs.writeFileSync(source, 'ordinary public text');
  const handoffPath = path.join(dir, 'stale-retry.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_stale_retry',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-stale-retry',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));
  const fresh = { secret, now: new Date('2026-06-26T15:01:00.000Z') };

  await assert.rejects(
    () => processNativeHandoffFile(handoffPath, { ...fresh, report: async () => null }),
    (error) => error && error.code === 'REDACTWALL_HANDOFF_AUDIT_UNAVAILABLE',
  );
  assert.strictEqual(nativeHandoff.readHandoffClaim(event, handoffPath, fresh).state, 'claimed');

  const completed = await processNativeHandoffFile(handoffPath, {
    secret,
    now: new Date('2026-06-26T16:00:00.000Z'),
    report: async () => ({ id: 'q_stale_retry', decision: 'allow', status: 'allowed' }),
  });
  assert.strictEqual(completed.status, 'processed');
  assert.strictEqual(completed.terminal.recorded, true);
  assert.strictEqual(fs.existsSync(handoffPath), false);
});

test('an incomplete native handoff claim is retried instead of erased', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-resume-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  nativeHandoff.ensurePrivateDirectory(dir);
  const source = path.join(dir, 'source.txt');
  fs.writeFileSync(source, 'Public branch schedule.');
  const handoffPath = path.join(dir, 'resume.json');
  const secret = 'native-handoff-secret-000000000000000001';
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: 'evt_resume_unit',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: source,
    destination: { app: 'Desktop AI' },
    user: 'native-user@example.test',
    nonce: 'nonce-resume-unit',
  }, secret);
  fs.writeFileSync(handoffPath, JSON.stringify(event));
  const common = {
    secret,
    now: new Date('2026-06-26T15:01:00.000Z'),
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
  };

  await assert.rejects(
    processNativeHandoffFile(handoffPath, { ...common, report: async () => { throw new Error('synthetic reporting crash'); } }),
    /synthetic reporting crash/,
  );
  assert.strictEqual(fs.existsSync(handoffPath), true, 'non-terminal work stays queued');
  assert.strictEqual(nativeHandoff.readHandoffClaim(event, handoffPath, common).state, 'claimed');

  let reports = 0;
  const resumed = await processNativeHandoffFile(handoffPath, {
    ...common,
    report: async () => { reports += 1; return { id: 'q_resumed', decision: 'allow', status: 'allowed' }; },
  });
  assert.strictEqual(resumed.status, 'processed');
  assert.strictEqual(resumed.result.decision, 'allow');
  assert.strictEqual(resumed.terminal.state, 'terminal');
  assert.strictEqual(reports, 1);
  assert.strictEqual(fs.existsSync(handoffPath), false);
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
  const originalUnlinkSync = fs.unlinkSync;
  const originalError = console.error;
  const errors = [];
  try {
    if (process.platform !== 'win32') {
      fs.unlinkSync = (target) => {
        if (String(target).includes('.processed.')) throw new Error('cleanup denied');
        return originalUnlinkSync(target);
      };
    }
    console.error = (...args) => errors.push(args.join(' '));
    const res = await processNativeHandoffFile(handoffPath, {
      secret: 'native-handoff-secret-000000000000000001',
      removeRejected: true,
      onBeforeExactFileDeleteClose() {
        throw new Error('cleanup denied');
      },
    });
    assert.strictEqual(res.status, 'rejected');
    assert.ok(errors.some((line) => /native handoff cleanup failed/.test(line)));
  } finally {
    console.error = originalError;
    fs.unlinkSync = originalUnlinkSync;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('native handoff safe wrapper logs unexpected async failures', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-safe-'));
  nativeHandoff.ensurePrivateDirectory(dir);
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
  let result;
  try {
    console.error = (...args) => errors.push(args.join(' '));
    result = await processNativeHandoffFileSafe(handoffPath, {
      secret,
      now: new Date('2026-06-26T15:01:00.000Z'),
      retryNativeHandoff: false,
      report: async () => { throw new Error('control plane unavailable'); },
    });
  } finally {
    console.error = originalError;
  }

  assert.deepStrictEqual(result, { status: 'retry_scheduled', reason: 'native_handoff_failed' });
  assert.ok(errors.some((line) => /native handoff failed: control plane unavailable/.test(line)));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('native handoff directory watcher processes existing and new event files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-native-watch-'));
  assert.strictEqual(processHandoffDirectory(dir, { secret: 'short' }), undefined);
  nativeHandoff.ensurePrivateDirectory(dir);
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
