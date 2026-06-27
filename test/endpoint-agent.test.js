'use strict';
/** Endpoint file sensor must inspect locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanFile, refreshPolicy, fetchPolicy, scannerConfig, ignoredByScanner, postJson, defaultWatchDir, configuredKey } = require('../endpoint-agent/agent');
const pkg = require('../package.json');

test('watch directory prefers CLI argument, then endpoint env, then temp default', () => {
  assert.strictEqual(defaultWatchDir(['node', 'agent.js', 'C:\\Watch'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'C:\\Watch');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'D:\\FromEnv');
  assert.match(defaultWatchDir(['node', 'agent.js'], {}), /promptsentinel-watch$/);
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

test('redact policy tokenizes structured file findings locally before holding for approval', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  fs.writeFileSync(path.join(dir, filename), 'Member SSN 524-71-9043 needs a summary.');

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    policy: { enforcementMode: 'redact', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { decision: 'block', mode: 'redact', status: 'pending', id: 'q_redacted' };
    },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(reportRequest.clientOutcome, 'awaiting_approval');
  assert.match(reportRequest.prompt, /\[\[US_SSN_1\]\]/);
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
