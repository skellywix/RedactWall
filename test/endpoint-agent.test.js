'use strict';
/** Endpoint file sensor must route real file content through /scan-file. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanFile, refreshPolicy, scannerConfig, ignoredByScanner, postJson, defaultWatchDir } = require('../endpoint-agent/agent');

test('watch directory prefers CLI argument, then endpoint env, then temp default', () => {
  assert.strictEqual(defaultWatchDir(['node', 'agent.js', 'C:\\Watch'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'C:\\Watch');
  assert.strictEqual(defaultWatchDir(['node', 'agent.js'], { ENDPOINT_AGENT_WATCH_DIR: 'D:\\FromEnv' }), 'D:\\FromEnv');
  assert.match(defaultWatchDir(['node', 'agent.js'], {}), /promptsentinel-watch$/);
});

test('sends supported file bytes to scan-file API instead of redacted gate preview', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  const raw = 'Loan file. SSN 524-71-9043. Card 4111 1111 1111 1111.';
  fs.writeFileSync(path.join(dir, filename), raw);

  let request;
  let gateCalled = false;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    scanFileApi: async (req) => {
      request = req;
      return { decision: 'block', mode: 'block', id: 'q_test', findings: [{ type: 'US_SSN' }], categories: [], riskScore: 74 };
    },
    report: async () => { gateCalled = true; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(gateCalled, false);
  assert.strictEqual(request.filename, filename);
  assert.strictEqual(Buffer.from(request.contentBase64, 'base64').toString('utf8'), raw);
  assert.ok(!request.contentBase64.includes('[US_SSN]'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('does not upload unsupported file bytes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'driver-license.png';
  const raw = 'pretend binary with SSN 524-71-9043';
  fs.writeFileSync(path.join(dir, filename), raw);

  let scanCalled = false;
  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    scanFileApi: async () => { scanCalled = true; },
    report: async (req) => { reportRequest = req; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.supported, false);
  assert.strictEqual(scanCalled, false);
  assert.strictEqual(reportRequest.clientOutcome, 'file_unsupported');
  assert.ok(!reportRequest.prompt.includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('blocks supported files locally when scan API is unavailable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  const raw = 'Loan file that must not pass during outage. SSN 524-71-9043.';
  fs.writeFileSync(path.join(dir, filename), raw);

  let reportRequest;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    scanFileApi: async () => null,
    report: async (req) => { reportRequest = req; return null; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  assert.strictEqual(res.supported, true);
  assert.strictEqual(reportRequest.clientOutcome, 'scan_unavailable');
  assert.match(reportRequest.prompt, /^\[file blocked unscanned\] loan\.txt$/);
  assert.ok(!JSON.stringify(reportRequest).includes('524-71-9043'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('postJson times out stalled control-plane requests', async () => {
  const started = Date.now();
  const res = await postJson('/api/v1/scan-file', { filename: 'loan.txt' }, {
    server: 'http://sentinel.test',
    key: 'unit-key',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      assert.strictEqual(url, 'http://sentinel.test/api/v1/scan-file');
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
  let scanCalled = false;
  const ignoredRes = await scanFile(ignored, {
    watchDir: dir,
    scanner,
    scanFileApi: async () => { scanCalled = true; },
  });
  assert.strictEqual(ignoredRes, undefined);
  assert.strictEqual(scanCalled, false);

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
