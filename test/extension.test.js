'use strict';
/** Static regression checks for MV3 extension wiring. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const content = fs.readFileSync(path.join(root, 'extension', 'content.js'), 'utf8');
const background = fs.readFileSync(path.join(root, 'extension', 'background.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'extension', 'manifest.json'), 'utf8'));

function loadBackground(opts = {}) {
  let onMessage;
  const storage = { ...(opts.local || {}) };
  const chrome = {
    storage: {
      local: {
        get: async (keys) => {
          if (!Array.isArray(keys)) return { ...storage };
          return keys.reduce((out, key) => {
            if (Object.prototype.hasOwnProperty.call(storage, key)) out[key] = storage[key];
            return out;
          }, {});
        },
        set: async (value) => Object.assign(storage, value),
      },
      managed: { get: async () => ({ ...(opts.managed || {}) }) },
    },
    runtime: {
      onInstalled: { addListener() {} },
      onStartup: { addListener() {} },
      onMessage: { addListener(fn) { onMessage = fn; } },
      getManifest: () => manifest,
      lastError: null,
    },
    alarms: { create() {}, onAlarm: { addListener() {} } },
    tabs: { onUpdated: { addListener() {} } },
  };
  const context = {
    AbortController,
    URL,
    chrome,
    clearTimeout,
    console,
    fetch: opts.fetch || (async () => ({ ok: true, json: async () => ({}) })),
    self: {},
    setTimeout,
  };
  vm.runInNewContext(background + '\nself.__test = { requestTimeoutMs, fetchJsonWithTimeout, failClosed, scanUnavailable };', context);
  return {
    context,
    storage,
    sendMessage: (msg) => new Promise((resolve) => onMessage(msg, {}, resolve)),
  };
}

test('redacted browser sends report tokenized text, not original prompt', () => {
  assert.match(content, /report\(t\.text,\s*verdict\.analysis,\s*'submit',\s*'redacted_sent'/);
  assert.doesNotMatch(content, /report\(text,\s*verdict\.analysis,\s*'submit',\s*'redacted_sent'/);
  assert.match(content, /clientPreRedacted:\s*true/);
  assert.match(background, /clientFindings:\s*msg\.payload\.clientFindings/);
  assert.match(background, /clientCategories:\s*msg\.payload\.clientCategories \|\| msg\.payload\.categories/);
});

test('redact mode blocks category-only hits that cannot be tokenized', () => {
  assert.match(content, /action:\s*\(a\.findings\.length && !a\.categories\.length\) \? 'redact' : 'block'/);
  assert.match(content, /Semantic categories/);
});

test('active content scripts receive policy updates from storage', () => {
  assert.match(content, /if \(c\.policy\) POLICY = \{ \.\.\.POLICY, \.\.\.c\.policy\.newValue \};/);
});

test('browser local analysis honors centralized detector policy', () => {
  assert.match(content, /function detectionPolicy\(\)/);
  assert.match(content, /ignore:\s*POLICY\.ignore \|\| \[\]/);
  assert.match(content, /disabledDetectors:\s*POLICY\.disabledDetectors \|\| \[\]/);
  assert.match(content, /D\.analyze\(text,\s*detectionPolicy\(\)\)/);
  assert.match(content, /const verdict = evaluate\(pasted\)/);
  assert.doesNotMatch(content, /const a = D\.analyze\(pasted\)/);
});

test('browser file uploads use scan-file API with base64 content', () => {
  assert.match(content, /type:\s*'scanFile'/);
  assert.match(content, /contentBase64:\s*bytesToBase64/);
  assert.match(content, /function handleFileScanResponse/);
  assert.match(background, /\/api\/v1\/scan-file/);
  assert.match(background, /if \(!c\.enabled\) \{\s*sendResponse && sendResponse\(null\);/);
});

test('background report fails closed when gate request times out', async () => {
  const bg = loadBackground({
    local: { ingestKey: 'unit-ingest-key', requestTimeoutMs: 50 },
    fetch: (url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        const err = new Error('aborted');
        err.name = 'AbortError';
        reject(err);
      });
    }),
  });
  assert.strictEqual(bg.context.self.__test.requestTimeoutMs(1), 50);
  const res = await bg.sendMessage({
    type: 'report',
    payload: {
      prompt: 'Member SSN 524-71-9043',
      destination: 'chatgpt.com',
      channel: 'submit',
      source: 'browser_extension',
      categories: [],
      outcome: 'sent_after_warning',
    },
  });
  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'control_plane_unavailable');
  assert.strictEqual(res.reason, 'gate_timeout');
});

test('background report fails closed when no ingest key is configured', async () => {
  const bg = loadBackground({
    fetch: async () => {
      throw new Error('fetch should not run without an ingest key');
    },
  });
  const res = await bg.sendMessage({
    type: 'report',
    payload: {
      prompt: 'Member SSN 524-71-9043',
      destination: 'chatgpt.com',
      channel: 'submit',
      source: 'browser_extension',
      categories: [],
      outcome: 'blocked',
    },
  });
  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'control_plane_unavailable');
  assert.strictEqual(res.reason, 'missing_ingest_key');
});

test('background report includes browser extension version metadata', async () => {
  let outbound;
  const bg = loadBackground({
    local: { ingestKey: 'unit-key' },
    fetch: async (url, options) => {
      outbound = { url, body: JSON.parse(options.body), headers: options.headers };
      return { ok: true, json: async () => ({ decision: 'allow' }) };
    },
  });
  const res = await bg.sendMessage({
    type: 'report',
    payload: {
      prompt: 'Summarize today\'s branch hours.',
      destination: 'chatgpt.com',
      channel: 'submit',
      source: 'browser_extension',
      categories: [],
      outcome: 'allowed',
    },
  });
  assert.strictEqual(res.decision, 'allow');
  assert.strictEqual(outbound.url, 'http://localhost:4000/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'unit-key');
  assert.deepStrictEqual(outbound.body.sensor, {
    name: 'browser_extension',
    version: manifest.version,
    platform: 'chrome_mv3',
  });
});

test('background file scan fails closed on control-plane errors', async () => {
  const bg = loadBackground({
    local: { ingestKey: 'unit-ingest-key' },
    fetch: async () => ({ ok: false, status: 503, json: async () => ({ error: 'unavailable' }) }),
  });
  const res = await bg.sendMessage({
    type: 'scanFile',
    payload: {
      filename: 'loan.txt',
      contentBase64: Buffer.from('synthetic').toString('base64'),
      destination: 'chatgpt.com',
      channel: 'file_upload',
      source: 'browser_extension',
    },
  });
  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  assert.strictEqual(res.supported, true);
  assert.strictEqual(res.inspected, false);
  assert.strictEqual(res.reason, 'scan_file_http_503');
});

test('background file scan includes browser extension version metadata', async () => {
  let outbound;
  const bg = loadBackground({
    local: { ingestKey: 'unit-ingest-key' },
    fetch: async (url, options) => {
      outbound = { url, body: JSON.parse(options.body) };
      return { ok: true, json: async () => ({ decision: 'allow', supported: true }) };
    },
  });

  const res = await bg.sendMessage({
    type: 'scanFile',
    payload: {
      filename: 'loan.txt',
      contentBase64: Buffer.from('synthetic').toString('base64'),
      destination: 'chatgpt.com',
      channel: 'file_upload',
      source: 'browser_extension',
    },
  });

  assert.strictEqual(res.decision, 'allow');
  assert.strictEqual(outbound.url, 'http://localhost:4000/api/v1/scan-file');
  assert.deepStrictEqual(outbound.body.sensor, {
    name: 'browser_extension',
    version: manifest.version,
    platform: 'chrome_mv3',
  });
});

test('warn and justify sends wait for recorded gate response before resend', () => {
  assert.match(content, /async function proceedAfterRecorded/);
  assert.match(content, /const res = await report\(text, analysis, 'submit', outcome, note\)/);
  assert.match(content, /recordedProceedResponse\(res, outcome\)/);
  assert.match(content, /Send blocked until the control plane is reachable/);
  assert.doesNotMatch(content, /report\(text, verdict\.analysis, 'submit', verdict\.action === 'justify' \? 'justified' : 'sent_after_warning', note\);\s*bypassOnce = true;\s*resend\(el\);/);
});

test('manifest grants alarms permission used for policy refresh', () => {
  assert.ok(manifest.permissions.includes('alarms'));
});
