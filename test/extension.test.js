'use strict';
/** Static regression checks for MV3 extension wiring. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const extensionDir = path.join(root, 'sensors', 'browser-extension');
const content = fs.readFileSync(path.join(extensionDir, 'content.js'), 'utf8');
const background = fs.readFileSync(path.join(extensionDir, 'background.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(extensionDir, 'manifest.json'), 'utf8'));
const adapters = require('../detection-engine/adapters');

function loadBackground(opts = {}) {
  let onMessage;
  let onInstalled;
  let onStartup;
  let onAlarm;
  const storage = { ...(opts.local || {}) };
  const createdAlarms = [];
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
      onInstalled: { addListener(fn) { onInstalled = fn; } },
      onStartup: { addListener(fn) { onStartup = fn; } },
      onMessage: { addListener(fn) { onMessage = fn; } },
      getManifest: () => manifest,
      lastError: null,
    },
    alarms: { create(name, spec) { createdAlarms.push({ name, spec }); }, onAlarm: { addListener(fn) { onAlarm = fn; } } },
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
  vm.runInNewContext(background + '\nself.__test = { requestTimeoutMs, fetchJsonWithTimeout, failClosed, scanUnavailable, buildHeartbeatBody, buildInstallChecks, reportInstallHealth };', context);
  return {
    context,
    createdAlarms,
    runAlarm: (name) => onAlarm && onAlarm({ name }),
    runInstalled: () => onInstalled && onInstalled(),
    runStartup: () => onStartup && onStartup(),
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
  assert.match(content, /msg\.type !== 'getPolicyState'/);
  assert.match(content, /blockUnapprovedAiDestinations:\s*POLICY\.blockUnapprovedAiDestinations !== false/);
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

test('browser blocks configured destinations before local prompt or file inspection', () => {
  assert.match(content, /function destinationBlocked\(\)/);
  assert.match(content, /function fileUploadBlocked\(\)/);
  assert.match(content, /POLICY\.allowedDestinations \|\| \[\]/);
  assert.match(content, /POLICY\.blockedDestinations \|\| \[\]/);
  assert.match(content, /POLICY\.blockedFileUploadDestinations \|\| \[\]/);
  assert.match(content, /POLICY\.blockedBrowserActions \|\| \[\]/);
  assert.match(content, /POLICY\.blockUnapprovedAiDestinations === false/);
  assert.match(content, /A\.isAiHost\(SITE\)/);
  assert.match(background, /clientOutcome:\s*msg\.payload\.outcome/);
  assert.match(content, /'destination_blocked'/);
  assert.match(content, /'file_upload_blocked'/);
  assert.match(content, /PromptWall blocked sends to/);
  assert.match(content, /PromptWall blocked file uploads to/);
  assert.match(background, /blockedDestinations:\s*\[\]/);
  assert.match(background, /blockedFileUploadDestinations:\s*\[\]/);
  assert.match(background, /blockedBrowserActions:\s*\[\]/);
  assert.match(background, /blockUnapprovedAiDestinations:\s*true/);
  assert.match(background, /allowedDestinations:\s*\[\]/);
});

test('browser blocks configured paste and drop actions without reporting clipboard or file text', () => {
  assert.match(content, /function browserActionBlockRule\(action\)/);
  assert.match(content, /const actionRule = browserActionBlockRule\('paste'\)/);
  assert.match(content, /const actionRule = browserActionBlockRule\('drop'\)/);
  assert.match(content, /e\.preventDefault\(\);\s*e\.stopPropagation\(\);\s*e\.stopImmediatePropagation\(\);/);
  assert.match(content, /function reportBlockedBrowserAction\(action, rule\)/);
  assert.match(content, /'\[browser action blocked\] ' \+ action \+ ' ' \+ SITE/);
  assert.match(content, /'action_blocked'/);
  assert.match(content, /PromptWall blocked paste into/);
  assert.match(content, /PromptWall blocked file drops into/);
  assert.match(background, /\.\.\.\(\(c\.policy && c\.policy\.blockedBrowserActions\) \|\| \[\]\)\.flatMap/);
});

test('browser fallback hard-stops match regulated endpoint defaults before policy sync', () => {
  assert.match(background, /MEDICAL_RECORD_NUMBER/);
  assert.match(background, /HEALTH_INSURANCE_ID/);
});

test('destination allowlist overrides wildcard destination blocks', () => {
  assert.match(content, /A\.isGoverned\(SITE, allowed\)\) return false/);
  assert.match(background, /\.\.\.\(\(c\.policy && c\.policy\.allowedDestinations\) \|\| \[\]\)/);
});

test('shadow AI reporting blocks unapproved AI destinations by default', () => {
  assert.match(background, /const blockUnapproved = !c\.policy \|\| c\.policy\.blockUnapprovedAiDestinations !== false/);
  assert.match(background, /clientOutcome:\s*blockUnapproved \? 'destination_blocked' : 'shadow_ai'/);
  assert.match(background, /\[unapproved AI blocked\]/);
});

test('browser block banner includes employee coaching guidance', () => {
  assert.match(content, /const LABELS = \{/);
  assert.match(content, /US_SSN:\s*'Social Security number'/);
  assert.match(content, /const COACHING = \{/);
  assert.match(content, /US_SSN:\s*'Use a member ID/);
  assert.match(content, /CONFIDENTIAL_BUSINESS:\s*'Remove unreleased plans/);
  assert.match(content, /function coachingFor\(items\)/);
  assert.match(content, /function listForScreen\(items\)/);
  assert.match(content, /function chipHtml\(items\)/);
  assert.match(content, /Sensitive data blocked/);
  assert.match(content, /before it could leave this browser/);
  assert.match(content, /'<div class="ps-coach">' \+ escapeHtml\(coach\) \+ '<\/div>'/);
  assert.match(content, /PromptWall found sensitive data: ' \+ listForScreen/);
  assert.doesNotMatch(content, /this prompt contains <b>' \+ items\.join/);
});

test('browser click interception uses shared send-button adapters', () => {
  assert.match(content, /function closestSendButton\(target\)/);
  assert.match(content, /A\.sendButtonSelectors\(location\.hostname\)/);
  assert.match(content, /button\[aria-label\*="Submit" i\]/);
});

test('manifest permits local control-plane URLs used by browser smoke tests', () => {
  assert.ok(manifest.host_permissions.includes('http://localhost/*'));
  assert.ok(manifest.host_permissions.includes('http://127.0.0.1/*'));
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

test('background install health posts secret-free browser heartbeat', async () => {
  const ingestKey = 'browser-ingest-key-0000000000000000000001';
  let outbound;
  const bg = loadBackground({
    managed: {
      serverUrl: 'https://promptwall.customer.example',
      ingestKey,
      email: 'analyst@example.test',
      orgId: 'cu-acme',
    },
    fetch: async (url, options) => {
      outbound = { url, headers: options.headers, body: JSON.parse(options.body), rawBody: options.body };
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 'q_browser_heartbeat', decision: 'recorded', status: 'sensor_heartbeat', failedChecks: [] }),
      };
    },
  });

  const res = await bg.context.self.__test.reportInstallHealth();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(outbound.url, 'https://promptwall.customer.example/api/v1/heartbeat');
  assert.strictEqual(outbound.headers['x-api-key'], ingestKey);
  assert.strictEqual(outbound.body.source, 'browser_extension');
  assert.strictEqual(outbound.body.destination, 'browser-install');
  assert.strictEqual(outbound.body.user, 'analyst@example.test');
  assert.strictEqual(outbound.body.orgId, 'cu-acme');
  assert.deepStrictEqual(outbound.body.sensor, {
    name: 'browser_extension',
    version: manifest.version,
    platform: 'chrome_mv3',
  });
  assert.ok(outbound.body.checks.every((item) => item.ok));
  assert.ok(outbound.body.checks.some((item) => item.id === 'managed_identity' && item.ok));
  assert.ok(outbound.body.checks.some((item) => item.id === 'content_script_coverage' && item.ok));
  assert.ok(!outbound.rawBody.includes(ingestKey));
  assert.ok(!JSON.stringify(outbound.body).includes(ingestKey));
});

test('background install health flags unmanaged local config without leaking keys', async () => {
  const ingestKey = 'local-browser-key-000000000000000000000001';
  let outbound;
  const bg = loadBackground({
    local: {
      serverUrl: 'http://localhost:4000',
      ingestKey,
      user: 'local-tech',
      orgId: 'local-cu',
    },
    fetch: async (url, options) => {
      outbound = { url, body: JSON.parse(options.body), rawBody: options.body };
      return { ok: true, status: 200, json: async () => ({ id: 'q_local_browser_heartbeat' }) };
    },
  });

  const res = await bg.context.self.__test.reportInstallHealth();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(outbound.url, 'http://localhost:4000/api/v1/heartbeat');
  assert.ok(outbound.body.checks.some((item) => item.id === 'managed_config' && !item.ok));
  assert.ok(outbound.body.checks.some((item) => item.id === 'managed_identity' && !item.ok));
  assert.ok(outbound.body.checks.some((item) => item.id === 'org_id' && !item.ok));
  assert.ok(!outbound.rawBody.includes(ingestKey));
});

test('background install health does not post without ingest key', async () => {
  const bg = loadBackground({
    managed: { serverUrl: 'https://promptwall.customer.example', email: 'analyst@example.test', orgId: 'cu-acme' },
    fetch: async () => {
      throw new Error('fetch should not run without an ingest key');
    },
  });
  const res = await bg.context.self.__test.reportInstallHealth();
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'missing_ingest_key');
  assert.ok(res.checks.some((item) => item.id === 'ingest_key' && !item.ok));
});

test('background install health does not throw on invalid server URL', async () => {
  const bg = loadBackground({
    managed: {
      serverUrl: 'not a url',
      ingestKey: 'browser-ingest-key-0000000000000000000001',
      email: 'analyst@example.test',
      orgId: 'cu-acme',
    },
    fetch: async () => {
      throw new Error('fetch should not run with an invalid server URL');
    },
  });
  const res = await bg.context.self.__test.reportInstallHealth();
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, 'invalid_server_url');
  assert.ok(res.checks.some((item) => item.id === 'server_url' && !item.ok));
});

test('background schedules browser install-health heartbeats', () => {
  const bg = loadBackground();
  assert.ok(bg.createdAlarms.some((item) => item.name === 'installHeartbeat' && item.spec.periodInMinutes === 60));
  assert.match(background, /onInstalled\.addListener\(\(\) => runAsync\(refreshPolicyAndHealth\)\)/);
  assert.match(background, /onStartup\.addListener\(\(\) => runAsync\(refreshPolicyAndHealth\)\)/);
});

test('governed Poe destination receives active content-script protection', () => {
  const matches = manifest.content_scripts.flatMap((entry) => entry.matches || []);
  assert.ok(manifest.host_permissions.includes('https://poe.com/*'));
  assert.ok(manifest.host_permissions.includes('https://www.poe.com/*'));
  assert.ok(matches.includes('https://poe.com/*'));
  assert.ok(matches.includes('https://www.poe.com/*'));
  assert.match(background, /shadow-AI/);
});

test('major Chinese AI destinations receive active content-script protection', () => {
  const matches = manifest.content_scripts.flatMap((entry) => entry.matches || []);
  for (const pattern of [
    'https://*.deepseek.com/*',
    'https://*.qwen.ai/*',
    'https://kimi.com/*',
    'https://doubao.com/*',
    'https://yuanbao.tencent.com/*',
    'https://yiyan.baidu.com/*',
    'https://chatglm.cn/*',
    'https://hailuoai.com/*',
    'https://xinghuo.xfyun.cn/*',
    'https://ai.360.com/*',
  ]) {
    assert.ok(manifest.host_permissions.includes(pattern), pattern);
    assert.ok(matches.includes(pattern), pattern);
  }
  for (const host of ['chat.deepseek.com', 'chat.qwen.ai', 'kimi.com', 'doubao.com', 'yuanbao.tencent.com']) {
    assert.strictEqual(adapters.isAiHost(host), true, host);
  }
});
