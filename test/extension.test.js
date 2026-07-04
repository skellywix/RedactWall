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
const contentCss = fs.readFileSync(path.join(extensionDir, 'content.css'), 'utf8');
const popupHtml = fs.readFileSync(path.join(extensionDir, 'popup.html'), 'utf8');
const background = fs.readFileSync(path.join(extensionDir, 'background.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(extensionDir, 'manifest.json'), 'utf8'));
const adapters = require('../detection-engine/adapters');

function loadBackground(opts = {}) {
  let onMessage;
  let onInstalled;
  let onStartup;
  let onAlarm;
  let onDownloadCreated;
  const storage = { ...(opts.local || {}) };
  const createdAlarms = [];
  const canceledDownloads = [];
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
    downloads: {
      onCreated: { addListener(fn) { onDownloadCreated = fn; } },
      cancel(id, cb) {
        canceledDownloads.push(id);
        if (cb) cb();
      },
    },
    tabs: { onUpdated: { addListener() {} } },
  };
  const context = {
    AbortController,
    URL,
    chrome,
    clearTimeout,
    console,
    fetch: opts.fetch || (async () => ({ ok: true, json: async () => ({}) })),
    self: { PSAdapters: opts.adapters || adapters },
    setTimeout,
  };
  vm.runInNewContext(background + '\nself.__test = { requestTimeoutMs, fetchJsonWithTimeout, failClosed, browserPlatform, buildHeartbeatBody, buildInstallChecks, reportInstallHealth, refreshPolicy, normalizeDestinationHost, downloadHostCandidates, downloadDestinationForPolicy, browserActionBlockRule, handleDownloadCreated };', context);
  return {
    context,
    createdAlarms,
    canceledDownloads,
    runAlarm: (name) => onAlarm && onAlarm({ name }),
    runDownloadCreated: (item) => onDownloadCreated && onDownloadCreated(item),
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
  assert.match(content, /const Ext = window\.PWBrowserApi/);
  assert.match(content, /Ext\.sendMessage\(\{ type: 'getConfig' \}\)/);
  assert.match(content, /Ext\.addStorageChangeListener/);
});

test('browser local analysis honors centralized detector policy', () => {
  assert.match(content, /function detectionPolicy\(\)/);
  assert.match(content, /ignore:\s*POLICY\.ignore \|\| \[\]/);
  assert.match(content, /disabledDetectors:\s*POLICY\.disabledDetectors \|\| \[\]/);
  assert.match(content, /D\.analyze\(text,\s*detectionPolicy\(\)\)/);
  assert.match(content, /const verdict = evaluate\(pasted\)/);
  assert.doesNotMatch(content, /const a = D\.analyze\(pasted\)/);
});

test('browser file uploads inspect locally and never send file bytes to the control plane', () => {
  assert.match(content, /function inspectTextUpload\(file, text\)/);
  assert.match(content, /D\.analyze\(text,\s*detectionPolicy\(\)\)/);
  assert.match(content, /reader\.readAsText\(f\)/);
  assert.match(content, /TEXT_UPLOAD_EXTENSIONS/);
  assert.match(content, /OCR_UPLOAD_EXTENSIONS/);
  assert.match(content, /CLEAN_UPLOAD_BYPASS_MS/);
  assert.match(content, /function textLooksReadable\(text\)/);
  assert.match(content, /if \(!textLooksReadable\(text\)\)/);
  assert.match(content, /function filesHaveCleanBypass\(files\)/);
  assert.match(content, /function consumeCleanUploadBypass\(files\)/);
  assert.match(content, /if \(destinationBlocked\(\)\)[\s\S]+if \(fileUploadBlocked\(\)\)[\s\S]+if \(filesHaveCleanBypass\(files\)\)/);
  assert.match(content, /if \(filesHaveCleanBypass\(files\)\) \{\s*consumeCleanUploadBypass\(files\);\s*return;/);
  assert.match(content, /String\(file\.name \|\| ''\)/);
  assert.match(content, /recordedEvidenceResponse\(res,\s*'allowed'\)\) rememberCleanUpload\(file\)/);
  assert.match(content, /function fileLabel\(file\)/);
  assert.match(content, /safeFileFindingPrompt\(file, analysis\)/);
  assert.match(content, /\[browser file blocked locally\]/);
  assert.match(content, /\[browser file inspected clean\] ' \+ fileLabel\(file\)/);
  assert.match(content, /\[browser file blocked\] ' \+ fileLabel\(file\)/);
  assert.match(content, /'awaiting_approval'/);
  assert.match(content, /clientPreRedacted:\s*true/);
  assert.match(content, /'file_unsupported'/);
  assert.match(content, /'ocr_required'/);
  assert.doesNotMatch(content, /type:\s*'scanFile'/);
  assert.doesNotMatch(content, /contentBase64|bytesToBase64|readAsArrayBuffer/);
  assert.doesNotMatch(background, /\/api\/v1\/scan-file|contentBase64|scanUnavailable/);
});

test('browser blocks configured destinations before local prompt or file inspection', () => {
  assert.match(content, /function destinationBlocked\(\)/);
  assert.match(content, /function fileUploadBlocked\(\)/);
  assert.match(content, /function recordedEvidenceResponse\(res, expectedStatus\)/);
  assert.match(content, /function updateEvidenceToast\(reportPromise, expectedStatus, recordedMessage, unrecordedMessage\)/);
  assert.match(content, /function updateBatchEvidenceToast\(reportPromises, expectedStatus, recordedMessage, unrecordedMessage\)/);
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
  assert.match(content, /Recording evidence/);
  assert.match(content, /Control-plane evidence was not recorded yet/);
  assert.match(content, /updateEvidenceToast\(\s*reportBlockedDestination\('submit'\),\s*'destination_blocked'/);
  assert.match(content, /updateBatchEvidenceToast\(\s*reports,\s*'destination_blocked'/);
  assert.match(content, /updateBatchEvidenceToast\(\s*reports,\s*'file_upload_blocked'/);
  assert.match(background, /blockedDestinations:\s*\[\]/);
  assert.match(background, /blockedFileUploadDestinations:\s*\[\]/);
  assert.match(background, /blockedBrowserActions:\s*\[\]/);
  assert.match(background, /blockUnapprovedAiDestinations:\s*true/);
  assert.match(background, /allowedDestinations:\s*\[\]/);
});

test('browser blocks configured paste, drop, copy, and download actions without reporting sensitive text', () => {
  assert.match(content, /function browserActionBlockRule\(action\)/);
  assert.match(content, /const actionRule = browserActionBlockRule\('paste'\)/);
  assert.match(content, /const actionRule = browserActionBlockRule\('drop'\)/);
  assert.match(content, /const actionRule = browserActionBlockRule\('copy'\)/);
  assert.match(content, /function copyOriginInComposerOrUI\(event\)/);
  assert.match(content, /selection\.anchorNode/);
  assert.match(content, /e\.preventDefault\(\);\s*e\.stopPropagation\(\);\s*e\.stopImmediatePropagation\(\);/);
  assert.match(content, /function reportBlockedBrowserAction\(action, rule\)/);
  assert.match(content, /updateEvidenceToast\(\s*reportBlockedBrowserAction\('copy', actionRule\),\s*'action_blocked'/);
  assert.match(content, /updateEvidenceToast\(\s*reportBlockedBrowserAction\('drop', actionRule\),\s*'action_blocked'/);
  assert.match(content, /'\[browser action blocked\] ' \+ action \+ ' ' \+ SITE/);
  assert.match(content, /'action_blocked'/);
  assert.match(content, /PromptWall blocked paste into/);
  assert.match(content, /PromptWall blocked file drops into/);
  assert.match(content, /PromptWall blocked copy from/);
  assert.match(background, /chrome\.downloads\?\.onCreated\?\.addListener/);
  assert.match(background, /function downloadDestinationForPolicy\(item = \{\}, pol = \{\}\)/);
  assert.match(background, /chrome\.downloads\.cancel\(id/);
  assert.match(background, /prompt:\s*'\[browser action blocked\] download ' \+ host/);
  assert.match(background, /channel:\s*'download'/);
  assert.match(background, /clientOutcome:\s*'action_blocked'/);
  assert.match(background, /\.\.\.\(\(c\.policy && c\.policy\.blockedBrowserActions\) \|\| \[\]\)\.flatMap/);
});

test('unscannable browser uploads hand name+size file intent to the endpoint native host', async () => {
  assert.match(content, /ENDPOINT_INTENT_OUTCOMES = new Set\(\['file_too_large', 'ocr_required', 'file_unsupported', 'scan_unavailable'\]\)/);
  assert.match(content, /sendEndpointFileIntent\(file, outcome\);/);
  assert.match(content, /type: 'fileIntent'/);
  assert.doesNotMatch(content, /fileIntent[\s\S]{0,300}readAsText/, 'intent payload never reads file bytes');
  assert.ok(manifest.permissions.includes('nativeMessaging'));

  const sent = [];
  const bg = loadBackground({ managed: { email: 'analyst@example.test' } });
  bg.context.chrome.runtime.sendNativeMessage = (hostName, message, cb) => {
    sent.push({ hostName, message });
    if (cb) cb({ ok: true, status: 'handoff_written' });
  };
  const ack = await bg.sendMessage({ type: 'fileIntent', payload: { fileName: 'member-report.pdf', sizeBytes: 42 } });
  assert.strictEqual(ack && ack.queued, true);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.strictEqual(sent.length, 1);
  assert.strictEqual(sent[0].hostName, 'com.promptwall.file_intent');
  assert.strictEqual(sent[0].message.type, 'upload_intent');
  assert.strictEqual(sent[0].message.fileName, 'member-report.pdf');
  assert.strictEqual(sent[0].message.sizeBytes, 42);
  assert.strictEqual(sent[0].message.user, 'analyst@example.test');
  assert.deepStrictEqual(
    Object.keys(sent[0].message).sort(),
    ['destination', 'fileName', 'sizeBytes', 'type', 'user'],
    'intent carries metadata only - no bytes, no prompt text',
  );

  await bg.sendMessage({ type: 'fileIntent', payload: { fileName: '', sizeBytes: 42 } });
  await bg.sendMessage({ type: 'fileIntent', payload: { fileName: 'x.pdf', sizeBytes: 0 } });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.strictEqual(sent.length, 1, 'invalid intents are dropped before the native host');
});

test('browser download blocks use host-only evidence and never report URLs or filenames', async () => {
  const fetchCalls = [];
  const bg = loadBackground({
    local: {
      ingestKey: 'unit-ingest-key-000',
      policy: {
        blockedBrowserActions: [{
          id: 'block_download_chatgpt',
          action: 'download',
          destinations: ['chatgpt.com'],
          reason: 'download_blocked',
        }],
      },
    },
    managed: { email: 'analyst@example.test', orgId: 'credit-union-1' },
    fetch: async (url, options) => {
      fetchCalls.push({ url, body: JSON.parse(options.body) });
      return { ok: true, json: async () => ({ id: 'q-download', status: 'action_blocked' }) };
    },
  });

  const result = await bg.context.self.__test.handleDownloadCreated({
    id: 42,
    referrer: 'https://chatgpt.com/c/member-case',
    url: 'https://files.example.test/member-loan-524-71-9043.pdf',
  });

  assert.strictEqual(result.ok, true);
  assert.deepStrictEqual(bg.canceledDownloads, [42]);
  assert.strictEqual(fetchCalls.length, 1);
  assert.strictEqual(fetchCalls[0].body.destination, 'chatgpt.com');
  assert.strictEqual(fetchCalls[0].body.channel, 'download');
  assert.strictEqual(fetchCalls[0].body.clientOutcome, 'action_blocked');
  assert.strictEqual(fetchCalls[0].body.prompt, '[browser action blocked] download chatgpt.com');
  assert.strictEqual(fetchCalls[0].body.note, 'download_blocked');
  assert.ok(!JSON.stringify(fetchCalls[0].body).includes('member-loan'));
  assert.ok(!JSON.stringify(fetchCalls[0].body).includes('524-71-9043'));
  assert.strictEqual(
    bg.context.self.__test.downloadDestinationForPolicy({
      referrer: 'https://unrelated.example/',
      finalUrl: 'blob:https://claude.ai/download-id',
    }, {
      blockedBrowserActions: [{ action: 'download', destinations: ['claude.ai'] }],
    }),
    'claude.ai',
  );
});

test('browser fallback hard-stops match regulated endpoint defaults before policy sync', () => {
  assert.match(background, /MEDICAL_RECORD_NUMBER/);
  assert.match(background, /HEALTH_INSURANCE_ID/);
});

test('browser policy refresh preserves cached state on disabled or failed refresh', async () => {
  const cachedPolicy = {
    enforcementMode: 'justify',
    governedDestinations: ['chatgpt.com'],
    blockedBrowserActions: [{ action: 'paste', destinations: ['chatgpt.com'] }],
  };
  const disabled = loadBackground({
    local: {
      enabled: false,
      ingestKey: 'unit-ingest-key-000',
      policy: cachedPolicy,
    },
    fetch: async () => {
      throw new Error('disabled refresh should not call fetch');
    },
  });
  await disabled.context.self.__test.refreshPolicy();
  assert.deepStrictEqual(disabled.storage.policy, cachedPolicy);

  const failed = loadBackground({
    local: {
      serverUrl: 'https://control.example.test',
      ingestKey: 'unit-ingest-key-000',
      policy: cachedPolicy,
    },
    fetch: async () => ({ ok: false, json: async () => ({ error: 'offline' }) }),
  });
  await failed.context.self.__test.refreshPolicy();
  assert.deepStrictEqual(failed.storage.policy, cachedPolicy);

  const refreshed = loadBackground({
    local: {
      serverUrl: 'https://control.example.test',
      ingestKey: 'unit-ingest-key-000',
      policy: cachedPolicy,
    },
    fetch: async () => ({
      ok: true,
      json: async () => ({
        enforcementMode: 'redact',
        governedDestinations: ['claude.ai'],
      }),
    }),
  });
  await refreshed.context.self.__test.refreshPolicy();
  assert.strictEqual(refreshed.storage.policy.enforcementMode, 'redact');
  assert.deepStrictEqual(Array.from(refreshed.storage.policy.governedDestinations), ['claude.ai']);
  assert.deepStrictEqual(Array.from(refreshed.storage.policy.blockedBrowserActions), []);
  assert.ok(Array.from(refreshed.storage.policy.alwaysBlock).includes('US_SSN'));
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
  assert.match(contentCss, /\.ps-banner\{[^}]*box-sizing:border-box/);
  assert.match(content, /Sensitive data blocked/);
  assert.match(content, /before it could leave this browser/);
  assert.match(content, /setAttribute\('role', 'alertdialog'\)/);
  assert.match(content, /setAttribute\('aria-labelledby', titleId\)/);
  assert.match(content, /setAttribute\('aria-describedby', detailId\)/);
  assert.match(content, /aria-label="Business reason"/);
  assert.match(content, /reasonInput\.setAttribute\('aria-invalid', 'true'\)/);
  assert.match(content, /reasonInput\.addEventListener\('input'/);
  assert.match(content, /reasonInput\.setAttribute\('aria-invalid', 'false'\)/);
  assert.match(content, /initialFocus\.focus\(\{ preventScroll: true \}\)/);
  assert.match(content, /'<div class="ps-coach">' \+ escapeHtml\(coach\) \+ '<\/div>'/);
  assert.match(content, /PromptWall found sensitive data: ' \+ listForScreen/);
  assert.doesNotMatch(content, /this prompt contains <b>' \+ items\.join/);
});

test('browser extension motion CSS honors reduced motion preferences', () => {
  assert.match(contentCss, /@media\s*\(prefers-reduced-motion:reduce\)\s*\{[^}]*\.ps-banner,\s*\.ps-toast\{animation:none!important\}/);
  assert.match(popupHtml, /@media\s*\(prefers-reduced-motion:reduce\)\s*\{\s*\.slider,\s*\.slider:before\{transition:none\}\s*\}/);
});

test('browser sensitive-paste blocks wait for recorded evidence status', () => {
  assert.match(content, /const reportPromise = report\(/);
  assert.match(content, /safeClientPrompt\(pasted, verdict\.analysis\)/);
  assert.match(content, /'paste_flagged'/);
  assert.match(content, /updateEvidenceToast\(\s*reportPromise,\s*'paste_flagged'/);
  assert.match(content, /PromptWall blocked sensitive paste and recorded the decision/);
  assert.match(content, /PromptWall blocked sensitive paste\. Control-plane evidence was not recorded yet/);
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

test('manifest declares download permission for policy-controlled browser egress blocks', () => {
  assert.ok(manifest.permissions.includes('downloads'));
});

test('manifest loads WebExtension API bridge before content runtime', () => {
  const scripts = manifest.content_scripts.flatMap((entry) => entry.js || []);
  assert.ok(scripts.includes('lib/browser-api.js'));
  assert.ok(scripts.indexOf('lib/browser-api.js') < scripts.indexOf('content.js'));
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

test('browser platform metadata distinguishes Firefox manifest and Edge user agent', () => {
  const bg = loadBackground();
  assert.strictEqual(bg.context.self.__test.browserPlatform(manifest), 'chrome_mv3');
  assert.strictEqual(bg.context.self.__test.browserPlatform({
    ...manifest,
    browser_specific_settings: { gecko: { id: 'promptwall@example.com' } },
  }), 'firefox_mv3');
  bg.context.navigator = { userAgent: 'Mozilla/5.0 AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0' };
  assert.strictEqual(bg.context.self.__test.browserPlatform(manifest), 'edge_mv3');
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

test('background install health rejects server URLs with embedded credentials', async () => {
  const bg = loadBackground({
    managed: {
      serverUrl: 'https://user:pass@promptwall.customer.example',
      ingestKey: 'browser-ingest-key-0000000000000000000001',
      email: 'analyst@example.test',
      orgId: 'cu-acme',
    },
    fetch: async () => {
      throw new Error('fetch should not run with URL credentials');
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
