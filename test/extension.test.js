'use strict';
/** Static regression checks for MV3 extension wiring. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('node:crypto');

const root = path.join(__dirname, '..');
const extensionDir = path.join(root, 'sensors', 'browser-extension');
const content = fs.readFileSync(path.join(extensionDir, 'content.js'), 'utf8');
const contentCss = fs.readFileSync(path.join(extensionDir, 'content.css'), 'utf8');
const popupHtml = fs.readFileSync(path.join(extensionDir, 'popup.html'), 'utf8');
const popup = fs.readFileSync(path.join(extensionDir, 'popup.js'), 'utf8');
const background = fs.readFileSync(path.join(extensionDir, 'background.js'), 'utf8');
const policyVerifier = fs.readFileSync(path.join(extensionDir, 'lib', 'policy-bundle.js'), 'utf8');
const destinationCoverageSource = fs.readFileSync(path.join(extensionDir, 'lib', 'destination-coverage.js'), 'utf8');
const rehydrateHtml = fs.readFileSync(path.join(extensionDir, 'rehydrate.html'), 'utf8');
const rehydrateScript = fs.readFileSync(path.join(extensionDir, 'rehydrate.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(extensionDir, 'manifest.json'), 'utf8'));
const adapters = require('../detection-engine/adapters');
const { DEFAULT_POLICY } = require('../server/policy');
const { MANDATORY_ALWAYS_BLOCK } = require('../sensors/shared/decision');
const POLICY_KEYS = crypto.generateKeyPairSync('ed25519');
const POLICY_PUBLIC_KEY = POLICY_KEYS.publicKey.export({ type: 'spki', format: 'pem' }).toString();

function signedPolicyBundle(policy, options = {}) {
  const issuedAt = options.issuedAt || new Date().toISOString();
  const expiresAt = options.expiresAt || new Date(Date.parse(issuedAt) + 15 * 60 * 1000).toISOString();
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  const input = JSON.stringify({ version: 1, issuedAt, expiresAt, policyHash });
  return { version: 1, issuedAt, expiresAt, policy, signature: crypto.sign(null, Buffer.from(input), POLICY_KEYS.privateKey).toString('base64') };
}

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function loadBackground(opts = {}) {
  let onMessage;
  let onInstalled;
  let onStartup;
  let onAlarm;
  let onDownloadCreated;
  let onTabRemoved;
  const storage = { ...(opts.local || {}) };
  const managedStorage = { ...(opts.managed || {}) };
  if (storage.policy && !storage.policyBundle) {
    storage.policyBundle = signedPolicyBundle(storage.policy);
    managedStorage.policyPublicKey = managedStorage.policyPublicKey || POLICY_PUBLIC_KEY;
  }
  const createdAlarms = [];
  const canceledDownloads = [];
  const registeredScripts = (opts.registeredScripts || []).map((item) => ({ ...item }));
  let dynamicRules = (opts.dynamicRules || []).map((item) => ({ ...item }));
  const updatedTabs = [];
  const createdTabs = [];
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
        set: async (value) => {
          if (typeof opts.storageSet === 'function') {
            await opts.storageSet(value, {
              storage,
              registeredScripts,
              dynamicRules: () => dynamicRules.map((item) => ({ ...item })),
            });
          }
          Object.assign(storage, value);
        },
      },
      managed: { get: async () => ({ ...managedStorage }) },
    },
    runtime: {
      id: 'unit',
      onInstalled: { addListener(fn) { onInstalled = fn; } },
      onStartup: { addListener(fn) { onStartup = fn; } },
      onMessage: { addListener(fn) { onMessage = fn; } },
      getManifest: () => manifest,
      getURL: (value) => `chrome-extension://unit/${value}`,
      lastError: null,
    },
    permissions: {
      contains: async (request) => (typeof opts.permissionsContains === 'function'
        ? opts.permissionsContains(request)
        : opts.permissionsContains !== false),
      onAdded: { addListener() {} },
      onRemoved: { addListener() {} },
    },
    scripting: {
      getRegisteredContentScripts: async () => registeredScripts.map((item) => ({ ...item })),
      registerContentScripts: async (items) => { registeredScripts.push(...items.map((item) => ({ ...item }))); },
      updateContentScripts: async (items) => {
        for (const item of items) {
          const index = registeredScripts.findIndex((current) => current.id === item.id);
          if (index >= 0) registeredScripts[index] = { ...item };
        }
      },
      unregisterContentScripts: async ({ ids }) => {
        for (let i = registeredScripts.length - 1; i >= 0; i -= 1) {
          if (ids.includes(registeredScripts[i].id)) registeredScripts.splice(i, 1);
        }
      },
    },
    declarativeNetRequest: {
      getDynamicRules: async () => dynamicRules.map((item) => ({ ...item })),
      updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => {
        dynamicRules = dynamicRules.filter((item) => !removeRuleIds.includes(item.id));
        dynamicRules.push(...addRules.map((item) => ({ ...item })));
      },
    },
    alarms: { create(name, spec) { createdAlarms.push({ name, spec }); }, onAlarm: { addListener(fn) { onAlarm = fn; } } },
    downloads: {
      onCreated: { addListener(fn) { onDownloadCreated = fn; } },
      cancel(id, cb) {
        canceledDownloads.push(id);
        if (cb) cb();
      },
    },
    tabs: {
      onUpdated: { addListener() {} },
      onRemoved: { addListener(fn) { onTabRemoved = fn; } },
      query: async () => opts.tabs || [],
      update: async (id, value) => { updatedTabs.push({ id, value }); },
      create: async (value) => {
        const fallback = { id: 100 + createdTabs.length, ...value };
        const tab = typeof opts.tabsCreate === 'function' ? await opts.tabsCreate(value, fallback) : fallback;
        createdTabs.push(tab);
        return tab;
      },
      remove: async () => {},
    },
  };
  chrome.storage.onChanged = { addListener() {} };
  const context = {
    AbortController,
    TextEncoder,
    TextDecoder,
    URL,
    chrome,
    clearTimeout,
    console,
    crypto: crypto.webcrypto,
    atob: (value) => Buffer.from(value, 'base64').toString('binary'),
    fetch: opts.fetch || (async () => jsonResponse(200, {})),
    self: { PSAdapters: opts.adapters || adapters },
    setTimeout,
  };
  vm.runInNewContext(policyVerifier, context);
  vm.runInNewContext(destinationCoverageSource, context);
  vm.runInNewContext(background + '\nself.__test = { requestTimeoutMs, readBoundedJsonResponse, fetchJsonWithTimeout, failClosed, serverPermissionPattern, hasServerPermission, browserPlatform, buildHeartbeatBody, buildInstallChecks, reportInstallHealth, refreshPolicy, syncDestinationCoverage, syncCurrentDestinationCoverage, normalizeDestinationHost, downloadHostCandidates, downloadDestinationForPolicy, browserActionBlockRule, handleDownloadCreated, cleanupExpiredRehydrations };', context);
  return {
    context,
    createdAlarms,
    canceledDownloads,
    createdTabs,
    dynamicRules: () => dynamicRules.map((item) => ({ ...item })),
    registeredScripts,
    updatedTabs,
    runAlarm: (name) => onAlarm && onAlarm({ name }),
    runDownloadCreated: (item) => onDownloadCreated && onDownloadCreated(item),
    runTabRemoved: (tabId) => onTabRemoved && onTabRemoved(tabId),
    runInstalled: () => onInstalled && onInstalled(),
    runStartup: () => onStartup && onStartup(),
    storage,
    sendMessage: (msg, sender = {}) => new Promise((resolve) => onMessage(msg, sender, resolve)),
  };
}

test('redacted browser sends report tokenized text, not original prompt', () => {
  // The redact path reports the tokenized text through the recorded-confirmation
  // helper (fail closed: resend only after the control plane records the send).
  assert.match(content, /beginRedactedSend\(t,\s*verdict\.analysis,\s*el,\s*reservation\)/);
  assert.match(content, /type:\s*'rehydrationStore'/);
  assert.match(content, /report\(tokenText,\s*analysis,\s*'submit',\s*'redacted_sent',\s*'',\s*\{ clientPreRedacted: true \}\)/);
  assert.doesNotMatch(content, /report\(text,\s*verdict\.analysis,\s*'submit',\s*'redacted_sent'/);
  assert.match(content, /clientPreRedacted:\s*true/);
  assert.match(background, /clientFindings:\s*msg\.payload\.clientFindings/);
  assert.match(background, /clientCategories:\s*msg\.payload\.clientCategories \|\| msg\.payload\.categories/);
});

test('raw browser mappings are revealed once only to the exact extension tab', async () => {
  const h = loadBackground();
  const contentSender = {
    id: 'unit',
    frameId: 0,
    url: 'https://chat.openai.com/c/example',
    tab: { id: 7, url: 'https://chat.openai.com/c/example' },
  };
  const stored = await h.sendMessage({
    type: 'rehydrationStore',
    site: 'chat.openai.com',
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  }, contentSender);
  assert.strictEqual(stored.ok, true);
  assert.match(stored.channel, /^[a-f0-9]{32}$/);

  const otherProviderTab = await h.sendMessage({
    type: 'rehydrationOpen', channel: stored.channel, site: 'chat.openai.com',
  }, { ...contentSender, tab: { id: 8, url: contentSender.url } });
  assert.strictEqual(otherProviderTab.ok, false, 'another provider tab cannot claim the channel');

  const opened = await h.sendMessage({
    type: 'rehydrationOpen', channel: stored.channel, site: 'chat.openai.com',
  }, contentSender);
  assert.strictEqual(opened.ok, true);
  assert.strictEqual(h.createdTabs.length, 1);
  assert.match(h.createdTabs[0].url, /^chrome-extension:\/\/unit\/rehydrate\.html#channel=[a-f0-9]{32}$/);

  const wrongTab = await h.sendMessage({ type: 'rehydrationReveal', channel: stored.channel }, {
    id: 'unit', url: 'chrome-extension://unit/rehydrate.html', tab: { id: 999 },
  });
  assert.strictEqual(wrongTab.ok, false, 'another extension tab cannot consume the channel');
  const wrongHash = await h.sendMessage({ type: 'rehydrationReveal', channel: stored.channel }, {
    id: 'unit', url: 'chrome-extension://unit/rehydrate.html#channel=' + '0'.repeat(32), tab: { id: h.createdTabs[0].id },
  });
  assert.strictEqual(wrongHash.ok, false, 'the page URL channel must match the runtime channel');

  const revealed = await h.sendMessage({ type: 'rehydrationReveal', channel: stored.channel }, {
    id: 'unit', url: 'chrome-extension://unit/rehydrate.html', tab: { id: h.createdTabs[0].id },
  });
  assert.deepStrictEqual(JSON.parse(JSON.stringify(revealed)), {
    ok: true,
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  });

  const replay = await h.sendMessage({ type: 'rehydrationReveal', channel: stored.channel }, {
    id: 'unit', url: 'chrome-extension://unit/rehydrate.html', tab: { id: h.createdTabs[0].id },
  });
  assert.strictEqual(replay.ok, false, 'revealing consumes and clears the in-memory mapping');
});

test('rehydration broker rejects spoofed origins, frames, sites, and malformed mappings', async () => {
  const h = loadBackground();
  const message = {
    type: 'rehydrationStore',
    site: 'chat.openai.com',
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  };
  const valid = { id: 'unit', frameId: 0, url: 'https://chat.openai.com/c/example', tab: { id: 7 } };
  const attempts = [
    [{ ...valid, id: 'another-extension' }, message],
    [{ ...valid, frameId: 2 }, message],
    [{ ...valid, url: 'https://evil.example/c/example' }, message],
    [valid, { ...message, entries: [{ token: '__proto__', value: '412-22-7843' }] }],
    [valid, { ...message, entries: [{ token: '[[US_SSN_1]]', value: '' }] }],
    [valid, { ...message, entries: [1, 2, 3].map((index) => ({ token: `[[SECRET_KEY_${index}]]`, value: '界'.repeat(8192) })) }],
  ];
  for (const [sender, payload] of attempts) {
    const response = await h.sendMessage(payload, sender);
    assert.strictEqual(response.ok, false);
  }
  assert.strictEqual(h.createdTabs.length, 0);
  const unauthorizedDiscard = await h.sendMessage({
    type: 'rehydrationDiscard', channel: '0'.repeat(32), site: 'chat.openai.com',
  }, { ...valid, id: 'another-extension' });
  assert.strictEqual(unauthorizedDiscard.ok, false);
});

test('one rehydration channel cannot concurrently open multiple reveal tabs', async () => {
  let finishOpen;
  const h = loadBackground({
    tabsCreate: (_value, fallback) => new Promise((resolve) => { finishOpen = () => resolve(fallback); }),
  });
  const sender = { id: 'unit', frameId: 0, url: 'https://chat.openai.com/', tab: { id: 7 } };
  const stored = await h.sendMessage({
    type: 'rehydrationStore', site: 'chat.openai.com',
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  }, sender);
  const first = h.sendMessage({ type: 'rehydrationOpen', channel: stored.channel, site: 'chat.openai.com' }, sender);
  const duplicate = await h.sendMessage({ type: 'rehydrationOpen', channel: stored.channel, site: 'chat.openai.com' }, sender);
  assert.strictEqual(duplicate.ok, false);
  assert.strictEqual(duplicate.reason, 'already_open');
  finishOpen();
  assert.strictEqual((await first).ok, true);
  assert.strictEqual(h.createdTabs.length, 1);
});

test('closing the isolated reveal tab destroys its unrevealed mapping', async () => {
  const h = loadBackground();
  const sender = { id: 'unit', frameId: 0, url: 'https://chat.openai.com/', tab: { id: 7 } };
  const stored = await h.sendMessage({
    type: 'rehydrationStore', site: 'chat.openai.com',
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  }, sender);
  await h.sendMessage({ type: 'rehydrationOpen', channel: stored.channel, site: 'chat.openai.com' }, sender);
  h.runTabRemoved(h.createdTabs[0].id);
  const response = await h.sendMessage({ type: 'rehydrationReveal', channel: stored.channel }, {
    id: 'unit', url: 'chrome-extension://unit/rehydrate.html', tab: { id: h.createdTabs[0].id },
  });
  assert.strictEqual(response.ok, false);
});

test('expired rehydration mappings are destroyed before they can open', async () => {
  const h = loadBackground();
  const sender = { id: 'unit', frameId: 0, url: 'https://chat.openai.com/', tab: { id: 7 } };
  const stored = await h.sendMessage({
    type: 'rehydrationStore', site: 'chat.openai.com',
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  }, sender);
  h.context.self.__test.cleanupExpiredRehydrations(Number.MAX_SAFE_INTEGER);
  const response = await h.sendMessage({
    type: 'rehydrationOpen', channel: stored.channel, site: 'chat.openai.com',
  }, sender);
  assert.strictEqual(response.ok, false);
  assert.strictEqual(h.createdTabs.length, 0);
});

test('rehydration broker bounds memory and keeps only the newest mapping per source tab', async () => {
  const h = loadBackground();
  const message = {
    type: 'rehydrationStore',
    site: 'chat.openai.com',
    entries: [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  };
  const sender = { id: 'unit', frameId: 0, url: 'https://chat.openai.com/', tab: { id: 7 } };
  const first = await h.sendMessage(message, sender);
  const replacement = await h.sendMessage(message, sender);
  assert.strictEqual(first.ok, true);
  assert.strictEqual(replacement.ok, true);
  assert.strictEqual((await h.sendMessage({
    type: 'rehydrationOpen', channel: first.channel, site: 'chat.openai.com',
  }, sender)).ok, false, 'a newer mapping destroys stale raw values from the same source tab');

  for (let id = 100; id < 199; id += 1) {
    const stored = await h.sendMessage(message, { ...sender, tab: { id } });
    assert.strictEqual(stored.ok, true);
  }
  const overflow = await h.sendMessage(message, { ...sender, tab: { id: 999 } });
  assert.deepStrictEqual(JSON.parse(JSON.stringify(overflow)), { ok: false, reason: 'capacity' });
});

test('the reveal UI has no provider-page bridge and requires explicit reveal and copy actions', () => {
  assert.match(rehydrateHtml, /<script src="lib\/browser-api\.js"><\/script>/);
  assert.match(rehydrateHtml, /id="reveal"/);
  assert.match(rehydrateHtml, /id="copy"[^>]*disabled/);
  assert.match(rehydrateScript, /history\.replaceState\(null, '', location\.pathname\)/);
  assert.match(rehydrateScript, /if \(!event\.isTrusted/);
  assert.match(rehydrateScript, /rehydrationReveal/);
  assert.match(rehydrateScript, /navigator\.clipboard\.writeText/);
  assert.match(rehydrateScript, /document\.hidden/);
  assert.doesNotMatch(rehydrateScript, /postMessage|innerHTML|localStorage|sessionStorage/);
  assert.ok(!manifest.web_accessible_resources, 'the provider cannot embed or request the reveal page');
  assert.ok(manifest.permissions.includes('clipboardWrite'), 'explicit Copy works in managed Chromium and Firefox installs');
});

test('redact path resends only after the control plane records the redacted send (fail closed)', () => {
  assert.match(content, /async function proceedRedactedAfterRecorded/);
  assert.match(content, /recordedProceedResponse\(res,\s*'redacted_sent'\)/);
  // On an unrecorded response the function returns before bypassOnce/resend.
  assert.match(content, /Held until the control plane is reachable/);
});

test('redact mode blocks category-only hits that cannot be tokenized', () => {
  assert.match(content, /action:\s*\(a\.findings\.length && !a\.categories\.length\) \? 'redact' : 'block'/);
});

test('active content scripts receive policy updates from storage', () => {
  assert.match(content, /if \(c\.policy \|\| c\.policyBundle \|\| c\.policyExpiresAt\) refreshRuntimeConfig/);
  assert.match(content, /msg\.type !== 'getPolicyState'/);
  assert.match(content, /blockUnapprovedAiDestinations:\s*POLICY\.blockUnapprovedAiDestinations !== false/);
  assert.match(content, /const Ext = window\.PWBrowserApi/);
  assert.match(content, /Ext\.sendMessage\(\{ type: 'getConfig' \}\)/);
  assert.match(content, /Ext\.addStorageChangeListener/);
});

test('browser local analysis honors centralized detector policy', () => {
  assert.match(content, /function detectionPolicy\(\)/);
  assert.match(content, /ignore:\s*\(POLICY\.ignore \|\| \[\]\)\.filter/);
  assert.match(content, /disabledDetectors:\s*\(POLICY\.disabledDetectors \|\| \[\]\)\.filter/);
  assert.match(content, /exactMatch:\s*POLICY\.exactMatch/);
  assert.match(content, /D\.analyze\(text,\s*detectionPolicy\(\)\)/);
  assert.match(content, /const verdict = evaluate\(pasted\)/);
  assert.doesNotMatch(content, /const a = D\.analyze\(pasted\)/);
});

test('browser file uploads inspect locally and never send file bytes to the control plane', () => {
  assert.match(content, /function inspectTextUpload\(file, text, done = \(\) => \{\}\)/);
  assert.match(content, /D\.analyze\(text,\s*detectionPolicy\(\)\)/);
  assert.match(content, /reader\.readAsText\(f\)/);
  assert.match(content, /TEXT_UPLOAD_EXTENSIONS/);
  assert.match(content, /OCR_UPLOAD_EXTENSIONS/);
  assert.match(content, /const cleanUploadBypass = new WeakSet\(\)/);
  assert.match(content, /function textLooksReadable\(text\)/);
  assert.match(content, /if \(!textLooksReadable\(text\)\)/);
  assert.match(content, /function filesHaveCleanBypass\(files\)/);
  assert.match(content, /function consumeCleanUploadBypass\(files\)/);
  assert.match(content, /if \(destinationBlocked\(\)\)[\s\S]+if \(fileUploadBlocked\(\)\)[\s\S]+if \(filesHaveCleanBypass\(list\)\)/);
  assert.match(content, /if \(filesHaveCleanBypass\(list\)\) \{\s*consumeCleanUploadBypass\(list\);\s*return;/);
  assert.match(content, /stopFileEvent\(e\);\s*clearBlockedFileInput\(e\);\s*let remaining/);
  assert.match(content, /allClean && replayCleanFileEvent\(list, e\)/);
  assert.match(content, /const ext = fileExtension\(file && file\.name\)/);
  assert.match(content, /reportPromise\.then\(\(res\) => done\(recordedEvidenceResponse\(res, 'allowed'\)\)\)/);
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
  assert.match(content, /RedactWall blocked sends to/);
  assert.match(content, /RedactWall blocked file uploads to/);
  assert.match(content, /Recording evidence/);
  assert.match(content, /Control-plane evidence was not recorded yet/);
  assert.match(content, /function trackPolicyBlock\(report, status, message, batch = false\)/);
  assert.match(content, /const update = batch \? updateBatchEvidenceToast : updateEvidenceToast/);
  assert.match(content, /const reportPromise = reportBlockedDestination\('submit'\);[\s\S]+trackPolicyBlock\(reportPromise, 'destination_blocked'/);
  assert.match(content, /trackPolicyBlock\(reports, 'destination_blocked',[\s\S]+true\)/);
  assert.match(content, /trackPolicyBlock\(reports, 'file_upload_blocked',[\s\S]+true\)/);
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
  assert.match(content, /trackPolicyBlock\(reportBlockedBrowserAction\('copy', actionRule\), 'action_blocked'/);
  assert.match(content, /trackPolicyBlock\(reportBlockedBrowserAction\('drop', actionRule\), 'action_blocked'/);
  assert.match(content, /'\[browser action blocked\] ' \+ action \+ ' ' \+ SITE/);
  assert.match(content, /'action_blocked'/);
  assert.match(content, /RedactWall blocked paste into/);
  assert.match(content, /RedactWall blocked file drops into/);
  assert.match(content, /RedactWall blocked copy from/);
  assert.match(background, /chrome\.downloads\?\.onCreated\?\.addListener/);
  assert.match(background, /function downloadDestinationForPolicy\(item = \{\}, pol = \{\}\)/);
  assert.match(background, /chrome\.downloads\.cancel\(id/);
  assert.match(background, /prompt:\s*'\[browser action blocked\] download ' \+ host/);
  assert.match(background, /channel:\s*'download'/);
  assert.match(background, /clientOutcome:\s*'action_blocked'/);
  assert.match(background, /\.\.\.\(\(c\.policy && c\.policy\.blockedBrowserActions\) \|\| \[\]\)\.flatMap/);
  assert.match(background, /rule && rule\.enabled !== false && String\(rule\.action \|\| ''\)\.trim\(\)/);
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
  assert.strictEqual(sent[0].hostName, 'com.redactwall.file_intent');
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
      return jsonResponse(200, { id: 'q-download', status: 'action_blocked' });
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

test('data-sending paths fail closed on a cleartext-http remote plane', async () => {
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
    // A managed policy pointing the plane at cleartext http on a REMOTE host
    // would leak the ingest key on the wire; the guard must refuse to send.
    managed: { email: 'analyst@example.test', serverUrl: 'http://plane.vendor.example' },
    fetch: async (url, options) => {
      fetchCalls.push({ url, body: JSON.parse(options.body) });
      return jsonResponse(200, { id: 'q', status: 'action_blocked' });
    },
  });

  const result = await bg.context.self.__test.handleDownloadCreated({
    id: 7,
    referrer: 'https://chatgpt.com/c/x',
    url: 'https://files.example.test/x.pdf',
  });

  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, 'invalid_server_url');
  assert.strictEqual(fetchCalls.length, 0);
});

test('browser fallback hard-stops exactly match committed server defaults before policy sync', async () => {
  const bg = loadBackground();
  const config = await bg.sendMessage({ type: 'getConfig' });
  assert.deepStrictEqual(Array.from(config.policy.alwaysBlock), DEFAULT_POLICY.alwaysBlock);
  assert.deepStrictEqual(Array.from(MANDATORY_ALWAYS_BLOCK), DEFAULT_POLICY.alwaysBlock);
});

test('an explicit local policy pin is trusted only for a loopback control plane', async () => {
  const policy = { enforcementMode: 'warn', alwaysBlock: ['US_SSN'] };
  const policyBundle = signedPolicyBundle(policy);
  const local = {
    serverUrl: 'http://127.0.0.1:4210',
    policyPublicKey: POLICY_PUBLIC_KEY,
    policyBundle,
    policy,
  };
  const loopback = await loadBackground({ local }).sendMessage({ type: 'getConfig' });
  assert.strictEqual(loopback.policyTrusted, true);
  assert.strictEqual(loopback.policy.enforcementMode, 'warn');

  const remote = await loadBackground({
    local: { ...local, serverUrl: 'https://control.example.test' },
  }).sendMessage({ type: 'getConfig' });
  assert.strictEqual(remote.policyTrusted, false);
  assert.strictEqual(remote.policy.enforcementMode, 'block');
});

test('managed browser configuration cannot be disabled by a stale local pause', async () => {
  let gateCalls = 0;
  const managed = {
    serverUrl: 'https://redactwall.customer.example',
    ingestKey: 'managed-browser-ingest-key',
    orgId: 'cu-acme',
    email: 'analyst@example.test',
  };
  const bg = loadBackground({
    local: { enabled: false },
    managed,
    fetch: async () => {
      gateCalls += 1;
      return jsonResponse(200, { decision: 'allow', status: 'allowed' });
    },
  });

  const config = await bg.sendMessage({ type: 'getConfig' });
  assert.strictEqual(config.enabled, true);
  assert.strictEqual(config.enabledLocked, true);
  const verdict = await bg.sendMessage({
    type: 'report',
    payload: {
      prompt: 'Public branch-hours draft.',
      destination: 'chatgpt.com',
      channel: 'submit',
      source: 'browser_extension',
      outcome: 'allowed',
    },
  });
  assert.strictEqual(verdict.decision, 'allow');
  assert.strictEqual(gateCalls, 1, 'managed protection still reports despite local enabled=false');

  const adminPaused = loadBackground({ local: { enabled: true }, managed: { ...managed, enabled: false } });
  const adminConfig = await adminPaused.sendMessage({ type: 'getConfig' });
  assert.strictEqual(adminConfig.enabled, false, 'an administrator can explicitly pause managed protection');
  assert.strictEqual(adminConfig.enabledLocked, true);

  const unmanaged = loadBackground({ local: { enabled: false } });
  const unmanagedConfig = await unmanaged.sendMessage({ type: 'getConfig' });
  assert.strictEqual(unmanagedConfig.enabled, false, 'unmanaged demo installs retain the local pause control');
  assert.strictEqual(unmanagedConfig.enabledLocked, false);
});

test('background approval polling authenticates with the release token', async () => {
  const calls = [];
  const bg = loadBackground({
    local: { serverUrl: 'https://control.example.test', ingestKey: 'unit-ingest-key-000' },
    fetch: async (url, options) => {
      calls.push({ url, options });
      return jsonResponse(200, { id: 'q/held', status: 'approved', released: true });
    },
  });

  const response = await Promise.race([
    bg.sendMessage({ type: 'approvalStatus', id: 'q/held', releaseToken: 'release-token-unit' }),
    new Promise((resolve) => setTimeout(() => resolve(null), 50)),
  ]);
  assert.strictEqual(response.id, 'q/held');
  assert.strictEqual(response.status, 'approved');
  assert.strictEqual(response.released, true);
  assert.strictEqual(calls[0].url, 'https://control.example.test/api/v1/status/q%2Fheld');
  assert.strictEqual(calls[0].options.headers['x-api-key'], 'unit-ingest-key-000');
  assert.strictEqual(calls[0].options.headers['x-release-token'], 'release-token-unit');
});

test('background resolves a held justification in place with its release token', async () => {
  const calls = [];
  const bg = loadBackground({
    local: { serverUrl: 'https://control.example.test', ingestKey: 'unit-ingest-key-000' },
    fetch: async (url, options) => {
      calls.push({ url, options });
      const body = JSON.parse(options.body);
      return jsonResponse(200, {
        id: 'q/held',
        decision: body.outcome === 'justified' ? 'allow' : 'block',
        status: body.outcome,
      });
    },
  });

  const response = await bg.sendMessage({
    type: 'resolveJustification',
    id: 'q/held',
    releaseToken: 'release-token-unit',
    outcome: 'justified',
    note: 'Approved member-service workflow',
  });

  assert.strictEqual(response.id, 'q/held');
  assert.strictEqual(response.decision, 'allow');
  assert.strictEqual(response.status, 'justified');
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].url, 'https://control.example.test/api/v1/justify/q%2Fheld');
  assert.strictEqual(calls[0].options.method, 'POST');
  assert.strictEqual(calls[0].options.headers['x-api-key'], 'unit-ingest-key-000');
  assert.strictEqual(calls[0].options.headers['x-release-token'], 'release-token-unit');
  assert.deepStrictEqual(JSON.parse(calls[0].options.body), {
    outcome: 'justified', note: 'Approved member-service workflow',
  });

  const cancelled = await bg.sendMessage({
    type: 'resolveJustification',
    id: 'q/held',
    releaseToken: 'release-token-unit',
    outcome: 'blocked_by_user',
    note: '',
  });
  assert.strictEqual(cancelled.id, 'q/held');
  assert.strictEqual(cancelled.decision, 'block');
  assert.strictEqual(cancelled.status, 'blocked_by_user');
  assert.strictEqual(calls.length, 2);
  assert.deepStrictEqual(JSON.parse(calls[1].options.body), { outcome: 'blocked_by_user', note: '' });

  const invalid = await bg.sendMessage({
    type: 'resolveJustification', id: 'q/held', releaseToken: 'release-token-unit',
    outcome: 'justified', note: '   ',
  });
  assert.strictEqual(invalid.reason, 'invalid_justification_request');
  assert.strictEqual(calls.length, 2, 'invalid business reasons never reach the control plane');
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
    fetch: async () => jsonResponse(503, { error: 'offline' }),
  });
  await failed.context.self.__test.refreshPolicy();
  assert.deepStrictEqual(failed.storage.policy, cachedPolicy);

  const sequenceNow = Date.now();
  const cachedBundle = signedPolicyBundle(cachedPolicy, {
    issuedAt: new Date(sequenceNow - 60_000).toISOString(),
  });
  const refreshedBundle = signedPolicyBundle({
    enforcementMode: 'redact',
    governedDestinations: ['claude.ai'],
    alwaysBlock: ['SOURCE_CODE'],
  }, { issuedAt: new Date(sequenceNow).toISOString() });
  const refreshed = loadBackground({
    local: {
      serverUrl: 'https://control.example.test',
      ingestKey: 'unit-ingest-key-000',
      policy: cachedPolicy,
      policyBundle: cachedBundle,
    },
    managed: { policyPublicKey: POLICY_PUBLIC_KEY },
    fetch: async () => jsonResponse(200, refreshedBundle),
  });
  await refreshed.context.self.__test.refreshPolicy();
  assert.strictEqual(refreshed.storage.policy.enforcementMode, 'redact');
  assert.deepStrictEqual(Array.from(refreshed.storage.policy.governedDestinations), ['claude.ai']);
  assert.deepStrictEqual(Array.from(refreshed.storage.policy.blockedBrowserActions), []);
  assert.ok(Array.from(refreshed.storage.policy.alwaysBlock).includes('US_SSN'));
  assert.ok(Array.from(refreshed.storage.policy.alwaysBlock).includes('SOURCE_CODE'));
});

test('browser policy publication failure retains fail-closed coverage for the durable policy', async () => {
  const now = Date.now();
  const host = 'custom-ai.customer.example';
  const incomingHost = 'replacement-ai.customer.example';
  const origin = `https://*.${host}/*`;
  const previous = signedPolicyBundle({
    enforcementMode: 'block',
    governedDestinations: [host],
  }, { issuedAt: new Date(now - 60_000).toISOString() });
  const incoming = signedPolicyBundle({
    enforcementMode: 'warn',
    governedDestinations: [incomingHost],
  }, { issuedAt: new Date(now).toISOString() });
  const publicationSnapshots = [];
  const bg = loadBackground({
    local: {
      serverUrl: 'https://control.example.test',
      ingestKey: 'unit-ingest-key-000',
      policyBundle: previous,
      policy: previous.policy,
      policyExpiresAt: previous.expiresAt,
    },
    managed: { policyPublicKey: POLICY_PUBLIC_KEY },
    registeredScripts: [{
      id: 'redactwall-policy-destinations',
      matches: [origin],
      js: ['lib/detect.js', 'content.js'],
    }],
    storageSet: async (value, state) => {
      if (!value.policyBundle) return;
      publicationSnapshots.push({
        scripts: state.registeredScripts.map((item) => ({ ...item })),
        rules: state.dynamicRules(),
      });
      throw new Error('simulated policy cache publication failure');
    },
    fetch: async () => jsonResponse(200, incoming),
  });

  await bg.context.self.__test.refreshPolicy();

  assert.strictEqual(bg.storage.policyBundle.signature, previous.signature, 'failed publication retains the durable bundle');
  assert.strictEqual(bg.storage.policy.enforcementMode, 'block');
  assert.deepStrictEqual(Array.from(bg.storage.policy.governedDestinations), [host]);
  assert.strictEqual(publicationSnapshots.length, 1);
  const atPublication = publicationSnapshots[0];
  assert.ok(atPublication.scripts.some((script) => Array.from(script.matches || []).includes(origin)),
    'the durable runtime script is not relaxed before bundle publication',
  );
  assert.deepStrictEqual(
    new Set(atPublication.rules.flatMap((rule) => Array.from(rule.condition.requestDomains || []))),
    new Set([host, incomingHost]),
    'old and incoming destinations are both blocked at the publication boundary',
  );
  assert.ok(bg.registeredScripts.some((script) => Array.from(script.matches || []).includes(origin)),
    'failed publication retains the durable runtime script',
  );
  assert.deepStrictEqual(
    new Set(bg.dynamicRules().flatMap((rule) => Array.from(rule.condition.requestDomains || []))),
    new Set([host, incomingHost]),
    'failed publication retains the conservative union blocks',
  );
});

test('successful browser policy publication converges from old dynamic coverage', async () => {
  const now = Date.now();
  const host = 'custom-ai.customer.example';
  const origin = `https://*.${host}/*`;
  const previous = signedPolicyBundle({
    enforcementMode: 'block',
    governedDestinations: [host],
  }, { issuedAt: new Date(now - 60_000).toISOString() });
  const incoming = signedPolicyBundle({
    enforcementMode: 'warn',
    governedDestinations: [],
  }, { issuedAt: new Date(now).toISOString() });
  const bg = loadBackground({
    local: {
      serverUrl: 'https://control.example.test',
      ingestKey: 'unit-ingest-key-000',
      policyBundle: previous,
      policy: previous.policy,
      policyExpiresAt: previous.expiresAt,
    },
    managed: { policyPublicKey: POLICY_PUBLIC_KEY },
    registeredScripts: [{
      id: 'redactwall-policy-destinations',
      matches: [origin],
      js: ['lib/detect.js', 'content.js'],
    }],
    fetch: async () => jsonResponse(200, incoming),
  });

  await bg.context.self.__test.refreshPolicy();

  assert.strictEqual(bg.storage.policyBundle.signature, incoming.signature);
  assert.strictEqual(bg.storage.policy.enforcementMode, 'warn');
  assert.deepStrictEqual(Array.from(bg.storage.policy.governedDestinations), []);
  assert.strictEqual(bg.registeredScripts.length, 0, 'obsolete dynamic script coverage is removed after publication');
  assert.strictEqual(bg.dynamicRules().length, 0, 'temporary conservative blocks are removed after coverage converges');
});

test('browser policy refresh rejects an older signed replay across worker restart', async () => {
  const now = Date.now();
  const older = signedPolicyBundle({ enforcementMode: 'warn', alwaysBlock: ['US_SSN'] }, {
    issuedAt: new Date(now - (2 * 60 * 1000)).toISOString(),
  });
  const newer = signedPolicyBundle({ enforcementMode: 'block', alwaysBlock: ['US_SSN'] }, {
    issuedAt: new Date(now - (60 * 1000)).toISOString(),
  });
  const local = {
    serverUrl: 'https://control.example.test',
    ingestKey: 'unit-ingest-key-000',
    policyBundle: newer,
    policy: newer.policy,
    policyExpiresAt: newer.expiresAt,
  };
  const first = loadBackground({
    local,
    managed: { policyPublicKey: POLICY_PUBLIC_KEY },
    fetch: async () => jsonResponse(200, older),
  });
  await first.context.self.__test.refreshPolicy();
  assert.strictEqual(first.storage.policyBundle.signature, newer.signature);
  assert.strictEqual(first.storage.policy.enforcementMode, 'block');

  const restarted = loadBackground({
    local: { ...first.storage },
    managed: { policyPublicKey: POLICY_PUBLIC_KEY },
    fetch: async () => jsonResponse(200, older),
  });
  await restarted.context.self.__test.refreshPolicy();
  assert.strictEqual(restarted.storage.policyBundle.signature, newer.signature);
  assert.strictEqual(restarted.storage.policy.enforcementMode, 'block');
});

test('browser policy refresh refuses to reset high-water from an invalid existing cache', async () => {
  const now = Date.now();
  const original = signedPolicyBundle({ enforcementMode: 'block', alwaysBlock: ['US_SSN'] }, {
    issuedAt: new Date(now - (2 * 60 * 1000)).toISOString(),
  });
  const tampered = { ...original, policy: { enforcementMode: 'warn', alwaysBlock: [] } };
  const incoming = signedPolicyBundle({ enforcementMode: 'warn', alwaysBlock: ['US_SSN'] }, {
    issuedAt: new Date(now - (60 * 1000)).toISOString(),
  });
  const bg = loadBackground({
    local: {
      serverUrl: 'https://control.example.test',
      ingestKey: 'unit-ingest-key-000',
      policyBundle: tampered,
      policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'] },
      policyExpiresAt: original.expiresAt,
    },
    managed: { policyPublicKey: POLICY_PUBLIC_KEY },
    fetch: async () => jsonResponse(200, incoming),
  });

  await bg.context.self.__test.refreshPolicy();
  assert.strictEqual(bg.storage.policyBundle.signature, tampered.signature);
  assert.strictEqual(bg.storage.policy.enforcementMode, 'block');
  const config = await bg.sendMessage({ type: 'getConfig' });
  assert.strictEqual(config.policyTrusted, false);
  assert.strictEqual(config.policy.enforcementMode, 'block');
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
  assert.match(content, /\(reasonInput \|\| banner\)\.focus\(\{ preventScroll: true \}\)/);
  assert.match(content, /'<div class="ps-coach">' \+ escapeHtml\(coachingFor\(items\)\) \+ '<\/div>'/);
  assert.match(content, /RedactWall found sensitive data: ' \+ listForScreen/);
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
  assert.match(content, /RedactWall blocked sensitive paste and recorded the decision/);
  assert.match(content, /RedactWall blocked sensitive paste\. Control-plane evidence was not recorded yet/);
});

test('browser click interception uses shared send-button adapters', () => {
  assert.match(content, /function closestSendButton\(target\)/);
  assert.match(content, /A\.sendButtonSelectors\(location\.hostname\)/);
  assert.match(content, /button\[aria-label\*="Submit" i\]/);
});

test('manifest permits local control-plane URLs used by browser smoke tests', () => {
  assert.ok(manifest.host_permissions.includes('http://localhost/*'));
  assert.ok(manifest.host_permissions.includes('http://127.0.0.1/*'));
  assert.deepStrictEqual(manifest.optional_host_permissions, ['https://*/*']);
  assert.ok(!manifest.host_permissions.includes('https://*/*'), 'arbitrary HTTPS origins require an exact runtime grant');
});

test('custom governed destinations stay blocked until exact access is granted, then gain active interception', async () => {
  let granted = false;
  const customOrigin = 'https://*.custom-ai.customer.example/*';
  const bg = loadBackground({
    permissionsContains: ({ origins }) => origins[0] === customOrigin && granted,
    tabs: [{ id: 41, url: 'https://custom-ai.customer.example/chat' }],
  });
  const policy = { ...DEFAULT_POLICY, governedDestinations: ['custom-ai.customer.example'] };

  const missing = await bg.context.self.__test.syncDestinationCoverage(policy);
  assert.strictEqual(missing.ready, false);
  assert.deepStrictEqual(Array.from(missing.missingOrigins), [customOrigin]);
  assert.strictEqual(bg.registeredScripts.length, 0);
  assert.strictEqual(bg.dynamicRules().length, 1);
  assert.deepStrictEqual(Array.from(bg.dynamicRules()[0].condition.requestDomains), ['custom-ai.customer.example']);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(bg.updatedTabs)), [
    { id: 41, value: { url: 'chrome-extension://unit/coverage-required.html' } },
  ]);

  bg.updatedTabs.length = 0;
  granted = true;
  const ready = await bg.context.self.__test.syncDestinationCoverage(policy);
  assert.strictEqual(ready.ready, true);
  assert.deepStrictEqual(Array.from(ready.missingOrigins), []);
  assert.strictEqual(bg.dynamicRules().length, 0);
  assert.strictEqual(bg.registeredScripts.length, 1);
  assert.deepStrictEqual(Array.from(bg.registeredScripts[0].matches), [customOrigin]);
  assert.ok(Array.from(bg.registeredScripts[0].js).includes('content.js'));
  assert.ok(Array.from(bg.registeredScripts[0].js).includes('lib/detect.js'));
  assert.deepStrictEqual(JSON.parse(JSON.stringify(bg.updatedTabs)), [
    { id: 41, value: { url: 'chrome-extension://unit/coverage-required.html' } },
  ], 'a tab that was already open is ejected before its first dynamic registration');
});

test('invalid, credentialed, cleartext, and all-HTTPS destination policies fail closed', async () => {
  const bg = loadBackground({ permissionsContains: true });
  const state = await bg.context.self.__test.syncDestinationCoverage({
    governedDestinations: ['http://cleartext.example', 'https://user:pass@credentialed.example', 'not a host', '*'],
  });

  assert.strictEqual(state.ready, false);
  assert.deepStrictEqual(
    new Set(Array.from(state.unsupported)),
    new Set(['non_https_destination', 'credentialed_destination', 'invalid_destination', 'all_https']),
  );
  assert.strictEqual(bg.registeredScripts.length, 0);
  assert.strictEqual(bg.dynamicRules().length, 1);
  assert.ok(bg.dynamicRules().some((rule) => rule.condition.urlFilter === '|https://'));
});

test('remote control-plane access is exact-origin, user-granted, and fail-closed', async () => {
  const bg = loadBackground({
    managed: {
      serverUrl: 'https://redactwall.customer.example/path',
      ingestKey: 'remote-ingest-key-000000000000',
      email: 'analyst@example.test',
      orgId: 'cu-acme',
    },
    permissionsContains: false,
    fetch: async () => { throw new Error('fetch must not run without host access'); },
  });
  assert.strictEqual(bg.context.self.__test.serverPermissionPattern('https://redactwall.customer.example/path'), 'https://redactwall.customer.example/*');
  assert.strictEqual(bg.context.self.__test.serverPermissionPattern('http://remote.example'), null);
  assert.strictEqual(bg.context.self.__test.serverPermissionPattern('https://user:pass@remote.example'), null);

  const health = await bg.context.self.__test.reportInstallHealth();
  assert.strictEqual(health.ok, false);
  assert.strictEqual(health.reason, 'missing_host_permission');
  assert.ok(health.checks.some((item) => item.id === 'server_host_permission' && !item.ok));

  const gate = await bg.sendMessage({
    type: 'report',
    payload: { prompt: 'public text', destination: 'chatgpt.com', channel: 'submit', source: 'browser_extension', outcome: 'allowed' },
  });
  assert.strictEqual(gate.decision, 'block');
  assert.strictEqual(gate.reason, 'gate_missing_host_permission');
  assert.match(popup, /storageGet\('managed', \['serverUrl', 'orgId', 'email', 'user', 'enabled'\]\)/);
  assert.match(popup, /permissions\.request\(\{ origins: \[pattern\] \}\)/);
  assert.match(popupHtml, /id="grantServerAccess"/);
});

test('popup requests only the exact managed HTTPS control-plane origin', async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      checked: false, className: '', disabled: false, hidden: id === 'serverAccess', href: '', textContent: '',
      addEventListener(type, fn) { this['on' + type] = fn; },
    });
    return elements.get(id);
  };
  let requested;
  const storageWrites = [];
  const context = {
    URL,
    document: { getElementById: element },
    window: {
      PWBrowserApi: {
        api: {
          permissions: {
            contains: async () => false,
            request: (value) => { requested = value; return Promise.resolve(true); },
          },
        },
        storageGet: async (area) => (area === 'managed'
          ? { serverUrl: 'https://managed-control.example/path' }
          : { serverUrl: 'https://local-control.example', enabled: false, policy: { enforcementMode: 'block' } }),
        storageSet: async (area, value) => { storageWrites.push({ area, value }); },
      },
    },
  };
  vm.runInNewContext(popup, context);
  await new Promise((resolve) => setImmediate(() => setImmediate(resolve)));
  assert.strictEqual(element('serverAccess').hidden, false);
  assert.strictEqual(element('dash').href, 'https://managed-control.example/path/app/');
  assert.strictEqual(element('toggle').checked, true, 'managed configuration overrides a stale local pause');
  assert.strictEqual(element('toggle').disabled, true);
  element('toggle').checked = false;
  element('toggle').onchange();
  assert.deepStrictEqual(storageWrites, [], 'managed toggle cannot persist a local override');

  element('grantServerAccess').onclick();
  assert.deepStrictEqual(JSON.parse(JSON.stringify(requested)), { origins: ['https://managed-control.example/*'] });
  await new Promise((resolve) => setImmediate(() => setImmediate(resolve)));
  assert.strictEqual(element('serverAccess').hidden, true);
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

test('background control-plane JSON reads time out and reject unknown-length overflow', async () => {
  let cancelled = 0;
  const stalled = loadBackground({
    local: { serverUrl: 'http://localhost:4000', ingestKey: 'unit-ingest-key' },
    fetch: async () => new Response(new ReadableStream({
      cancel() { cancelled += 1; },
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  });
  const timedOut = await stalled.context.self.__test.fetchJsonWithTimeout(
    'http://localhost:4000/api/v1/policy',
    { headers: { 'x-api-key': 'unit-ingest-key' } },
    50,
  );
  assert.strictEqual(timedOut.ok, false);
  assert.strictEqual(timedOut.reason, 'timeout');
  assert.strictEqual(cancelled, 1);

  const oversized = loadBackground({
    local: { serverUrl: 'http://localhost:4000', ingestKey: 'unit-ingest-key' },
    fetch: async () => jsonResponse(200, { padding: 'x'.repeat(600 * 1024) }),
  });
  const tooLarge = await oversized.context.self.__test.fetchJsonWithTimeout(
    'http://localhost:4000/api/v1/policy',
    { headers: { 'x-api-key': 'unit-ingest-key' } },
    1000,
  );
  assert.strictEqual(tooLarge.ok, false);
  assert.strictEqual(tooLarge.reason, 'response_too_large');
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
      return jsonResponse(200, { decision: 'allow' });
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
    local: {
      policy: DEFAULT_POLICY,
    },
    managed: {
      serverUrl: 'https://redactwall.customer.example',
      ingestKey,
      email: 'analyst@example.test',
      orgId: 'cu-acme',
      policyPublicKey: POLICY_PUBLIC_KEY,
    },
    fetch: async (url, options) => {
      outbound = { url, headers: options.headers, body: JSON.parse(options.body), rawBody: options.body };
      return jsonResponse(200, { id: 'q_browser_heartbeat', decision: 'recorded', status: 'sensor_heartbeat', failedChecks: [] });
    },
  });

  const res = await bg.context.self.__test.reportInstallHealth();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(outbound.url, 'https://redactwall.customer.example/api/v1/heartbeat');
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
    browser_specific_settings: { gecko: { id: 'redactwall@example.com' } },
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
      return jsonResponse(200, { id: 'q_local_browser_heartbeat' });
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
    managed: { serverUrl: 'https://redactwall.customer.example', email: 'analyst@example.test', orgId: 'cu-acme' },
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
      serverUrl: 'https://user:pass@redactwall.customer.example',
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
    assert.ok(matches.includes(pattern), pattern);
  }
  for (const host of ['chat.deepseek.com', 'chat.qwen.ai', 'kimi.com', 'doubao.com', 'yuanbao.tencent.com']) {
    assert.strictEqual(adapters.isAiHost(host), true, host);
  }
});
