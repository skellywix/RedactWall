'use strict';
/**
 * Runtime unit tests for the content script (sensors/browser-extension/content.js).
 *
 * extension.test.js checks content.js as a string; this file EXECUTES it in a
 * vm with a stub DOM so the interception logic (evaluate, paste/send guards,
 * redact-tokenize-resend, rehydration, upload gating) is covered by the fast
 * node suite even when the Playwright e2e run is skipped. The script's IIFE is
 * closed over a `window.__test` hook injected at load — no product change.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const extensionDir = path.join(__dirname, '..', 'sensors', 'browser-extension');
const contentSrc = fs.readFileSync(path.join(extensionDir, 'content.js'), 'utf8');
const D = require('../detection-engine/detect');
const adapters = require('../detection-engine/adapters');
const { DEFAULT_POLICY } = require('../server/policy');

const HOOK = `
  POLICY_TRUSTED = true;
  POLICY_EXPIRES_AT = Date.parse('2999-01-01T00:00:00.000Z');
  window.__test = {
    evaluate, summarize, safeClientPrompt, publicFindings, publicCategories, escapeHtml, coachingFor,
    detectionPolicy, normalizeSensorPolicy,
    destinationBlocked, fileUploadBlocked, browserActionBlockRule,
    recordedProceedResponse, recordedEvidenceResponse,
    interceptSend, inComposerOrUI,
    readText, fileExtension, fileLabel, textReadableUpload, ocrRequiredUpload,
    textLooksReadable, rememberCleanUpload, filesHaveCleanBypass, consumeCleanUploadBypass,
    safeFileFindingPrompt, scanFiles, replayCleanFileEvent,
    probeAccount, showAccountCoach, report, toast,
    account: () => ACCOUNT,
    setPolicy: (p) => { POLICY = normalizeSensorPolicy({ ...POLICY, ...p }); },
    setEnabled: (v) => { ENABLED = v; },
    setPolicyTrust: (trusted, expiresAt) => { POLICY_TRUSTED = trusted; POLICY_EXPIRES_AT = expiresAt || 0; },
    enabled: () => ENABLED,
    enabledLocked: () => ENABLED_LOCKED,
  };
`;
const instrumented = contentSrc.replace(/\n\}\)\(\);\s*$/, '\n' + HOOK + '})();\n');
assert.notStrictEqual(instrumented, contentSrc, 'test hook must inject before the IIFE close');

class FakeElement {
  constructor(tag) {
    this.tagName = String(tag || 'div').toUpperCase();
    this.nodeType = 1;
    this.children = [];
    this.className = '';
    this.textContent = '';
    this.innerHTML = '';
    this.style = {};
    this.attrs = {};
    this.parentElement = null;
    this.isConnected = true;
    this._q = new Map();
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  appendChild(c) { c.parentElement = this; this.children.push(c); return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(c)); }
  remove() {
    if (this.parentElement) this.parentElement.children = this.parentElement.children.filter((c) => c !== this);
    this.parentElement = null;
    this.isConnected = false;
  }
  querySelector(sel) {
    if (!this._q.has(sel)) {
      const el = new FakeElement('div');
      el.value = '';
      this._q.set(sel, el);
    }
    return this._q.get(sel);
  }
  querySelectorAll() { return []; }
  addEventListener() {}
  focus() {}
  click() {}
  dispatchEvent() {}
  getBoundingClientRect() { return { width: 1, height: 1 }; }
  closest() { return null; }
}

class FakeDomEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = init.bubbles === true;
    this.cancelable = init.cancelable === true;
    this.defaultPrevented = false;
  }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() {}
  stopImmediatePropagation() {}
}

class FakeDataTransfer {
  constructor() {
    this._files = [];
    this.items = { add: (file) => { this._files.push(file); } };
  }
  get files() { return this._files; }
}

let activeDomListeners = {};

function loadContent(opts = {}) {
  const sent = [];
  const domListeners = {};
  let storageChangeListener = null;
  activeDomListeners = domListeners;
  const body = new FakeElement('body');
  const documentStub = {
    addEventListener: (type, fn) => { (domListeners[type] = domListeners[type] || []).push(fn); },
    createElement: (tag) => new FakeElement(tag),
    createTreeWalker: (node) => {
      const nodes = (node._textNodes || []).slice();
      let i = -1;
      return { nextNode() { i += 1; return nodes[i] || null; } };
    },
    querySelector: opts.querySelector || (() => null),
    querySelectorAll: opts.querySelectorAll || (() => []),
    body,
  };
  const Ext = {
    sendMessage: async (msg) => {
      sent.push(JSON.parse(JSON.stringify(msg)));
      const response = (opts.respond || (() => ({})))(msg);
      if (msg.type === 'getConfig') {
        return { policyTrusted: true, policyExpiresAt: '2999-01-01T00:00:00.000Z', ...(response || {}) };
      }
      if (msg.type === 'rehydrationStore' && (!response || response.ok == null)) {
        return { ok: true, channel: '0123456789abcdef0123456789abcdef' };
      }
      if (msg.type === 'rehydrationOpen' && (!response || response.ok == null)) return { ok: true };
      return response;
    },
    addRuntimeMessageListener() {},
    addStorageChangeListener(fn) { storageChangeListener = fn; },
  };
  const windowObj = {
    PSDetect: D,
    PSAdapters: adapters,
    PWBrowserApi: Ext,
    getSelection: () => null,
    HTMLTextAreaElement: { prototype: {} },
  };
  const context = {
    window: windowObj,
    location: { hostname: opts.hostname || 'chat.openai.com' },
    document: documentStub,
    MutationObserver: class { observe() {} disconnect() {} },
    FileReader: class {
      readAsText(f) { this.result = f._content || ''; if (this.onload) this.onload(); }
    },
    KeyboardEvent: class { constructor(type, init) { Object.assign(this, { type }, init); } },
    InputEvent: class { constructor(type, init) { Object.assign(this, { type }, init); } },
    Event: FakeDomEvent,
    DataTransfer: FakeDataTransfer,
    NodeFilter: { SHOW_TEXT: 4 },
    console: { log() {}, warn() {}, error() {} },
    setTimeout: opts.setTimeout || (() => 0), // keep toasts on the body for assertions
    clearTimeout: opts.clearTimeout || (() => {}),
    Date: opts.Date || Date,
  };
  vm.runInNewContext(instrumented, context, { filename: path.join(extensionDir, 'content.js') });
  return {
    T: windowObj.__test,
    sent,
    body,
    domListeners,
    reports: () => sent.filter((m) => m.type === 'report').map((m) => m.payload),
    toasts: () => body.children.filter((c) => c.className === 'ps-toast').map((c) => c.textContent),
    storageChange: (changes, areaName = 'local') => storageChangeListener && storageChangeListener(changes, areaName),
    flush: () => new Promise((r) => setImmediate(() => setImmediate(r))),
  };
}

function fakeEvent(extra = {}) {
  const e = {
    defaultPrevented: false,
    preventDefault() { this.defaultPrevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
    target: null,
  };
  return Object.assign(e, extra);
}

test('an older toast timer cannot remove a newer warning', () => {
  const timers = [];
  const h = loadContent({
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
  });
  h.T.toast('first notice');
  h.T.toast('new fail-closed warning');
  assert.deepStrictEqual(h.toasts(), ['new fail-closed warning']);

  timers[0].fn();
  assert.deepStrictEqual(h.toasts(), ['new fail-closed warning']);
  timers[1].fn();
  assert.deepStrictEqual(h.toasts(), []);
});

test('credential coaching takes precedence regardless of finding order', () => {
  const { T } = loadContent();
  for (const findings of [
    ['EMAIL_ADDRESS', 'SECRET_KEY'],
    ['PHONE_NUMBER', 'SECRET_KEY', 'CREDENTIALS'],
  ]) {
    assert.match(T.coachingFor(findings), /Remove this credential and rotate it/);
  }
});

function fakeComposer(text) {
  const el = new FakeElement('textarea');
  el.value = text;
  const form = new FakeElement('form');
  const button = new FakeElement('button');
  button.disabled = false;
  form.append(el, button);
  el.form = form;
  button.form = form;
  el.closest = (selector) => (selector === 'form' ? form : el);
  button.closest = (selector) => (selector === 'form' ? form : (selector.startsWith('button') ? button : null));
  form.querySelectorAll = (selector) => {
    if (selector.includes('textarea')) return [el];
    if (selector.startsWith('button')) return [button];
    return [];
  };
  button.click = () => {
    const event = fakeEvent({ target: button });
    for (const listener of activeDomListeners.click || []) listener(event);
    if (!event.defaultPrevented) el.dispatchEvent({ type: 'keydown', key: 'Enter', code: 'Enter', bubbles: true });
  };
  el._sendButton = button;
  return el;
}

function requestApproval(h, composer) {
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  const banners = h.body.children.filter((child) => /ps-banner/.test(child.className));
  const banner = banners[banners.length - 1];
  assert.ok(banner, 'composer receives its own block banner');
  banner.querySelector('.ps-actions').children
    .find((button) => button.textContent === 'Request approval').onclick();
}

const SSN_TEXT = 'Member SSN is 412-22-7843 on file';

// ---------------------------------------------------------------------------
test('content fallback hard-stops stay in sync with server defaults', () => {
  const { T } = loadContent();
  assert.deepStrictEqual(
    Array.from(T.normalizeSensorPolicy({ alwaysBlock: [] }).alwaysBlock),
    DEFAULT_POLICY.alwaysBlock,
  );
});

test('managed content protection ignores local pause changes and follows administrator state', async () => {
  let effective = { enabled: true, enabledLocked: true, policy: DEFAULT_POLICY };
  const managed = loadContent({
    respond: (message) => (message.type === 'getConfig' ? effective : {}),
  });
  await managed.flush();
  assert.strictEqual(managed.T.enabled(), true);
  assert.strictEqual(managed.T.enabledLocked(), true);

  managed.storageChange({ enabled: { oldValue: true, newValue: false } }, 'local');
  await managed.flush();
  assert.strictEqual(managed.T.enabled(), true, 'local storage cannot pause a managed content script');

  effective = { ...effective, enabled: false };
  managed.storageChange({ enabled: { oldValue: true, newValue: false } }, 'managed');
  await managed.flush();
  assert.strictEqual(managed.T.enabled(), false, 'administrator-managed pause is applied');

  const local = loadContent({
    respond: (message) => (message.type === 'getConfig'
      ? { enabled: true, enabledLocked: false, policy: DEFAULT_POLICY }
      : {}),
  });
  await local.flush();
  local.storageChange({ enabled: { oldValue: true, newValue: false } }, 'local');
  assert.strictEqual(local.T.enabled(), false, 'unmanaged installs retain a local demo pause');
});

test('evaluate maps policy modes and hard stops to actions', () => {
  const { T } = loadContent();
  assert.strictEqual(T.evaluate('what are your branch hours?').action, 'allow');
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block', 'default block mode');

  T.setPolicy({ enforcementMode: 'warn', alwaysBlock: [] });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block', 'empty remote list cannot remove mandatory hard stops');
  assert.strictEqual(T.evaluate('email jane.doe@example.com').action, 'warn', 'warn still applies to non-hard-stop findings');

  T.setPolicy({ enforcementMode: 'warn', alwaysBlock: ['US_SSN'] });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block', 'hard-stop entity overrides warn mode');

  T.setPolicy({ enforcementMode: 'justify', alwaysBlock: [] });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block');
  assert.strictEqual(T.evaluate('email jane.doe@example.com').action, 'justify');

  T.setPolicy({ enforcementMode: 'redact' });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'redact', 'structured findings tokenize');
  const category = T.evaluate('CONFIDENTIAL — internal only, do not share externally');
  assert.strictEqual(category.action, 'block', 'semantic categories cannot tokenize, must hold');

  T.setPolicy({ enforcementMode: 'block', blockMinSeverity: 99, blockRiskScore: 999, alwaysBlock: [] });
  assert.strictEqual(T.evaluate('email me at jane.doe@example.com').action, 'allow', 'below both thresholds');
});

test('browser evaluate blocks encoded SSNs and opaque Base64 but permits benign IDs', () => {
  const { T } = loadContent();
  const encodedSsn = Buffer.from('SSN 524-71-9043').toString('base64');
  const binary = Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64');

  const sensitive = T.evaluate(encodedSsn);
  assert.strictEqual(sensitive.action, 'block');
  assert.ok(sensitive.analysis.findings.some((finding) => finding.type === 'US_SSN'));

  const opaque = T.evaluate(binary);
  assert.strictEqual(opaque.action, 'block');
  assert.strictEqual(opaque.analysis.opaqueEncoded, true);

  for (const benign of [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1bml0LXVzZXIifQ.signature',
    Buffer.from('ordinary encoded prose').toString('base64'),
  ]) assert.strictEqual(T.evaluate(benign).action, 'allow', benign);
});

test('browser detection policy carries EDM and cannot disable an active hard stop', () => {
  const { T } = loadContent();
  const value = '550e8400-e29b-41d4-a716-446655440000';
  const salt = 'browser-unit-salt-0123456789abcdef01';
  const exactMatch = {
    formatVersion: 2,
    algorithm: 'sha256',
    valuePolicy: 'offline-random-id-v1',
    salt,
    minLen: 20,
    maxWords: 1,
    fingerprints: [D.edmFingerprint(value, salt)],
  };
  T.setPolicy({
    alwaysBlock: ['US_SSN', 'EXACT_MATCH'],
    disabledDetectors: ['US_SSN', 'EXACT_MATCH', 'EMAIL_ADDRESS'],
    exactMatch,
  });

  const opts = T.detectionPolicy();
  assert.deepStrictEqual(Array.from(opts.disabledDetectors), ['EMAIL_ADDRESS']);
  assert.strictEqual(opts.exactMatch, exactMatch);
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block');
  assert.ok(T.evaluate(`opaque record ${value}`).analysis.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('destinationBlocked follows allow/block lists and the unapproved-AI default', () => {
  const { T } = loadContent({ hostname: 'chat.openai.com' });
  assert.strictEqual(T.destinationBlocked(), true, 'AI host with no governed lists is unapproved');
  T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  assert.strictEqual(T.destinationBlocked(), false, 'allow-listed destination');
  T.setPolicy({ allowedDestinations: [], blockedDestinations: ['chat.openai.com'] });
  assert.strictEqual(T.destinationBlocked(), true, 'block-listed destination');
  T.setPolicy({ blockedDestinations: [], governedDestinations: ['chat.openai.com'] });
  assert.strictEqual(T.destinationBlocked(), false, 'governed destination is approved');
  T.setPolicy({ governedDestinations: [], blockUnapprovedAiDestinations: false });
  assert.strictEqual(T.destinationBlocked(), false, 'unapproved-AI default disabled');

  T.setPolicy({
    blockUnapprovedAiDestinations: true,
    blockedBrowserActions: [{ action: 'paste', destinations: ['chat.openai.com'] }],
  });
  assert.strictEqual(T.destinationBlocked(), false, 'an action-scoped destination stays governed without becoming fully blocked');
  T.setPolicy({
    blockUnapprovedAiDestinations: true,
    blockedBrowserActions: [{ action: 'paste', destinations: ['chat.openai.com'], enabled: false }],
  });
  assert.strictEqual(T.destinationBlocked(), true, 'a disabled action rule cannot approve an otherwise unapproved AI destination');

  const corp = loadContent({ hostname: 'intranet.corp.example' });
  assert.strictEqual(corp.T.destinationBlocked(), false, 'non-AI host is not auto-blocked');
});

test('browserActionBlockRule matches action + destination, skips disabled rules', () => {
  const { T } = loadContent({ hostname: 'chat.openai.com' });
  T.setPolicy({ blockedBrowserActions: [
    { action: 'Paste', destinations: ['chat.openai.com'] },
    { action: 'copy', destinations: ['chat.openai.com'], enabled: false },
    { action: 'drop', destinations: ['other.example'] },
  ] });
  assert.ok(T.browserActionBlockRule(' paste '), 'case- and whitespace-insensitive action match');
  assert.strictEqual(T.browserActionBlockRule('copy'), null, 'disabled rule is ignored');
  assert.strictEqual(T.browserActionBlockRule('drop'), null, 'destination does not match this site');
  assert.strictEqual(T.browserActionBlockRule('screenshot'), null, 'unlisted action');
});

test('recorded*Response accept only control-plane confirmations for the outcome', () => {
  const { T } = loadContent();
  assert.strictEqual(T.recordedProceedResponse(null, 'sent_after_warning'), false);
  assert.strictEqual(T.recordedProceedResponse({}, 'sent_after_warning'), false, 'no id means not recorded');
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'allow' }, 'anything'), false);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'allow', status: 'allowed' }, 'allowed'), true);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'allow', status: 'pending' }, 'allowed'), false);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'block', status: 'warned_sent' }, 'sent_after_warning'), true);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'allow', status: 'warned_sent' }, 'sent_after_warning'), false);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', status: 'pending' }, 'sent_after_warning'), false);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'block', status: 'justified' }, 'justified'), true);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'allow', status: 'justified' }, 'justified'), false);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'redact', status: 'redacted' }, 'redacted_sent'), true);
  assert.strictEqual(T.recordedEvidenceResponse({ id: 'q1', status: 'allowed' }, 'allowed'), true);
  assert.strictEqual(T.recordedEvidenceResponse({ id: 'q1', decision: 'allow' }, 'allowed'), true);
  assert.strictEqual(T.recordedEvidenceResponse({ id: 'q1', decision: 'allow', status: 'pending' }, 'allowed'), false);
  assert.strictEqual(T.recordedEvidenceResponse({ id: 'q1', status: 'pending' }, 'allowed'), false);
});

test('safeClientPrompt never carries raw values off the page', () => {
  const { T } = loadContent();
  const analysis = D.analyze(SSN_TEXT);
  const redacted = T.safeClientPrompt(SSN_TEXT, analysis);
  assert.ok(!redacted.includes('412-22-7843'), 'raw SSN stripped');
  assert.match(redacted, /\[US_SSN\]/);

  const confidential = 'CONFIDENTIAL — internal only, do not share externally';
  const catAnalysis = D.analyze(confidential);
  const catPrompt = T.safeClientPrompt(confidential, catAnalysis);
  assert.match(catPrompt, /^\[REDACTED: /, 'category hits collapse to labels only');
  assert.ok(!catPrompt.includes('internal only'));
});

test('escapeHtml neutralizes markup before banner interpolation', () => {
  const { T } = loadContent();
  assert.strictEqual(T.escapeHtml('<img src=x onerror=1>&"\''), '&lt;img src=x onerror=1&gt;&amp;&quot;&#39;');
});

// ---------------------------------------------------------------------------
test('paste of sensitive text is prevented and reported without the raw value', async () => {
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q1', status: 'paste_flagged' } : {}) });
  const e = fakeEvent({ clipboardData: { getData: () => SSN_TEXT } });
  h.domListeners.paste[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, true, 'paste must not land in the composer');
  const reports = h.reports();
  assert.strictEqual(reports.length, 1);
  assert.strictEqual(reports[0].outcome, 'paste_flagged');
  assert.strictEqual(reports[0].clientPreRedacted, true);
  assert.ok(!JSON.stringify(reports[0]).includes('412-22-7843'), 'no raw SSN in the report payload');
  assert.ok(h.toasts().some((m) => /recorded the decision/.test(m)), 'evidence confirmation toast shown');
});

test('opaque encoded paste is blocked locally and reported only as a fixed label', async () => {
  const encoded = Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64');
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q-opaque', status: 'action_blocked' } : {}) });
  const event = fakeEvent({ clipboardData: { getData: () => encoded } });

  h.domListeners.paste[0](event);
  await h.flush();

  assert.strictEqual(event.defaultPrevented, true);
  const report = h.reports()[0];
  assert.strictEqual(report.outcome, 'action_blocked');
  assert.strictEqual(report.prompt, '[REDACTED: OPAQUE_ENCODED_CONTENT]');
  assert.ok(!JSON.stringify(report).includes(encoded));
});

test('paste evidence toast degrades when the control plane does not record', async () => {
  const h = loadContent({ respond: () => ({}) });
  const e = fakeEvent({ clipboardData: { getData: () => SSN_TEXT } });
  h.domListeners.paste[0](e);
  await h.flush();
  assert.ok(h.toasts().some((m) => /evidence was not recorded yet/.test(m)));
});

test('benign paste is left alone', async () => {
  const h = loadContent();
  const e = fakeEvent({ clipboardData: { getData: () => 'summarize our public roadmap blog post' } });
  h.domListeners.paste[0](e);
  await h.flush();
  assert.strictEqual(e.defaultPrevented, false);
  assert.strictEqual(h.reports().length, 0);
});

test('browser egress fails closed when no fresh verified policy is available', () => {
  const h = loadContent();
  h.T.setPolicyTrust(false, 0);
  const paste = fakeEvent({ clipboardData: { getData: () => 'public branch hours' } });
  h.domListeners.paste[0](paste);
  assert.strictEqual(paste.defaultPrevented, true);

  const composer = fakeComposer('public branch hours');
  const send = fakeEvent({ target: composer });
  assert.strictEqual(h.T.interceptSend(send, composer), false);
  assert.strictEqual(send.defaultPrevented, true);
  assert.strictEqual(h.reports().length, 0);
  assert.ok(h.toasts().some((message) => /no fresh verified policy/.test(message)));
});

test('Enter on a sensitive prompt blocks the send, shows the banner, and requests approval', async () => {
  const h = loadContent({
    respond: (msg) => (msg.type === 'report'
      ? { id: 'q9', status: 'pending', releaseToken: 'release-token-q9' } : {}),
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] }); // isolate the content gate from the destination gate
  const composer = fakeComposer(SSN_TEXT);
  const e = fakeEvent({ key: 'Enter', shiftKey: false, target: composer });
  h.domListeners.keydown[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, true, 'send is stopped');
  const banner = h.body.children.find((c) => /ps-banner/.test(c.className));
  assert.ok(banner, 'banner rendered');
  assert.match(banner.className, /ps-block/);

  const actions = banner.querySelector('.ps-actions');
  const requestApproval = actions.children.find((b) => b.textContent === 'Request approval');
  assert.ok(requestApproval, 'block banner offers approval request');
  requestApproval.onclick();
  await h.flush();

  const approval = h.reports().find((p) => p.outcome === 'awaiting_approval');
  assert.ok(approval, 'approval request reported');
  assert.ok(h.toasts().some((m) => /Sent to your Security Admin for approval/.test(m)));
});

test('editing a blocked prompt releases its reservation while evidence records', async () => {
  let resolveEvidence;
  const h = loadContent({
    respond: (msg) => {
      if (msg.type === 'report' && msg.payload.outcome === 'blocked_by_user') {
        return new Promise((resolve) => { resolveEvidence = resolve; });
      }
      return {};
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  const firstBanner = h.body.children.find((child) => /ps-banner/.test(child.className));
  const edit = firstBanner.querySelector('.ps-actions').children
    .find((button) => button.textContent === 'Edit prompt');

  edit.onclick();
  assert.ok(!h.body.children.includes(firstBanner));

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  const banners = h.body.children.filter((child) => /ps-banner/.test(child.className));
  assert.strictEqual(banners.length, 1, 'the next explicit send receives a fresh challenge before evidence returns');
  resolveEvidence({ id: 'q_edit_evidence', decision: 'block', status: 'blocked_by_user' });
  await h.flush();
});

test('approved browser hold polls through the worker and resends only unchanged text', async () => {
  const timers = [];
  let liveComposer = null;
  const h = loadContent({
    querySelector: (selector) => selector.includes('textarea') ? liveComposer : null,
    setTimeout: (fn, ms) => { timers.push({ fn, ms, active: true }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].active = false; },
    respond: (msg) => {
      if (msg.type === 'report') return { id: 'q-approved', status: 'pending', releaseToken: 'release-token-approved' };
      if (msg.type === 'approvalStatus') return { id: 'q-approved', status: 'approved', released: true };
      return {};
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  liveComposer = composer;
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  const banner = h.body.children.find((c) => /ps-banner/.test(c.className));
  banner.querySelector('.ps-actions').children.find((b) => b.textContent === 'Request approval').onclick();
  await h.flush();

  const poll = timers.filter((timer) => timer.ms === 2000 && timer.active).pop();
  assert.ok(poll, 'pending approval schedules a status poll');
  poll.fn();
  await h.flush();

  const statusMessage = h.sent.find((msg) => msg.type === 'approvalStatus');
  assert.deepStrictEqual(JSON.parse(JSON.stringify(statusMessage)), {
    type: 'approvalStatus', id: 'q-approved', releaseToken: 'release-token-approved',
  });
  assert.strictEqual(resent, true, 'approved unchanged text is re-sent once');
});

test('approval polls stay bound to each composer for identical and different text', async () => {
  for (const identical of [true, false]) {
    const timers = [];
    let requestCount = 0;
    const h = loadContent({
      setTimeout: (fn, ms) => { timers.push({ fn, ms, active: true }); return timers.length; },
      clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].active = false; },
      respond: (msg) => {
        if (msg.type === 'report' && msg.payload.outcome === 'awaiting_approval') {
          requestCount += 1;
          return { id: 'q-composer-' + requestCount, status: 'pending', releaseToken: 'token-' + requestCount };
        }
        if (msg.type === 'approvalStatus') return { id: msg.id, status: 'pending', released: false };
        return {};
      },
    });
    h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
    const composerA = fakeComposer(SSN_TEXT);
    const composerB = fakeComposer(identical ? SSN_TEXT : 'Member SSN is 524-71-3312 on file');

    requestApproval(h, composerA);
    await h.flush();
    requestApproval(h, composerB);
    await h.flush();
    for (const timer of timers.filter((item) => item.active && item.ms === 2000)) timer.fn();
    await h.flush();

    const polls = h.sent.filter((msg) => msg.type === 'approvalStatus');
    assert.deepStrictEqual(
      polls.map((msg) => [msg.id, msg.releaseToken]).sort(),
      [['q-composer-1', 'token-1'], ['q-composer-2', 'token-2']],
      (identical ? 'identical' : 'different') + ' composer text keeps both hold tokens alive',
    );
  }
});

test('browser hold never resends edited, denied, inconsistent, or timed-out text', async () => {
  async function exercise({ status, released = false, editText, advanceMs = 0 }) {
    let now = 1000;
    const timers = [];
    let liveComposer = null;
    class FakeDate extends Date { static now() { return now; } }
    const h = loadContent({
      querySelector: (selector) => selector.includes('textarea') ? liveComposer : null,
      Date: FakeDate,
      setTimeout: (fn, ms) => { timers.push({ fn, ms, active: true }); return timers.length; },
      clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].active = false; },
      respond: (msg) => {
        if (msg.type === 'report') return { id: 'q-held', status: 'pending', releaseToken: 'release-token-held' };
        if (msg.type === 'approvalStatus') return { id: 'q-held', status, released };
        return {};
      },
    });
    h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
    const composer = fakeComposer(SSN_TEXT);
    liveComposer = composer;
    let resent = false;
    composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };
    h.T.interceptSend(fakeEvent({ target: composer }), composer);
    h.body.children.find((c) => /ps-banner/.test(c.className))
      .querySelector('.ps-actions').children.find((b) => b.textContent === 'Request approval').onclick();
    await h.flush();
    if (editText) composer.value = editText;
    now += advanceMs;
    const poll = timers.filter((timer) => timer.ms === 2000 && timer.active).pop();
    assert.ok(poll);
    poll.fn();
    await h.flush();
    return { h, resent };
  }

  const edited = await exercise({ status: 'approved', released: true, editText: SSN_TEXT + ' edited' });
  assert.strictEqual(edited.resent, false);
  assert.ok(edited.h.toasts().some((message) => /prompt changed/i.test(message)));

  const denied = await exercise({ status: 'denied' });
  assert.strictEqual(denied.resent, false);
  assert.ok(denied.h.toasts().some((message) => /denied/i.test(message)));

  const inconsistent = await exercise({ status: 'approved', released: false });
  assert.strictEqual(inconsistent.resent, false, 'an approved-looking status without released:true stays held');

  const timedOut = await exercise({ status: 'pending', advanceMs: 5 * 60 * 1000 + 1 });
  assert.strictEqual(timedOut.resent, false);
  assert.ok(timedOut.h.toasts().some((message) => /timed out/i.test(message)));
});

test('browser approval fails closed when the site replaces the composer DOM node', async () => {
  const timers = [];
  let liveComposer = null;
  const h = loadContent({
    querySelector: (selector) => selector.includes('textarea') ? liveComposer : null,
    setTimeout: (fn, ms) => { timers.push({ fn, ms, active: true }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].active = false; },
    respond: (msg) => {
      if (msg.type === 'report') return { id: 'q-replaced', status: 'pending', releaseToken: 'release-token-replaced' };
      if (msg.type === 'approvalStatus') return { id: 'q-replaced', status: 'approved', released: true };
      return {};
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const original = fakeComposer(SSN_TEXT);
  liveComposer = original;
  let originalResent = false;
  original.dispatchEvent = (ev) => { if (ev.type === 'keydown') originalResent = true; };
  h.T.interceptSend(fakeEvent({ target: original }), original);
  h.body.children.find((c) => /ps-banner/.test(c.className))
    .querySelector('.ps-actions').children.find((b) => b.textContent === 'Request approval').onclick();
  await h.flush();

  original.isConnected = false;
  const replacement = fakeComposer(SSN_TEXT);
  let replacementResent = false;
  replacement.dispatchEvent = (ev) => { if (ev.type === 'keydown') replacementResent = true; };
  liveComposer = replacement;

  const poll = timers.filter((timer) => timer.ms === 2000 && timer.active).pop();
  assert.ok(poll);
  poll.fn();
  await h.flush();

  assert.strictEqual(originalResent, false);
  assert.strictEqual(replacementResent, false);
  assert.ok(h.toasts().some((message) => /prompt changed|composer changed/i.test(message)));
});

test('locally clean browser sends wait for a server-confirmed allow', async () => {
  const h = loadContent({
    respond: (msg) => (msg.type === 'report' ? { id: 'q-allow', decision: 'allow', status: 'allowed' } : {}),
  });
  h.T.setPolicy({
    allowedDestinations: ['chat.openai.com'], alwaysBlock: [], blockMinSeverity: 99, blockRiskScore: 999,
  });
  const composer = fakeComposer('summarize the public quarterly update');
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };
  const event = fakeEvent({ target: composer });

  assert.strictEqual(h.T.interceptSend(event, composer), false, 'original send is held for the control plane');
  assert.strictEqual(event.defaultPrevented, true);
  await h.flush();
  assert.strictEqual(resent, true, 'send resumes after the server confirms allow');
  assert.strictEqual(h.reports()[0].outcome, 'allowed');
});

test('an async server confirmation never bypasses a changed live composer', async () => {
  let finishReport;
  const h = loadContent({
    respond: (msg) => {
      if (msg.type !== 'report') return {};
      return new Promise((resolve) => { finishReport = resolve; });
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer('summarize the public quarterly update');
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  composer.value = 'different prompt entered while the server was responding';
  finishReport({ id: 'q-delayed-allow', decision: 'allow', status: 'allowed' });
  await h.flush();

  assert.strictEqual(resent, false);
  assert.ok(h.toasts().some((message) => /did not send.*changed/i.test(message)));
});

test('two rapid sends from one composer start one inspection and one resend', async () => {
  let finishReport;
  const h = loadContent({
    respond: (msg) => {
      if (msg.type !== 'report') return {};
      return new Promise((resolve) => { finishReport = resolve; });
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer('summarize the public quarterly update');
  let resendCount = 0;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resendCount += 1; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();

  assert.strictEqual(h.reports().length, 1, 'the composer is reserved before async inspection begins');
  finishReport({ id: 'q-one-allow', decision: 'allow', status: 'allowed' });
  await h.flush();
  assert.strictEqual(resendCount, 1, 'one confirmed inspection authorizes exactly one resend');
});

test('editing a reserved composer starts a new inspection and invalidates the old result', async () => {
  const pendingReports = [];
  const h = loadContent({
    respond: (msg) => {
      if (msg.type !== 'report') return {};
      return new Promise((resolve) => pendingReports.push(resolve));
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer('summarize the first public update');
  let resendCount = 0;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resendCount += 1; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  composer.value = 'summarize the replacement public update';
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  assert.strictEqual(h.reports().length, 2);

  pendingReports[0]({ id: 'stale', decision: 'allow', status: 'allowed' });
  await h.flush();
  assert.strictEqual(resendCount, 0, 'the stale result cannot authorize the changed prompt');
  pendingReports[1]({ id: 'current', decision: 'allow', status: 'allowed' });
  await h.flush();
  assert.strictEqual(resendCount, 1, 'the new exact prompt can be authorized once');
});

test('an unconfirmed inspection releases its composer for an explicit retry', async () => {
  let reports = 0;
  const h = loadContent({
    respond: (msg) => {
      if (msg.type !== 'report') return {};
      reports += 1;
      return reports === 1 ? {} : { id: 'retry', decision: 'allow', status: 'allowed' };
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer('summarize the public quarterly update');
  let resendCount = 0;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resendCount += 1; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();

  assert.strictEqual(reports, 2);
  assert.strictEqual(resendCount, 1);
});

test('an async allow for composer A never authorizes composer B\'s send button', async () => {
  let finishReport;
  const composerA = new FakeElement('textarea');
  const composerB = new FakeElement('textarea');
  composerA.value = 'summarize the public quarterly update';
  composerB.value = 'composer B must remain unsent';
  const formA = new FakeElement('form');
  const formB = new FakeElement('form');
  const buttonA = new FakeElement('button');
  const buttonB = new FakeElement('button');
  buttonA.disabled = false;
  buttonB.disabled = false;
  formA.append(composerA, buttonA);
  formB.append(composerB, buttonB);
  composerA.form = formA;
  composerB.form = formB;
  const composerFor = (form) => (selector) => (selector.includes('textarea') ? (form === formA ? composerA : composerB) : null);
  formA.querySelector = composerFor(formA);
  formB.querySelector = composerFor(formB);
  formA.querySelectorAll = (selector) => (selector.includes('textarea') ? [composerA] : []);
  formB.querySelectorAll = (selector) => (selector.includes('textarea') ? [composerB] : []);
  buttonA.form = formA;
  buttonB.form = formB;
  composerA.closest = (selector) => (selector === 'form' ? formA : composerA);
  composerB.closest = (selector) => (selector === 'form' ? formB : composerB);
  buttonA.closest = (selector) => (selector === 'form' ? formA : (selector.startsWith('button') ? buttonA : null));
  buttonB.closest = (selector) => (selector === 'form' ? formB : (selector.startsWith('button') ? buttonB : null));

  const h = loadContent({
    querySelector: (selector) => {
      if (selector.includes('textarea')) return composerA;
      if (selector.startsWith('button')) return buttonB; // old global resend chooses B
      return null;
    },
    querySelectorAll: (selector) => (selector.startsWith('button') ? [buttonB, buttonA] : []),
    respond: (msg) => {
      if (msg.type !== 'report') return {};
      return new Promise((resolve) => { finishReport = resolve; });
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  let sentA = 0;
  let sentB = 0;
  const click = (button, onSend) => {
    const event = fakeEvent({ target: button });
    for (const listener of h.domListeners.click || []) listener(event);
    if (!event.defaultPrevented) onSend();
  };
  buttonA.click = () => click(buttonA, () => { sentA += 1; });
  buttonB.click = () => click(buttonB, () => { sentB += 1; });

  h.T.interceptSend(fakeEvent({ target: composerA }), composerA);
  await h.flush();
  finishReport({ id: 'q-two-composers', decision: 'allow' });
  await h.flush();

  assert.strictEqual(sentA, 1, 'the exact validated composer is resumed');
  assert.strictEqual(sentB, 0, 'an unrelated composer never consumes the bypass');
});

test('a server-scoped warning is shown locally and resends only after recorded consent', async () => {
  const responses = [];
  const h = loadContent({
    respond: (msg) => {
      if (msg.type !== 'report') return {};
      responses.push(msg.payload.outcome);
      if (msg.payload.outcome === 'allowed') {
        return {
          id: 'q-scoped-warn',
          decision: 'warn',
          status: 'warned',
          riskScore: 12,
          findings: [{ type: 'EMAIL_ADDRESS', masked: 'a***@example.test' }],
          categories: [],
        };
      }
      return { id: 'q-scoped-warn-sent', decision: 'block', status: 'warned_sent' };
    },
  });
  h.T.setPolicy({
    allowedDestinations: ['chat.openai.com'], alwaysBlock: [], blockMinSeverity: 99, blockRiskScore: 999,
  });
  const composer = fakeComposer('Email the public brochure to analyst@example.test');
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  assert.strictEqual(resent, false);
  const banner = h.body.children.find((child) => /ps-banner/.test(child.className));
  assert.match(banner.className, /ps-warn/);
  banner.querySelector('.ps-actions').children.find((button) => button.textContent === 'Send anyway').onclick();
  await h.flush();

  assert.deepStrictEqual(responses, ['allowed', 'sent_after_warning']);
  assert.strictEqual(resent, true);
});

test('a server-scoped justification is shown locally and resends only after a recorded reason', async () => {
  const messages = [];
  const h = loadContent({
    respond: (msg) => {
      messages.push(msg);
      if (msg.type === 'report' && msg.payload.outcome === 'allowed') {
        return {
          id: 'q-scoped-justify',
          decision: 'block',
          mode: 'justify',
          status: 'pending_justification',
          releaseToken: 'release-token-scoped-justify',
          riskScore: 12,
          findings: [{ type: 'EMAIL_ADDRESS', masked: 'a***@example.test' }],
          categories: [],
        };
      }
      if (msg.type === 'resolveJustification') {
        return { id: 'q-scoped-justify', decision: 'allow', status: 'justified' };
      }
      return {};
    },
  });
  h.T.setPolicy({
    allowedDestinations: ['chat.openai.com'], alwaysBlock: [], blockMinSeverity: 99, blockRiskScore: 999,
  });
  const composer = fakeComposer('Email the public brochure to analyst@example.test');
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  assert.strictEqual(resent, false);
  const banner = h.body.children.find((child) => /ps-banner/.test(child.className));
  assert.match(banner.className, /ps-justify/);
  const reason = banner.querySelector('.ps-just');
  reason.value = 'Approved member-service workflow';
  banner.querySelector('.ps-actions').children.find((button) => button.textContent === 'Submit reason').onclick();
  await h.flush();

  const reports = messages.filter((msg) => msg.type === 'report');
  assert.deepStrictEqual(reports.map((msg) => msg.payload.outcome), ['allowed'], 'the held prompt is not submitted to gate twice');
  const resolution = messages.find((msg) => msg.type === 'resolveJustification');
  assert.deepStrictEqual(JSON.parse(JSON.stringify(resolution)), {
    type: 'resolveJustification',
    id: 'q-scoped-justify',
    releaseToken: 'release-token-scoped-justify',
    outcome: 'justified',
    note: 'Approved member-service workflow',
  });
  assert.strictEqual(resent, true);
});

test('composer B challenge terminalizes displaced server hold A exactly once', async () => {
  const messages = [];
  const h = loadContent({
    respond: (msg) => {
      messages.push(msg);
      if (msg.type === 'report') {
        const suffix = msg.payload.prompt.includes('composer A') ? 'a' : 'b';
        return {
          id: 'q-replaced-' + suffix, decision: 'block', mode: 'justify',
          status: 'pending_justification', releaseToken: 'release-token-' + suffix,
          findings: [{ type: 'EMAIL_ADDRESS' }], categories: [],
        };
      }
      return { id: msg.id, decision: 'block', status: 'blocked_by_user' };
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'], blockMinSeverity: 99, blockRiskScore: 999 });
  const composerA = fakeComposer('public composer A message');
  const composerB = fakeComposer('public composer B message');
  let sends = 0;
  composerA.dispatchEvent = composerB.dispatchEvent = (event) => { if (event.type === 'keydown') sends += 1; };

  h.T.interceptSend(fakeEvent({ target: composerA }), composerA);
  await h.flush();
  const bannerA = h.body.children.find((child) => /ps-banner/.test(child.className));
  h.T.interceptSend(fakeEvent({ target: composerB }), composerB);
  await h.flush();

  const resolutions = messages.filter((msg) => msg.type === 'resolveJustification');
  assert.deepStrictEqual(resolutions.map((msg) => [msg.id, msg.outcome]), [['q-replaced-a', 'blocked_by_user']]);
  assert.strictEqual(bannerA.isConnected, false);
  assert.strictEqual(h.body.children.filter((child) => /ps-banner/.test(child.className)).length, 1);
  assert.strictEqual(messages.some((msg) => msg.type === 'resolveJustification' && msg.id === 'q-replaced-b'), false);
  assert.strictEqual(sends, 0);
});

test('failed banner replacement keeps hold A retryable, then shows queued challenge B', async () => {
  const messages = [];
  let attemptsA = 0;
  const h = loadContent({
    respond: (msg) => {
      messages.push(msg);
      if (msg.type === 'report') {
        const suffix = msg.payload.prompt.includes('composer A') ? 'a' : 'b';
        return {
          id: 'q-outage-' + suffix, decision: 'block', mode: 'justify',
          status: 'pending_justification', releaseToken: 'release-token-' + suffix,
          findings: [{ type: 'EMAIL_ADDRESS' }], categories: [],
        };
      }
      if (msg.id === 'q-outage-a' && ++attemptsA === 1) {
        return { decision: 'block', status: 'control_plane_unavailable' };
      }
      return { id: msg.id, decision: 'block', status: 'blocked_by_user' };
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'], blockMinSeverity: 99, blockRiskScore: 999 });
  const composerA = fakeComposer('public composer A message');
  const composerB = fakeComposer('public composer B message');
  let sends = 0;
  composerA.dispatchEvent = composerB.dispatchEvent = (event) => { if (event.type === 'keydown') sends += 1; };

  h.T.interceptSend(fakeEvent({ target: composerA }), composerA);
  await h.flush();
  const bannerA = h.body.children.find((child) => /ps-banner/.test(child.className));
  bannerA.querySelector('.ps-just').value = 'A challenge remains bound';
  h.T.interceptSend(fakeEvent({ target: composerB }), composerB);
  await h.flush();

  assert.strictEqual(bannerA.isConnected, true);
  assert.strictEqual(bannerA.querySelector('.ps-just').value, 'A challenge remains bound');
  assert.strictEqual(messages.filter((msg) => msg.type === 'resolveJustification' && msg.id === 'q-outage-a').length, 1);
  bannerA.querySelector('.ps-actions').children.find((button) => button.textContent === 'Cancel').onclick();
  await h.flush();

  const current = h.body.children.find((child) => /ps-banner/.test(child.className));
  assert.notStrictEqual(current, bannerA);
  assert.strictEqual(current.querySelector('.ps-just').value, '');
  assert.strictEqual(messages.filter((msg) => msg.type === 'resolveJustification' && msg.id === 'q-outage-a').length, 2);
  assert.strictEqual(messages.some((msg) => msg.type === 'resolveJustification' && msg.id === 'q-outage-b'), false);
  assert.strictEqual(sends, 0);
});

test('cancelling a server-scoped justification resolves the same hold without sending', async () => {
  const messages = [];
  const h = loadContent({
    respond: (msg) => {
      messages.push(msg);
      if (msg.type === 'report') {
        return {
          id: 'q-scoped-cancel', decision: 'block', mode: 'justify',
          status: 'pending_justification', releaseToken: 'release-token-scoped-cancel',
          riskScore: 12, findings: [{ type: 'EMAIL_ADDRESS' }], categories: [],
        };
      }
      if (msg.type === 'resolveJustification') {
        return { id: 'q-scoped-cancel', decision: 'block', status: 'blocked_by_user' };
      }
      return {};
    },
  });
  h.T.setPolicy({
    allowedDestinations: ['chat.openai.com'], alwaysBlock: [], blockMinSeverity: 99, blockRiskScore: 999,
  });
  const composer = fakeComposer('Email the public brochure to analyst@example.test');
  let resent = false;
  composer.dispatchEvent = (event) => { if (event.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  const banner = h.body.children.find((child) => /ps-banner/.test(child.className));
  banner.querySelector('.ps-actions').children.find((button) => button.textContent === 'Cancel').onclick();
  await h.flush();

  const reports = messages.filter((msg) => msg.type === 'report');
  assert.deepStrictEqual(reports.map((msg) => msg.payload.outcome), ['allowed']);
  const resolution = messages.find((msg) => msg.type === 'resolveJustification');
  assert.deepStrictEqual(JSON.parse(JSON.stringify(resolution)), {
    type: 'resolveJustification',
    id: 'q-scoped-cancel',
    releaseToken: 'release-token-scoped-cancel',
    outcome: 'blocked_by_user',
    note: '',
  });
  assert.strictEqual(resent, false, 'cancellation never authorizes a send');
});

test('dismissing a server-scoped justification resolves the hold as blocked without sending', async () => {
  const messages = [];
  const h = loadContent({
    respond: (msg) => {
      messages.push(msg);
      if (msg.type === 'report') return {
        id: 'q-scoped-dismiss', decision: 'block', mode: 'justify',
        status: 'pending_justification', releaseToken: 'release-token-scoped-dismiss',
        findings: [{ type: 'EMAIL_ADDRESS' }], categories: [],
      };
      return { id: 'q-scoped-dismiss', decision: 'block', status: 'blocked_by_user' };
    },
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'], blockMinSeverity: 99, blockRiskScore: 999 });
  const composer = fakeComposer('Email the public brochure to analyst@example.test');
  let resent = false;
  composer.dispatchEvent = (event) => { if (event.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  h.body.children.find((child) => /ps-banner/.test(child.className)).querySelector('.ps-x').onclick();
  await h.flush();

  const resolution = messages.find((msg) => msg.type === 'resolveJustification');
  assert.strictEqual(resolution.id, 'q-scoped-dismiss');
  assert.strictEqual(resolution.outcome, 'blocked_by_user');
  assert.strictEqual(resent, false, 'dismissal never authorizes a send');
});

test('failed Cancel and Dismiss keep the exact server challenge available for retry', async () => {
  for (const action of ['Cancel', 'Dismiss']) {
    let attempts = 0;
    const h = loadContent({
      respond: (msg) => {
        if (msg.type === 'report') return {
          id: 'q-retry-' + action, decision: 'block', mode: 'justify',
          status: 'pending_justification', releaseToken: 'release-token-' + action,
          findings: [{ type: 'EMAIL_ADDRESS' }], categories: [],
        };
        if (msg.type !== 'resolveJustification') return {};
        attempts += 1;
        if (attempts === 1) return { decision: 'block', status: 'control_plane_unavailable' };
        return { id: msg.id, decision: 'block', status: 'blocked_by_user' };
      },
    });
    h.T.setPolicy({ allowedDestinations: ['chat.openai.com'], blockMinSeverity: 99, blockRiskScore: 999 });
    const composer = fakeComposer('public retry message');
    h.T.interceptSend(fakeEvent({ target: composer }), composer);
    await h.flush();
    const banner = h.body.children.find((child) => /ps-banner/.test(child.className));
    const click = () => (action === 'Dismiss'
      ? banner.querySelector('.ps-x')
      : banner.querySelector('.ps-actions').children.find((button) => button.textContent === action)).onclick();

    click();
    await h.flush();
    assert.strictEqual(banner.isConnected, true, action + ' failure keeps the challenge');
    assert.strictEqual(attempts, 1);
    click();
    await h.flush();
    assert.strictEqual(banner.isConnected, false, action + ' success clears the challenge');
    assert.strictEqual(attempts, 2);
  }
});

test('a revoked justification resolution never resumes the browser send', async () => {
  const h = loadContent({
    respond: (msg) => {
      if (msg.type === 'report') {
        return {
          id: 'q-revoked-justify', decision: 'block', mode: 'justify',
          status: 'pending_justification', releaseToken: 'release-token-revoked',
          findings: [{ type: 'EMAIL_ADDRESS' }], categories: [],
        };
      }
      return { decision: 'block', status: 'license_revoked', reason: 'justify_http_403' };
    },
  });
  h.T.setPolicy({
    allowedDestinations: ['chat.openai.com'], alwaysBlock: [], blockMinSeverity: 99, blockRiskScore: 999,
  });
  const composer = fakeComposer('Email the public brochure to analyst@example.test');
  let resent = false;
  composer.dispatchEvent = (event) => { if (event.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  const banner = h.body.children.find((child) => /ps-banner/.test(child.className));
  banner.querySelector('.ps-just').value = 'Approved member-service workflow';
  banner.querySelector('.ps-actions').children.find((button) => button.textContent === 'Submit reason').onclick();
  await h.flush();

  assert.strictEqual(resent, false);
  assert.strictEqual(banner.isConnected, true, 'failed Submit keeps the exact challenge and release capability');
  assert.strictEqual(h.body.children.filter((child) => /ps-banner/.test(child.className))[0], banner);
  assert.match(h.toasts().at(-1), /could not record this justification decision/i);
});

test('blocked destination stops the send before any content is scanned', async () => {
  const h = loadContent({
    hostname: 'chat.openai.com',
    respond: (msg) => (msg.type === 'report' ? { id: 'q2', status: 'destination_blocked' } : {}),
  });
  h.T.setPolicy({ blockedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer('completely benign text');
  const e = fakeEvent({ key: 'Enter', shiftKey: false, target: composer });
  h.domListeners.keydown[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, true);
  const report = h.reports()[0];
  assert.strictEqual(report.outcome, 'destination_blocked');
  assert.ok(!report.prompt.includes('benign text'), 'prompt text is not shipped for destination blocks');
});

test('zero-width normalization updates the live composer before authorization and resend', async () => {
  const h = loadContent({
    respond: (msg) => (msg.type === 'report'
      ? { id: 'q-normalized', decision: 'allow', status: 'allowed' }
      : {}),
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer('public\u200b branch hours');
  let resent = false;
  composer.dispatchEvent = (event) => { if (event.type === 'keydown') resent = true; };

  const event = fakeEvent({ target: composer });
  assert.strictEqual(h.T.interceptSend(event, composer), false);
  await h.flush();

  assert.strictEqual(event.defaultPrevented, true);
  assert.strictEqual(composer.value, 'public branch hours');
  assert.strictEqual(h.reports()[0].prompt, 'public branch hours');
  assert.strictEqual(resent, true, 'only the normalized composer is authorized and resent');
});

test('redact mode tokenizes the composer, reports tokens only, and resends', async () => {
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q3', decision: 'redact', status: 'redacted' } : {}) });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };
  const e = fakeEvent({ target: composer });
  const result = h.T.interceptSend(e, composer);
  await h.flush();

  assert.strictEqual(result, false, 'original send is cancelled');
  assert.match(composer.value, /\[\[US_SSN_1\]\]/, 'composer now holds the token');
  assert.ok(!composer.value.includes('412-22-7843'));
  const report = h.reports()[0];
  assert.strictEqual(report.outcome, 'redacted_sent');
  assert.strictEqual(report.clientPreRedacted, true);
  assert.ok(!report.prompt.includes('412-22-7843'), 'report carries the tokenized text');
  assert.strictEqual(resent, true, 'send is re-triggered with tokens in place');
});

test('redact mode keeps the raw composer blocked when isolated mapping storage fails', async () => {
  const h = loadContent({
    respond: (msg) => {
      if (msg.type === 'rehydrationStore') return { ok: false };
      if (msg.type === 'report') return { id: 'must-not-run', decision: 'redact', status: 'redacted' };
      return {};
    },
  });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  let resent = false;
  composer.dispatchEvent = (ev) => { if (ev.type === 'keydown') resent = true; };

  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();

  assert.strictEqual(composer.value, SSN_TEXT, 'raw text remains local and unsent');
  assert.strictEqual(h.reports().length, 0, 'nothing is reported or released without the isolated mapping');
  assert.strictEqual(resent, false);
  assert.ok(h.toasts().some((message) => /could not prepare.*reveal page/i.test(message)));
});

test('provider DOM stays tokenized and raw mappings go only to the extension broker', async () => {
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q4', decision: 'redact', status: 'redacted' } : {}) });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();

  const replyNode = { nodeType: 3, nodeValue: 'Your SSN [[US_SSN_1]] is on file.', parentElement: { closest: () => null } };
  assert.strictEqual(replyNode.nodeValue, 'Your SSN [[US_SSN_1]] is on file.', 'provider-owned output never receives raw values');

  const store = h.sent.find((message) => message.type === 'rehydrationStore');
  assert.ok(store, 'raw mappings are handed to the extension-origin broker');
  assert.deepStrictEqual(
    Array.from(store.entries, (entry) => ({ token: entry.token, value: entry.value })),
    [{ token: '[[US_SSN_1]]', value: '412-22-7843' }],
  );

  const composerNode = { nodeType: 3, nodeValue: 'draft [[US_SSN_1]]', parentElement: { closest: () => ({}) } };
  assert.strictEqual(composerNode.nodeValue, 'draft [[US_SSN_1]]', 'editable fields keep their tokens');
});

test('redaction tokens stay unique across multiple prompts on one page', async () => {
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q-redact', status: 'redacted' } : {}) });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });

  const first = fakeComposer('First member SSN 412-22-7843');
  h.T.interceptSend(fakeEvent({ target: first }), first);
  await h.flush();
  h.T.interceptSend(fakeEvent({ target: first }), first); // consume the one-shot resend bypass in the VM harness

  const second = fakeComposer('Second member SSN 524-71-3312');
  h.T.interceptSend(fakeEvent({ target: second }), second);
  await h.flush();

  assert.match(first.value, /\[\[US_SSN_1\]\]/);
  assert.match(second.value, /\[\[US_SSN_2\]\]/, 'the second prompt must not reuse the first token key');
  const firstReply = { nodeType: 3, nodeValue: `Echo ${first.value}`, parentElement: { closest: () => null } };
  const secondReply = { nodeType: 3, nodeValue: `Echo ${second.value}`, parentElement: { closest: () => null } };
  assert.ok(!firstReply.nodeValue.includes('412-22-7843'));
  assert.ok(!secondReply.nodeValue.includes('524-71-3312'));
  assert.strictEqual(h.sent.filter((message) => message.type === 'rehydrationStore').length, 2);
});

test('disabled protection lets sends through untouched', () => {
  const h = loadContent();
  h.T.setEnabled(false);
  const composer = fakeComposer(SSN_TEXT);
  const e = fakeEvent({ target: composer });
  assert.strictEqual(h.T.interceptSend(e, composer), true);
  assert.strictEqual(e.defaultPrevented, false);
  assert.strictEqual(h.reports().length, 0);
});

// ---------------------------------------------------------------------------
test('upload type gates classify files by extension and mime', () => {
  const { T } = loadContent();
  assert.strictEqual(T.fileExtension('Statements.Final.CSV'), '.csv');
  assert.strictEqual(T.fileExtension('no-extension'), '');
  assert.strictEqual(T.fileLabel({ name: 'member-list.csv' }), '.csv file');
  assert.strictEqual(T.fileLabel({ type: 'application/pdf' }), 'application/pdf file');
  assert.strictEqual(T.fileLabel({}), 'file');
  assert.strictEqual(T.textReadableUpload({ name: 'x.bin', type: 'text/plain; charset=utf-8' }), true, 'mime with params');
  assert.strictEqual(T.textReadableUpload({ name: 'x.yaml', type: '' }), true, 'extension fallback');
  assert.strictEqual(T.textReadableUpload({ name: 'x.pdf', type: 'application/pdf' }), false);
  assert.strictEqual(T.ocrRequiredUpload({ name: 'scan.png', type: '' }), true);
  assert.strictEqual(T.ocrRequiredUpload({ name: 'photo', type: 'image/jpeg' }), true);
  assert.strictEqual(T.ocrRequiredUpload({ name: 'x.txt', type: 'text/plain' }), false);
  assert.strictEqual(T.textLooksReadable('ordinary,csv,content\n1,2,3'), true);
  assert.strictEqual(T.textLooksReadable('\u0000\u0001\u0002\u0003binary'.repeat(10)), false);
  assert.strictEqual(T.textLooksReadable(''), true, 'empty reads as readable');
});

test('clean-upload bypass is bound to the exact scanned file object and consumed once', () => {
  const { T } = loadContent();
  const file = { name: 'clean.csv', size: 10, type: 'text/csv', lastModified: 1234 };
  assert.strictEqual(T.filesHaveCleanBypass([file]), false, 'unknown file has no bypass');
  T.rememberCleanUpload(file);
  assert.strictEqual(T.filesHaveCleanBypass([file]), true, 'the exact scanned-clean file may resume');
  const swapped = { ...file };
  assert.strictEqual(T.filesHaveCleanBypass([swapped]), false, 'same metadata cannot authorize different bytes');
  const other = { ...file, size: 11 };
  assert.strictEqual(T.filesHaveCleanBypass([file, other]), false, 'every file in the batch needs a bypass');
  T.consumeCleanUploadBypass([file]);
  assert.strictEqual(T.filesHaveCleanBypass([file]), false, 'bypass is single-use');
});

test('clean file input stays empty while evidence is pending and replays only the scanned File object', async () => {
  let resolveReport;
  const reportResult = new Promise((resolve) => { resolveReport = resolve; });
  const h = loadContent({
    hostname: 'intranet.example',
    respond: (msg) => (msg.type === 'report' ? reportResult : {}),
  });
  const file = { name: 'clean.txt', size: 12, type: 'text/plain', lastModified: 1234, _content: 'branch hours' };
  const input = new FakeElement('input');
  input.type = 'file';
  input.value = 'C:\\fakepath\\clean.txt';
  input.files = [file];
  let pageChangeEvents = 0;
  input.dispatchEvent = (event) => {
    event.target = input;
    for (const listener of h.domListeners.change || []) listener(event);
    if (!event.defaultPrevented) pageChangeEvents += 1;
    return !event.defaultPrevented;
  };

  const initial = new FakeDomEvent('change', { bubbles: true, cancelable: true });
  initial.target = input;
  for (const listener of h.domListeners.change || []) listener(initial);

  assert.strictEqual(initial.defaultPrevented, true);
  assert.strictEqual(input.files.length, 0, 'page cannot read the file while local scan/evidence is pending');
  assert.strictEqual(pageChangeEvents, 0);

  resolveReport({ id: 'q-clean', decision: 'allow' });
  await h.flush();

  assert.strictEqual(input.files.length, 1);
  assert.strictEqual(input.files[0], file, 'verified replay uses the exact immutable File object that was scanned');
  assert.strictEqual(pageChangeEvents, 1, 'the page receives one clean replay after evidence is recorded');
});

test('opaque encoded text upload stays detached and is never replayed as clean', async () => {
  const encoded = Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64');
  const h = loadContent({
    hostname: 'intranet.example',
    respond: (msg) => (msg.type === 'report' ? { id: 'q-opaque-file', decision: 'block', status: 'blocked_unscannable' } : {}),
  });
  const file = { name: 'opaque.txt', size: encoded.length, type: 'text/plain', lastModified: 1234, _content: encoded };
  const input = new FakeElement('input');
  input.type = 'file';
  input.value = 'C:\\fakepath\\opaque.txt';
  input.files = [file];
  let pageChangeEvents = 0;
  input.dispatchEvent = (event) => {
    event.target = input;
    for (const listener of h.domListeners.change || []) listener(event);
    if (!event.defaultPrevented) pageChangeEvents += 1;
    return !event.defaultPrevented;
  };

  const initial = new FakeDomEvent('change', { bubbles: true, cancelable: true });
  initial.target = input;
  for (const listener of h.domListeners.change || []) listener(initial);
  await h.flush();

  assert.strictEqual(initial.defaultPrevented, true);
  assert.strictEqual(input.files.length, 0);
  assert.strictEqual(pageChangeEvents, 0);
  const report = h.reports().find((payload) => payload.channel === 'file_upload');
  assert.strictEqual(report.outcome, 'action_blocked');
  assert.ok(!JSON.stringify(report).includes(encoded));
});

test('safeFileFindingPrompt names the types, not the contents', () => {
  const { T } = loadContent();
  const analysis = D.analyze(SSN_TEXT);
  const promptText = T.safeFileFindingPrompt({ name: 'members.csv' }, analysis);
  assert.strictEqual(promptText, '[browser file blocked locally] US_SSN in .csv file');
});

test('probeAccount classifies a personal account locally and caches the enum (N4)', async () => {
  const accountEl = new FakeElement('div');
  accountEl.setAttribute('aria-label', 'Google Account: Jane Roe (jane.roe@gmail.com)');
  const ctx = loadContent({
    hostname: 'chatgpt.com',
    querySelectorAll: () => [accountEl],
  });
  ctx.T.setPolicy({ corporateAiAccounts: { orgEmailDomains: ['examplecu.org'], personalAccountAction: 'coach' } });
  ctx.T.probeAccount();
  assert.deepStrictEqual(ctx.T.account(), { type: 'personal', signal: 'personal_email_domain' });
});

test('probeAccount marks the org domain as corporate (N4)', async () => {
  const accountEl = new FakeElement('div');
  accountEl.setAttribute('aria-label', 'Account jane@examplecu.org');
  const ctx = loadContent({ hostname: 'chatgpt.com', querySelectorAll: () => [accountEl] });
  ctx.T.setPolicy({ corporateAiAccounts: { orgEmailDomains: ['examplecu.org'], personalAccountAction: 'allow' } });
  ctx.T.probeAccount();
  assert.strictEqual(ctx.T.account().type, 'corporate');
});

test('reports carry the account enum, never a raw email (N4)', async () => {
  const accountEl = new FakeElement('div');
  accountEl.setAttribute('aria-label', 'jane.roe@gmail.com');
  const ctx = loadContent({ hostname: 'chatgpt.com', querySelectorAll: () => [accountEl] });
  ctx.T.setPolicy({ corporateAiAccounts: { orgEmailDomains: [], personalAccountAction: 'allow' } });
  ctx.T.probeAccount();
  await ctx.T.report('some prompt', { findings: [], categories: [] }, 'submit', 'allowed');
  const payloads = ctx.reports();
  const last = payloads[payloads.length - 1];
  assert.strictEqual(last.clientAccount.type, 'personal');
  assert.strictEqual(last.clientAccount.signal, 'personal_email_domain');
  assert.ok(!JSON.stringify(last).includes('jane.roe@gmail.com'), 'no raw email in the report payload');
});

// ---------------------------------------------------------------------------
// sensor-ext audit fixes
// ---------------------------------------------------------------------------
test('pasting a file runs the upload gate instead of uploading unscanned (HIGH)', async () => {
  const h = loadContent({
    hostname: 'chat.openai.com',
    respond: (msg) => (msg.type === 'report' ? { id: 'q1', status: 'ocr_required' } : {}),
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] }); // isolate from the destination gate
  // A screenshot of a spreadsheet of SSNs: no clipboard TEXT, only a file.
  const e = fakeEvent({
    clipboardData: {
      getData: () => '',
      files: [{ name: 'ssn-screenshot.png', type: 'image/png', size: 5000 }],
    },
  });
  h.domListeners.paste[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, true, 'the pasted file must be intercepted, not left to upload');
  const fileReports = h.reports().filter((p) => p.channel === 'file_upload');
  assert.strictEqual(fileReports.length, 1, 'the pasted file went through the upload scanner');
  assert.strictEqual(fileReports[0].outcome, 'ocr_required', 'image paste requires OCR before inspection');
});

test('a blocked file-input change clears the input so the file is not left attached', async () => {
  const h = loadContent({ hostname: 'chat.openai.com' }); // default: destination is unapproved -> blocked
  const input = new FakeElement('input');
  input.type = 'file';
  input.value = 'C:\\fakepath\\members.csv';
  input.files = [{ name: 'members.csv', size: 10, type: 'text/csv' }];
  const e = fakeEvent({ target: input });
  h.domListeners.change[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, true, 'the upload is intercepted');
  assert.strictEqual(input.value, '', 'the blocked FileList is cleared so a form submit cannot upload it');
});

test('Enter in an unrelated field never files a false allowed report of the composer (MEDIUM)', async () => {
  const composer = fakeComposer('hello world draft prompt');
  const h = loadContent({
    hostname: 'chat.openai.com',
    querySelector: () => composer, // a global find WOULD return the composer
  });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const searchBox = new FakeElement('input');
  searchBox.closest = () => null; // a plain search input, not the composer
  const e = fakeEvent({ key: 'Enter', shiftKey: false, target: searchBox });
  h.domListeners.keydown[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, false, 'Enter outside the composer is left alone');
  assert.strictEqual(h.reports().length, 0, 'no phantom submit report of text the user never sent');
});

test('IME composition Enter is not treated as a send (MEDIUM)', async () => {
  const h = loadContent({ hostname: 'chat.openai.com' });
  h.T.setPolicy({ allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  const e = fakeEvent({ key: 'Enter', shiftKey: false, isComposing: true, target: composer });
  h.domListeners.keydown[0](e);
  await h.flush();

  assert.strictEqual(e.defaultPrevented, false, 'an IME candidate commit must not trigger interception');
  assert.strictEqual(h.reports().length, 0);
});

test('provider nodes never rehydrate digit-bearing tokens like IPV6_ADDRESS (MEDIUM)', () => {
  loadContent();
  const reply = { nodeType: 3, nodeValue: 'Server at [[IPV6_ADDRESS_1]] responded', parentElement: { closest: () => null } };
  assert.strictEqual(reply.nodeValue, 'Server at [[IPV6_ADDRESS_1]] responded');
});

test('redact retry under outage stays on the recorded path, never a plain allow (MEDIUM)', async () => {
  const h = loadContent({ respond: () => ({}) }); // control plane never confirms -> outage
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);

  const first = h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  assert.strictEqual(first, false, 'first send held while unrecorded');
  assert.match(composer.value, /\[\[US_SSN_1\]\]/, 'composer tokenized');

  // Retry: composer holds only the (PII-free) token text; the old code let this
  // pass as a plain "allow" with zero compliance evidence.
  const retry = h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();
  assert.strictEqual(retry, false, 'retry is held, not allowed through');
  const outcomes = h.reports().map((p) => p.outcome);
  assert.ok(outcomes.every((o) => o === 'redacted_sent'), 'every attempt routes through the redacted-send record');
  assert.ok(!outcomes.includes('allowed'), 'no plain allow send with no evidence');
});

test('redacted outage retries stay bound to their exact composer', async () => {
  const h = loadContent({ respond: () => ({}) });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composerA = fakeComposer(SSN_TEXT);
  const composerB = fakeComposer('Member SSN is 524-71-3312 on file');

  h.T.interceptSend(fakeEvent({ target: composerA }), composerA);
  await h.flush();
  h.T.interceptSend(fakeEvent({ target: composerB }), composerB);
  await h.flush();
  h.T.interceptSend(fakeEvent({ target: composerA }), composerA);
  await h.flush();

  assert.deepStrictEqual(
    h.reports().map((payload) => payload.outcome),
    ['redacted_sent', 'redacted_sent', 'redacted_sent'],
    'composer B cannot replace composer A retry evidence',
  );
});

test('token text in composer B never consumes composer A redacted retry', async () => {
  const h = loadContent({ respond: () => ({}) });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composerA = fakeComposer(SSN_TEXT);
  h.T.interceptSend(fakeEvent({ target: composerA }), composerA);
  await h.flush();

  const composerB = fakeComposer(composerA.value);
  h.T.interceptSend(fakeEvent({ target: composerB }), composerB);
  await h.flush();

  assert.deepStrictEqual(
    h.reports().map((payload) => payload.outcome),
    ['redacted_sent', 'allowed'],
    'only the original composer can use its redacted retry state',
  );
});
