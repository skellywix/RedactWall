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

const HOOK = `
  window.__test = {
    evaluate, summarize, safeClientPrompt, publicFindings, publicCategories, escapeHtml,
    destinationBlocked, fileUploadBlocked, browserActionBlockRule,
    recordedProceedResponse, recordedEvidenceResponse,
    interceptSend, mergeRehydrate, rehydrateNode, inComposerOrUI,
    readText, fileExtension, fileLabel, textReadableUpload, ocrRequiredUpload,
    textLooksReadable, rememberCleanUpload, filesHaveCleanBypass, consumeCleanUploadBypass,
    safeFileFindingPrompt,
    probeAccount, showAccountCoach, report,
    account: () => ACCOUNT,
    setPolicy: (p) => { POLICY = { ...POLICY, ...p }; },
    setEnabled: (v) => { ENABLED = v; },
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
    this._q = new Map();
  }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  appendChild(c) { c.parentElement = this; this.children.push(c); return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(c)); }
  remove() {
    if (this.parentElement) this.parentElement.children = this.parentElement.children.filter((c) => c !== this);
    this.parentElement = null;
  }
  querySelector(sel) {
    if (!this._q.has(sel)) {
      const el = new FakeElement('div');
      el.value = '';
      this._q.set(sel, el);
    }
    return this._q.get(sel);
  }
  addEventListener() {}
  focus() {}
  click() {}
  dispatchEvent() {}
  getBoundingClientRect() { return { width: 1, height: 1 }; }
  closest() { return null; }
}

function loadContent(opts = {}) {
  const sent = [];
  const domListeners = {};
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
    sendMessage: async (msg) => { sent.push(msg); return (opts.respond || (() => ({})))(msg); },
    addRuntimeMessageListener() {},
    addStorageChangeListener() {},
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
    NodeFilter: { SHOW_TEXT: 4 },
    console: { log() {}, warn() {}, error() {} },
    setTimeout: () => 0, // keep toasts on the body for assertions
    clearTimeout() {},
    Date,
  };
  vm.runInNewContext(instrumented, context, { filename: path.join(extensionDir, 'content.js') });
  return {
    T: windowObj.__test,
    sent,
    body,
    domListeners,
    reports: () => sent.filter((m) => m.type === 'report').map((m) => m.payload),
    toasts: () => body.children.filter((c) => c.className === 'ps-toast').map((c) => c.textContent),
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

function fakeComposer(text) {
  const el = new FakeElement('textarea');
  el.value = text;
  el.closest = () => el;
  return el;
}

const SSN_TEXT = 'Member SSN is 412-22-7843 on file';

// ---------------------------------------------------------------------------
test('evaluate maps policy modes and hard stops to actions', () => {
  const { T } = loadContent();
  assert.strictEqual(T.evaluate('what are your branch hours?').action, 'allow');
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block', 'default block mode');

  T.setPolicy({ enforcementMode: 'warn', alwaysBlock: [] });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'warn');

  T.setPolicy({ enforcementMode: 'warn', alwaysBlock: ['US_SSN'] });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'block', 'hard-stop entity overrides warn mode');

  T.setPolicy({ enforcementMode: 'justify', alwaysBlock: [] });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'justify');

  T.setPolicy({ enforcementMode: 'redact' });
  assert.strictEqual(T.evaluate(SSN_TEXT).action, 'redact', 'structured findings tokenize');
  const category = T.evaluate('CONFIDENTIAL — internal only, do not share externally');
  assert.strictEqual(category.action, 'block', 'semantic categories cannot tokenize, must hold');

  T.setPolicy({ enforcementMode: 'block', blockMinSeverity: 99, blockRiskScore: 999, alwaysBlock: [] });
  assert.strictEqual(T.evaluate('email me at jane.doe@example.com').action, 'allow', 'below both thresholds');
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
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', decision: 'allow' }, 'anything'), true);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', status: 'warned_sent' }, 'sent_after_warning'), true);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', status: 'pending' }, 'sent_after_warning'), false);
  assert.strictEqual(T.recordedProceedResponse({ id: 'q1', status: 'justified' }, 'justified'), true);
  assert.strictEqual(T.recordedEvidenceResponse({ id: 'q1', status: 'allowed' }, 'allowed'), true);
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

test('Enter on a sensitive prompt blocks the send, shows the banner, and requests approval', async () => {
  const h = loadContent({
    respond: (msg) => (msg.type === 'report' ? { id: 'q9', status: 'pending' } : {}),
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

test('redact mode tokenizes the composer, reports tokens only, and resends', async () => {
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q3', status: 'redacted' } : {}) });
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

test('rehydration restores tokens in rendered output but never inside the composer', async () => {
  const h = loadContent({ respond: (msg) => (msg.type === 'report' ? { id: 'q4', status: 'redacted' } : {}) });
  h.T.setPolicy({ enforcementMode: 'redact', allowedDestinations: ['chat.openai.com'] });
  const composer = fakeComposer(SSN_TEXT);
  h.T.interceptSend(fakeEvent({ target: composer }), composer);
  await h.flush();

  const replyNode = { nodeType: 3, nodeValue: 'Your SSN [[US_SSN_1]] is on file.', parentElement: { closest: () => null } };
  h.T.rehydrateNode(replyNode);
  assert.strictEqual(replyNode.nodeValue, 'Your SSN 412-22-7843 is on file.', 'model reply is restored locally');

  const composerNode = { nodeType: 3, nodeValue: 'draft [[US_SSN_1]]', parentElement: { closest: () => ({}) } };
  h.T.rehydrateNode(composerNode);
  assert.strictEqual(composerNode.nodeValue, 'draft [[US_SSN_1]]', 'editable fields keep their tokens');
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

test('clean-upload bypass remembers a scanned file once and consumes it on reattach', () => {
  const { T } = loadContent();
  const file = { name: 'clean.csv', size: 10, type: 'text/csv', lastModified: 1234 };
  assert.strictEqual(T.filesHaveCleanBypass([file]), false, 'unknown file has no bypass');
  T.rememberCleanUpload(file);
  assert.strictEqual(T.filesHaveCleanBypass([file]), true, 'scanned-clean file may reattach');
  const other = { ...file, size: 11 };
  assert.strictEqual(T.filesHaveCleanBypass([file, other]), false, 'every file in the batch needs a bypass');
  T.consumeCleanUploadBypass([file]);
  assert.strictEqual(T.filesHaveCleanBypass([file]), false, 'bypass is single-use');
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

test('rehydration restores digit-bearing tokens like IPV6_ADDRESS (MEDIUM)', () => {
  const { T } = loadContent();
  T.mergeRehydrate({ '[[IPV6_ADDRESS_1]]': 'fe80::1ff:fe23:4567:890a' });
  const reply = { nodeType: 3, nodeValue: 'Server at [[IPV6_ADDRESS_1]] responded', parentElement: { closest: () => null } };
  T.rehydrateNode(reply);
  assert.strictEqual(reply.nodeValue, 'Server at fe80::1ff:fe23:4567:890a responded');
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
