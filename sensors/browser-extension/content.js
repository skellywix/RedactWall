/* PromptWall content script — pre-send inspection on AI chat sites.
 *
 * Strategy: catch the prompt BEFORE it leaves the page.
 *   - Enter keydown (capture phase) on the composer
 *   - Send-button click (capture phase)
 *   - Paste (warn the moment sensitive data lands in the box)
 *   - Copy (optionally block AI response exfiltration without reading text)
 *   - File drops / uploads
 * Detection is local (lib/detect.js) so it is instant and nothing leaves the
 * device just to be scanned. Enforcement follows the org policy: warn / justify / block.
 */
(function () {
  'use strict';
  if (window.__promptSentinelLoaded) return;
  window.__promptSentinelLoaded = true;

  const D = window.PSDetect;
  const SITE = location.hostname;
  let POLICY = { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, allowedDestinations: [], blockedBrowserActions: [], blockUnapprovedAiDestinations: true, alwaysBlock: [] };
  let ENABLED = true;

  // Pull policy + enabled state from the background worker.
  chrome.runtime.sendMessage({ type: 'getConfig' }, (res) => {
    if (res && res.policy) POLICY = res.policy;
    if (res && typeof res.enabled === 'boolean') ENABLED = res.enabled;
  });
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== 'getPolicyState') return false;
    sendResponse({
      enabled: ENABLED,
      policy: {
        governedDestinations: POLICY.governedDestinations || [],
        allowedDestinations: POLICY.allowedDestinations || [],
        blockedDestinations: POLICY.blockedDestinations || [],
        blockedFileUploadDestinations: POLICY.blockedFileUploadDestinations || [],
        blockedBrowserActions: POLICY.blockedBrowserActions || [],
        blockUnapprovedAiDestinations: POLICY.blockUnapprovedAiDestinations !== false,
      },
    });
    return false;
  });
  chrome.storage.onChanged.addListener((c) => {
    if (c.enabled) ENABLED = c.enabled.newValue;
    if (c.policy) POLICY = { ...POLICY, ...c.policy.newValue };
  });

  // ---- find the prompt text the user is about to send -----------------------
  const SELECTORS = [
    'textarea#prompt-textarea', 'div#prompt-textarea[contenteditable="true"]', // ChatGPT
    'div[contenteditable="true"].ProseMirror',                                  // Claude
    'textarea[aria-label]', 'div[contenteditable="true"][role="textbox"]',      // Gemini/Copilot
    'textarea', 'div[contenteditable="true"]',                                  // fallback
  ];
  function findComposer(start) {
    if (start) {
      const e = start.closest && start.closest('textarea, div[contenteditable="true"]');
      if (e) return e;
    }
    for (const sel of SELECTORS) {
      const el = document.querySelector(sel);
      if (el && isVisible(el)) return el;
    }
    return null;
  }
  function isVisible(el) { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; }
  function readText(el) {
    if (!el) return '';
    return (el.value !== undefined ? el.value : el.innerText || el.textContent || '').trim();
  }

  // ---- decide what to do ----------------------------------------------------
  function detectionPolicy() {
    return {
      ignore: POLICY.ignore || [],
      disabledDetectors: POLICY.disabledDetectors || [],
      customDetectors: POLICY.customDetectors || [],
    };
  }

  function destinationBlocked() {
    const allowed = POLICY.allowedDestinations || [];
    const blocked = POLICY.blockedDestinations || [];
    const A = window.PSAdapters;
    if (A && A.isGoverned && A.isGoverned(SITE, allowed)) return false;
    if (allowed.some((host) => SITE === host || SITE.endsWith('.' + host))) return false;
    if (A && A.isGoverned && A.isGoverned(SITE, blocked)) return true;
    if (blocked.some((host) => SITE === host || SITE.endsWith('.' + host))) return true;
    if (POLICY.blockUnapprovedAiDestinations === false || !A || !A.isAiHost || !A.isGoverned) return false;
    return A.isAiHost(SITE) && !A.isGoverned(SITE, [
      ...(POLICY.governedDestinations || []),
      ...(POLICY.allowedDestinations || []),
      ...(POLICY.blockedDestinations || []),
      ...(POLICY.blockedFileUploadDestinations || []),
    ]);
  }

  function fileUploadBlocked() {
    const allowed = POLICY.allowedDestinations || [];
    const blocked = POLICY.blockedFileUploadDestinations || [];
    const A = window.PSAdapters;
    if (A && A.isGoverned && A.isGoverned(SITE, allowed)) return false;
    if (allowed.some((host) => SITE === host || SITE.endsWith('.' + host))) return false;
    if (A && A.isGoverned) return A.isGoverned(SITE, blocked);
    return blocked.some((host) => SITE === host || SITE.endsWith('.' + host));
  }

  function browserActionBlockRule(action) {
    const normalizedAction = String(action || '').trim().toLowerCase();
    for (const rule of POLICY.blockedBrowserActions || []) {
      if (!rule || rule.enabled === false) continue;
      if (String(rule.action || '').trim().toLowerCase() !== normalizedAction) continue;
      const destinations = rule.destinations || [];
      const A = window.PSAdapters;
      if (A && A.isGoverned && A.isGoverned(SITE, destinations)) return rule;
      if (destinations.some((host) => SITE === host || SITE.endsWith('.' + host))) return rule;
    }
    return null;
  }

  function emptyAnalysis() {
    return {
      findings: [],
      categories: [],
      entityCounts: {},
      riskScore: 0,
      maxSeverity: 0,
      maxSeverityLabel: 'none',
    };
  }

  function evaluate(text) {
    const a = D.analyze(text, detectionPolicy());
    if (!a.findings.length && !a.categories.length) return { action: 'allow', analysis: a };
    const hardStop = a.findings.some((f) => (POLICY.alwaysBlock || []).includes(f.type));
    // REDACT mode neutralizes structured values locally. Semantic categories
    // have no span-level token to swap, so any category hit must stay held
    // rather than leaking confidential context with only the PII tokenized.
    if ((POLICY.enforcementMode || 'block') === 'redact') {
      return { action: (a.findings.length && !a.categories.length) ? 'redact' : 'block', analysis: a };
    }
    const breach = hardStop || a.maxSeverity >= POLICY.blockMinSeverity || a.riskScore >= POLICY.blockRiskScore;
    if (!breach) return { action: 'allow', analysis: a };
    // Map org policy → UX. Hard-stop entities always block regardless of mode.
    const mode = hardStop ? 'block' : (POLICY.enforcementMode || 'block');
    return { action: mode, analysis: a };
  }

  function summarize(a) {
    const items = a.findings.map((f) => f.type).concat(a.categories.map((c) => c.category));
    return [...new Set(items)];
  }

  const LABELS = {
    US_SSN: 'Social Security number',
    CREDIT_CARD: 'payment card number',
    BANK_ACCOUNT: 'bank account number',
    ROUTING_NUMBER: 'routing number',
    IBAN: 'international bank account number',
    US_PASSPORT: 'passport number',
    US_TIN_EIN: 'tax ID',
    US_ITIN: 'individual taxpayer ID',
    US_NPI: 'provider identifier',
    US_DRIVERS_LICENSE: 'driver license number',
    MEMBER_ID: 'member ID',
    LOAN_NUMBER: 'loan number',
    MEDICAL_RECORD_NUMBER: 'medical record number',
    HEALTH_INSURANCE_ID: 'health insurance ID',
    HEALTH_RECORD: 'health record',
    SWIFT_BIC: 'SWIFT/BIC code',
    DOB: 'date of birth',
    SECRET_KEY: 'API key or token',
    PRIVATE_KEY: 'private key',
    PASSWORD: 'password',
    CREDENTIALS: 'login credentials',
    SOURCE_CODE: 'source code',
    LEGAL_CONTRACT: 'contract language',
    CONFIDENTIAL_BUSINESS: 'confidential business information',
    CANARY_TOKEN: 'canary token',
    PERSON_NAME: 'person name',
    US_ADDRESS: 'street address',
    PHONE_NUMBER: 'phone number',
    EMAIL_ADDRESS: 'email address',
    IP_ADDRESS: 'IP address',
    IPV6_ADDRESS: 'IPv6 address',
    US_LICENSE_PLATE: 'license plate',
    VIN: 'vehicle ID number',
  };

  const COACHING = {
    US_SSN: 'Use a member ID, the last four digits, or a synthetic example instead.',
    CREDIT_CARD: 'Remove the card number or replace it with a tokenized placeholder.',
    BANK_ACCOUNT: 'Use masked last four digits or a synthetic account example.',
    ROUTING_NUMBER: 'Remove the routing number unless Security Admin approves this prompt.',
    IBAN: 'Replace the bank identifier with a synthetic value.',
    US_PASSPORT: 'Use a masked placeholder instead of a passport number.',
    US_TIN_EIN: 'Remove taxpayer identifiers or use a synthetic value.',
    US_ITIN: 'Remove taxpayer identifiers or use a synthetic value.',
    US_NPI: 'Use a provider placeholder unless Security Admin approves this prompt.',
    US_DRIVERS_LICENSE: 'Remove the driver license number before sending.',
    MEMBER_ID: 'Use a synthetic member ID or a masked last four instead.',
    LOAN_NUMBER: 'Use a synthetic loan number or a masked last four instead.',
    MEDICAL_RECORD_NUMBER: 'Remove medical record identifiers before sending.',
    HEALTH_INSURANCE_ID: 'Remove health insurance identifiers before sending.',
    HEALTH_RECORD: 'Remove patient details or use an approved de-identified workflow.',
    DOB: 'Generalize the age or date instead of sending a full date of birth.',
    SECRET_KEY: 'Remove the key or token. Rotate it if it may have been exposed.',
    PRIVATE_KEY: 'Remove the private key. Rotate it if it may have been exposed.',
    PASSWORD: 'Remove the password. Rotate it if it may have been exposed.',
    CREDENTIALS: 'Replace credentials with a neutral placeholder.',
    SOURCE_CODE: 'Use an approved code-review workflow before sending proprietary code.',
    LEGAL_CONTRACT: 'Remove contract text unless approved for external AI review.',
    CONFIDENTIAL_BUSINESS: 'Remove unreleased plans, pricing, vendor changes, or strategy details.',
    CANARY_TOKEN: 'Stop and notify Security Admin before continuing.',
  };

  function labelFor(item) {
    return LABELS[item] || String(item || 'sensitive information').toLowerCase().replace(/_/g, ' ');
  }

  function labelsFor(items) {
    return [...new Set(items || [])].map(labelFor);
  }

  function escapeHtml(value) {
    return String(value || '').replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[ch]));
  }

  function coachingFor(items) {
    for (const item of items || []) {
      if (COACHING[item]) return COACHING[item];
    }
    return 'Edit out sensitive details, use placeholders, or request approval with a business reason.';
  }

  function listForScreen(items) {
    const labels = labelsFor(items);
    if (!labels.length) return 'sensitive information';
    if (labels.length === 1) return labels[0];
    if (labels.length === 2) return labels[0] + ' and ' + labels[1];
    return labels.slice(0, -1).join(', ') + ', and ' + labels[labels.length - 1];
  }

  function chipHtml(items) {
    return labelsFor(items)
      .map((label) => '<span class="ps-chip">' + escapeHtml(label) + '</span>')
      .join('');
  }

  // ---- report to the server (telemetry + queue) -----------------------------
  function publicFindings(analysis) {
    return (analysis.findings || []).map((f) => ({
      type: f.type,
      severity: f.severity,
      score: f.score,
      masked: D.maskValue(f.type, f.value),
    }));
  }
  function publicCategories(analysis) {
    return (analysis.categories || []).map((c) => ({ category: c.category, score: c.score }));
  }
  function safeClientPrompt(text, analysis) {
    const items = summarize(analysis);
    if ((analysis.categories || []).length) return '[REDACTED: ' + items.join(', ') + ']';
    return D.redact(text, analysis.findings || []);
  }
  function report(text, analysis, channel, outcome, note, extra) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({
          type: 'report',
          payload: {
            prompt: text, destination: SITE, channel, source: 'browser_extension',
            categories: (analysis.categories || []).map((c) => c.category),
            clientFindings: publicFindings(analysis),
            clientCategories: publicCategories(analysis),
            clientEntityCounts: analysis.entityCounts || {},
            clientRiskScore: analysis.riskScore || 0,
            clientMaxSeverity: analysis.maxSeverity || 0,
            clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
            outcome, note: note || '',
            ...(extra || {}),
          },
        }, (res) => {
          if (chrome.runtime.lastError) return resolve(null);
          resolve(res || null);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  function recordedProceedResponse(res, outcome) {
    if (!res || typeof res !== 'object' || !res.id) return false;
    if (res.decision === 'allow') return true;
    if (outcome === 'sent_after_warning') return res.status === 'warned_sent';
    if (outcome === 'justified') return res.status === 'justified';
    return false;
  }
  function recordedEvidenceResponse(res, expectedStatus) {
    return !!(res && typeof res === 'object' && res.id && res.status === expectedStatus);
  }

  function updateEvidenceToast(reportPromise, expectedStatus, recordedMessage, unrecordedMessage) {
    Promise.resolve(reportPromise)
      .then((res) => toast(recordedEvidenceResponse(res, expectedStatus) ? recordedMessage : unrecordedMessage))
      .catch(() => toast(unrecordedMessage));
  }

  function updateBatchEvidenceToast(reportPromises, expectedStatus, recordedMessage, unrecordedMessage) {
    Promise.all(reportPromises.map((p) => Promise.resolve(p)
      .then((res) => recordedEvidenceResponse(res, expectedStatus))
      .catch(() => false)))
      .then((results) => toast(results.every(Boolean) ? recordedMessage : unrecordedMessage))
      .catch(() => toast(unrecordedMessage));
  }

  async function proceedAfterRecorded(text, analysis, outcome, note, el) {
    const res = await report(text, analysis, 'submit', outcome, note);
    if (!recordedProceedResponse(res, outcome)) {
      toast('PromptWall could not record this decision. Send blocked until the control plane is reachable.');
      return;
    }
    bypassOnce = true;
    resend(el);
  }

  async function sendApprovalRequest(text, analysis) {
    const res = await report(text, analysis, 'submit', 'awaiting_approval');
    if (res && res.id && res.status === 'pending') {
      toast('Sent to your Security Admin for approval.');
      return;
    }
    toast('PromptWall could not reach the control plane. Approval request blocked for now.');
  }

  function reportBlockedDestination(channel) {
    return report('[destination blocked] ' + SITE, emptyAnalysis(), channel, 'destination_blocked', 'destination blocked by policy');
  }

  function reportBlockedFileUpload() {
    return report('[file upload blocked] ' + SITE, emptyAnalysis(), 'file_upload', 'file_upload_blocked', 'file upload blocked by policy');
  }

  function reportBlockedBrowserAction(action, rule) {
    const reason = (rule && rule.reason) || (action + ' blocked by policy');
    return report('[browser action blocked] ' + action + ' ' + SITE, emptyAnalysis(), action, 'action_blocked', reason);
  }

  // ---- inline banner UI -----------------------------------------------------
  let banner;
  function clearBanner() { if (banner) { banner.remove(); banner = null; } }
  function showBanner({ mode, items, risk, onProceed, onBlock, justify }) {
    clearBanner();
    banner = document.createElement('div');
    banner.className = 'ps-banner ps-' + mode;
    const title = mode === 'block' ? 'Sensitive data blocked' : mode === 'justify' ? 'Business reason required' : 'Review before sending';
    const detail = mode === 'block'
      ? 'PromptWall found ' + listForScreen(items) + ' before it could leave this browser.'
      : 'PromptWall found ' + listForScreen(items) + ' in this prompt. Review it before sending to ' + SITE + '.';
    const riskText = mode === 'block' ? '' : ' Risk ' + risk + '/100.';
    const coach = coachingFor(items);
    const chips = chipHtml(items);
    banner.innerHTML =
      '<div class="ps-row"><span class="ps-status-dot"></span>' +
      '<div class="ps-msg"><div class="ps-title">' + escapeHtml(title) + '</div>' +
      '<div class="ps-detail">' + escapeHtml(detail + riskText) + '</div></div>' +
      '<button class="ps-x" title="Dismiss" aria-label="Dismiss">x</button></div>' +
      '<div class="ps-chips">' + chips + '</div>' +
      '<div class="ps-coach">' + escapeHtml(coach) + '</div>' +
      (justify ? '<textarea class="ps-just" placeholder="Business reason required to proceed. Recorded for compliance."></textarea>' : '') +
      '<div class="ps-actions"></div>';
    const actions = banner.querySelector('.ps-actions');
    banner.querySelector('.ps-x').onclick = clearBanner;

    if (mode === 'warn') {
      const edit = mk('button', 'ps-btn ps-secondary', 'Edit prompt'); edit.onclick = clearBanner;
      const go = mk('button', 'ps-btn ps-primary', 'Send anyway'); go.onclick = () => { clearBanner(); onProceed(); };
      actions.append(edit, go);
    } else if (mode === 'justify') {
      const edit = mk('button', 'ps-btn ps-secondary', 'Cancel'); edit.onclick = () => { clearBanner(); onBlock(); };
      const go = mk('button', 'ps-btn ps-primary', 'Submit reason'); go.onclick = () => {
        const note = banner.querySelector('.ps-just').value.trim();
        if (note.length < 4) { banner.querySelector('.ps-just').style.borderColor = '#dc2626'; return; }
        clearBanner(); onProceed(note);
      };
      actions.append(edit, go);
    } else { // block
      const req = mk('button', 'ps-btn ps-secondary', 'Request approval'); req.onclick = () => { clearBanner(); onBlock(true); };
      const ok = mk('button', 'ps-btn ps-primary', 'Edit prompt'); ok.onclick = () => { clearBanner(); onBlock(false); };
      actions.append(req, ok);
    }
    document.body.appendChild(banner);
  }
  function mk(tag, cls, txt) { const e = document.createElement(tag); e.className = cls; e.textContent = txt; return e; }

  // ---- intercept SEND -------------------------------------------------------
  let bypassOnce = false;
  function interceptSend(e, composer) {
    if (!ENABLED || bypassOnce) { bypassOnce = false; return true; }
    const el = composer || findComposer(e.target);
    let text = readText(el);
    if (!text) return true;
    if (destinationBlocked()) {
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
      toast('PromptWall blocked sends to ' + SITE + ' by policy. Recording evidence...');
      updateEvidenceToast(
        reportBlockedDestination('submit'),
        'destination_blocked',
        'PromptWall blocked sends to ' + SITE + ' by policy and recorded the decision.',
        'PromptWall blocked sends to ' + SITE + ' by policy. Control-plane evidence was not recorded yet.',
      );
      return false;
    }
    // Man-in-the-Prompt: strip invisible zero-width payloads silently; HARD-stop
    // strong injection signals (bidi overrides / Unicode tag chars) a malicious
    // extension could use to smuggle hidden instructions under the user's name.
    const A = window.PSAdapters;
    if (A) {
      const inj = A.scanInjection(text);
      if (inj.suspicious) {
        if (inj.reasons.some((r) => /bidi|tag/i.test(r))) {
          e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
          report(text, { findings: [], categories: [] }, 'submit', 'injection_blocked', inj.reasons.join(', '));
          toast('PromptWall blocked hidden instructions in this prompt (' + inj.reasons.join(', ') + ').');
          return false;
        }
        text = inj.stripped;
      }
    }
    const verdict = evaluate(text);
    if (verdict.action === 'allow') { report(text, verdict.analysis, 'submit', 'allowed'); return true; }

    // REDACT: tokenize in place, let the (now PII-free) prompt send, and restore
    // the real values in the model's reply locally. The AI service and the
    // server only ever see tokens; the map never leaves this page.
    if (verdict.action === 'redact') {
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
      const t = D.tokenize(text, verdict.analysis.findings);
      mergeRehydrate(t.map);
      setComposerText(el, t.text);
      report(t.text, verdict.analysis, 'submit', 'redacted_sent', '', { clientPreRedacted: true });
      toast('PromptWall: ' + Object.keys(t.map).length + ' sensitive value(s) tokenized before sending — the reply is restored here automatically.');
      bypassOnce = true;
      resend(el);
      return false;
    }

    // stop the send
    e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
    const items = summarize(verdict.analysis);
    showBanner({
      mode: verdict.action, items, risk: verdict.analysis.riskScore,
      justify: verdict.action === 'justify',
      onProceed: (note) => proceedAfterRecorded(text, verdict.analysis, verdict.action === 'justify' ? 'justified' : 'sent_after_warning', note, el),
      onBlock: (requestApproval) => {
        if (requestApproval) sendApprovalRequest(text, verdict.analysis);
        else report(text, verdict.analysis, 'submit', 'blocked_by_user');
      },
    });
    return false;
  }
  function resend(el) {
    // Prefer clicking the site's REAL send button — its onClick reads the
    // composer and actually submits — over re-dispatching a synthetic key event
    // that React composers ignore as untrusted (REVIEW #7).
    const A = window.PSAdapters;
    if (A) {
      for (const sel of A.sendButtonSelectors(location.hostname)) {
        const btn = document.querySelector(sel);
        if (btn && !btn.disabled) { btn.click(); return; }
      }
    }
    if (!el) return;
    el.focus();
    el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true }));
  }

  // ---- redact-mode: local tokenization + response re-hydration --------------
  const REHYDRATE_MAP = {};
  function mergeRehydrate(map) {
    let added = 0;
    for (const k in map) { if (!(k in REHYDRATE_MAP)) added++; REHYDRATE_MAP[k] = map[k]; }
    if (added) startRehydrator();
  }
  function setComposerText(el, text) {
    if (!el) return;
    el.focus();
    if (el.value !== undefined) { // textarea — use the native setter so React sees it
      const d = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
      if (d && d.set) d.set.call(el, text); else el.value = text;
    } else {                      // contenteditable
      el.textContent = text;
    }
    el.dispatchEvent(new InputEvent('input', { bubbles: true, data: text, inputType: 'insertText' }));
  }
  // The composer must keep its TOKENS (so tokens are what gets sent); only
  // restore real values in rendered messages, never inside an editable field.
  function inComposerOrUI(node) {
    const el = node && (node.nodeType === 1 ? node : node.parentElement);
    return !!(el && el.closest && el.closest('textarea, [contenteditable="true"], .ps-banner, .ps-toast'));
  }
  function copyOriginInComposerOrUI(event) {
    if (inComposerOrUI(event && event.target)) return true;
    const selection = window.getSelection && window.getSelection();
    if (!selection || selection.rangeCount === 0) return false;
    return inComposerOrUI(selection.anchorNode) || inComposerOrUI(selection.focusNode);
  }
  let rehydrating = false, observer = null;
  const TOKEN_RE = /\[\[[A-Z_]+_\d+\]\]/;
  function startRehydrator() {
    if (observer) return;
    observer = new MutationObserver((muts) => {
      if (rehydrating || !Object.keys(REHYDRATE_MAP).length) return;
      rehydrating = true;
      try {
        for (const m of muts) {
          for (const node of (m.addedNodes || [])) rehydrateNode(node);
          if (m.type === 'characterData') rehydrateNode(m.target);
        }
      } finally { rehydrating = false; }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }
  function rehydrateNode(node) {
    if (!node || inComposerOrUI(node)) return;
    if (node.nodeType === 3) {
      if (TOKEN_RE.test(node.nodeValue || '')) node.nodeValue = D.detokenize(node.nodeValue, REHYDRATE_MAP);
      return;
    }
    if (node.nodeType === 1) {
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
      let n; const hits = [];
      while ((n = walker.nextNode())) if (TOKEN_RE.test(n.nodeValue || '') && !inComposerOrUI(n)) hits.push(n);
      for (const tn of hits) tn.nodeValue = D.detokenize(tn.nodeValue, REHYDRATE_MAP);
    }
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      const el = findComposer(e.target);
      if (el && readText(el)) interceptSend(e, el);
    }
  }, true);

  function closestSendButton(target) {
    if (!target || !target.closest) return null;
    const A = window.PSAdapters;
    const selectors = A && A.sendButtonSelectors ? A.sendButtonSelectors(location.hostname)
      : ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]', 'button[aria-label*="Submit" i]', 'button[type="submit"]'];
    for (const sel of selectors) {
      try {
        const btn = target.closest(sel);
        if (btn) return btn;
      } catch (_) {}
    }
    return null;
  }

  document.addEventListener('click', (e) => {
    if (closestSendButton(e.target)) {
      const el = findComposer();
      if (el && readText(el)) interceptSend(e, el);
    }
  }, true);

  // ---- intercept PASTE (early warning) --------------------------------------
  document.addEventListener('paste', (e) => {
    if (!ENABLED) return;
    const actionRule = browserActionBlockRule('paste');
    if (actionRule) {
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
      reportBlockedBrowserAction('paste', actionRule);
      toast('PromptWall blocked paste into ' + SITE + ' by policy.');
      return;
    }
    const t = (e.clipboardData || window.clipboardData);
    const pasted = t ? t.getData('text') : '';
    if (!pasted || pasted.length < 6) return;
    const verdict = evaluate(pasted);
    if (verdict.action !== 'allow') {
      const items = summarize(verdict.analysis).slice(0, 3);
      if (verdict.action === 'block') {
        e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
        const reportPromise = report(
          safeClientPrompt(pasted, verdict.analysis),
          verdict.analysis,
          'paste',
          'paste_flagged',
          'blocked locally: sensitive paste prevented before insertion',
          { clientPreRedacted: true },
        );
        toast('PromptWall blocked sensitive paste: ' + listForScreen(items) + '. Recording evidence...');
        updateEvidenceToast(
          reportPromise,
          'paste_flagged',
          'PromptWall blocked sensitive paste and recorded the decision.',
          'PromptWall blocked sensitive paste. Control-plane evidence was not recorded yet.',
        );
        return;
      }
      report(pasted, verdict.analysis, 'paste', 'paste_flagged');
      toast('PromptWall found sensitive data: ' + listForScreen(items));
    }
  }, true);

  // ---- intercept COPY (output exfiltration control) ------------------------
  document.addEventListener('copy', (e) => {
    if (!ENABLED) return;
    if (copyOriginInComposerOrUI(e)) return;
    const actionRule = browserActionBlockRule('copy');
    if (actionRule) {
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
      toast('PromptWall blocked copy from ' + SITE + ' by policy. Recording evidence...');
      updateEvidenceToast(
        reportBlockedBrowserAction('copy', actionRule),
        'action_blocked',
        'PromptWall blocked copy from ' + SITE + ' by policy and recorded the decision.',
        'PromptWall blocked copy from ' + SITE + ' by policy. Control-plane evidence was not recorded yet.',
      );
    }
  }, true);

  // ---- intercept FILE drops / selection -------------------------------------
  document.addEventListener('drop', (e) => {
    if (!ENABLED) return;
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      const actionRule = browserActionBlockRule('drop');
      if (actionRule) {
        e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
        toast('PromptWall blocked file drops into ' + SITE + ' by policy. Recording evidence...');
        updateEvidenceToast(
          reportBlockedBrowserAction('drop', actionRule),
          'action_blocked',
          'PromptWall blocked file drops into ' + SITE + ' by policy and recorded the decision.',
          'PromptWall blocked file drops into ' + SITE + ' by policy. Control-plane evidence was not recorded yet.',
        );
        return;
      }
      scanFiles(files, e);
    }
  }, true);
  document.addEventListener('change', (e) => {
    if (!ENABLED) return;
    if (e.target && e.target.type === 'file' && e.target.files && e.target.files.length) scanFiles(e.target.files, e);
  }, true);
  function scanFiles(files, e) {
    try { e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); } catch (_) {}
    if (destinationBlocked()) {
      const reports = [...files].map(() => reportBlockedDestination('file_upload'));
      toast('PromptWall blocked file uploads to ' + SITE + ' by policy. Recording evidence...');
      updateBatchEvidenceToast(
        reports,
        'destination_blocked',
        'PromptWall blocked file uploads to ' + SITE + ' by policy and recorded the decision.',
        'PromptWall blocked file uploads to ' + SITE + ' by policy. Control-plane evidence was not recorded yet.',
      );
      return;
    }
    if (fileUploadBlocked()) {
      const reports = [...files].map(() => reportBlockedFileUpload());
      toast('PromptWall blocked file uploads to ' + SITE + ' by file policy. Recording evidence...');
      updateBatchEvidenceToast(
        reports,
        'file_upload_blocked',
        'PromptWall blocked file uploads to ' + SITE + ' by file policy and recorded the decision.',
        'PromptWall blocked file uploads to ' + SITE + ' by file policy. Control-plane evidence was not recorded yet.',
      );
      return;
    }
    [...files].forEach(scanOneFile);
  }
  function scanOneFile(f) {
    if (f.size > 6_300_000) {
      reportUnscannedFile(f.name, 'file_too_large', 'blocked locally: file too large to inspect');
      toast('PromptWall blocked ' + f.name + ': file is too large to inspect.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => sendFileScan(f.name, new Uint8Array(reader.result || []));
    reader.readAsArrayBuffer(f);
  }
  function sendFileScan(filename, bytes) {
    chrome.runtime.sendMessage({
      type: 'scanFile',
      payload: {
        filename,
        contentBase64: bytesToBase64(bytes),
        destination: SITE,
        channel: 'file_upload',
        source: 'browser_extension',
      },
    }, (res) => handleFileScanResponse(filename, res));
  }
  function handleFileScanResponse(filename, res) {
    if (!res) {
      toast('PromptWall could not verify ' + filename + '. Upload blocked.');
      return;
    }
    const items = (res.findings || []).map((x) => x.type).concat(res.categories || []);
    if (res.decision === 'allow' && res.supported !== false) {
      toast('PromptWall scanned ' + filename + ' clean. Attach it again to upload.');
    } else if (res.status === 'ocr_required') {
      toast('PromptWall blocked ' + filename + ': OCR is required before inspection.');
    } else if (res.status === 'scan_unavailable') {
      toast('PromptWall could not verify ' + filename + '. Upload blocked until the control plane is reachable.');
    } else if (res.supported === false || res.inspected === false) {
      toast('PromptWall could not inspect ' + filename + '. Upload blocked and recorded.');
    } else {
      toast('PromptWall blocked ' + filename + ': ' + listForScreen(items.slice(0, 3)));
    }
  }
  function reportUnscannedFile(filename, outcome, note) {
    chrome.runtime.sendMessage({
      type: 'report',
      payload: {
        prompt: '[file blocked unscanned] ' + filename,
        destination: SITE,
        channel: 'file_upload',
        source: 'browser_extension',
        categories: [],
        outcome,
        note,
      },
    });
  }
  function bytesToBase64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  // ---- tiny toast -----------------------------------------------------------
  let toastEl;
  function toast(msg) {
    if (toastEl) toastEl.remove();
    toastEl = document.createElement('div');
    toastEl.className = 'ps-toast';
    toastEl.textContent = msg;
    document.body.appendChild(toastEl);
    setTimeout(() => { if (toastEl) { toastEl.remove(); toastEl = null; } }, 4200);
  }

  console.log('[PromptWall] active on ' + SITE + ' — pre-send inspection enabled.');
})();
