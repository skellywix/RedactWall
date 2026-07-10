
(function () {
  'use strict';
  if (window.__redactwallLoaded) return;
  window.__redactwallLoaded = true;

  const D = window.PSDetect;
  const Ext = window.PWBrowserApi;
  const SITE = location.hostname;
  const MANDATORY_ALWAYS_BLOCK = ('US_SSN CREDIT_CARD BANK_ACCOUNT ROUTING_NUMBER IBAN US_PASSPORT '
    + 'US_ITIN US_NPI MEMBER_ID LOAN_NUMBER MEDICAL_RECORD_NUMBER HEALTH_INSURANCE_ID UK_NINO UK_NHS_NUMBER '
    + 'CANADA_SIN AUSTRALIA_TFN INDIA_AADHAAR SECRET_KEY PRIVATE_KEY CANARY_TOKEN EXACT_MATCH').split(' ');
  function normalizeSensorPolicy(value = {}) {
    const configured = Array.isArray(value.alwaysBlock) ? value.alwaysBlock : [];
    return {
      ...value,
      alwaysBlock: [...new Set([...MANDATORY_ALWAYS_BLOCK, ...configured]
        .filter((type) => typeof type === 'string' && type.trim())
        .map((type) => type.trim().toUpperCase()))],
    };
  }
  let POLICY = normalizeSensorPolicy({ enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, allowedDestinations: [], blockedBrowserActions: [], blockUnapprovedAiDestinations: true });
  let ENABLED = true;
  let ENABLED_LOCKED = false;
  let POLICY_TRUSTED = false;
  let POLICY_EXPIRES_AT = 0;

  function applyRuntimeConfig(res) {
    if (res && res.policy) POLICY = normalizeSensorPolicy(res.policy);
    if (res && typeof res.enabled === 'boolean') ENABLED = res.enabled;
    ENABLED_LOCKED = !!(res && res.enabledLocked);
    POLICY_TRUSTED = !!(res && res.policyTrusted);
    POLICY_EXPIRES_AT = Date.parse((res && res.policyExpiresAt) || '') || 0;
  }
  function trustedPolicyAvailable() { return POLICY_TRUSTED && POLICY_EXPIRES_AT > Date.now(); }
  function requireTrustedPolicy(e, action) {
    if (trustedPolicyAvailable()) return true;
    stopEvent(e); toast('RedactWall blocked this ' + action + ' because no fresh verified policy is available.');
    return false;
  }
  function refreshRuntimeConfig() {
    return Ext.sendMessage({ type: 'getConfig' }).then((res) => { applyRuntimeConfig(res); return res; });
  }

  refreshRuntimeConfig().then(scheduleAccountProbe);





  let ACCOUNT = { type: 'unknown', signal: 'none' };
  let accountCoached = false;
  const ACCOUNT_EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  function probeAccount() {
    try {
      const A = window.PSAdapters;
      if (!A || !A.accountMarkersFor || !A.accountMarkersFor(SITE)) return;
      const nodes = document.querySelectorAll(
        '[aria-label*="account" i],[data-testid*="account" i],[data-testid*="profile" i],[class*="workspace" i],[class*="account" i],header,nav',
      );
      const emails = new Set();
      let badgeText = '';
      let count = 0;
      for (const el of nodes) {
        if (count++ > 20) break;
        const t = ((el.getAttribute && el.getAttribute('aria-label')) || '') + ' ' + ((el.textContent || '').slice(0, 512));
        badgeText += ' ' + t;
        const found = t.match(ACCOUNT_EMAIL_RE);
        if (found) for (const e of found) emails.add(e);
      }
      const orgDomains = (POLICY.corporateAiAccounts && POLICY.corporateAiAccounts.orgEmailDomains) || [];
      ACCOUNT = A.classifyAccount({ host: SITE, emails: [...emails], badgeText }, orgDomains);
      maybeCoachAccount();
    } catch (_) {  }
  }
  function scheduleAccountProbe() {
    probeAccount();
    setTimeout(probeAccount, 2000);
    setTimeout(probeAccount, 6000);
    setTimeout(probeAccount, 15000);
  }
  let lastFocusProbe = 0;
  if (typeof window.addEventListener === 'function') {
    window.addEventListener('focus', () => {
      const now = Date.now();
      if (now - lastFocusProbe < 300000) return;
      lastFocusProbe = now;
      probeAccount();
    });
  }
  function personalAccountAction() {
    return (POLICY.corporateAiAccounts && POLICY.corporateAiAccounts.personalAccountAction) || 'allow';
  }
  function maybeCoachAccount() {
    if (accountCoached || ACCOUNT.type !== 'personal') return;
    if (personalAccountAction() !== 'coach') return;
    accountCoached = true;
    showAccountCoach();
  }
  function showAccountCoach() {
    try {
      const el = document.createElement('div');
      el.className = 'ps-account-coach';
      el.textContent = 'RedactWall: you appear to be signed into a personal account on this AI site. '
        + 'Use your corporate workspace account for work data.';
      el.style.cssText = 'position:fixed;bottom:16px;right:16px;max-width:320px;z-index:2147483647;'
        + 'background:#3b2f00;color:#ffe9a8;border:1px solid #7a5c00;border-radius:8px;padding:12px 14px;'
        + 'font:13px/1.4 system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.3)';
      document.documentElement.appendChild(el);
      setTimeout(() => { try { el.remove(); } catch (_) {} }, 12000);
    } catch (_) {  }
  }
  Ext.addRuntimeMessageListener((msg, sender, sendResponse) => {
    if (!msg || msg.type !== 'getPolicyState') return false;
    sendResponse({
      enabled: ENABLED,
      policyTrusted: trustedPolicyAvailable(),
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
  Ext.addStorageChangeListener((c, areaName) => {
    if (areaName === 'managed' || (c.enabled && ENABLED_LOCKED)) {
      refreshRuntimeConfig().catch(() => {});
    } else if (c.enabled) {
      ENABLED = c.enabled.newValue;
    }
    if (c.policy || c.policyBundle || c.policyExpiresAt) refreshRuntimeConfig().catch(() => {});
  });


  const SELECTORS = [
    'textarea#prompt-textarea', 'div#prompt-textarea[contenteditable="true"]',
    'div[contenteditable="true"].ProseMirror',
    'textarea[aria-label]', 'div[contenteditable="true"][role="textbox"]',
    'textarea', 'div[contenteditable="true"]',
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
  function stopEvent(e) { e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); }
  function readText(el) {
    if (!el) return '';
    return (el.value !== undefined ? el.value : el.innerText || el.textContent || '').trim();
  }


  function detectionPolicy() {
    const hardStops = new Set(POLICY.alwaysBlock || []);
    return {
      ignore: (POLICY.ignore || []).filter((type) => !hardStops.has(type)),
      disabledDetectors: (POLICY.disabledDetectors || []).filter((type) => !hardStops.has(type)),
      customDetectors: POLICY.customDetectors || [],
      exactMatch: POLICY.exactMatch,
      opaqueEncodedContent: true,
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
      ...(POLICY.blockedBrowserActions || []).flatMap((rule) => (
        rule && rule.enabled !== false && String(rule.action || '').trim() ? (rule.destinations || []) : []
      )),
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
    if (a.opaqueEncoded === true) return { action: 'block', analysis: a };
    if (!a.findings.length && !a.categories.length) return { action: 'allow', analysis: a };
    const hardStop = a.findings.some((f) => (POLICY.alwaysBlock || []).includes(f.type));

    if ((POLICY.enforcementMode || 'block') === 'redact') {
      return { action: (a.findings.length && !a.categories.length) ? 'redact' : 'block', analysis: a };
    }
    const breach = hardStop || a.maxSeverity >= POLICY.blockMinSeverity || a.riskScore >= POLICY.blockRiskScore;
    if (!breach) return { action: 'allow', analysis: a };
    const mode = hardStop ? 'block' : (POLICY.enforcementMode || 'block');
    return { action: mode, analysis: a };
  }

  function summarize(a) {
    const items = a.findings.map((f) => f.type).concat(a.categories.map((c) => c.category));
    if (a.opaqueEncoded === true) items.push('OPAQUE_ENCODED_CONTENT');
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
    OPAQUE_ENCODED_CONTENT: 'encoded content that could not be inspected',
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
    FINANCIAL_STATEMENT: 'financial statement',
    TAX_FILING: 'tax filing',
    HR_RECORD: 'HR record',
  };

  const COACHING = {
    US_SSN: 'Use a member ID, the last four digits, or a synthetic example instead.',
    SOURCE_CODE: 'Use an approved code-review workflow before sending proprietary code.',
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
    const first = (items || [])[0];
    for (const item of items || []) if (COACHING[item]) return COACHING[item];
    if ((items || []).some((item) => /KEY|PASSWORD|CREDENTIAL/.test(item || ''))) {
      return 'Remove this credential and rotate it if it may have been exposed.';
    }
    const label = labelFor(first);
    return 'Remove ' + label + ', use a placeholder, or request approval with a business reason.';
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


  function publicFindings(analysis) {
    return (analysis.findings || []).map((f) => ({
      type: f.type,
      severity: f.severity,
      score: f.score,
      masked: D.maskValue(f.type, f.value),
      ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}),
    }));
  }
  function publicCategories(analysis) {
    return (analysis.categories || []).map((c) => ({ category: c.category, score: c.score }));
  }
  function safeClientPrompt(text, analysis) {
    const items = summarize(analysis);
    if (analysis.opaqueEncoded === true) return '[REDACTED: OPAQUE_ENCODED_CONTENT]';
    if ((analysis.categories || []).length) return '[REDACTED: ' + items.join(', ') + ']';
    return D.redact(text, analysis.findings || []);
  }
  function report(text, analysis, channel, outcome, note, extra) {
    return new Promise((resolve) => {
      try {
        Ext.sendMessage({
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
            clientAccount: { type: ACCOUNT.type, signal: ACCOUNT.signal },
            outcome, note: note || '',
            ...(extra || {}),
          },
        }).then((res) => resolve(res || null)).catch(() => resolve(null));
      } catch (_) {
        resolve(null);
      }
    });
  }

  function recordedProceedResponse(res, outcome) {
    if (!res || typeof res !== 'object' || !res.id) return false;
    if (outcome === 'allowed') return res.decision === 'allow' && (res.status == null || res.status === 'allowed');
    if (outcome === 'sent_after_warning') return res.status === 'warned_sent' && res.decision === 'block';
    if (outcome === 'justified') return res.status === 'justified' && res.decision === 'block';
    if (outcome === 'redacted_sent') return res.status === 'redacted' && res.decision === 'redact';
    return false;
  }
  function recordedEvidenceResponse(res, expectedStatus) {
    if (!res || typeof res !== 'object' || !res.id) return false;
    if (expectedStatus === 'allowed' && res.decision === 'allow') {
      return res.status == null || res.status === 'allowed';
    }
    return res.status === expectedStatus;
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

  function trackPolicyBlock(report, status, message, batch = false) {
    toast(message + '. Recording evidence...');
    const update = batch ? updateBatchEvidenceToast : updateEvidenceToast;
    update(report, status, message + ' and recorded the decision.',
      message + '. Control-plane evidence was not recorded yet.');
  }

  const composerReservations = new WeakMap();
  function releaseComposerReservation(reservation) {
    if (!reservation || composerReservations.get(reservation.el) !== reservation) return false;
    composerReservations.delete(reservation.el);
    return true;
  }
  function reserveComposer(el, text) {
    const current = composerReservations.get(el);
    if (current) {
      if (el && el.isConnected === true && readText(el) === current.expectedText) return null;
      releaseComposerReservation(current);
    }
    const reservation = { el, expectedText: text };
    composerReservations.set(el, reservation);
    return reservation;
  }
  function ownsComposerReservation(reservation) {
    return !!reservation && composerReservations.get(reservation.el) === reservation;
  }
  function updateComposerReservation(reservation, text) {
    if (!ownsComposerReservation(reservation)) return false;
    reservation.expectedText = text;
    return true;
  }
  function releaseReservationWhenSettled(promise, reservation) {
    Promise.resolve(promise).then(
      () => releaseComposerReservation(reservation),
      () => releaseComposerReservation(reservation),
    );
  }

  async function proceedAfterRecorded(text, analysis, outcome, note, el, reservation) {
    const res = await report(text, analysis, 'submit', outcome, note);
    if (!recordedProceedResponse(res, outcome)) {
      releaseComposerReservation(reservation);
      toast('RedactWall could not record this decision. Send blocked until the control plane is reachable.');
      return;
    }
    resumeUnchangedComposer(el, text, reservation);
  }

  async function resolveServerJustification(hold, text, el, outcome, note, reservation) {
    let result = null;
    try {
      result = await Ext.sendMessage({
        type: 'resolveJustification',
        id: String(hold.id),
        releaseToken: String(hold.releaseToken),
        outcome,
        note: note || '',
      });
    } catch (_) {  }
    const expectedDecision = outcome === 'justified' ? 'allow' : 'block';
    const recorded = result && result.id === String(hold.id)
      && result.status === outcome && result.decision === expectedDecision;
    if (!recorded) {
      toast('RedactWall could not record this justification decision. Prompt not sent.');
      return false;
    }
    if (outcome === 'blocked_by_user') {
      releaseComposerReservation(reservation);
      toast('Cancellation recorded. Prompt not sent.');
      return true;
    }
    resumeUnchangedComposer(el, text, reservation);
    return true;
  }

  async function proceedAllowedAfterServer(text, analysis, el, reservation) {
    const res = await report(text, analysis, 'submit', 'allowed');
    if (recordedProceedResponse(res, 'allowed')) {
      resumeUnchangedComposer(el, text, reservation);
      return;
    }
    if (showServerPolicyChallenge(res, text, analysis, el, reservation)) return;
    if (beginApprovalWait(res, text, el, reservation, 'Security Admin approval required.')) return;
    releaseComposerReservation(reservation);
    toast('Send not confirmed; blocked.');
  }

  function serverEvidenceItems(res, fallbackAnalysis) {
    const items = [];
    for (const finding of (res && Array.isArray(res.findings) ? res.findings : [])) {
      if (finding && typeof finding.type === 'string') items.push(finding.type);
    }
    for (const category of (res && Array.isArray(res.categories) ? res.categories : [])) {
      const id = typeof category === 'string' ? category : (category && category.category);
      if (typeof id === 'string') items.push(id);
    }
    return items.length ? [...new Set(items)] : summarize(fallbackAnalysis);
  }

  function showServerPolicyChallenge(res, text, analysis, el, reservation) {
    if (!res || typeof res !== 'object' || !res.id) return false;
    const warning = res.status === 'warned' && res.decision === 'warn';
    const justification = res.status === 'pending_justification'
      && res.mode === 'justify'
      && typeof res.releaseToken === 'string'
      && res.releaseToken.length > 0;
    if (!warning && !justification) return false;
    const items = serverEvidenceItems(res, analysis);
    const risk = Math.max(0, Math.min(100, Number(res.riskScore) || Number(analysis.riskScore) || 0));
    const onBlock = () => {
      if (justification) return resolveServerJustification(res, text, el, 'blocked_by_user', '', reservation);
      const reportPromise = report(text, analysis, 'submit', 'blocked_by_user');
      releaseReservationWhenSettled(reportPromise, reservation);
      return reportPromise;
    };
    showBanner({
      mode: warning ? 'warn' : 'justify',
      items,
      risk,
      justify: justification,
      onReplace: justification ? onBlock : null,
      onDismiss: () => releaseComposerReservation(reservation),
      onProceed: (note) => (justification
        ? resolveServerJustification(res, text, el, 'justified', note, reservation)
        : proceedAfterRecorded(text, analysis, 'sent_after_warning', note, el, reservation)),
      onBlock,
    });
    return true;
  }


  const pendingRedacted = new WeakMap();

  const APPROVAL_POLL_MS = 2000;
  const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
  const pendingApprovals = new Set();

  function approvalFor(el) {
    for (const pending of pendingApprovals) if (pending.el === el) return pending;
    return null;
  }
  function clearApprovalWait(pending) {
    if (!pendingApprovals.delete(pending)) return;
    if (pending.timer != null) clearTimeout(pending.timer);
  }

  function scheduleApprovalPoll(pending) {
    if (!pendingApprovals.has(pending) || pending.timer != null) return;
    pending.timer = setTimeout(() => {
      pending.timer = null;
      pollApprovalStatus(pending);
    }, APPROVAL_POLL_MS);
  }

  function beginApprovalWait(res, text, el, reservation, message) {
    if (!res || !res.id || !['pending', 'pending_justification'].includes(res.status) || !res.releaseToken) return false;
    const pending = {
      id: String(res.id),
      releaseToken: String(res.releaseToken),
      text,
      el,
      reservation,
      startedAt: Date.now(),
      timer: null,
    };
    pendingApprovals.add(pending);
    toast(message || 'Sent to your Security Admin for approval.');
    scheduleApprovalPoll(pending);
    return true;
  }

  function unchangedLiveComposer(el, expectedText) {
    if (!el || el.isConnected !== true || !isVisible(el) || readText(el) !== expectedText) return null;
    return el;
  }

  function resumeUnchangedComposer(el, expectedText, reservation) {
    if (!ownsComposerReservation(reservation)) return false;
    const live = unchangedLiveComposer(el, expectedText);
    if (!live) {
      releaseComposerReservation(reservation);
      toast('Did not send: prompt changed or composer replaced.');
      return false;
    }
    const sent = resend(live);
    releaseComposerReservation(reservation);
    if (sent) return true;
    toast('Send button unavailable; prompt not sent.');
    return false;
  }

  async function pollApprovalStatus(pending) {
    if (!pendingApprovals.has(pending)) return;
    if (Date.now() - pending.startedAt >= APPROVAL_TIMEOUT_MS) {
      clearApprovalWait(pending);
      releaseComposerReservation(pending.reservation);
      toast('Approval timed out. Prompt not sent.');
      return;
    }
    let res = null;
    try {
      res = await Ext.sendMessage({
        type: 'approvalStatus', id: pending.id, releaseToken: pending.releaseToken,
      });
    } catch (_) {  }
    if (!pendingApprovals.has(pending)) return;
    if (res && res.released === true && (res.status === 'approved' || res.status === 'allowed')) {
      clearApprovalWait(pending);
      if (resumeUnchangedComposer(pending.el, pending.text, pending.reservation)) {
        toast('Approval granted. Sending unchanged prompt.');
      }
      return;
    }
    if (res && ['denied', 'rejected', 'expired', 'cancelled'].includes(res.status)) {
      clearApprovalWait(pending);
      releaseComposerReservation(pending.reservation);
      toast('Approval denied. Prompt not sent.');
      return;
    }
    scheduleApprovalPoll(pending);
  }

  function validRehydrationChannel(value) {
    return typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
  }

  function discardRehydration(channel) {
    if (!validRehydrationChannel(channel)) return;
    Promise.resolve(Ext.sendMessage({ type: 'rehydrationDiscard', channel, site: SITE })).catch(() => {});
  }

  async function openRehydrationSurface(channel) {
    if (!validRehydrationChannel(channel)) return false;
    let result = null;
    try {
      result = await Ext.sendMessage({ type: 'rehydrationOpen', channel, site: SITE });
    } catch (_) {  }
    if (result && result.ok === true) return true;
    toast('RedactWall sent tokens safely, but the isolated reveal page is no longer available.');
    return false;
  }

  async function storeRehydrationMapping(map) {
    const entries = Object.keys(map || {}).map((token) => ({ token, value: map[token] }));
    let result = null;
    try {
      result = await Ext.sendMessage({ type: 'rehydrationStore', site: SITE, entries });
    } catch (_) {  }
    finally {
      for (const entry of entries) { entry.token = ''; entry.value = ''; }
      for (const token of Object.keys(map || {})) { map[token] = ''; delete map[token]; }
    }
    return result && result.ok === true && validRehydrationChannel(result.channel) ? result.channel : null;
  }

  async function beginRedactedSend(tokenized, analysis, el, reservation) {
    const originalText = reservation.expectedText;
    const tokenText = tokenized.text;
    const channel = await storeRehydrationMapping(tokenized.map);
    if (!ownsComposerReservation(reservation)) {
      discardRehydration(channel);
      return;
    }
    if (!channel) {
      releaseComposerReservation(reservation);
      toast('RedactWall could not prepare the isolated reveal page. Prompt not sent.');
      return;
    }
    if (!unchangedLiveComposer(el, originalText)) {
      discardRehydration(channel);
      releaseComposerReservation(reservation);
      toast('Did not send: prompt changed or composer replaced.');
      return;
    }
    try {
      setComposerText(el, tokenText, reservation);
    } catch (_) {
      if (ownsComposerReservation(reservation)) {
        try { setComposerText(el, originalText, reservation); } catch (_) {  }
      }
      discardRehydration(channel);
      releaseComposerReservation(reservation);
      toast('RedactWall could not replace the prompt with tokens. Prompt not sent.');
      return;
    }
    toast('RedactWall tokenized sensitive values before sending. Originals stay in a separate extension page and appear only when you reveal them.');
    void proceedRedactedAfterRecorded(tokenText, analysis, el, reservation, channel).catch(() => {
      discardRehydration(channel);
      releaseComposerReservation(reservation);
      toast('RedactWall could not record the tokenized send. Prompt not sent.');
    });
  }

  async function proceedRedactedAfterRecorded(tokenText, analysis, el, reservation, channel) {
    const retry = { text: tokenText, analysis, channel };
    pendingRedacted.set(el, retry);
    const res = await report(tokenText, analysis, 'submit', 'redacted_sent', '', { clientPreRedacted: true });
    if (!recordedProceedResponse(res, 'redacted_sent')) {
      releaseComposerReservation(reservation);
      toast('Held until the control plane is reachable; retry send.');
      return;
    }
    if (pendingRedacted.get(el) === retry) pendingRedacted.delete(el);
    if (resumeUnchangedComposer(el, tokenText, reservation)) void openRehydrationSurface(channel);
    else discardRehydration(channel);
  }

  async function sendApprovalRequest(text, analysis, el, reservation) {
    const res = await report(text, analysis, 'submit', 'awaiting_approval');
    if (beginApprovalWait(res, text, el, reservation)) return;
    releaseComposerReservation(reservation);
    toast('Approval request failed. Prompt not sent.');
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





  const ENDPOINT_INTENT_OUTCOMES = new Set(['file_too_large', 'ocr_required', 'file_unsupported', 'scan_unavailable']);

  function sendEndpointFileIntent(file, outcome) {
    if (!ENDPOINT_INTENT_OUTCOMES.has(outcome)) return;
    try {
      Promise.resolve(Ext.sendMessage({
        type: 'fileIntent',
        payload: {
          fileName: String((file && file.name) || '').slice(0, 255),
          sizeBytes: Number((file && file.size) || 0),
        },
      })).catch(() => {});
    } catch (_) {  }
  }

  function reportLocalFileEvent(file, outcome) {
    sendEndpointFileIntent(file, outcome);
    return report('[browser file blocked] ' + fileLabel(file), emptyAnalysis(), 'file_upload', outcome,
      'blocked locally: ' + outcome.replace(/_/g, ' '));
  }

  function trackFileBlock(reportPromise, status, file, detail, noteMissingEvidence = false) {
    const message = 'RedactWall blocked ' + file.name + ': ' + detail;
    toast(message + '.');
    updateEvidenceToast(reportPromise, status, message + ' and evidence was recorded.',
      message + (noteMissingEvidence ? '. Control-plane evidence was not recorded yet.' : '.'));
  }


  let banner, bannerState, bannerId = 0;
  const bannerQueue = [];
  function clearBanner(state) {
    if (state && state !== bannerState) return;
    if (banner) banner.remove();
    banner = null; bannerState = null;
  }
  function setBannerBusy(state, busy) {
    state.busy = busy;
    for (const button of state.buttons) button.disabled = busy;
  }
  function runBannerAction(state, action) {
    if (state.onReplace) void settleBanner(state, action);
    else { clearBanner(state); action(); }
  }
  function showQueuedBanner() {
    const next = bannerQueue.shift();
    if (!next) return;
    showBanner(next);
    if (!bannerQueue.length) return;
    if (bannerState.onReplace) void settleBanner(bannerState, bannerState.onReplace);
    else {
      const displaced = bannerState;
      clearBanner(displaced);
      if (displaced.onDismiss) displaced.onDismiss();
      showQueuedBanner();
    }
  }
  async function settleBanner(state, action) {
    if (state !== bannerState || state.busy) return false;
    setBannerBusy(state, true);
    let recorded = false;
    try { recorded = (await action()) === true; } catch (_) {}
    if (state !== bannerState) return recorded;
    setBannerBusy(state, false);
    if (!recorded) return false;
    clearBanner(state); showQueuedBanner();
    return true;
  }
  function showBanner(options) {
    if (bannerState && bannerState.onReplace) {
      bannerQueue.push(options);
      void settleBanner(bannerState, bannerState.onReplace);
      return;
    }
    if (bannerState) {
      const displaced = bannerState;
      clearBanner(displaced);
      if (displaced.onDismiss) displaced.onDismiss();
    }
    const { mode, items, risk, onProceed, onBlock, justify, onReplace, onDismiss } = options;
    banner = document.createElement('div');
    const state = bannerState = { busy: false, buttons: [], onReplace, onDismiss };
    const idBase = 'ps_banner_' + (++bannerId);
    const titleId = idBase + '_title';
    const detailId = idBase + '_detail';
    banner.className = 'ps-banner ps-' + mode;
    banner.tabIndex = -1;
    banner.setAttribute('role', 'alertdialog');
    banner.setAttribute('aria-labelledby', titleId);
    banner.setAttribute('aria-describedby', detailId);
    const title = mode === 'block' ? 'Sensitive data blocked' : mode === 'justify' ? 'Business reason required' : 'Review before sending';
    const detail = mode === 'block'
      ? 'RedactWall found ' + listForScreen(items) + ' before it could leave this browser.'
      : 'RedactWall found ' + listForScreen(items) + ' in this prompt. Review it before sending to ' + SITE + '.';
    const riskText = mode === 'block' ? '' : ' Risk ' + risk + '/100.';
    banner.innerHTML =
      '<div class="ps-row"><span class="ps-status-dot" aria-hidden="true"></span>' +
      '<div class="ps-msg"><div class="ps-title" id="' + titleId + '">' + escapeHtml(title) + '</div>' +
      '<div class="ps-detail" id="' + detailId + '">' + escapeHtml(detail + riskText) + '</div></div>' +
      '<button class="ps-x" aria-label="Dismiss">x</button></div>' +
      '<div class="ps-chips">' + chipHtml(items) + '</div>' +
      '<div class="ps-coach">' + escapeHtml(coachingFor(items)) + '</div>' +
      (justify ? '<textarea class="ps-just" aria-label="Business reason" aria-describedby="' + detailId + '" aria-invalid="false" placeholder="Required; recorded for compliance."></textarea>' : '') +
      '<div class="ps-actions"></div>';
    const actions = banner.querySelector('.ps-actions');
    const reasonInput = justify ? banner.querySelector('.ps-just') : null;
    if (reasonInput) {
      reasonInput.addEventListener('input', () => {
        if (reasonInput.value.trim().length >= 4) {
          reasonInput.style.borderColor = '';
          reasonInput.setAttribute('aria-invalid', 'false');
        }
      });
    }
    banner.querySelector('.ps-x').onclick = () => {
      if (justify) runBannerAction(state, onBlock);
      else {
        clearBanner(state);
        if (onDismiss) onDismiss();
      }
    };

    if (mode === 'warn') {
      const edit = btn('ps-secondary', 'Edit prompt', () => {
        clearBanner(state);
        if (onDismiss) onDismiss();
      });
      const go = btn('ps-primary', 'Send anyway', () => runBannerAction(state, onProceed));
      actions.append(edit, go);
    } else if (mode === 'justify') {
      const edit = btn('ps-secondary', 'Cancel', () => runBannerAction(state, onBlock));
      const go = btn('ps-primary', 'Submit reason', () => {
        const note = reasonInput.value.trim();
        if (note.length < 4) {
          reasonInput.style.borderColor = '#dc2626';
          reasonInput.setAttribute('aria-invalid', 'true');
          reasonInput.focus();
          return;
        }
        runBannerAction(state, () => onProceed(note));
      });
      actions.append(edit, go);
    } else {
      const req = btn('ps-secondary', 'Request approval', () => runBannerAction(state, () => onBlock(true)));
      const ok = btn('ps-primary', 'Edit prompt', () => runBannerAction(state, () => onBlock(false)));
      actions.append(req, ok);
    }
    state.buttons = [banner.querySelector('.ps-x'), ...actions.children];
    document.body.appendChild(banner);
    (reasonInput || banner).focus({ preventScroll: true });
  }
  function btn(cls, text, onclick) { const b = document.createElement('button'); b.className = 'ps-btn ' + cls; b.textContent = text; b.onclick = onclick; return b; }


  let sendBypass = null;
  function consumeSendBypass(e, composer) {
    const bypass = sendBypass;
    if (!bypass || bypass.composer !== composer || closestSendButton(e && e.target) !== bypass.button) return false;
    bypass.consumed = true;
    sendBypass = null;
    return true;
  }
  function interceptSend(e, composer) {
    const el = composer || findComposer(e.target);
    if (!ENABLED) return true;
    if (!requireTrustedPolicy(e, 'send')) return false;
    if (consumeSendBypass(e, el)) return true;
    let text = readText(el);
    if (!text) return true;

    if (approvalFor(el)) {
      stopEvent(e);
      toast('Still waiting for Security Admin approval.');
      return false;
    }
    const reservation = reserveComposer(el, text);
    if (!reservation) {
      stopEvent(e);
      toast('RedactWall is already inspecting this unchanged prompt.');
      return false;
    }

    const redactedRetry = pendingRedacted.get(el);
    if (redactedRetry && text === redactedRetry.text.trim()) {
      stopEvent(e);
      proceedRedactedAfterRecorded(redactedRetry.text, redactedRetry.analysis, el, reservation, redactedRetry.channel);
      return false;
    }
    if (redactedRetry) {
      pendingRedacted.delete(el);
      discardRehydration(redactedRetry.channel);
    }
    if (destinationBlocked()) {
      stopEvent(e);
      const reportPromise = reportBlockedDestination('submit');
      releaseReservationWhenSettled(reportPromise, reservation);
      trackPolicyBlock(reportPromise, 'destination_blocked', 'RedactWall blocked sends to ' + SITE + ' by policy');
      return false;
    }
    const A = window.PSAdapters;
    if (A) {
      const inj = A.scanInjection(text);
      if (inj.suspicious) {
        if (inj.reasons.some((r) => /bidi|tag/i.test(r))) {
          stopEvent(e);
          const reportPromise = report(text, { findings: [], categories: [] }, 'submit', 'injection_blocked', inj.reasons.join(', '));
          releaseReservationWhenSettled(reportPromise, reservation);
          toast('RedactWall blocked hidden instructions in this prompt (' + inj.reasons.join(', ') + ').');
          return false;
        }
        text = inj.stripped;
        try {
          setComposerText(el, text, reservation);
        } catch (_) {
          stopEvent(e);
          releaseComposerReservation(reservation);
          toast('RedactWall could not safely normalize this prompt. Send blocked.');
          return false;
        }
      }
    }
    const verdict = evaluate(text);
    if (verdict.analysis.opaqueEncoded === true) {
      stopEvent(e);
      const reportPromise = report(
        safeClientPrompt(text, verdict.analysis),
        verdict.analysis,
        'submit',
        'action_blocked',
        'blocked locally: encoded content could not be inspected',
      );
      releaseReservationWhenSettled(reportPromise, reservation);
      updateEvidenceToast(
        reportPromise,
        'action_blocked',
        'RedactWall blocked encoded content it could not inspect and recorded the decision.',
        'RedactWall blocked encoded content it could not inspect. Control-plane evidence was not recorded yet.',
      );
      toast('RedactWall blocked encoded content it could not inspect.');
      return false;
    }
    if (verdict.action === 'allow') {
      stopEvent(e);
      proceedAllowedAfterServer(text, verdict.analysis, el, reservation);
      return false;
    }

    if (verdict.action === 'redact') {
      stopEvent(e);
      const t = pageScopedTokens(D.tokenize(text, verdict.analysis.findings));
      void beginRedactedSend(t, verdict.analysis, el, reservation).catch(() => {
        releaseComposerReservation(reservation);
        toast('RedactWall could not prepare the tokenized send. Prompt not sent.');
      });
      return false;
    }


    stopEvent(e);
    const items = summarize(verdict.analysis);
    showBanner({
      mode: verdict.action, items, risk: verdict.analysis.riskScore,
      justify: verdict.action === 'justify',
      onDismiss: () => releaseComposerReservation(reservation),
      onProceed: (note) => proceedAfterRecorded(text, verdict.analysis, verdict.action === 'justify' ? 'justified' : 'sent_after_warning', note, el, reservation),
      onBlock: (requestApproval) => {
        if (requestApproval) sendApprovalRequest(text, verdict.analysis, el, reservation);
        else {
          releaseComposerReservation(reservation);
          const reportPromise = report(text, verdict.analysis, 'submit', 'blocked_by_user');
          return reportPromise;
        }
      },
    });
    return false;
  }
  function resend(el) {
    const button = scopedSendButtonForComposer(el);
    if (!button) return false;
    const authorization = { composer: el, button, consumed: false };
    sendBypass = authorization;
    try {
      button.click();
      return authorization.consumed;
    } catch (_) {
      return false;
    } finally {
      if (sendBypass === authorization) sendBypass = null;
    }
  }


  const REHYDRATE_COUNTERS = {};
  function pageScopedTokens(tokenized) {
    let text = tokenized.text;
    const map = {};
    for (const token of Object.keys(tokenized.map || {})) {
      const match = /^\[\[([A-Z][A-Z0-9_]*)_\d+\]\]$/.exec(token);
      if (!match) continue;
      const type = match[1];
      const next = (REHYDRATE_COUNTERS[type] = (REHYDRATE_COUNTERS[type] || 0) + 1);
      const scoped = '[[' + type + '_' + next + ']]';
      text = text.split(token).join(scoped);
      map[scoped] = tokenized.map[token];
    }
    return { text, map, tokens: Object.keys(map).length };
  }
  function setComposerText(el, text, reservation) {
    if (!el) return;
    el.focus();
    if (el.value !== undefined) {
      const d = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
      if (d && d.set) d.set.call(el, text); else el.value = text;
    } else {
      el.textContent = text;
    }
    if (reservation && !updateComposerReservation(reservation, text)) throw new Error('reservation_changed');
    el.dispatchEvent(new InputEvent('input', { bubbles: true, data: text, inputType: 'insertText' }));
  }
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
  function composerFromTarget(target) {
    if (!target || !target.closest) return null;
    return target.closest('textarea, div[contenteditable="true"]');
  }

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing || e.keyCode === 229) return;
    const el = composerFromTarget(e.target);
    if (el && readText(el)) interceptSend(e, el);
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




  function composerNearButton(btn) {
    if (!btn || !btn.closest) return null;
    const form = btn.form || btn.closest('form');
    if (form) return uniqueVisibleComposer(form);
    let scope = btn.parentElement;
    while (scope) {
      const composers = visibleComposers(scope);
      if (composers.length === 1) return composers[0];
      if (composers.length > 1) return null;
      if (scope === document.body || scope === document.documentElement) break;
      scope = scope.parentElement;
    }
    return null;
  }

  function visibleComposers(scope) {
    if (!scope || typeof scope.querySelectorAll !== 'function') return [];
    const found = new Set();
    for (const selector of SELECTORS) {
      try {
        for (const composer of scope.querySelectorAll(selector)) {
          if (composer && composer.isConnected === true && isVisible(composer)) found.add(composer);
        }
      } catch (_) {}
    }
    return [...found];
  }

  function uniqueVisibleComposer(scope) {
    const composers = visibleComposers(scope);
    return composers.length === 1 ? composers[0] : null;
  }

  function sendButtonSelectors() {
    const A = window.PSAdapters;
    return A && A.sendButtonSelectors ? A.sendButtonSelectors(location.hostname)
      : ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]', 'button[aria-label*="Submit" i]', 'button[type="submit"]'];
  }

  function addSendButtons(scope, buttons) {
    if (!scope || typeof scope.querySelectorAll !== 'function') return;
    for (const selector of sendButtonSelectors()) {
      try { for (const button of scope.querySelectorAll(selector)) buttons.add(button); } catch (_) {}
    }
  }

  function scopedSendButtonForComposer(composer) {
    if (!composer) return null;
    const buttons = new Set();
    const form = composer.form || (composer.closest && composer.closest('form'));
    if (form) addSendButtons(form, buttons);
    addSendButtons(document, buttons);
    const matches = [...buttons].filter((button) => (
      button && button.isConnected === true && button.disabled !== true
      && String((button.getAttribute && button.getAttribute('aria-disabled')) || '').toLowerCase() !== 'true'
      && isVisible(button) && composerNearButton(button) === composer
    ));
    return matches.length === 1 ? matches[0] : null;
  }

  document.addEventListener('click', (e) => {
    const btn = closestSendButton(e.target);
    if (!btn) return;
    if (!ENABLED) return;
    const el = composerNearButton(btn);
    if (!el) {
      stopEvent(e);
      toast('RedactWall could not safely associate this send button with one composer. Send blocked for review.');
      return;
    }
    if (el && readText(el)) interceptSend(e, el);
  }, true);


  document.addEventListener('paste', (e) => {
    if (!ENABLED) return;
    if (!requireTrustedPolicy(e, 'paste')) return;
    const actionRule = browserActionBlockRule('paste');
    if (actionRule) {
      stopEvent(e);
      reportBlockedBrowserAction('paste', actionRule);
      toast('RedactWall blocked paste into ' + SITE + ' by policy.');
      return;
    }
    const t = (e.clipboardData || window.clipboardData);

    const files = clipboardFiles(t);
    if (files.length) { scanFiles(files, e); return; }
    const pasted = t ? t.getData('text') : '';
    if (!pasted || pasted.length < 6) return;
    const verdict = evaluate(pasted);
    if (verdict.action !== 'allow') {
      const items = summarize(verdict.analysis).slice(0, 3);
      if (verdict.action === 'block') {
        stopEvent(e);
        const opaqueEncoded = verdict.analysis.opaqueEncoded === true;
        const reportPromise = report(
          safeClientPrompt(pasted, verdict.analysis),
          verdict.analysis,
          'paste',
          opaqueEncoded ? 'action_blocked' : 'paste_flagged',
          opaqueEncoded
            ? 'blocked locally: encoded paste could not be inspected'
            : 'blocked locally: sensitive paste prevented before insertion',
          opaqueEncoded ? undefined : { clientPreRedacted: true },
        );
        toast('RedactWall blocked sensitive paste: ' + listForScreen(items) + '. Recording evidence...');
        updateEvidenceToast(
          reportPromise,
          'paste_flagged',
          'RedactWall blocked sensitive paste and recorded the decision.',
          'RedactWall blocked sensitive paste. Control-plane evidence was not recorded yet.',
        );
        return;
      }
      report(pasted, verdict.analysis, 'paste', 'paste_flagged');
      toast('RedactWall found sensitive data: ' + listForScreen(items));
    }
  }, true);


  document.addEventListener('copy', (e) => {
    if (!ENABLED) return;
    if (copyOriginInComposerOrUI(e)) return;
    const actionRule = browserActionBlockRule('copy');
    if (actionRule) {
      stopEvent(e);
      trackPolicyBlock(reportBlockedBrowserAction('copy', actionRule), 'action_blocked',
        'RedactWall blocked copy from ' + SITE + ' by policy');
    }
  }, true);


  document.addEventListener('drop', (e) => {
    if (!ENABLED) return;
    if (!requireTrustedPolicy(e, 'drop')) return;
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      const actionRule = browserActionBlockRule('drop');
      if (actionRule) {
        stopEvent(e);
        trackPolicyBlock(reportBlockedBrowserAction('drop', actionRule), 'action_blocked',
          'RedactWall blocked file drops into ' + SITE + ' by policy');
        return;
      }
      scanFiles(files, e);
    }
  }, true);
  document.addEventListener('change', (e) => {
    if (!ENABLED) return;
    const input = e.target;
    if (!input || input.type !== 'file' || !input.files || !input.files.length) return;
    if (!requireTrustedPolicy(e, 'upload')) {
      clearFileInput(input);
      return;
    }
    scanFiles(input.files, e);
  }, true);

  function clearFileInput(input) {
    try {
      input.value = '';
      if (input.files && input.files.length && typeof DataTransfer === 'function') {
        input.files = new DataTransfer().files;
      }
    } catch (_) {  }
  }



  function clipboardFiles(data) {
    if (!data) return [];
    if (data.files && data.files.length) return [...data.files];
    const items = data.items ? [...data.items] : [];
    const out = [];
    for (const item of items) {
      if (item && item.kind === 'file' && typeof item.getAsFile === 'function') {
        const file = item.getAsFile();
        if (file) out.push(file);
      }
    }
    return out;
  }
  const MAX_BROWSER_FILE_BYTES = 6_300_000;
  const TEXT_UPLOAD_EXTENSIONS = new Set(('.txt .text .csv .tsv .json .jsonl .ndjson .xml .html .htm '
    + '.md .markdown .log .ini .conf .cfg .env .yaml .yml .js .jsx .ts .tsx .mjs .cjs .css .scss .less '
    + '.py .rb .php .java .kt .kts .go .rs .c .cc .cpp .h .hpp .cs .swift .scala .sh .bash .zsh .ps1 .bat .cmd .sql').split(' '));
  const TEXT_UPLOAD_MIME_TYPES = new Set(('application/json application/ld+json application/xml application/javascript '
    + 'application/x-javascript application/typescript application/x-typescript application/x-ndjson application/yaml application/x-yaml').split(' '));
  const OCR_UPLOAD_EXTENSIONS = new Set('.png .jpg .jpeg .tif .tiff .bmp .webp .gif'.split(' '));
  const cleanUploadBypass = new WeakSet();

  function stopFileEvent(e) {
    try { stopEvent(e); } catch (_) {}
  }

  function clearBlockedFileInput(e) {
    const input = e && e.target;
    if (input && input.type === 'file') clearFileInput(input);
  }

  function restoreFileInput(input, files) {
    if (!input || input.type !== 'file') return true;
    if (typeof DataTransfer !== 'function') return false;
    try {
      const transfer = new DataTransfer();
      for (const file of files) transfer.items.add(file);
      input.files = transfer.files;
      return input.files.length === files.length && files.every((file, index) => input.files[index] === file);
    } catch (_) {
      clearFileInput(input);
      return false;
    }
  }

  function replayCleanFileEvent(files, e) {
    const target = e && e.target;
    if (!target || typeof target.dispatchEvent !== 'function' || typeof Event !== 'function') return false;
    const list = [...files];
    if (!restoreFileInput(target, list)) return false;
    list.forEach(rememberCleanUpload);
    try {
      const replay = new Event(e.type || 'change', { bubbles: true, cancelable: true });
      if (e.dataTransfer) Object.defineProperty(replay, 'dataTransfer', { value: e.dataTransfer });
      if (e.clipboardData) Object.defineProperty(replay, 'clipboardData', { value: e.clipboardData });
      target.dispatchEvent(replay);
      return true;
    } catch (_) {
      consumeCleanUploadBypass(list);
      clearBlockedFileInput(e);
      return false;
    }
  }

  function scanFiles(files, e) {
    const list = [...files];
    if (destinationBlocked()) {
      stopFileEvent(e);
      clearBlockedFileInput(e);
      const reports = list.map(() => reportBlockedDestination('file_upload'));
      trackPolicyBlock(reports, 'destination_blocked',
        'RedactWall blocked file uploads to ' + SITE + ' by policy', true);
      return;
    }
    if (fileUploadBlocked()) {
      stopFileEvent(e);
      clearBlockedFileInput(e);
      const reports = list.map(() => reportBlockedFileUpload());
      trackPolicyBlock(reports, 'file_upload_blocked',
        'RedactWall blocked file uploads to ' + SITE + ' by file policy', true);
      return;
    }
    if (filesHaveCleanBypass(list)) {
      consumeCleanUploadBypass(list);
      return;
    }
    stopFileEvent(e);
    clearBlockedFileInput(e);
    let remaining = list.length;
    let allClean = true;
    const finished = (clean) => {
      allClean = allClean && clean === true;
      remaining -= 1;
      if (remaining > 0) return;
      if (allClean && replayCleanFileEvent(list, e)) {
        toast('RedactWall verified and released the unchanged clean file upload.');
        return;
      }
      clearBlockedFileInput(e);
      if (allClean) toast('RedactWall verified the file, but the page could not resume the upload. Select it again to retry.');
    };
    list.forEach((file) => scanOneFile(file, finished));
  }
  function scanOneFile(f, done = () => {}) {
    if (f.size > MAX_BROWSER_FILE_BYTES) {
      trackFileBlock(
        reportLocalFileEvent(f, 'file_too_large'),
        'file_blocked_unscanned',
        f,
        'file is too large to inspect',
      );
      done(false);
      return;
    }
    if (ocrRequiredUpload(f)) {
      trackFileBlock(
        reportLocalFileEvent(f, 'ocr_required'),
        'ocr_required',
        f,
        'OCR is required before inspection',
      );
      done(false);
      return;
    }
    if (!textReadableUpload(f)) {
      trackFileBlock(
        reportLocalFileEvent(f, 'file_unsupported'),
        'file_blocked_unscanned',
        f,
        'this file type needs endpoint inspection',
      );
      done(false);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => inspectTextUpload(f, String(reader.result || ''), done);
    reader.onerror = () => {
      updateEvidenceToast(
        reportLocalFileEvent(f, 'scan_unavailable'),
        'file_blocked_unscanned',
        'RedactWall could not verify ' + f.name + ' and recorded the block.',
        'RedactWall could not verify ' + f.name + '. Upload blocked.',
      );
      toast('RedactWall could not verify ' + f.name + '. Upload blocked.');
      done(false);
    };
    reader.readAsText(f);
  }
  function inspectTextUpload(file, text, done = () => {}) {
    if (!textLooksReadable(text)) {
      trackFileBlock(
        reportLocalFileEvent(file, 'file_unsupported'),
        'file_blocked_unscanned',
        file,
        'this file is not text-readable',
      );
      done(false);
      return;
    }
    const analysis = D.analyze(text, detectionPolicy());
    const items = summarize(analysis);
    if (analysis.opaqueEncoded === true) {
      trackFileBlock(
        report(
          safeFileFindingPrompt(file, analysis), analysis, 'file_upload', 'action_blocked',
          'blocked locally: encoded file content could not be inspected',
        ),
        'action_blocked',
        file,
        'encoded content could not be inspected',
        true,
      );
      done(false);
      return;
    }
    if (!items.length) {
      const reportPromise = report(
        '[browser file inspected clean] ' + fileLabel(file),
        emptyAnalysis(),
        'file_upload',
        'allowed',
        'browser upload inspected locally; no sensitive content detected',
      );
      reportPromise.then((res) => done(recordedEvidenceResponse(res, 'allowed'))).catch(() => done(false));
      updateEvidenceToast(
        reportPromise,
        'allowed',
        'RedactWall scanned ' + file.name + ' locally and recorded clean evidence.',
        'RedactWall scanned ' + file.name + ' locally, but evidence was not recorded yet.',
      );
      toast('RedactWall scanned ' + file.name + ' locally. Waiting for recorded evidence before release.');
      return;
    }
    updateEvidenceToast(
      report(safeFileFindingPrompt(file, analysis), analysis, 'file_upload', 'awaiting_approval', 'browser upload inspected locally; sensitive content blocked before upload', { clientPreRedacted: true }),
      'pending',
      'RedactWall blocked ' + file.name + ': ' + listForScreen(items.slice(0, 3)) + '. Security Admin review is queued.',
      'RedactWall blocked ' + file.name + ': ' + listForScreen(items.slice(0, 3)) + '. Control-plane evidence was not recorded yet.',
    );
    toast('RedactWall blocked ' + file.name + ': ' + listForScreen(items.slice(0, 3)));
    done(false);
  }

  function fileExtension(name) {
    const base = String(name || '').toLowerCase().split(/[\\/]/).pop() || '';
    const idx = base.lastIndexOf('.');
    return idx > 0 ? base.slice(idx) : '';
  }
  function fileLabel(file) {
    const ext = fileExtension(file && file.name);
    if (ext) return ext.slice(0, 16) + ' file';
    const type = String((file && file.type) || '').toLowerCase().split(';')[0].replace(/[^a-z0-9/_.+-]+/g, '');
    return type ? type.slice(0, 48) + ' file' : 'file';
  }
  function textReadableUpload(file) {
    const type = String((file && file.type) || '').toLowerCase().split(';')[0];
    if (type.startsWith('text/')) return true;
    if (TEXT_UPLOAD_MIME_TYPES.has(type)) return true;
    return TEXT_UPLOAD_EXTENSIONS.has(fileExtension(file && file.name));
  }
  function ocrRequiredUpload(file) {
    const type = String((file && file.type) || '').toLowerCase().split(';')[0];
    return type.startsWith('image/') || OCR_UPLOAD_EXTENSIONS.has(fileExtension(file && file.name));
  }
  function textLooksReadable(text) {
    const sample = String(text || '').slice(0, 8192);
    if (!sample) return true;
    let suspicious = 0;
    for (let i = 0; i < sample.length; i += 1) {
      const code = sample.charCodeAt(i);
      if (code === 0 || code === 0xfffd || (code < 32 && code !== 9 && code !== 10 && code !== 13)) suspicious += 1;
    }
    return suspicious / sample.length <= 0.02;
  }
  function rememberCleanUpload(file) {
    if (file && typeof file === 'object') cleanUploadBypass.add(file);
  }
  function filesHaveCleanBypass(files) {
    const list = [...files];
    return !!list.length && list.every((file) => file && typeof file === 'object' && cleanUploadBypass.has(file));
  }
  function consumeCleanUploadBypass(files) {
    [...files].forEach((file) => cleanUploadBypass.delete(file));
  }
  function safeFileFindingPrompt(file, analysis) {
    const items = summarize(analysis);
    return '[browser file blocked locally] ' + (items.length ? items.join(', ') : 'sensitive content') + ' in ' + fileLabel(file);
  }


  let toastEl;
  function toast(msg) {
    if (toastEl) toastEl.remove();
    const current = document.createElement('div');
    current.className = 'ps-toast';
    current.textContent = msg;
    toastEl = current;
    document.body.appendChild(current);
    setTimeout(() => {
      current.remove();
      if (toastEl === current) toastEl = null;
    }, 4200);
  }

  console.log('[RedactWall] active on ' + SITE + ' — pre-send inspection enabled.');
})();
