/* PromptSentinel content script — pre-send inspection on AI chat sites.
 *
 * Strategy: catch the prompt BEFORE it leaves the page.
 *   - Enter keydown (capture phase) on the composer
 *   - Send-button click (capture phase)
 *   - Paste (warn the moment sensitive data lands in the box)
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
  let POLICY = { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, alwaysBlock: [] };
  let ENABLED = true;

  // Pull policy + enabled state from the background worker.
  chrome.runtime.sendMessage({ type: 'getConfig' }, (res) => {
    if (res && res.policy) POLICY = res.policy;
    if (res && typeof res.enabled === 'boolean') ENABLED = res.enabled;
  });
  chrome.storage.onChanged.addListener((c) => { if (c.enabled) ENABLED = c.enabled.newValue; });

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
  function evaluate(text) {
    const a = D.analyze(text);
    if (!a.findings.length && !a.categories.length) return { action: 'allow', analysis: a };
    const hardStop = a.findings.some((f) => (POLICY.alwaysBlock || []).includes(f.type));
    // REDACT mode neutralizes everything token-able locally, so it takes
    // precedence over hard-stop blocking: if there are structured findings we
    // tokenize and let it through; a categories-only hit has nothing to swap.
    if ((POLICY.enforcementMode || 'block') === 'redact') {
      return { action: a.findings.length ? 'redact' : 'allow', analysis: a };
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

  // ---- report to the server (telemetry + queue) -----------------------------
  function report(text, analysis, channel, outcome, note) {
    chrome.runtime.sendMessage({
      type: 'report',
      payload: {
        prompt: text, destination: SITE, channel, source: 'browser_extension',
        categories: analysis.categories.map((c) => c.category),
        outcome, note: note || '',
      },
    });
  }

  // ---- inline banner UI -----------------------------------------------------
  let banner;
  function clearBanner() { if (banner) { banner.remove(); banner = null; } }
  function showBanner({ mode, items, risk, onProceed, onBlock, justify }) {
    clearBanner();
    banner = document.createElement('div');
    banner.className = 'ps-banner ps-' + mode;
    const sev = mode === 'block' ? 'Blocked' : mode === 'justify' ? 'Justification required' : 'Heads up';
    const icon = mode === 'block' ? '⛔' : mode === 'justify' ? '✋' : '⚠️';
    banner.innerHTML =
      '<div class="ps-row"><span class="ps-ic">' + icon + '</span>' +
      '<div class="ps-msg"><b>' + sev + '</b> — this prompt contains <b>' + items.join(', ') + '</b>' +
      (mode === 'block' ? ' and cannot be sent to ' + SITE + '.' : ' (risk ' + risk + '/100).') + '</div>' +
      '<button class="ps-x" title="Dismiss">✕</button></div>' +
      (justify ? '<textarea class="ps-just" placeholder="Business reason (required to proceed) — recorded for compliance"></textarea>' : '') +
      '<div class="ps-actions"></div>';
    const actions = banner.querySelector('.ps-actions');
    banner.querySelector('.ps-x').onclick = clearBanner;

    if (mode === 'warn') {
      const edit = mk('button', 'ps-btn ps-secondary', 'Let me edit'); edit.onclick = clearBanner;
      const go = mk('button', 'ps-btn ps-primary', 'Send anyway'); go.onclick = () => { clearBanner(); onProceed(); };
      actions.append(edit, go);
    } else if (mode === 'justify') {
      const edit = mk('button', 'ps-btn ps-secondary', 'Cancel'); edit.onclick = () => { clearBanner(); onBlock(); };
      const go = mk('button', 'ps-btn ps-primary', 'Submit & send'); go.onclick = () => {
        const note = banner.querySelector('.ps-just').value.trim();
        if (note.length < 4) { banner.querySelector('.ps-just').style.borderColor = '#ef4444'; return; }
        clearBanner(); onProceed(note);
      };
      actions.append(edit, go);
    } else { // block
      const req = mk('button', 'ps-btn ps-secondary', 'Request approval'); req.onclick = () => { clearBanner(); onBlock(true); };
      const ok = mk('button', 'ps-btn ps-primary', 'OK, I\'ll edit'); ok.onclick = () => { clearBanner(); onBlock(false); };
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
          toast('PromptSentinel blocked hidden instructions in this prompt (' + inj.reasons.join(', ') + ').');
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
      report(text, verdict.analysis, 'submit', 'redacted_sent');
      toast('PromptSentinel: ' + Object.keys(t.map).length + ' sensitive value(s) tokenized before sending — the reply is restored here automatically.');
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
      onProceed: (note) => {
        report(text, verdict.analysis, 'submit', verdict.action === 'justify' ? 'justified' : 'sent_after_warning', note);
        bypassOnce = true;
        resend(el);
      },
      onBlock: (requestApproval) => {
        report(text, verdict.analysis, 'submit', requestApproval ? 'awaiting_approval' : 'blocked_by_user');
        if (requestApproval) toast('Sent to your Security Admin for approval.');
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

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-testid="send-button"], button[aria-label*="Send" i], button[type="submit"]');
    if (btn) { const el = findComposer(); if (el && readText(el)) interceptSend(e, el); }
  }, true);

  // ---- intercept PASTE (early warning) --------------------------------------
  document.addEventListener('paste', (e) => {
    if (!ENABLED) return;
    const t = (e.clipboardData || window.clipboardData);
    const pasted = t ? t.getData('text') : '';
    if (!pasted || pasted.length < 6) return;
    const a = D.analyze(pasted);
    if (a.findings.length || a.categories.length) {
      const verdict = evaluate(pasted);
      if (verdict.action !== 'allow') {
        report(pasted, a, 'paste', 'paste_flagged');
        toast('PromptSentinel: pasted content contains ' + summarize(a).slice(0, 3).join(', '));
      }
    }
  }, true);

  // ---- intercept FILE drops / selection -------------------------------------
  document.addEventListener('drop', (e) => {
    if (!ENABLED) return;
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) scanFiles(files, e);
  }, true);
  document.addEventListener('change', (e) => {
    if (!ENABLED) return;
    if (e.target && e.target.type === 'file' && e.target.files && e.target.files.length) scanFiles(e.target.files, e);
  }, true);
  function scanFiles(files, e) {
    [...files].forEach((f) => {
      if (f.size > 2_000_000 || !/text|json|csv|javascript|x-|plain|md|xml/.test(f.type || '') && !/\.(txt|csv|json|js|ts|py|java|sql|env|md|log|xml|yaml|yml)$/i.test(f.name)) {
        toast('PromptSentinel: file ' + f.name + ' attached to AI tool (recorded).');
        chrome.runtime.sendMessage({ type: 'report', payload: { prompt: '[file] ' + f.name, destination: SITE, channel: 'file_upload', source: 'browser_extension', categories: [], outcome: 'file_flagged' } });
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result || '');
        const a = D.analyze(text);
        if (a.findings.length || a.categories.length) {
          const verdict = evaluate(text);
          report('[file:' + f.name + '] ' + text.slice(0, 500), a, 'file_upload', verdict.action === 'allow' ? 'file_flagged' : 'file_' + verdict.action);
          if (verdict.action === 'block') { try { e.preventDefault(); e.stopPropagation(); } catch (_) {} }
          toast('PromptSentinel: ' + f.name + ' contains ' + summarize(a).slice(0, 3).join(', '));
        }
      };
      reader.readAsText(f.slice(0, 200000));
    });
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

  console.log('[PromptSentinel] active on ' + SITE + ' — pre-send inspection enabled.');
})();
