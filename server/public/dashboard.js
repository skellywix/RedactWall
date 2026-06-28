const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : '-');
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-');
const sevClass = (l) => String(l || 'low').toLowerCase();
let selected = null;
let csrfToken = '';
let currentQueue = [];
let currentActivity = [];
let currentCoverage = null;
let searchTerm = '';
let currentRole = 'auditor';

const icons = {
  check: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5 12 4 4L19 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  deny: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" stroke="currentColor" stroke-width="1.7"/><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" stroke="currentColor" stroke-width="1.7"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 12a8 8 0 0 1-13.7 5.6M4 12A8 8 0 0 1 17.7 6.4M17.7 6.4H14M17.7 6.4V2.7M6.3 17.6H10M6.3 17.6v3.7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4l7 3v5c0 4.2-2.6 6.8-7 8-4.4-1.2-7-3.8-7-8V7l7-3Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>',
};

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function humanize(s) {
  return String(s || '-').replace(/_/g, ' ');
}

function policyListText(items) {
  return (items || []).join('\n');
}

function parsePolicyList(value) {
  return [...new Set(String(value || '')
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean))];
}

function statusTone(status) {
  const s = String(status || '').toLowerCase();
  if (['approved', 'allowed', 'justified', 'warned_sent', 'redacted'].includes(s)) return 'good';
  if (['denied', 'blocked_by_user', 'destination_blocked', 'file_upload_blocked', 'injection_blocked', 'response_flagged', 'seat_limit_blocked'].includes(s)) return 'bad';
  if (['pending', 'shadow_ai', 'paste_flagged'].includes(s)) return 'warn';
  return 'info';
}

function postureTone(state) {
  return state === 'covered' ? 'good' : 'warn';
}

function sourceLabel(source) {
  return ({
    browser_extension: 'Browser',
    endpoint_agent: 'Endpoint',
    mcp_guard: 'MCP',
    api: 'API',
    proxy: 'Proxy',
  })[source] || source || 'API';
}

function normalizeRole(role) {
  return role === 'security_admin' ? 'security_admin' : 'auditor';
}

function roleLabel(role) {
  return normalizeRole(role) === 'security_admin' ? 'Security Admin' : 'Auditor';
}

function canAdminWrite() {
  return currentRole === 'security_admin';
}

function queryText(q) {
  return [
    q.id, q.user, q.destination, q.source, q.channel, q.status, q.maxSeverityLabel,
    q.redactedPrompt, ...(q.reasons || []), ...(q.categories || []),
    ...(q.findings || []).map((f) => `${f.type} ${f.masked || ''}`),
    ...Object.keys(q.entityCounts || {}),
  ].join(' ').toLowerCase();
}

function matchesSearch(q) {
  return !searchTerm || queryText(q).includes(searchTerm);
}

function updateSearch(value) {
  searchTerm = String(value || '').trim().toLowerCase();
  renderQueueView();
  renderActivityRows(currentActivity);
}

async function api(path, opts = {}) {
  const { allowAuthError = false, ...fetchOpts } = opts;
  const next = { ...fetchOpts };
  const method = String(next.method || 'GET').toUpperCase();
  const headers = new Headers(next.headers || {});
  if (csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) headers.set('x-csrf-token', csrfToken);
  next.headers = headers;
  const r = await fetch(path, next);
  if (r.status === 401 && !allowAuthError) { location.href = '/login.html'; return null; }
  if (r.status === 403) alert('Request not allowed for this session. Refresh or use a Security Admin account.');
  return r;
}

async function loadCsrf() {
  const r = await api('/api/csrf');
  if (!r) return;
  const body = await r.json();
  csrfToken = body.csrfToken || '';
}

function askStepUpPassword({ title, message, confirmText, icon = '', buttonClass = 'reveal' }) {
  return new Promise((resolve) => {
    const dialog = document.createElement('dialog');
    dialog.className = 'stepup-dialog';
    dialog.innerHTML = `
      <form method="dialog" class="stepup-panel">
        <div>
          <h2>${escapeHtml(title)}</h2>
          <p>${escapeHtml(message)}</p>
        </div>
        <label>Admin password
          <input name="password" type="password" autocomplete="current-password" required />
        </label>
        <div class="stepup-actions">
          <button class="btn" value="cancel" type="button">Cancel</button>
          <button class="btn ${escapeHtml(buttonClass)}" value="confirm" type="submit">${icon}${escapeHtml(confirmText)}</button>
        </div>
      </form>`;
    document.body.appendChild(dialog);
    const input = $('input[name=password]', dialog);
    const cleanup = (value) => {
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    $('.stepup-actions .btn', dialog).onclick = () => cleanup(null);
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      cleanup(null);
    });
    $('form', dialog).addEventListener('submit', (event) => {
      event.preventDefault();
      cleanup(input.value);
    });
    dialog.showModal();
    input.focus();
  });
}

function askRevealPassword() {
  return askStepUpPassword({
    title: 'Confirm raw reveal',
    message: 'This action is audit-logged and may display sensitive prompt content.',
    confirmText: 'Reveal',
    icon: icons.eye,
  });
}

function askApprovePassword() {
  return askStepUpPassword({
    title: 'Confirm release',
    message: 'Approving releases this held prompt to the requesting sensor.',
    confirmText: 'Approve release',
    icon: icons.check,
    buttonClass: 'approve',
  });
}

async function init() {
  const meRes = await api('/api/me');
  if (!meRes) return;
  const me = await meRes.json();
  await loadCsrf();
  currentRole = normalizeRole(me.role);
  $('#who').textContent = `${me.user} / ${roleLabel(currentRole)}`;
  if (me.defaultPassword) {
    const b = $('#banner');
    b.style.display = 'block';
    b.textContent = 'Default admin password is active. Set ADMIN_PASSWORD before production.';
  }
  await refreshAll();
  connectStream();
}

async function refreshAll() {
  await Promise.all([loadStats(), loadQueue(), loadActivity()]);
}

async function loadStats() {
  const [r, seatRes] = await Promise.all([api('/api/stats'), api('/api/billing/seats')]);
  if (!r) return;
  const s = await r.json();
  const seats = seatRes && seatRes.ok ? await seatRes.json() : null;
  const totalDecisions = (s.approved || 0) + (s.denied || 0);
  const approveRate = totalDecisions ? `${Math.round(((s.approved || 0) / totalDecisions) * 100)}%` : '-';
  const seatValue = seats && seats.seatLimit ? `${seats.seatsUsed}/${seats.seatLimit}` : (seats ? seats.seatsUsed : '-');
  const seatMeta = seats && seats.seatLimit ? `${seats.seatsRemaining} remaining` : 'billable users';
  const cards = [
    ['pending', s.pending, 'Pending approval', 'held for review'],
    ['alert', s.todayBlocked, 'Blocked today', 'policy stops'],
    ['good', s.approved, 'Approved', 'released by admin'],
    ['', s.denied, 'Denied', 'never released'],
    ['', approveRate, 'Approval rate', 'admin decisions'],
    [seats && seats.overLimit ? 'alert' : '', seatValue, seats && seats.saasMode ? 'Seats used' : 'Users observed', seatMeta],
  ];
  $('#stats').innerHTML = cards.map(([c, n, l, m]) => `
    <div class="stat ${c}">
      <div class="l">${escapeHtml(l)}</div>
      <div class="n">${escapeHtml(n)}</div>
      <div class="m">${escapeHtml(m)}</div>
      <div class="stat-rule"></div>
    </div>`).join('');
  const b = $('#qBadge');
  if (s.pending > 0) { b.classList.remove('hidden'); b.textContent = s.pending; }
  else b.classList.add('hidden');
  $('#topEntities').innerHTML = (s.topEntities.length ? s.topEntities : []).map(([k, v]) => {
    const max = s.topEntities[0][1] || 1;
    return `<div class="barrow"><div class="name">${escapeHtml(k)}</div><div class="bar"><i style="--w:${Math.round((v / max) * 100)}%"></i></div><div class="v">${escapeHtml(v)}</div></div>`;
  }).join('') || '<div class="empty"><div class="big">No detections</div>Current data set has no classified prompt findings.</div>';
}

function findingChips(findings, categories) {
  const fc = (findings || []).map((f) => `<span class="chip"><b>${escapeHtml(f.type)}</b> ${escapeHtml(f.masked || '')}</span>`).join('');
  const cc = (categories || []).map((c) => `<span class="chip category"><b>${escapeHtml(c)}</b></span>`).join('');
  return fc + cc;
}

async function loadQueue() {
  const r = await api('/api/queries?status=pending');
  if (!r) return;
  currentQueue = await r.json();
  if (currentQueue.length && !currentQueue.some((q) => q.id === selected)) selected = currentQueue[0].id;
  if (!currentQueue.length) selected = null;
  renderQueueView();
}

function renderQueueView() {
  const el = $('#queueList');
  const rows = currentQueue.filter(matchesSearch);
  if (!currentQueue.length) {
    el.innerHTML = '<div class="empty"><div class="big">Queue clear</div>No prompts are awaiting approval.</div>';
    renderIncident(null);
    return;
  }
  if (!rows.length) {
    el.innerHTML = '<div class="empty"><div class="big">No matches</div>No pending prompts match the current search.</div>';
    renderIncident(null);
    return;
  }
  if (!rows.some((q) => q.id === selected)) selected = rows[0].id;
  el.innerHTML = rows.map(renderQueueItem).join('');
  renderIncident(rows.find((q) => q.id === selected) || rows[0]);
}

function renderQueueItem(q) {
  const sev = sevClass(q.maxSeverityLabel);
  const detected = Object.keys(q.entityCounts || {}).join(', ') || (q.categories || []).join(', ') || 'policy match';
  const controls = canAdminWrite()
    ? `<textarea class="note" id="note_${escapeHtml(q.id)}" placeholder="Decision note, recorded in audit log"></textarea>
    <div class="actions">
      <button class="btn approve" data-act="approve" data-id="${escapeHtml(q.id)}" type="button">${icons.check}Approve release</button>
      <button class="btn deny" data-act="deny" data-id="${escapeHtml(q.id)}" type="button">${icons.deny}Deny</button>
      <button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button">${icons.eye}Reveal gated</button>
    </div>`
    : '<div class="readonly-note">Read-only auditor view</div>';
  return `<article class="q ${selected === q.id ? 'selected' : ''}" data-id="${escapeHtml(q.id)}" tabindex="0">
    <div class="top">
      <span class="select-dot" aria-hidden="true"></span>
      <span class="sev ${sev}">${escapeHtml(q.maxSeverityLabel || 'low')}</span>
      <span class="risk">Risk <b>${escapeHtml(q.riskScore ?? 0)}</b>/100</span>
    </div>
    <div class="queue-mainline">
      <strong>${escapeHtml(q.user || 'unknown user')}</strong>
      <span>${escapeHtml(sourceLabel(q.source))} -> ${escapeHtml(q.destination || 'unknown destination')}</span>
      <span>${escapeHtml(fmtTime(q.createdAt))}</span>
    </div>
    <div class="prompt" id="p_${escapeHtml(q.id)}">${escapeHtml(q.redactedPrompt)}</div>
    <div class="chips">${findingChips(q.findings, q.categories)}</div>
    <div class="reasons">Detected: ${escapeHtml(detected)}${(q.reasons || []).length ? `; ${escapeHtml((q.reasons || []).join('; '))}` : ''}</div>
    ${controls}
  </article>`;
}

function renderIncident(q) {
  const el = $('#incidentDetail');
  if (!q) {
    el.innerHTML = '<div class="empty"><div class="big">No selected incident</div>The approval queue is clear.</div>';
    return;
  }
  const sev = sevClass(q.maxSeverityLabel);
  const risk = Math.max(0, Math.min(100, Number(q.riskScore || 0)));
  const matches = (q.findings || []).slice(0, 5).map((f) => `
    <div class="posture-item"><span>${escapeHtml(f.type)}</span><b>${escapeHtml(f.masked || 'redacted')}</b></div>`).join('')
    || '<div class="posture-item"><span>Policy category</span><b>Context match</b></div>';
  el.innerHTML = `
    <div class="detail-grid">
      <div class="datum"><label>User</label><b>${escapeHtml(q.user || 'unknown')}</b></div>
      <div class="datum"><label>Destination</label><b>${escapeHtml(q.destination || 'unknown')}</b></div>
      <div class="datum"><label>Sensor</label><b>${escapeHtml(sourceLabel(q.source))}</b></div>
      <div class="datum"><label>Created</label><b>${escapeHtml(fmt(q.createdAt))}</b></div>
    </div>
    <div class="risk-meter" style="--risk-width:${risk}%">
      <div class="top"><span class="sev ${sev}">${escapeHtml(q.maxSeverityLabel || 'low')}</span><span class="risk">Risk <b>${risk}</b>/100</span></div>
      <div class="risk-track"><i></i></div>
    </div>
    <div class="prompt">${escapeHtml(q.redactedPrompt)}</div>
    <div class="posture-list">${matches}</div>`;
}

document.addEventListener('click', async (e) => {
  const actionButton = e.target.closest('[data-act]');
  if (actionButton) {
    if (!canAdminWrite()) {
      alert('Request not allowed for this session. Use a Security Admin account.');
      return;
    }
    const act = actionButton.dataset.act;
    const id = actionButton.dataset.id;
    if (act === 'reveal') {
      const password = await askRevealPassword();
      if (!password) return;
      const r = await api(`/api/queries/${encodeURIComponent(id)}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
        allowAuthError: true,
      });
      if (!r) return;
      if (r.status === 401) {
        const body = await r.json().catch(() => ({}));
        if (body.error === 'unauthenticated') { location.href = '/login.html'; return; }
        alert('Password confirmation failed.');
        return;
      }
      if (r.status === 429) { alert('Too many confirmation attempts. Try again later.'); return; }
      if (!r.ok) return;
      const body = await r.json();
      const p = $(`#p_${CSS.escape(id)}`);
      if (p) { p.textContent = body.rawPrompt; p.classList.add('revealed'); }
      actionButton.textContent = 'Raw shown and logged';
      actionButton.disabled = true;
      return;
    }
    if (act === 'approve' || act === 'deny') {
      const note = ($(`#note_${CSS.escape(id)}`) || {}).value || '';
      const password = act === 'approve' ? await askApprovePassword() : '';
      if (act === 'approve' && !password) return;
      actionButton.disabled = true;
      const r = await api(`/api/queries/${encodeURIComponent(id)}/${act}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(act === 'approve' ? { note, password } : { note }),
        allowAuthError: act === 'approve',
      });
      if (r && r.status === 401 && act === 'approve') {
        const body = await r.json().catch(() => ({}));
        if (body.error === 'unauthenticated') { location.href = '/login.html'; return; }
        alert('Password confirmation failed.');
        actionButton.disabled = false;
        return;
      }
      if (r && r.status === 429 && act === 'approve') {
        alert('Too many confirmation attempts. Try again later.');
        actionButton.disabled = false;
        return;
      }
      if (r && r.ok) await refreshAll();
      else actionButton.disabled = false;
    }
    return;
  }
  const jump = e.target.closest('[data-tab-jump]');
  if (jump) {
    activateTab(jump.dataset.tabJump);
    return;
  }
  const row = e.target.closest('.q[data-id]');
  if (row && !e.target.closest('textarea,input,button,select,a')) {
    selected = row.dataset.id;
    renderQueueView();
  }
});

document.addEventListener('keydown', (e) => {
  const row = e.target.closest('.q[data-id]');
  if (!row || !['Enter', ' '].includes(e.key)) return;
  if (e.target.closest('textarea,input,button,select,a')) return;
  e.preventDefault();
  selected = row.dataset.id;
  renderQueueView();
});

async function loadActivity() {
  const r = await api('/api/queries?limit=200');
  if (!r) return;
  currentActivity = await r.json();
  renderActivityRows(currentActivity);
}

function renderActivityRows(rows) {
  const filtered = (rows || []).filter(matchesSearch);
  $('#activityRows').innerHTML = filtered.map((q) => `<tr>
    <td class="mono">${escapeHtml(fmt(q.createdAt))}</td>
    <td>${escapeHtml(sourceLabel(q.source))}</td>
    <td>${escapeHtml(q.user || '-')}</td>
    <td class="mono">${escapeHtml(q.destination || '-')}</td>
    <td><span class="sev ${sevClass(q.maxSeverityLabel)}">${escapeHtml(q.maxSeverityLabel || 'low')}</span></td>
    <td class="mono">${escapeHtml(q.riskScore ?? 0)}</td>
    <td>${escapeHtml(Object.keys(q.entityCounts || {}).join(', ') || '-')}</td>
    <td><span class="pill ${statusTone(q.status)}">${escapeHtml(humanize(q.status))}</span></td>
  </tr>`).join('') || '<tr><td colspan="8" class="empty">No matching activity</td></tr>';
}

async function loadCoverage() {
  const r = await api('/api/coverage');
  if (!r) return;
  currentCoverage = await r.json();
  renderCoverage(currentCoverage);
}

function renderCoverage(c) {
  if (!c) return;
  const totals = c.totals || {};
  const sensorMetaLine = (s) => {
    const parts = [];
    if (s.lastSeen) parts.push(fmt(s.lastSeen));
    else parts.push('No events observed');
    if (s.latestVersion) parts.push('v' + s.latestVersion);
    else if (s.events) parts.push('version unknown');
    if (s.versionHealth === 'mixed') parts.push((s.versions || []).length + ' versions');
    if ((s.platforms || []).length) parts.push((s.platforms || []).join(', '));
    return parts.join(' | ');
  };
  $('#coverageScore').innerHTML = `
    <div class="score-ring" style="--score:${escapeHtml(c.score || 0)}%"><b>${escapeHtml(c.score || 0)}</b></div>
    <span>Coverage score</span>
    <div class="coverage-kpis">
      <div class="mini-kpi"><b>${escapeHtml(totals.events || 0)}</b><span>Events</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.governedActive || 0)}/${escapeHtml(totals.governedDestinations || 0)}</b><span>Governed</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.shadowEvents || 0)}</b><span>Shadow AI</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.blocked || 0)}</b><span>Blocked</span></div>
    </div>`;
  $('#coveragePosture').innerHTML = (c.posture || []).map((p) => `
    <div class="posture-item">
      <span>${escapeHtml(p.label)} <span class="pill ${postureTone(p.state)}">${escapeHtml(p.state)}</span></span>
      <b>${escapeHtml(p.detail)}</b>
    </div>`).join('');
  $('#sensorMix').innerHTML = (c.sensors || []).map((s) => `
    <div class="sensor-row">
      <div><strong>${escapeHtml(s.label)}</strong><span>${escapeHtml(sensorMetaLine(s))}</span></div>
      <div class="count">${escapeHtml(s.events || 0)}</div>
    </div>`).join('');
  $('#governedRows').innerHTML = (c.governedDestinations || []).map((d) => `<tr>
    <td class="mono">${escapeHtml(d.destination)}</td>
    <td class="mono">${escapeHtml(d.events)}</td>
    <td class="mono">${escapeHtml(d.blocked)}</td>
    <td class="mono">${escapeHtml(d.redacted)}</td>
    <td class="mono">${escapeHtml(d.users)}</td>
    <td class="mono">${escapeHtml(d.lastSeen ? fmt(d.lastSeen) : '-')}</td>
  </tr>`).join('') || '<tr><td colspan="6" class="empty">No governed destinations are configured.</td></tr>';
  $('#shadowRows').innerHTML = (c.shadowDestinations || []).map((d) => `
    <div class="shadow-row">
      <div><strong>${escapeHtml(d.destination)}</strong><span>${escapeHtml(d.users)} users / last ${escapeHtml(d.lastSeen ? fmt(d.lastSeen) : '-')}</span></div>
      <div class="count">${escapeHtml(d.shadow)}</div>
    </div>`).join('') || '<div class="empty"><div class="big">No shadow AI</div>No ungoverned AI tools have been reported.</div>';
}

async function loadAudit() {
  const r = await api('/api/audit');
  if (!r) return;
  const d = await r.json();
  const ig = d.integrity;
  $('#integrity').className = `integrity ${ig.ok ? 'ok' : 'bad'}`;
  $('#integrity').innerHTML = ig.ok
    ? `${icons.shield}<span>Chain verified: ${escapeHtml(ig.count)} cryptographically linked entries.</span>`
    : `${icons.shield}<span>Integrity check failed at ${escapeHtml(ig.brokenAt)}.</span>`;
  $('#auditRows').innerHTML = d.entries.map((a) => `<tr>
    <td class="mono">${escapeHtml(fmt(a.ts))}</td>
    <td><span class="pill ${statusTone(a.action)}">${escapeHtml(humanize(a.action))}</span></td>
    <td>${escapeHtml(a.actor || '-')}</td>
    <td class="mono">${escapeHtml(a.queryId || '-')}</td>
    <td>${escapeHtml(a.detail || '')}</td>
  </tr>`).join('');
}

async function exportEvidence(){
  const btn = $('#exportEvidence');
  const status = $('#exportStatus');
  btn.disabled = true;
  status.textContent = 'Preparing...';
  try {
    const r = await api('/api/export/evidence?queryLimit=1000&auditLimit=1000');
    if (!r || !r.ok) throw new Error('export failed');
    const pack = await r.json();
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    a.href = url;
    a.download = `promptwall-evidence-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    status.textContent = 'Downloaded';
    setTimeout(() => { status.textContent = ''; }, 2200);
  } catch (err) {
    status.textContent = 'Export failed';
  } finally {
    btn.disabled = false;
  }
}

async function loadPolicy() {
  const pRes = await api('/api/policy');
  const tRes = await api('/api/policy/templates');
  if (!pRes || !tRes) return;
  const p = await pRes.json();
  const tpls = await tRes.json();
  const readonly = !canAdminWrite();
  const modes = [
    ['warn', 'Warn', 'Nudge the user, let them proceed'],
    ['justify', 'Require justification', 'User must give a business reason'],
    ['redact', 'Redact and send', 'Tokenize PII before release'],
    ['block', 'Block', 'Hold for admin approval'],
  ];
  const tplBar = `<div class="template-bar"><div class="template-title">Regulation templates</div>
    <div class="chips">${tpls.map((t) => (readonly
    ? `<span class="chip" title="${escapeHtml(t.description)}"><b>${escapeHtml(t.label)}</b></span>`
    : `<button class="chip ps-tpl" data-tpl="${escapeHtml(t.id)}" title="${escapeHtml(t.description)}" type="button"><b>${escapeHtml(t.label)}</b></button>`)).join('')}</div></div>`;
  $('#policyBox').innerHTML = `${tplBar}
    <div class="policy-label">When a sensor detects sensitive content</div>
    <div class="policy-options">
      ${modes.map(([v, t, d]) => `<label class="policy-option ${p.enforcementMode === v ? 'selected' : ''} ${readonly ? 'readonly' : ''}">
        <span><input type="radio" name="mode" value="${v}" ${p.enforcementMode === v ? 'checked' : ''} ${readonly ? 'disabled' : ''}/>${t}</span>
        <p>${d}</p>
      </label>`).join('')}
    </div>
    <div class="policy-label">Trigger thresholds</div>
    <div class="field-grid">
      <label for="pol_sev">Block at minimum severity</label>
      <select id="pol_sev" ${readonly ? 'disabled' : ''}>
        ${[[1, 'low'], [2, 'medium'], [3, 'high'], [4, 'critical']].map(([v, l]) => `<option value="${v}" ${p.blockMinSeverity === v ? 'selected' : ''}>${l}</option>`).join('')}
      </select>
      <label for="pol_risk">Block at risk score greater than or equal to</label>
      <input id="pol_risk" type="number" min="0" max="100" value="${escapeHtml(p.blockRiskScore)}" ${readonly ? 'disabled' : ''}/>
      <label for="pol_retention">Purge retained raw approval data after days</label>
      <input id="pol_retention" type="number" min="0" max="3650" value="${escapeHtml(p.rawRetentionDays ?? 30)}" ${readonly ? 'disabled' : ''}/>
    </div>
    <div class="template-bar"><div class="template-title">Hard-stop entities</div>
      <div class="chips">${(p.alwaysBlock || []).map((x) => `<span class="chip"><b>${escapeHtml(x)}</b></span>`).join('')}</div></div>
    <div class="policy-list-grid">
      <label class="policy-list-field">Governed AI destinations
        ${readonly
    ? `<div class="chips">${(p.governedDestinations || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('')}</div>`
    : `<textarea id="pol_governed_destinations" class="policy-textarea" spellcheck="false">${escapeHtml(policyListText(p.governedDestinations))}</textarea>`}
      </label>
      <label class="policy-list-field">Allowed AI destinations
        ${readonly
    ? `<div class="chips">${(p.allowedDestinations || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_allowed_destinations" class="policy-textarea" spellcheck="false" placeholder="chatgpt.com&#10;claude.ai">${escapeHtml(policyListText(p.allowedDestinations))}</textarea>`}
      </label>
      <label class="policy-list-field">Blocked AI destinations
        ${readonly
    ? `<div class="chips">${(p.blockedDestinations || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_blocked_destinations" class="policy-textarea" spellcheck="false" placeholder="deepseek.com&#10;*.example-ai.com">${escapeHtml(policyListText(p.blockedDestinations))}</textarea>`}
      </label>
      <label class="policy-list-field">Blocked file uploads
        ${readonly
    ? `<div class="chips">${(p.blockedFileUploadDestinations || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_blocked_file_upload_destinations" class="policy-textarea" spellcheck="false" placeholder="chatgpt.com&#10;desktop-ai-app">${escapeHtml(policyListText(p.blockedFileUploadDestinations))}</textarea>`}
      </label>
    </div>
    ${readonly
    ? '<div class="readonly-note">Read-only auditor view</div>'
    : `<button class="btn approve" id="savePolicy" type="button">${icons.check}Save policy</button>
    <button class="btn" id="runRetentionPurge" type="button">${icons.refresh}Run retention purge</button>`}
    <span id="polSaved" class="save-status"></span>`;
  $$('input[name=mode]').forEach((radio) => {
    radio.onchange = () => {
      $$('.policy-option').forEach((option) => option.classList.toggle('selected', option.contains(radio) && radio.checked));
    };
  });
  if (readonly) return;
  $('#savePolicy').onclick = async () => {
    const mode = (document.querySelector('input[name=mode]:checked') || {}).value || p.enforcementMode;
    const body = {
      enforcementMode: mode,
      blockMinSeverity: Number($('#pol_sev').value),
      blockRiskScore: Number($('#pol_risk').value),
      rawRetentionDays: Number($('#pol_retention').value),
      governedDestinations: parsePolicyList($('#pol_governed_destinations').value),
      allowedDestinations: parsePolicyList($('#pol_allowed_destinations').value),
      blockedDestinations: parsePolicyList($('#pol_blocked_destinations').value),
      blockedFileUploadDestinations: parsePolicyList($('#pol_blocked_file_upload_destinations').value),
    };
    const r = await api('/api/policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r || !r.ok) return;
    $('#polSaved').textContent = 'Saved';
    setTimeout(() => { $('#polSaved').textContent = ''; }, 2000);
  };
  $('#runRetentionPurge').onclick = async () => {
    const r = await api('/api/retention/purge', { method: 'POST' });
    if (!r || !r.ok) return;
    const body = await r.json();
    $('#polSaved').textContent = `Purged ${body.purged || 0} record(s)`;
    setTimeout(() => { $('#polSaved').textContent = ''; }, 3000);
  };
  $$('.ps-tpl').forEach((b) => {
    b.onclick = async () => {
      await api('/api/policy/apply-template', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: b.dataset.tpl }) });
      loadPolicy();
    };
  });
}

function activateTab(name) {
  $$('.tab').forEach((x) => x.classList.toggle('active', x.dataset.tab === name));
  $$('section[id^=tab-]').forEach((s) => s.classList.add('hidden'));
  $(`#tab-${CSS.escape(name)}`).classList.remove('hidden');
  if (name === 'audit') loadAudit();
  if (name === 'policy') loadPolicy();
  if (name === 'activity') loadActivity();
  if (name === 'coverage') loadCoverage();
}

$$('.tab').forEach((t) => {
  t.onclick = () => activateTab(t.dataset.tab);
});

$('#refreshQueue').onclick = loadQueue;
$('#refreshCoverage').onclick = loadCoverage;
$('#logout').onclick = async () => { await api('/api/logout', { method: 'POST' }); location.href = '/login.html'; };
$('#exportEvidence').onclick = exportEvidence;
$('#globalSearch').addEventListener('input', (e) => updateSearch(e.target.value));

function connectStream() {
  const es = new EventSource('/api/stream');
  es.addEventListener('query', () => { loadStats(); loadQueue(); if (!$('#tab-coverage').classList.contains('hidden')) loadCoverage(); flash(); });
  es.addEventListener('decision', () => { loadStats(); loadQueue(); loadActivity(); });
  es.addEventListener('stats', () => loadStats());
  es.onerror = () => { $('#liveTxt').textContent = 'Reconnecting'; };
  es.onopen = () => { $('#liveTxt').textContent = 'Live'; };
}

function flash() {
  const d = document.querySelector('.dot');
  d.style.background = '#f6a21a';
  setTimeout(() => { d.style.background = '#40d98a'; }, 500);
}

init();
