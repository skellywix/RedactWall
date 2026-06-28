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
let currentLineage = null;
let searchTerm = '';
let currentRole = 'auditor';
let currentUser = '';
let queueFilter = 'all';
let queueCategoryFilter = 'all';
let queueDestinationFilter = 'all';

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

function policyMapText(items) {
  return Object.entries(items || {}).map(([key, value]) => `${key}=${value}`).join('\n');
}

function parsePolicyMap(value) {
  const out = {};
  for (const line of String(value || '').split(/[\n,]+/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const separator = trimmed.includes('=') ? trimmed.indexOf('=') : trimmed.search(/\s/);
    if (separator <= 0) continue;
    const key = trimmed.slice(0, separator).trim();
    const version = trimmed.slice(separator + 1).trim();
    if (!key || !version) continue;
    out[key] = version;
  }
  return out;
}

function policyJsonText(value) {
  return JSON.stringify(value || [], null, 2);
}

function shortPolicyValue(value) {
  const text = String(value || '');
  return text.length > 36 ? `${text.slice(0, 33)}...` : text;
}

function policyMatcherSummary(rule = {}) {
  const keys = ['users', 'groups', 'orgIds', 'sources', 'channels', 'destinations', 'detectors', 'categories'];
  return keys
    .filter((key) => Array.isArray(rule[key]) && rule[key].length)
    .map((key) => `${key}:${rule[key].slice(0, 2).map(shortPolicyValue).join('|')}${rule[key].length > 2 ? '+' : ''}`)
    .join(' ');
}

function parsePolicyJsonArray(value, label) {
  const raw = String(value || '').trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('expected array');
    return parsed;
  } catch {
    alert(`${label} must be valid JSON array syntax.`);
    return null;
  }
}

function cleanPolicyId(value, fallback = 'rule') {
  const id = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 64);
  return id || fallback;
}

function firstPolicyValue(value, fallback) {
  return parsePolicyList(value)[0] || fallback;
}

function addPolicyRuleToTextarea(selector, rule, label) {
  const textarea = $(selector);
  const existing = parsePolicyJsonArray(textarea.value, label);
  if (existing == null) return false;
  const next = existing.filter((item) => item && item.id !== rule.id);
  next.push(rule);
  textarea.value = JSON.stringify(next, null, 2);
  return true;
}

function collectPolicyMatchers(prefix) {
  const out = {};
  for (const key of ['users', 'groups', 'destinations', 'detectors', 'categories']) {
    const values = parsePolicyList($(`#${prefix}_${key}`).value);
    if (values.length) out[key] = values;
  }
  return out;
}

function suggestedPolicyId(prefix, matcherPrefix) {
  const pieces = [
    firstPolicyValue($(`#${matcherPrefix}_groups`).value, ''),
    firstPolicyValue($(`#${matcherPrefix}_users`).value, ''),
    firstPolicyValue($(`#${matcherPrefix}_destinations`).value, ''),
    firstPolicyValue($(`#${matcherPrefix}_categories`).value, ''),
    firstPolicyValue($(`#${matcherPrefix}_detectors`).value, ''),
  ].filter(Boolean);
  return cleanPolicyId(`${prefix}_${pieces.join('_')}`, `${prefix}_rule`);
}

function appendGuidedScopeRule() {
  const matchers = collectPolicyMatchers('scope_builder');
  if (!Object.keys(matchers).length) {
    alert('Scoped enforcement needs at least one matcher.');
    return;
  }
  const rule = {
    id: cleanPolicyId($('#scope_builder_id').value, suggestedPolicyId('scope', 'scope_builder')),
    ...matchers,
    enforcementMode: $('#scope_builder_mode').value,
  };
  const severityRaw = $('#scope_builder_severity').value;
  if (severityRaw !== '') {
    const severity = Number(severityRaw);
    if (Number.isFinite(severity)) rule.blockMinSeverity = severity;
  }
  const riskRaw = $('#scope_builder_risk').value;
  if (riskRaw !== '') {
    const risk = Number(riskRaw);
    if (Number.isFinite(risk)) rule.blockRiskScore = risk;
  }
  const reason = cleanPolicyId($('#scope_builder_reason').value, '');
  if (reason) rule.reason = reason;
  if (addPolicyRuleToTextarea('#pol_policy_scopes', rule, 'Scoped enforcement rules')) {
    $('#polSaved').textContent = `Added scoped rule ${rule.id}`;
  }
}

function appendGuidedExceptionRule() {
  const matchers = collectPolicyMatchers('exception_builder');
  if (!Object.keys(matchers).length) {
    alert('Time-bound exception needs at least one matcher.');
    return;
  }
  const hours = Math.max(1, Math.min(24 * 30, Number($('#exception_builder_hours').value) || 24));
  const rule = {
    id: cleanPolicyId($('#exception_builder_id').value, suggestedPolicyId('exception', 'exception_builder')),
    ...matchers,
    action: 'allow',
    expiresAt: new Date(Date.now() + hours * 60 * 60 * 1000).toISOString(),
  };
  const reason = cleanPolicyId($('#exception_builder_reason').value, '');
  if (reason) rule.reason = reason;
  if (addPolicyRuleToTextarea('#pol_policy_exceptions', rule, 'Time-bound exceptions')) {
    $('#polSaved').textContent = `Added exception ${rule.id}`;
  }
}

function statusTone(status) {
  const s = String(status || '').toLowerCase();
  if (['approved', 'allowed', 'justified', 'warned_sent', 'redacted'].includes(s)) return 'good';
  if (['denied', 'blocked_by_user', 'destination_blocked', 'file_upload_blocked', 'injection_blocked', 'response_flagged', 'seat_limit_blocked', 'ocr_required'].includes(s)) return 'bad';
  if (['pending', 'shadow_ai', 'paste_flagged'].includes(s)) return 'warn';
  if (s === 'sensor_heartbeat') return 'good';
  return 'info';
}

function postureTone(state) {
  return state === 'covered' ? 'good' : 'warn';
}

function fleetTone(state) {
  const s = String(state || '').toLowerCase();
  if (s === 'covered') return 'good';
  if (s === 'attention' || s === 'missing' || s === 'outdated') return 'bad';
  return 'warn';
}

function destinationPolicyLabel(state) {
  return ({
    allowed: 'Allowed',
    blocked: 'Blocked',
    file_upload_blocked: 'File uploads blocked',
    governed: 'Governed',
    review: 'Needs review',
  })[state] || 'Needs review';
}

function destinationPolicyTone(state) {
  if (state === 'allowed' || state === 'governed') return 'good';
  if (state === 'blocked' || state === 'file_upload_blocked') return 'bad';
  return 'warn';
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
  return ['security_admin', 'approver', 'operator', 'auditor'].includes(role) ? role : 'auditor';
}

function roleLabel(role) {
  return ({
    security_admin: 'Security Admin',
    approver: 'Approver',
    operator: 'Operator',
    auditor: 'Auditor',
  })[normalizeRole(role)] || humanize(role);
}

function canAdminWrite() {
  return currentRole === 'security_admin';
}

function canDecide(q = {}) {
  if (currentRole === 'security_admin') return true;
  if (currentRole !== 'approver') return false;
  return q.assignedRole === 'approver' && (!q.assignedUser || q.assignedUser === currentUser);
}

function canReveal(q = {}) {
  return currentRole === 'security_admin' && !!q;
}

function queueDecisionLabel(q = {}) {
  if (currentRole === 'auditor') return 'Read-only auditor view';
  if (currentRole === 'operator') return 'Operator view';
  if (currentRole === 'approver') return canDecide(q) ? '' : 'Not assigned to your role';
  return 'Read-only view';
}

function workflowOwner(q) {
  const group = q.assignedGroup || 'unassigned';
  const role = q.assignedRole ? ` / ${roleLabel(q.assignedRole)}` : '';
  return `${group}${role}`;
}

function isEscalated(q) {
  if (q.escalatedAt) return true;
  const due = Date.parse(q.slaDueAt || '');
  return Number.isFinite(due) && due < Date.now();
}

function queueFilterMatches(q) {
  if (queueFilter === 'mine') return q.assignedRole === currentRole || q.assignedUser === currentUser;
  if (queueFilter === 'unassigned') return !q.assignedRole && !q.assignedGroup;
  if (queueFilter === 'escalated') return isEscalated(q);
  return true;
}

function queueCategoryLabels(q = {}) {
  const labels = [
    ...(q.categories || []).map((category) => (typeof category === 'string' ? category : category && category.category)),
    ...(q.findings || []).map((finding) => finding && finding.type),
    ...Object.keys(q.entityCounts || {}),
  ];
  return [...new Set(labels.map((label) => String(label || '').trim()).filter(Boolean))];
}

function queueDestinationLabel(q = {}) {
  return String(q.destination || 'unknown').trim() || 'unknown';
}

function normalizeFilterValue(value) {
  return String(value || '').trim().toLowerCase();
}

function categoryFilterMatches(q) {
  if (queueCategoryFilter === 'all') return true;
  return queueCategoryLabels(q).some((label) => normalizeFilterValue(label) === queueCategoryFilter);
}

function destinationFilterMatches(q) {
  if (queueDestinationFilter === 'all') return true;
  return normalizeFilterValue(queueDestinationLabel(q)) === queueDestinationFilter;
}

function queueMetadataMatches(q) {
  return queueFilterMatches(q) && categoryFilterMatches(q) && destinationFilterMatches(q);
}

function uniqueSorted(values) {
  return [...new Set((values || []).map((value) => String(value || '').trim()).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
}

function syncSelectOptions(select, selected, allLabel, values) {
  if (!select) return 'all';
  const options = uniqueSorted(values);
  const normalizedOptions = new Set(options.map(normalizeFilterValue));
  const nextSelected = selected === 'all' || normalizedOptions.has(selected) ? selected : 'all';
  select.innerHTML = [
    `<option value="all">${escapeHtml(allLabel)}</option>`,
    ...options.map((value) => `<option value="${escapeHtml(normalizeFilterValue(value))}">${escapeHtml(value)}</option>`),
  ].join('');
  select.value = nextSelected;
  return nextSelected;
}

function syncQueueFilterOptions() {
  queueCategoryFilter = syncSelectOptions(
    $('#queueCategoryFilter'),
    queueCategoryFilter,
    'All categories',
    currentQueue.flatMap(queueCategoryLabels),
  );
  queueDestinationFilter = syncSelectOptions(
    $('#queueDestinationFilter'),
    queueDestinationFilter,
    'All destinations',
    currentQueue.map(queueDestinationLabel),
  );
}

function workflowChips(q) {
  const chips = [];
  if (q.assignedGroup || q.assignedRole) chips.push(`<span class="chip"><b>Owner</b> ${escapeHtml(workflowOwner(q))}</span>`);
  if (q.slaDueAt) chips.push(`<span class="chip ${isEscalated(q) ? 'category' : ''}"><b>SLA</b> ${escapeHtml(fmt(q.slaDueAt))}</span>`);
  if (q.escalationReason) chips.push(`<span class="chip category"><b>Escalated</b> ${escapeHtml(humanize(q.escalationReason))}</span>`);
  if (q.notificationStatus) chips.push(`<span class="chip"><b>Notify</b> ${escapeHtml(humanize(q.notificationStatus))}</span>`);
  if ((q.notificationChannels || []).length) chips.push(`<span class="chip"><b>Channels</b> ${escapeHtml((q.notificationChannels || []).join(', '))}</span>`);
  return chips.join('');
}

function queryText(q) {
  return [
    q.id, q.user, q.destination, q.source, q.channel, q.status, q.maxSeverityLabel,
    q.assignedRole, q.assignedGroup, q.workflowReason, q.escalationReason, q.notificationStatus,
    ...(q.notificationChannels || []), q.redactedPrompt, ...(q.reasons || []), ...(q.categories || []),
    ...(q.findings || []).map((f) => `${f.type} ${f.masked || ''}`),
    ...Object.keys(q.entityCounts || {}),
  ].join(' ').toLowerCase();
}

function matchesSearch(q) {
  return !searchTerm || queryText(q).includes(searchTerm);
}

function lineageText(bucket) {
  return [
    bucket.key,
    ...(bucket.categories || []),
    bucket.events,
    bucket.blocked,
    bucket.redacted,
    bucket.allowed,
    bucket.warned,
    bucket.maxRiskScore,
  ].join(' ').toLowerCase();
}

function matchesLineage(bucket) {
  return !searchTerm || lineageText(bucket || {}).includes(searchTerm);
}

function updateSearch(value) {
  searchTerm = String(value || '').trim().toLowerCase();
  renderQueueView();
  renderActivityRows(currentActivity);
  renderLineage(currentLineage);
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
        <label>Account password
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

function askDestinationReviewReason({ destination, decision }) {
  const labels = { govern: 'govern', allow: 'allow', block: 'block' };
  return new Promise((resolve) => {
    const dialog = document.createElement('dialog');
    dialog.className = 'stepup-dialog';
    dialog.innerHTML = `
      <form method="dialog" class="stepup-panel">
        <div>
          <h2>Record destination reason</h2>
          <p>${escapeHtml(labels[decision] || 'review')} ${escapeHtml(destination)} with a short examiner-facing reason.</p>
        </div>
        <label>Admin reason
          <textarea name="reason" rows="3" maxlength="240" required></textarea>
        </label>
        <div class="stepup-actions">
          <button class="btn" value="cancel" type="button">Cancel</button>
          <button class="btn approve" value="confirm" type="submit">${icons.check}Save review</button>
        </div>
      </form>`;
    document.body.appendChild(dialog);
    const input = $('textarea[name=reason]', dialog);
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
      const reason = (input.value || '').trim();
      if (!reason) {
        input.focus();
        return;
      }
      cleanup(reason);
    });
    dialog.showModal();
    input.focus();
  });
}

async function init() {
  const meRes = await api('/api/me');
  if (!meRes) return;
  const me = await meRes.json();
  await loadCsrf();
  currentRole = normalizeRole(me.role);
  currentUser = me.user || '';
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
  $$('.queue-tools [data-queue-filter]').forEach((button) => {
    button.classList.toggle('active', button.dataset.queueFilter === queueFilter);
  });
  syncQueueFilterOptions();
  const rows = currentQueue.filter(queueMetadataMatches).filter(matchesSearch);
  if (!currentQueue.length) {
    el.innerHTML = '<div class="empty"><div class="big">Queue clear</div>No prompts are awaiting approval.</div>';
    renderIncident(null);
    return;
  }
  if (!rows.length) {
    el.innerHTML = '<div class="empty"><div class="big">No matches</div>No pending prompts match the current queue filter.</div>';
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
    || canDecide(q)
    ? `<textarea class="note" id="note_${escapeHtml(q.id)}" placeholder="Decision note, recorded in audit log"></textarea>
    <div class="actions">
      <button class="btn approve" data-act="approve" data-id="${escapeHtml(q.id)}" type="button">${icons.check}Approve release</button>
      <button class="btn deny" data-act="deny" data-id="${escapeHtml(q.id)}" type="button">${icons.deny}Deny</button>
      ${canReveal(q) ? `<button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button">${icons.eye}Reveal gated</button>` : ''}
    </div>`
    : `<div class="readonly-note">${escapeHtml(queueDecisionLabel(q))}</div>`;
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
    <div class="chips">${findingChips(q.findings, q.categories)}${workflowChips(q)}</div>
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
      <div class="datum"><label>Owner</label><b>${escapeHtml(workflowOwner(q))}</b></div>
      <div class="datum"><label>SLA</label><b>${escapeHtml(q.slaDueAt ? fmt(q.slaDueAt) : '-')}</b></div>
      <div class="datum"><label>Notification</label><b>${escapeHtml(humanize(q.notificationStatus || 'not configured'))}</b></div>
      <div class="datum"><label>Escalation</label><b>${escapeHtml(q.escalatedAt ? fmt(q.escalatedAt) : '-')}</b></div>
    </div>
    <div class="risk-meter" style="--risk-width:${risk}%">
      <div class="top"><span class="sev ${sev}">${escapeHtml(q.maxSeverityLabel || 'low')}</span><span class="risk">Risk <b>${risk}</b>/100</span></div>
      <div class="risk-track"><i></i></div>
    </div>
    <div class="prompt">${escapeHtml(q.redactedPrompt)}</div>
    <div class="posture-list">${matches}</div>`;
}

document.addEventListener('click', async (e) => {
  const filterButton = e.target.closest('[data-queue-filter]');
  if (filterButton) {
    queueFilter = filterButton.dataset.queueFilter || 'all';
    renderQueueView();
    return;
  }
  const destinationReview = e.target.closest('[data-destination-review]');
  if (destinationReview) {
    if (!canAdminWrite()) {
      alert('Request not allowed for this session. Use a Security Admin account.');
      return;
    }
    const destination = destinationReview.dataset.destination;
    const decision = destinationReview.dataset.destinationReview;
    const reason = await askDestinationReviewReason({ destination, decision });
    if (!reason) return;
    destinationReview.disabled = true;
    const r = await api('/api/destinations/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ destination, decision, reason }),
    });
    if (!r || !r.ok) {
      destinationReview.disabled = false;
      alert('Destination review could not be saved.');
      return;
    }
    const body = await r.json();
    currentCoverage = body.coverage || currentCoverage;
    renderCoverage(currentCoverage);
    await loadStats();
    if (!$('#tab-policy').classList.contains('hidden')) await loadPolicy();
    return;
  }
  const actionButton = e.target.closest('[data-act]');
  if (actionButton) {
    const act = actionButton.dataset.act;
    const id = actionButton.dataset.id;
    const q = currentQueue.find((item) => item.id === id) || {};
    if (act === 'reveal') {
      if (!canReveal(q)) {
        alert('Request not allowed for this session. Use a Security Admin account.');
        return;
      }
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
      if (!canDecide(q)) {
        alert('Request not allowed for this session.');
        return;
      }
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

document.addEventListener('change', (e) => {
  if (e.target.matches('#queueCategoryFilter')) {
    queueCategoryFilter = e.target.value || 'all';
    renderQueueView();
    return;
  }
  if (e.target.matches('#queueDestinationFilter')) {
    queueDestinationFilter = e.target.value || 'all';
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
    <td>${escapeHtml(workflowOwner(q))}</td>
    <td><span class="sev ${sevClass(q.maxSeverityLabel)}">${escapeHtml(q.maxSeverityLabel || 'low')}</span></td>
    <td class="mono">${escapeHtml(q.riskScore ?? 0)}</td>
    <td>${escapeHtml(Object.keys(q.entityCounts || {}).join(', ') || '-')}</td>
    <td><span class="pill ${statusTone(q.status)}">${escapeHtml(humanize(q.status))}</span></td>
  </tr>`).join('') || '<tr><td colspan="9" class="empty">No matching activity</td></tr>';
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
    if (s.desiredVersion) parts.push('desired v' + s.desiredVersion);
    if (s.versionHealth === 'mixed') parts.push((s.versions || []).length + ' versions');
    if (s.versionHealth === 'outdated') parts.push('outdated');
    if (s.installHealth && s.installHealth.state === 'attention') parts.push(((s.installHealth.failedChecks || []).length || 1) + ' failed checks');
    else if (s.installHealth && s.installHealth.state === 'covered') parts.push('install checks ok');
    if (s.required) parts.push('required');
    if ((s.platforms || []).length) parts.push((s.platforms || []).join(', '));
    return parts.join(' | ');
  };
  const fleetVersionLine = (row) => {
    const parts = [];
    if (row.latestVersion) parts.push('v' + row.latestVersion);
    else if (row.events) parts.push('version unknown');
    if (row.desiredVersion) parts.push('desired v' + row.desiredVersion);
    if ((row.platforms || []).length) parts.push((row.platforms || []).join(', '));
    return parts.join(' | ') || '-';
  };
  const fleetFailedChecks = (row) => {
    const failed = row.installHealth && row.installHealth.failedChecks;
    if (Array.isArray(failed) && failed.length) return failed.join(', ');
    if (row.installHealth && row.installHealth.state === 'covered') return 'checks ok';
    if (row.state === 'missing') return 'no required sensor evidence';
    if (row.state === 'unknown') return 'no install-health heartbeat';
    return '-';
  };
  $('#coverageScore').innerHTML = `
    <div class="score-ring" style="--score:${escapeHtml(c.score || 0)}%"><b>${escapeHtml(c.score || 0)}</b></div>
    <span>Coverage score</span>
    <div class="coverage-kpis">
      <div class="mini-kpi"><b>${escapeHtml(totals.events || 0)}</b><span>Events</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.governedActive || 0)}/${escapeHtml(totals.governedDestinations || 0)}</b><span>Governed</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.shadowEvents || 0)}</b><span>Shadow AI</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.blocked || 0)}</b><span>Blocked</span></div>
      <div class="mini-kpi"><b>${escapeHtml(totals.fleetAttention || 0)}</b><span>Fleet gaps</span></div>
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
  $('#fleetRows').innerHTML = (c.fleet || []).map((row) => `<tr>
    <td>${escapeHtml(row.user || 'unknown')}</td>
    <td class="mono">${escapeHtml(row.orgId || '-')}</td>
    <td>${escapeHtml(row.label || sourceLabel(row.source))}</td>
    <td><span class="pill ${fleetTone(row.state)}">${escapeHtml(row.state || 'unknown')}</span></td>
    <td class="mono">${escapeHtml(fleetVersionLine(row))}</td>
    <td>${escapeHtml(fleetFailedChecks(row))}</td>
    <td class="mono">${escapeHtml(row.lastSeen ? fmt(row.lastSeen) : '-')}</td>
  </tr>`).join('') || '<tr><td colspan="7" class="empty">No fleet sensor evidence yet.</td></tr>';
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
      <div class="destination-review">
        <span class="pill ${destinationPolicyTone(d.policyState)}">${escapeHtml(destinationPolicyLabel(d.policyState))}</span>
        <span class="count">${escapeHtml(d.shadow)}</span>
        ${(d.policyState || 'review') === 'review' && canAdminWrite()
    ? `<div class="destination-actions">
          <button class="ghost mini" data-destination-review="govern" data-destination="${escapeHtml(d.destination)}" type="button">${icons.shield}Govern</button>
          <button class="ghost mini" data-destination-review="allow" data-destination="${escapeHtml(d.destination)}" type="button">${icons.check}Allow</button>
          <button class="ghost mini danger" data-destination-review="block" data-destination="${escapeHtml(d.destination)}" type="button">${icons.deny}Block</button>
        </div>`
    : ''}
      </div>
    </div>`).join('') || '<div class="empty"><div class="big">No shadow AI</div>No ungoverned AI tools have been reported.</div>';
}

async function loadLineage() {
  const r = await api('/api/lineage?limit=1000');
  if (!r) return;
  const body = await r.json();
  currentLineage = body.lineage || {};
  renderLineage(currentLineage);
}

function renderLineageRows(selector, rows, emptyLabel) {
  const filtered = (rows || []).filter(matchesLineage);
  $(selector).innerHTML = filtered.map((row) => `<tr>
    <td class="mono">${escapeHtml(row.key || '-')}</td>
    <td class="mono">${escapeHtml(row.events || 0)}</td>
    <td class="mono">${escapeHtml(row.blocked || 0)}</td>
    <td class="mono">${escapeHtml(row.redacted || 0)}</td>
    <td class="mono">${escapeHtml(row.maxRiskScore || 0)}</td>
  </tr>`).join('') || `<tr><td colspan="5" class="empty">${escapeHtml(emptyLabel)}</td></tr>`;
}

function lineageTotals(lineage = {}) {
  const decisions = lineage.byDecision || [];
  const totalEvents = decisions.reduce((sum, row) => sum + (Number(row.events) || 0), 0);
  const blocked = decisions.find((row) => row.key === 'blocked');
  const redacted = decisions.find((row) => row.key === 'redacted');
  const allowed = decisions.find((row) => row.key === 'allowed');
  return {
    events: totalEvents,
    users: (lineage.byUser || []).length,
    destinations: (lineage.byDestination || []).length,
    blocked: blocked ? blocked.events : 0,
    redacted: redacted ? redacted.events : 0,
    allowed: allowed ? allowed.events : 0,
  };
}

function renderLineage(lineage) {
  if (!lineage) return;
  const totals = lineageTotals(lineage);
  $('#lineageSummary').innerHTML = [
    ['Events', totals.events, 'recent sanitized records'],
    ['Users', totals.users, 'unique lineage buckets'],
    ['Destinations', totals.destinations, 'AI tools and apps'],
    ['Blocked', totals.blocked, 'policy stops'],
    ['Redacted', totals.redacted, 'tokenized or masked'],
    ['Allowed', totals.allowed, 'below thresholds'],
  ].map(([label, value, meta]) => `
    <div class="mini-kpi"><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span><em>${escapeHtml(meta)}</em></div>`).join('');
  renderLineageRows('#lineageUsers', lineage.byUser, 'No user lineage yet.');
  renderLineageRows('#lineageDestinations', lineage.byDestination, 'No destination lineage yet.');
  renderLineageRows('#lineageSensors', lineage.bySensor, 'No sensor lineage yet.');
  renderLineageRows('#lineageCategories', lineage.byCategory, 'No category lineage yet.');
  renderLineageRows('#lineageChannels', lineage.byChannel, 'No channel lineage yet.');
  renderLineageRows('#lineageDecisions', lineage.byDecision, 'No decision lineage yet.');
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
      <label for="pol_desktop_destination">Default desktop upload destination</label>
      <input id="pol_desktop_destination" type="text" maxlength="80" value="${escapeHtml(p.desktopCollectorDestination || 'Desktop AI')}" ${readonly ? 'disabled' : ''}/>
      <label for="pol_block_unapproved_ai">Block unapproved AI destinations</label>
      <input id="pol_block_unapproved_ai" type="checkbox" ${p.blockUnapprovedAiDestinations !== false ? 'checked' : ''} ${readonly ? 'disabled' : ''}/>
    </div>
    <div class="policy-label">Fleet posture</div>
    <div class="policy-list-grid">
      <label class="policy-list-field">Required sensors
        ${readonly
    ? `<div class="chips">${(p.requiredSensors || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_required_sensors" class="policy-textarea" spellcheck="false" placeholder="browser_extension&#10;endpoint_agent&#10;mcp_guard">${escapeHtml(policyListText(p.requiredSensors))}</textarea>`}
      </label>
      <label class="policy-list-field">Desired sensor versions
        ${readonly
    ? `<div class="chips">${Object.entries(p.desiredSensorVersions || {}).map(([k, v]) => `<span class="chip"><b>${escapeHtml(k)}</b> ${escapeHtml(v)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_desired_sensor_versions" class="policy-textarea" spellcheck="false" placeholder="browser_extension=0.3.0&#10;endpoint_agent=0.3.0">${escapeHtml(policyMapText(p.desiredSensorVersions))}</textarea>`}
      </label>
    </div>
    <div class="policy-label">Approval routing rules</div>
    <div class="template-bar">
      ${readonly
    ? `<div class="chips">${(p.approvalRoutingRules || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.id)}</b> ${escapeHtml(rule.assignedGroup || '')} / ${escapeHtml(roleLabel(rule.assignedRole))} ${escapeHtml(policyMatcherSummary(rule))}</span>`).join('') || '<span class="chip">default routing</span>'}</div>`
    : `<textarea id="pol_approval_routing_rules" class="policy-textarea" spellcheck="false" style="min-height:160px" placeholder='[{"id":"legal_group_contracts","groups":["PromptWall Legal"],"categories":["LEGAL_CONTRACT"],"destinations":["claude.ai"],"assignedGroup":"legal","assignedRole":"approver","slaMinutes":60}]'>${escapeHtml(policyJsonText(p.approvalRoutingRules))}</textarea>`}
    </div>
    <div class="policy-label">Scoped policy and exceptions</div>
    ${readonly ? '' : `<div class="policy-builder-grid">
      <div class="policy-builder" id="scopeRuleBuilder">
        <h3>Guided scoped enforcement</h3>
        <div class="mini-grid">
          <label>Rule id<input id="scope_builder_id" type="text" placeholder="legal_contract_review"/></label>
          <label>SCIM groups<input id="scope_builder_groups" type="text" placeholder="PromptWall Legal"/></label>
          <label>Users<input id="scope_builder_users" type="text" placeholder="counsel@example.test"/></label>
          <label>Destinations<input id="scope_builder_destinations" type="text" placeholder="claude.ai"/></label>
          <label>Categories<input id="scope_builder_categories" type="text" placeholder="LEGAL_CONTRACT"/></label>
          <label>Detectors<input id="scope_builder_detectors" type="text" placeholder="SECRET_KEY"/></label>
          <label>Mode<select id="scope_builder_mode">
            <option value="block">Block</option>
            <option value="justify">Require justification</option>
            <option value="redact">Redact</option>
            <option value="warn">Warn</option>
          </select></label>
          <label>Min severity<select id="scope_builder_severity">
            <option value="">No override</option>
            <option value="1">low</option>
            <option value="2" selected>medium</option>
            <option value="3">high</option>
            <option value="4">critical</option>
          </select></label>
          <label>Risk score<input id="scope_builder_risk" type="number" min="0" max="100" placeholder="25"/></label>
          <label>Reason<input id="scope_builder_reason" type="text" placeholder="legal_contract_review"/></label>
        </div>
        <button class="btn" id="addScopeRule" type="button">${icons.check}Add scoped rule</button>
      </div>
      <div class="policy-builder" id="exceptionRuleBuilder">
        <h3>Guided time-bound exception</h3>
        <div class="mini-grid">
          <label>Exception id<input id="exception_builder_id" type="text" placeholder="legal_vendor_24h"/></label>
          <label>SCIM groups<input id="exception_builder_groups" type="text" placeholder="PromptWall Legal"/></label>
          <label>Users<input id="exception_builder_users" type="text" placeholder="counsel@example.test"/></label>
          <label>Destinations<input id="exception_builder_destinations" type="text" placeholder="claude.ai"/></label>
          <label>Categories<input id="exception_builder_categories" type="text" placeholder="LEGAL_CONTRACT"/></label>
          <label>Detectors<input id="exception_builder_detectors" type="text" placeholder="SOURCE_CODE"/></label>
          <label>Expires after hours<input id="exception_builder_hours" type="number" min="1" max="720" value="24"/></label>
          <label>Reason<input id="exception_builder_reason" type="text" placeholder="approved_vendor_review"/></label>
        </div>
        <button class="btn" id="addExceptionRule" type="button">${icons.check}Add exception</button>
      </div>
    </div>`}
    <div class="policy-advanced-grid">
      <label class="policy-list-field">Scoped enforcement rules
        ${readonly
    ? `<div class="chips">${(p.policyScopes || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.id)}</b> ${escapeHtml(rule.enforcementMode || 'scope')} ${escapeHtml(policyMatcherSummary(rule))}</span>`).join('') || '<span class="chip">no scoped rules</span>'}</div>`
    : `<textarea id="pol_policy_scopes" class="policy-textarea" spellcheck="false" style="min-height:190px" placeholder='[{"id":"legal_contract_review","groups":["PromptWall Legal"],"destinations":["claude.ai"],"categories":["LEGAL_CONTRACT"],"enforcementMode":"block","blockMinSeverity":2}]'>${escapeHtml(policyJsonText(p.policyScopes))}</textarea>`}
      </label>
      <label class="policy-list-field">Time-bound exceptions
        ${readonly
    ? `<div class="chips">${(p.policyExceptions || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.id)}</b> ${escapeHtml(rule.expiresAt || '')} ${escapeHtml(policyMatcherSummary(rule))}</span>`).join('') || '<span class="chip">no exceptions</span>'}</div>`
    : `<textarea id="pol_policy_exceptions" class="policy-textarea" spellcheck="false" style="min-height:190px" placeholder='[{"id":"legal_vendor_24h","users":["counsel@example.test"],"destinations":["claude.ai"],"categories":["LEGAL_CONTRACT"],"expiresAt":"2030-01-01T00:00:00.000Z"}]'>${escapeHtml(policyJsonText(p.policyExceptions))}</textarea>`}
      </label>
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
  $('#addScopeRule').onclick = appendGuidedScopeRule;
  $('#addExceptionRule').onclick = appendGuidedExceptionRule;
  $('#savePolicy').onclick = async () => {
    const mode = (document.querySelector('input[name=mode]:checked') || {}).value || p.enforcementMode;
    const approvalRoutingRules = parsePolicyJsonArray($('#pol_approval_routing_rules').value, 'Approval routing rules');
    if (approvalRoutingRules == null) return;
    const policyScopes = parsePolicyJsonArray($('#pol_policy_scopes').value, 'Scoped enforcement rules');
    if (policyScopes == null) return;
    const policyExceptions = parsePolicyJsonArray($('#pol_policy_exceptions').value, 'Time-bound exceptions');
    if (policyExceptions == null) return;
    const body = {
      enforcementMode: mode,
      blockMinSeverity: Number($('#pol_sev').value),
      blockRiskScore: Number($('#pol_risk').value),
      rawRetentionDays: Number($('#pol_retention').value),
      desktopCollectorDestination: ($('#pol_desktop_destination').value || '').trim(),
      requiredSensors: parsePolicyList($('#pol_required_sensors').value),
      desiredSensorVersions: parsePolicyMap($('#pol_desired_sensor_versions').value),
      approvalRoutingRules,
      policyScopes,
      policyExceptions,
      governedDestinations: parsePolicyList($('#pol_governed_destinations').value),
      allowedDestinations: parsePolicyList($('#pol_allowed_destinations').value),
      blockedDestinations: parsePolicyList($('#pol_blocked_destinations').value),
      blockedFileUploadDestinations: parsePolicyList($('#pol_blocked_file_upload_destinations').value),
      blockUnapprovedAiDestinations: $('#pol_block_unapproved_ai').checked,
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
  if (name === 'lineage') loadLineage();
}

$$('.tab').forEach((t) => {
  t.onclick = () => activateTab(t.dataset.tab);
});

$('#refreshQueue').onclick = loadQueue;
$('#refreshCoverage').onclick = loadCoverage;
$('#refreshLineage').onclick = loadLineage;
$('#logout').onclick = async () => { await api('/api/logout', { method: 'POST' }); location.href = '/login.html'; };
$('#exportEvidence').onclick = exportEvidence;
$('#globalSearch').addEventListener('input', (e) => updateSearch(e.target.value));

function connectStream() {
  const es = new EventSource('/api/stream');
  es.addEventListener('query', () => { loadStats(); loadQueue(); if (!$('#tab-coverage').classList.contains('hidden')) loadCoverage(); if (!$('#tab-lineage').classList.contains('hidden')) loadLineage(); flash(); });
  es.addEventListener('decision', () => { loadStats(); loadQueue(); loadActivity(); if (!$('#tab-lineage').classList.contains('hidden')) loadLineage(); });
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
