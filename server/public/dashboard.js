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
let currentIdentitySetup = null;
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

function exceptionLifecycleSummary(rule = {}) {
  const now = Date.now();
  const expires = Date.parse(rule.expiresAt || '');
  const reviewAfter = Date.parse(rule.reviewAfter || '');
  let status = 'active';
  if (rule.enabled === false) status = 'disabled';
  else if (Number.isFinite(expires) && expires <= now) status = 'expired';
  else if (Number.isFinite(reviewAfter) && reviewAfter <= now) status = 'review due';
  else if (Number.isFinite(expires) && expires <= now + 7 * 24 * 60 * 60 * 1000) status = 'expiring soon';
  const parts = [status];
  if (rule.ownerGroup) parts.push(`owner ${rule.ownerGroup}`);
  if (rule.reviewerRole) parts.push(`reviewer ${rule.reviewerRole}`);
  if (rule.reviewAfter) parts.push(`review ${rule.reviewAfter}`);
  return parts.join(' ');
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
  const now = Date.now();
  const rule = {
    id: cleanPolicyId($('#exception_builder_id').value, suggestedPolicyId('exception', 'exception_builder')),
    ...matchers,
    action: 'allow',
    expiresAt: new Date(now + hours * 60 * 60 * 1000).toISOString(),
  };
  const ownerGroup = cleanPolicyId($('#exception_builder_owner_group').value, '');
  if (ownerGroup) rule.ownerGroup = ownerGroup;
  const reviewerRole = $('#exception_builder_reviewer_role').value;
  if (reviewerRole) rule.reviewerRole = reviewerRole;
  const reviewHoursRaw = $('#exception_builder_review_hours').value;
  if (reviewHoursRaw !== '') {
    const reviewHours = Math.max(1, Math.min(hours, Number(reviewHoursRaw) || hours));
    rule.reviewAfter = new Date(now + reviewHours * 60 * 60 * 1000).toISOString();
  }
  const reason = cleanPolicyId($('#exception_builder_reason').value, '');
  if (reason) rule.reason = reason;
  if (addPolicyRuleToTextarea('#pol_policy_exceptions', rule, 'Time-bound exceptions')) {
    $('#polSaved').textContent = `Added exception ${rule.id}`;
  }
}

function statusTone(status) {
  const s = String(status || '').toLowerCase();
  if (['approved', 'allowed', 'justified', 'warned_sent', 'redacted', 'response_redacted'].includes(s)) return 'good';
  if (['denied', 'blocked_by_user', 'destination_blocked', 'file_upload_blocked', 'action_blocked', 'injection_blocked', 'response_flagged', 'response_blocked', 'seat_limit_blocked', 'ocr_required'].includes(s)) return 'bad';
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

function endpointAiToolTone(state) {
  return String(state || '').toLowerCase() === 'approved' ? 'good' : 'bad';
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
  $('#endpointAiToolRows').innerHTML = (c.endpointAiTools || []).map((tool) => {
    const meta = [
      tool.user || 'unknown',
      tool.orgId || '',
      (tool.platforms || []).join(', '),
      tool.lastSeen ? fmt(tool.lastSeen) : '',
    ].filter(Boolean).join(' | ');
    return `<div class="tool-row">
      <div><strong>${escapeHtml(tool.label || tool.id || 'Unknown AI tool')}</strong><span>${escapeHtml(meta || '-')}</span></div>
      <div class="tool-state">
        <span class="pill ${endpointAiToolTone(tool.state)}">${escapeHtml(tool.state || 'unknown')}</span>
        <span>${escapeHtml(tool.detail || '-')}</span>
      </div>
    </div>`;
  }).join('') || '<div class="empty"><div class="big">No endpoint AI tools</div>No endpoint AI tool inventory has been reported.</div>';
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

function identityProviderLabel(provider) {
  return ({
    entra: 'Microsoft Entra ID',
    okta: 'Okta',
  })[provider] || humanize(provider);
}

async function loadIdentitySetup() {
  const provider = ($('#identityProvider') && $('#identityProvider').value) || 'entra';
  const tenantId = ($('#identityTenant') && $('#identityTenant').value.trim()) || '';
  const params = new URLSearchParams({ provider });
  if (tenantId) params.set('tenantId', tenantId);
  const r = await api(`/api/identity/setup-guide?${params.toString()}`);
  if (!r) return;
  currentIdentitySetup = await r.json();
  if (currentIdentitySetup.error) {
    $('#identitySummary').innerHTML = `<div class="empty"><div class="big">Identity setup unavailable</div>${escapeHtml(currentIdentitySetup.error)}</div>`;
    return;
  }
  renderIdentitySetup(currentIdentitySetup);
}

function identityValueRows(rows) {
  return rows.map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td class="mono">${escapeHtml(value || '-')}</td></tr>`).join('');
}

function renderIdentitySummary(guide) {
  $('#identitySummary').innerHTML = [
    ['Provider', guide.label || identityProviderLabel(guide.provider), guide.tenantLabel || 'Tenant'],
    ['SCIM URL', guide.scim && guide.scim.tenantUrl, 'Provisioning'],
    ['Redirect URI', guide.oidc && guide.oidc.redirectUri, 'Console SSO'],
    ['Preflight', (guide.preflightChecks || []).join(', '), 'Checks'],
  ].map(([label, value, meta]) => `
    <div class="mini-kpi"><b>${escapeHtml(label)}</b><em>${escapeHtml(value || '-')}</em><span>${escapeHtml(meta)}</span></div>
  `).join('');
}

function renderIdentityTables(guide) {
  $('#identityScimRows').innerHTML = identityValueRows([
    ['Tenant URL', guide.scim && guide.scim.tenantUrl],
    ['Base URL', guide.scim && guide.scim.baseUrl],
    ['Authentication', guide.scim && guide.scim.authMode],
    ['Token env', guide.scim ? `${guide.scim.tokenEnv} / ${guide.scim.tokenAlias}` : ''],
    ['Unique ID', guide.scim && guide.scim.uniqueIdentifier],
    ['Content type', guide.scim && guide.scim.contentType],
  ]);
  $('#identityOidcRows').innerHTML = identityValueRows([
    ['Application type', guide.oidc && guide.oidc.applicationType],
    ['Issuer', guide.oidc && guide.oidc.issuer],
    ['Redirect URI', guide.oidc && guide.oidc.redirectUri],
    ['Scopes', guide.oidc ? (guide.oidc.scopes || []).join(' ') : ''],
    ['Discovery', guide.oidc && guide.oidc.discovery],
  ]);
  $('#identityEnvRows').innerHTML = (guide.env || []).map((row) => `<tr>
    <td class="mono">${escapeHtml(row.key)}</td>
    <td class="mono">${escapeHtml(row.alias)}</td>
    <td class="mono">${escapeHtml(row.value)}</td>
  </tr>`).join('');
  $('#identityRoleRows').innerHTML = (guide.roleGroups || []).map((row) => `<tr>
    <td><span class="pill info">${escapeHtml(roleLabel(row.role))}</span></td>
    <td>${escapeHtml((row.groups || []).join(', '))}</td>
  </tr>`).join('');
}

function renderIdentityValidation(guide) {
  $('#identityValidation').innerHTML = [
    ...(guide.validation || []).map((item) => ['Command', item]),
    ...(guide.safety || []).map((item) => ['Safety', item]),
  ].map(([label, detail]) => `
    <div class="posture-item"><span>${escapeHtml(label)}</span><b>${escapeHtml(detail)}</b></div>
  `).join('');
}

function renderIdentitySetup(guide) {
  renderIdentitySummary(guide);
  renderIdentityTables(guide);
  renderIdentityValidation(guide);
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

function checkMap(preflight) {
  return new Map(((preflight && preflight.checks) || []).map((item) => [item.id, item]));
}

function checkGroupState(preflight, ids) {
  const checks = checkMap(preflight);
  const selected = ids.map((id) => checks.get(id)).filter(Boolean);
  if (!selected.length) return 'warn';
  if (selected.some((item) => !item.ok && item.severity === 'error')) return 'bad';
  if (selected.some((item) => !item.ok)) return 'warn';
  return 'good';
}

function stateLabel(state) {
  return ({ good: 'Ready', warn: 'Needs review', bad: 'Blocked' })[state] || 'Review';
}

function statePill(state, label = stateLabel(state)) {
  const tone = state === 'bad' ? 'bad' : state === 'warn' ? 'warn' : 'good';
  return `<span class="pill ${tone}">${escapeHtml(label)}</span>`;
}

function configHealth(preflight) {
  const checks = (preflight && preflight.checks) || [];
  const ok = checks.filter((item) => item.ok).length;
  const score = checks.length ? Math.round((ok / checks.length) * 100) : 0;
  const state = preflight && preflight.level === 'blocked' ? 'bad' : score < 100 ? 'warn' : 'good';
  return {
    score,
    ok,
    total: checks.length,
    state,
    failed: checks.length - ok,
    label: preflight && preflight.level ? humanize(preflight.level) : 'unknown',
  };
}

function setupChecklist(p, preflight, coverage) {
  const health = configHealth(preflight);
  const sensorCount = (coverage && coverage.sensors || []).filter((sensor) => sensor.events || sensor.required).length;
  const items = [
    ['Admin access', checkGroupState(preflight, ['admin_password', 'admin_password_strength', 'admin_mfa', 'session_secret']), 'MFA, password, session'],
    ['Identity provider', checkGroupState(preflight, ['oidc_config', 'oidc_scim_users', 'scim_bearer_token_strength']), 'OIDC and SCIM'],
    ['Deploy sensors', sensorCount ? 'good' : 'warn', `${sensorCount || 0} observed`],
    ['Define destinations', (p.governedDestinations || []).length ? 'good' : 'warn', `${(p.governedDestinations || []).length} governed`],
    ['Choose policy mode', p.enforcementMode ? 'good' : 'warn', humanize(p.enforcementMode)],
    ['Set approval routing', (p.approvalRoutingRules || []).length ? 'good' : 'warn', `${(p.approvalRoutingRules || []).length} rules`],
    ['Review DLP rules', (p.alwaysBlock || []).length ? 'good' : 'warn', `${(p.alwaysBlock || []).length} hard stops`],
    ['Test configuration', health.state === 'bad' ? 'bad' : 'good', `${health.ok}/${health.total || 0} checks`],
  ];
  const done = items.filter(([, state]) => state === 'good').length;
  return { items, done, total: items.length };
}

function renderSetupChecklist(p, preflight, coverage) {
  const checklist = setupChecklist(p, preflight, coverage);
  return `<div class="config-card pad">
    <div class="sensor-head">
      <div><h3>Setup Checklist</h3><p>Fast path from install to governed pilot.</p></div>
      <span class="pill ${checklist.done === checklist.total ? 'good' : 'warn'}">${escapeHtml(checklist.done)}/${escapeHtml(checklist.total)} ready</span>
    </div>
    <div class="setup-list">${checklist.items.map(([label, state, detail]) => `
      <div class="setup-item">
        <span class="setup-dot ${escapeHtml(state)}">${state === 'bad' ? '!' : ''}</span>
        <span>${escapeHtml(label)}</span>
        <small>${escapeHtml(detail)}</small>
      </div>`).join('')}</div>
  </div>`;
}

function renderHealthCard(preflight, coverage, p) {
  const health = configHealth(preflight);
  const totals = (coverage && coverage.totals) || {};
  return `<div class="config-card pad">
    <div class="sensor-head">
      <div><h3>Configuration Health</h3><p>Readiness across auth, sensors, data, and governance.</p></div>
      ${statePill(health.state, health.state === 'good' ? 'Good' : health.label)}
    </div>
    <div class="health-score ${escapeHtml(health.state)}"><b>${escapeHtml(health.score)}</b><span>/ 100</span></div>
    <div class="health-rows">
      <div class="health-row"><span>Sensors</span><b>${escapeHtml((p.requiredSensors || []).length || 0)} required</b></div>
      <div class="health-row"><span>Destinations</span><b>${escapeHtml((p.governedDestinations || []).length || 0)} governed</b></div>
      <div class="health-row"><span>Fleet gaps</span><b>${escapeHtml(totals.fleetAttention || 0)}</b></div>
      <div class="health-row"><span>Preflight checks</span><b>${escapeHtml(health.failed)} open</b></div>
    </div>
  </div>`;
}

function sensorCard(id, p, coverage) {
  const labels = {
    browser_extension: ['Browser Extension', 'Web AI prompts and responses'],
    endpoint_agent: ['Endpoint Agent', 'Desktop AI apps and file handoff'],
    mcp_guard: ['MCP Guard', 'Agent tool calls and document context'],
  };
  const [label, detail] = labels[id] || [humanize(id), 'Custom sensor'];
  const sensor = ((coverage && coverage.sensors) || []).find((item) => item.source === id) || {};
  const required = (p.requiredSensors || []).includes(id);
  const state = sensor.installHealth && sensor.installHealth.state === 'attention'
    ? 'warn'
    : sensor.events || required ? 'good' : 'warn';
  const version = (p.desiredSensorVersions || {})[id] || sensor.desiredVersion || sensor.latestVersion || '-';
  return `<div class="sensor-card">
    <div class="sensor-head">
      <div><b>${escapeHtml(label)}</b><p>${escapeHtml(detail)}</p></div>
      ${statePill(state, sensor.events ? 'Observed' : required ? 'Required' : 'Optional')}
    </div>
    <dl>
      <div><dt>Desired version</dt><dd>${escapeHtml(version)}</dd></div>
      <div><dt>Events</dt><dd>${escapeHtml(sensor.events || 0)}</dd></div>
      <div><dt>Last seen</dt><dd>${escapeHtml(sensor.lastSeen ? fmt(sensor.lastSeen) : 'No events yet')}</dd></div>
    </dl>
    <button class="ghost mini" data-tab-jump="coverage" type="button">Configure sensor</button>
  </div>`;
}

function renderSensorSetup(p, coverage) {
  const ids = [...new Set(['browser_extension', 'endpoint_agent', 'mcp_guard', ...((p.requiredSensors || []))])];
  return `<div class="config-card pad">
    <div class="sensor-head">
      <div><h3>Sensor Setup</h3><p>Deploy and manage the control points that feed one shared policy.</p></div>
      <button class="ghost mini" data-tab-jump="coverage" type="button">View coverage</button>
    </div>
    <div class="sensor-cards">${ids.map((id) => sensorCard(id, p, coverage)).join('')}</div>
  </div>`;
}

function envRow(label, state, detail) {
  return `<div class="settings-row"><span>${escapeHtml(label)}</span><b>${statePill(state, detail)}</b></div>`;
}

function renderEnvironmentSettings(preflight) {
  return `<div class="config-card pad">
    <h3>Environment Settings</h3>
    <p>Security-critical setup status without exposing secret values.</p>
    <div class="settings-list">
      ${envRow('Runtime', preflight && preflight.production ? 'good' : 'warn', preflight && preflight.production ? 'Production' : 'Local / pilot')}
      ${envRow('Admin auth', checkGroupState(preflight, ['admin_password', 'admin_password_strength', 'admin_mfa']), stateLabel(checkGroupState(preflight, ['admin_password', 'admin_password_strength', 'admin_mfa'])))}
      ${envRow('Sensor ingest key', checkGroupState(preflight, ['ingest_key', 'ingest_key_strength']), stateLabel(checkGroupState(preflight, ['ingest_key', 'ingest_key_strength'])))}
      ${envRow('Session secret', checkGroupState(preflight, ['session_secret', 'session_secret_strength']), stateLabel(checkGroupState(preflight, ['session_secret', 'session_secret_strength'])))}
      ${envRow('Raw approval encryption', checkGroupState(preflight, ['raw_prompt_encryption', 'data_key_strength']), stateLabel(checkGroupState(preflight, ['raw_prompt_encryption', 'data_key_strength'])))}
      ${envRow('Evidence store', checkGroupState(preflight, ['sqlite_local_disk']), stateLabel(checkGroupState(preflight, ['sqlite_local_disk'])))}
      ${envRow('Tenant controls', checkGroupState(preflight, ['saas_tenant_id', 'saas_seat_limit', 'saas_tenant_context', 'saas_user_identity']), stateLabel(checkGroupState(preflight, ['saas_tenant_id', 'saas_seat_limit', 'saas_tenant_context', 'saas_user_identity'])))}
    </div>
  </div>`;
}

function renderPolicyTemplates(tpls, readonly) {
  return `<div class="config-card pad">
    <div class="sensor-head">
      <div><h3>Policy Templates</h3><p>Start from a compliance preset, then tune thresholds and destinations.</p></div>
    </div>
    <div class="chips">${tpls.map((t) => (readonly
    ? `<span class="chip" title="${escapeHtml(t.description)}"><b>${escapeHtml(t.label)}</b></span>`
    : `<button class="chip ps-tpl" data-tpl="${escapeHtml(t.id)}" title="${escapeHtml(t.description)}" type="button"><b>${escapeHtml(t.label)}</b></button>`)).join('')}</div>
  </div>`;
}

async function loadPolicy() {
  const [pRes, tRes, preflightRes, coverageRes] = await Promise.all([
    api('/api/policy'),
    api('/api/policy/templates'),
    api('/api/preflight'),
    api('/api/coverage'),
  ]);
  if (!pRes || !tRes) return;
  const p = await pRes.json();
  const tpls = await tRes.json();
  const preflight = preflightRes && preflightRes.ok ? await preflightRes.json() : null;
  const coverage = coverageRes && coverageRes.ok ? await coverageRes.json() : currentCoverage;
  currentCoverage = coverage || currentCoverage;
  const readonly = !canAdminWrite();
  const modes = [
    ['warn', 'Monitor', 'Warn users and allow them to continue'],
    ['justify', 'Justify', 'Require a business reason before send'],
    ['redact', 'Redact', 'Tokenize PII before release'],
    ['block', 'Enforce', 'Hold risky prompts for approval'],
  ];
  const health = configHealth(preflight);
  const configStatus = $('#configurationStatus');
  if (configStatus) configStatus.innerHTML = statePill(health.state, `${health.score}/100 ready`);
  $('#policyBox').innerHTML = `
    <div class="config-actions">
      <button class="ghost" id="discardPolicy" type="button">Discard changes</button>
      <button class="ghost" id="testConfiguration" type="button">${icons.refresh}Test configuration</button>
      ${readonly ? '<span class="readonly-note">Read-only auditor view</span>' : `<button class="btn approve" id="savePolicy" type="button">${icons.check}Save changes</button>`}
      <span id="polSaved" class="save-status"></span>
    </div>
    <div class="config-grid">
      ${renderSetupChecklist(p, preflight, coverage)}
      <div class="config-card pad">
        <h3>Policy Mode</h3>
        <p>Choose what every PromptWall sensor does when it sees sensitive content.</p>
        <div class="policy-options mode-grid">
          ${modes.map(([v, t, d]) => `<label class="policy-option ${p.enforcementMode === v ? 'selected' : ''} ${readonly ? 'readonly' : ''}">
            <span><input type="radio" name="mode" value="${v}" ${p.enforcementMode === v ? 'checked' : ''} ${readonly ? 'disabled' : ''}/>${t}</span>
            <p>${d}</p>
          </label>`).join('')}
        </div>
        <p class="config-subtitle">Always-block identifiers still hard stop regardless of the selected mode.</p>
      </div>
      ${renderHealthCard(preflight, coverage, p)}
    </div>
    ${renderSensorSetup(p, coverage)}
    <div class="config-two">
      <div class="config-card pad">
        <h3>Core Policy Settings</h3>
        <p>Set thresholds, retention, response handling, and default desktop destination.</p>
        <div class="field-grid" style="margin-top:14px">
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
          <label for="pol_response_scan_mode">When AI responses contain sensitive data</label>
          <select id="pol_response_scan_mode" ${readonly ? 'disabled' : ''}>
            ${[
    ['flag', 'Flag and alert'],
    ['redact', 'Redact before display'],
    ['block', 'Block display'],
  ].map(([v, l]) => `<option value="${v}" ${(p.responseScanMode || 'flag') === v ? 'selected' : ''}>${l}</option>`).join('')}
          </select>
        </div>
      </div>
      ${renderEnvironmentSettings(preflight)}
    </div>
    <div class="config-two">
      ${renderPolicyTemplates(tpls, readonly)}
      <div class="config-card pad">
        <h3>Hard-stop Entities</h3>
        <p>These identifiers block or tokenize even if the global mode is softer.</p>
        <div class="chips">${(p.alwaysBlock || []).map((x) => `<span class="chip"><b>${escapeHtml(x)}</b></span>`).join('')}</div>
      </div>
    </div>
    <div class="config-card pad">
      <h3>Destination Governance</h3>
      <p>Define approved AI platforms, explicit allowlists, hard blocks, and file-upload restrictions.</p>
      <div class="policy-list-grid" style="margin-top:14px">
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
    </div>
    <div class="config-two">
      <div class="config-card pad">
        <h3>Browser Action Controls</h3>
        <p>Block paste, drop, or copy actions on specific destinations before data leaves the browser.</p>
        ${readonly
    ? `<div class="chips">${(p.blockedBrowserActions || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.action || 'action')}</b> ${escapeHtml((rule.destinations || []).join(', '))}</span>`).join('') || '<span class="chip">no action blocks</span>'}</div>`
    : `<textarea id="pol_blocked_browser_actions" class="policy-textarea" spellcheck="false" style="min-height:130px;margin-top:12px" placeholder='[{"id":"block_paste_chatgpt","action":"paste","destinations":["chatgpt.com"],"reason":"clipboard_paste_blocked"},{"id":"block_drop_claude","action":"drop","destinations":["claude.ai"],"reason":"file_drop_blocked"},{"id":"block_copy_chatgpt","action":"copy","destinations":["chatgpt.com"],"reason":"response_copy_blocked"}]'>${escapeHtml(policyJsonText(p.blockedBrowserActions))}</textarea>`}
      </div>
      <div class="config-card pad">
        <h3>Fleet Posture</h3>
        <p>Required sensors and desired versions used by install-health checks.</p>
        <div class="policy-list-grid" style="grid-template-columns:1fr;margin-top:12px">
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
      </div>
    </div>
    <div class="config-card pad">
      <h3>Approval Routing</h3>
      <p>Route held prompts to the right group and role with SLA context.</p>
      ${readonly
    ? `<div class="chips">${(p.approvalRoutingRules || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.id)}</b> ${escapeHtml(rule.assignedGroup || '')} / ${escapeHtml(roleLabel(rule.assignedRole))} ${escapeHtml(policyMatcherSummary(rule))}</span>`).join('') || '<span class="chip">default routing</span>'}</div>`
    : `<textarea id="pol_approval_routing_rules" class="policy-textarea" spellcheck="false" style="min-height:160px;margin-top:12px" placeholder='[{"id":"legal_group_contracts","groups":["PromptWall Legal"],"categories":["LEGAL_CONTRACT"],"destinations":["claude.ai"],"assignedGroup":"legal","assignedRole":"approver","slaMinutes":60}]'>${escapeHtml(policyJsonText(p.approvalRoutingRules))}</textarea>`}
    </div>
    ${readonly ? '' : `<div class="policy-builder-grid">
      <div class="policy-builder" id="scopeRuleBuilder">
        <h3>Guided Scoped Enforcement</h3>
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
        <h3>Guided Time-bound Exception</h3>
        <div class="mini-grid">
          <label>Exception id<input id="exception_builder_id" type="text" placeholder="legal_vendor_24h"/></label>
          <label>SCIM groups<input id="exception_builder_groups" type="text" placeholder="PromptWall Legal"/></label>
          <label>Users<input id="exception_builder_users" type="text" placeholder="counsel@example.test"/></label>
          <label>Destinations<input id="exception_builder_destinations" type="text" placeholder="claude.ai"/></label>
          <label>Categories<input id="exception_builder_categories" type="text" placeholder="LEGAL_CONTRACT"/></label>
          <label>Detectors<input id="exception_builder_detectors" type="text" placeholder="SOURCE_CODE"/></label>
          <label>Expires after hours<input id="exception_builder_hours" type="number" min="1" max="720" value="24"/></label>
          <label>Owner group<input id="exception_builder_owner_group" type="text" placeholder="legal"/></label>
          <label>Reviewer role<select id="exception_builder_reviewer_role">
            <option value="">Unassigned</option>
            <option value="security_admin">Security Admin</option>
            <option value="approver">Approver</option>
          </select></label>
          <label>Review after hours<input id="exception_builder_review_hours" type="number" min="1" max="720" value="24"/></label>
          <label>Reason<input id="exception_builder_reason" type="text" placeholder="approved_vendor_review"/></label>
        </div>
        <button class="btn" id="addExceptionRule" type="button">${icons.check}Add exception</button>
      </div>
    </div>`}
    <div class="config-card pad">
      <h3>Advanced Policy JSON</h3>
      <p>Edit scoped enforcement and time-bound exceptions directly when the guided builders are not enough.</p>
      <div class="policy-advanced-grid" style="margin-top:12px">
        <label class="policy-list-field">Scoped enforcement rules
          ${readonly
    ? `<div class="chips">${(p.policyScopes || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.id)}</b> ${escapeHtml(rule.enforcementMode || 'scope')} ${escapeHtml(policyMatcherSummary(rule))}</span>`).join('') || '<span class="chip">no scoped rules</span>'}</div>`
    : `<textarea id="pol_policy_scopes" class="policy-textarea" spellcheck="false" style="min-height:190px" placeholder='[{"id":"legal_contract_review","groups":["PromptWall Legal"],"destinations":["claude.ai"],"categories":["LEGAL_CONTRACT"],"enforcementMode":"block","blockMinSeverity":2}]'>${escapeHtml(policyJsonText(p.policyScopes))}</textarea>`}
        </label>
        <label class="policy-list-field">Time-bound exceptions
          ${readonly
    ? `<div class="chips">${(p.policyExceptions || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.id)}</b> ${escapeHtml(rule.expiresAt || '')} ${escapeHtml(policyMatcherSummary(rule))} ${escapeHtml(exceptionLifecycleSummary(rule))}</span>`).join('') || '<span class="chip">no exceptions</span>'}</div>`
    : `<textarea id="pol_policy_exceptions" class="policy-textarea" spellcheck="false" style="min-height:190px" placeholder='[{"id":"legal_vendor_24h","users":["counsel@example.test"],"destinations":["claude.ai"],"categories":["LEGAL_CONTRACT"],"expiresAt":"2030-01-01T00:00:00.000Z","ownerGroup":"legal","reviewerRole":"security_admin","reviewAfter":"2029-12-15T00:00:00.000Z"}]'>${escapeHtml(policyJsonText(p.policyExceptions))}</textarea>`}
        </label>
      </div>
      ${readonly ? '<div class="readonly-note">Read-only auditor view</div>' : `<button class="btn" id="runRetentionPurge" type="button">${icons.refresh}Run retention purge</button>`}
    </div>`;
  $$('input[name=mode]').forEach((radio) => {
    radio.onchange = () => {
      $$('.policy-option').forEach((option) => option.classList.toggle('selected', option.contains(radio) && radio.checked));
    };
  });
  $('#discardPolicy').onclick = loadPolicy;
  $('#testConfiguration').onclick = async () => {
    const status = $('#polSaved');
    status.textContent = 'Testing...';
    const [nextPreflightRes, nextCoverageRes] = await Promise.all([api('/api/preflight'), api('/api/coverage')]);
    const nextPreflight = nextPreflightRes && nextPreflightRes.ok ? await nextPreflightRes.json() : null;
    if (nextCoverageRes && nextCoverageRes.ok) currentCoverage = await nextCoverageRes.json();
    const nextHealth = configHealth(nextPreflight);
    const configStatus = $('#configurationStatus');
    if (configStatus) configStatus.innerHTML = statePill(nextHealth.state, `${nextHealth.score}/100 ready`);
    status.textContent = nextHealth.state === 'bad'
      ? `${nextHealth.failed} blocking check(s)`
      : `${nextHealth.failed} warning(s), ${nextHealth.ok}/${nextHealth.total || 0} checks ready`;
    setTimeout(() => { status.textContent = ''; }, 3600);
  };
  if (readonly) return;
  $('#addScopeRule').onclick = appendGuidedScopeRule;
  $('#addExceptionRule').onclick = appendGuidedExceptionRule;
  $('#savePolicy').onclick = async () => {
    const mode = (document.querySelector('input[name=mode]:checked') || {}).value || p.enforcementMode;
    const approvalRoutingRules = parsePolicyJsonArray($('#pol_approval_routing_rules').value, 'Approval routing rules');
    if (approvalRoutingRules == null) return;
    const blockedBrowserActions = parsePolicyJsonArray($('#pol_blocked_browser_actions').value, 'Browser action controls');
    if (blockedBrowserActions == null) return;
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
      blockedBrowserActions,
      blockUnapprovedAiDestinations: $('#pol_block_unapproved_ai').checked,
      responseScanMode: $('#pol_response_scan_mode').value,
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
  document.body.dataset.activeTab = name;
  $$('.tab').forEach((x) => x.classList.toggle('active', x.dataset.tab === name));
  $$('section[id^=tab-]').forEach((s) => s.classList.add('hidden'));
  $(`#tab-${CSS.escape(name)}`).classList.remove('hidden');
  window.scrollTo(0, 0);
  if (name === 'audit') loadAudit();
  if (name === 'policy') loadPolicy();
  if (name === 'activity') loadActivity();
  if (name === 'coverage') loadCoverage();
  if (name === 'identity') loadIdentitySetup();
  if (name === 'lineage') loadLineage();
}

$$('.tab').forEach((t) => {
  t.onclick = () => activateTab(t.dataset.tab);
});

$('#refreshQueue').onclick = loadQueue;
$('#refreshCoverage').onclick = loadCoverage;
$('#refreshIdentity').onclick = loadIdentitySetup;
$('#identityProvider').addEventListener('change', loadIdentitySetup);
$('#identityTenant').addEventListener('change', loadIdentitySetup);
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
