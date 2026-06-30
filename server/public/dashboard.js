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
let revealedPrompts = new Map();
let expandedActivityId = '';
let statusPopover = null;
let tooltipEl = null;
let monitorStatusFilter = 'all';
let monitorSearchTerm = '';
let monitorSearchFocused = false;
let monitorSelectedKind = '';
let monitorSelectedId = '';
let monitorInspectorLoading = false;
let monitorInspectorTimer = null;
let monitorExpandedPanelId = '';
let monitorExpandedEventId = '';
let monitorRefreshing = false;
let monitorUpdateSequence = 0;
let monitorLastUpdated = new Date().toISOString();
let monitorRecentEventId = 'evt-7902';

const icons = {
  check: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5 12 4 4L19 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  deny: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" stroke="currentColor" stroke-width="1.7"/><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" stroke="currentColor" stroke-width="1.7"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 12a8 8 0 0 1-13.7 5.6M4 12A8 8 0 0 1 17.7 6.4M17.7 6.4H14M17.7 6.4V2.7M6.3 17.6H10M6.3 17.6v3.7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4l7 3v5c0 4.2-2.6 6.8-7 8-4.4-1.2-7-3.8-7-8V7l7-3Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>',
};

const monitorStatusOptions = [
  { id: 'all', label: 'All' },
  { id: 'online', label: 'Online' },
  { id: 'idle', label: 'Idle' },
  { id: 'warning', label: 'Warn' },
  { id: 'error', label: 'Critical' },
  { id: 'loading', label: 'Syncing' },
  { id: 'offline', label: 'Offline' },
];

const monitorItems = [
  {
    id: 'node-browser-chat',
    name: 'Browser Chat Sensor',
    type: 'browser extension',
    status: 'online',
    source: 'browser_extension',
    location: 'Managed Chrome fleet',
    health: 98,
    confidence: 94,
    relatedMetric: 'Protected sessions',
    lastUpdated: '22 sec ago',
    description: 'Inline prompt inspection is connected for governed AI destinations.',
  },
  {
    id: 'node-endpoint-upload',
    name: 'Endpoint Upload Watch',
    type: 'endpoint agent',
    status: 'warning',
    source: 'endpoint_agent',
    location: 'Windows desktop collectors',
    health: 72,
    confidence: 88,
    relatedMetric: 'File path coverage',
    lastUpdated: '1 min ago',
    description: 'Desktop upload collector is active, but two seats reported delayed inventory.',
  },
  {
    id: 'node-mcp-drive',
    name: 'MCP Drive Redactor',
    type: 'mcp guard',
    status: 'online',
    source: 'mcp_guard',
    location: 'SharePoint and Drive connectors',
    health: 91,
    confidence: 90,
    relatedMetric: 'Redaction path',
    lastUpdated: '35 sec ago',
    description: 'Connector payloads are redacted before model access and recorded without raw bodies.',
  },
  {
    id: 'node-approval-gate',
    name: 'Approval Release Gate',
    type: 'workflow',
    status: 'idle',
    source: 'approval_queue',
    location: 'Security admin console',
    health: 84,
    confidence: 86,
    relatedMetric: 'Pending queue',
    lastUpdated: '3 min ago',
    description: 'Held prompts are waiting for assigned reviewers without breaching SLA.',
  },
  {
    id: 'node-audit-verifier',
    name: 'Audit Chain Verifier',
    type: 'audit integrity',
    status: 'error',
    source: 'audit_log',
    location: 'Evidence pack worker',
    health: 41,
    confidence: 97,
    relatedMetric: 'Verifier lag',
    lastUpdated: '7 min ago',
    description: 'Regional evidence worker missed its verification window and needs operator review.',
  },
  {
    id: 'node-shadow-inventory',
    name: 'Desktop AI Inventory',
    type: 'shadow ai',
    status: 'offline',
    source: 'endpoint_agent',
    location: 'Mac and Windows inventory',
    health: 0,
    confidence: 62,
    relatedMetric: 'Shadow AI scan',
    lastUpdated: '18 min ago',
    description: 'Inventory heartbeat stopped for one monitored segment.',
  },
  {
    id: 'node-policy-compiler',
    name: 'Policy Compiler',
    type: 'policy engine',
    status: 'loading',
    source: 'policy',
    location: 'Scoped rule resolver',
    health: 67,
    confidence: 80,
    relatedMetric: 'Rule propagation',
    lastUpdated: 'syncing',
    description: 'Scoped policy rules are being reconciled against the latest destination list.',
  },
];

const monitorEvents = [
  {
    id: 'evt-7902',
    timestamp: new Date(Date.now() - 30000).toISOString(),
    severity: 'critical',
    source: 'browser_extension',
    title: 'SSN paste blocked before egress',
    description: 'A governed chat destination received a hard-stop identifier and the prompt was held.',
    confidence: 99,
    relatedMetric: 'Critical holds',
    status: 'error',
  },
  {
    id: 'evt-7899',
    timestamp: new Date(Date.now() - 105000).toISOString(),
    severity: 'warning',
    source: 'endpoint_agent',
    title: 'Ungoverned desktop AI tool observed',
    description: 'Endpoint inventory reported an AI client not present in the governed destination list.',
    confidence: 82,
    relatedMetric: 'Shadow AI scan',
    status: 'warning',
  },
  {
    id: 'evt-7894',
    timestamp: new Date(Date.now() - 165000).toISOString(),
    severity: 'info',
    source: 'mcp_guard',
    title: 'Drive connector redacted document context',
    description: 'Connector payload was transformed before model access.',
    confidence: 91,
    relatedMetric: 'Redaction path',
    status: 'online',
  },
  {
    id: 'evt-7890',
    timestamp: new Date(Date.now() - 235000).toISOString(),
    severity: 'critical',
    source: 'audit_log',
    title: 'Verifier lag crossed evidence threshold',
    description: 'Audit chain verification is delayed for one evidence worker.',
    confidence: 97,
    relatedMetric: 'Verifier lag',
    status: 'error',
  },
  {
    id: 'evt-7886',
    timestamp: new Date(Date.now() - 315000).toISOString(),
    severity: 'info',
    source: 'approval_queue',
    title: 'Reviewer assignment confirmed',
    description: 'Held prompt routed to the Security Admin queue.',
    confidence: 86,
    relatedMetric: 'Pending queue',
    status: 'idle',
  },
];

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function monitorStatusLabel(status) {
  return ({
    online: 'Online',
    idle: 'Idle',
    warning: 'Warning',
    error: 'Critical',
    loading: 'Syncing',
    offline: 'Offline',
  })[status] || 'Unknown';
}

function monitorPulseStatus(status) {
  return ['loading', 'warning', 'error'].includes(status);
}

function monitorStatusDot(status, label, options = {}) {
  const pulse = monitorPulseStatus(status) || options.pulse ? ' is-pulsing' : '';
  return `<span class="signal-dot status-${escapeHtml(status)}${pulse}" role="img" aria-label="${escapeHtml(label || monitorStatusLabel(status))}"></span>`;
}

function monitorSearchState() {
  if (monitorRefreshing) {
    return { state: 'disabled', message: 'Refreshing.' };
  }
  const q = monitorSearchTerm;
  if (!q && monitorSearchFocused) {
    return { state: 'focus', message: 'Ready.' };
  }
  if (!q) {
    return { state: 'default', message: 'Type to filter.' };
  }
  if (q.length > 64) {
    return { state: 'error', message: 'Query too long.' };
  }
  if (/[<>`{}]/.test(q)) {
    return { state: 'error', message: 'Unsupported characters.' };
  }
  if (q.length < 2) {
    return { state: 'warning', message: 'Too broad.' };
  }
  return { state: 'valid', message: `Filtered: "${q}".` };
}

function monitorSearchText(record) {
  return [
    record.id,
    record.name,
    record.type,
    record.status,
    record.severity,
    record.source,
    record.location,
    record.title,
    record.description,
    record.relatedMetric,
  ].join(' ').toLowerCase();
}

function monitorMatchesSearch(record) {
  const state = monitorSearchState();
  if (state.state === 'error') return false;
  if (!monitorSearchTerm) return true;
  return monitorSearchText(record).includes(monitorSearchTerm.toLowerCase());
}

function monitorMatchesStatus(record) {
  if (monitorStatusFilter === 'all') return true;
  if (record.status === monitorStatusFilter) return true;
  if (monitorStatusFilter === 'error' && record.severity === 'critical') return true;
  if (monitorStatusFilter === 'warning' && record.severity === 'warning') return true;
  if (monitorStatusFilter === 'online' && record.severity === 'info') return true;
  return false;
}

function monitorAllEvents() {
  if (!monitorUpdateSequence) return monitorEvents;
  const id = `evt-refresh-${monitorUpdateSequence}`;
  const refreshEvent = {
    id,
    timestamp: monitorLastUpdated,
    severity: 'info',
    source: 'signal_console',
    title: 'Signal refresh completed',
    description: 'Telemetry refresh updated metrics, timestamps, and recent activity.',
    confidence: 93,
    relatedMetric: 'Refresh cadence',
    status: 'online',
  };
  return [refreshEvent, ...monitorEvents];
}

function monitorFilteredItems() {
  return monitorItems.filter(monitorMatchesStatus).filter(monitorMatchesSearch);
}

function monitorFilteredEvents() {
  return monitorAllEvents().filter(monitorMatchesStatus).filter(monitorMatchesSearch);
}

function monitorStatusCounts() {
  const counts = monitorItems.reduce((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1;
    return acc;
  }, { all: monitorItems.length });
  return counts;
}

function monitorMetrics() {
  const seq = monitorUpdateSequence;
  return [
    {
      id: 'active-sensors',
      label: 'Active sensors',
      value: 14 + (seq ? 1 : 0),
      unit: '',
      trend: seq ? 'increased' : 'neutral',
      status: 'normal',
      lastUpdated: monitorLastUpdated,
      updating: seq > 0,
    },
    {
      id: 'risk-pressure',
      label: 'Risk pressure',
      value: Math.max(54, 61 - seq),
      unit: '%',
      trend: seq ? 'decreased' : 'neutral',
      status: 'warning',
      lastUpdated: monitorLastUpdated,
      updating: seq > 0,
    },
    {
      id: 'critical-holds',
      label: 'Critical holds',
      value: 3,
      unit: '',
      trend: 'neutral',
      status: 'critical',
      lastUpdated: monitorLastUpdated,
      updating: false,
    },
    {
      id: 'audit-lag',
      label: 'Verifier lag',
      value: monitorRefreshing ? '' : Math.max(38, 412 - (seq * 46)),
      unit: monitorRefreshing ? '' : 'sec',
      trend: seq ? 'decreased' : 'neutral',
      status: monitorRefreshing ? 'loading' : 'critical',
      lastUpdated: monitorLastUpdated,
      updating: monitorRefreshing,
    },
  ];
}

function renderMonitorStatusFilters() {
  const counts = monitorStatusCounts();
  $('#monitorStatusFilters').innerHTML = monitorStatusOptions.map((option) => {
    const disabled = option.disabled || !counts[option.id];
    const selectedChip = monitorStatusFilter === option.id;
    const statusClass = option.id === 'warning' ? ' status-warning' : option.id === 'error' ? ' status-error' : '';
    const dot = option.id === 'all' || option.id === 'archived'
      ? ''
      : monitorStatusDot(option.id, `${option.label} status filter`);
    return `<button class="signal-chip${statusClass} ${selectedChip ? 'is-selected' : ''}" type="button" data-monitor-status="${escapeHtml(option.id)}" aria-pressed="${selectedChip ? 'true' : 'false'}" ${disabled ? 'disabled aria-disabled="true"' : ''}>
      ${dot}<span>${escapeHtml(option.label)}</span><b>${escapeHtml(counts[option.id] || 0)}</b>
    </button>`;
  }).join('');
}

function renderMonitorMetrics() {
  $('#monitorMetrics').innerHTML = monitorMetrics().map((metric) => {
    const statusClass = metric.status === 'normal' ? '' : ` status-${escapeHtml(metric.status)}`;
    const value = metric.status === 'loading'
      ? '<div class="metric-skeleton" aria-hidden="true"></div><span class="metric-unit">Loading</span>'
      : `<span>${escapeHtml(metric.value)}</span><span class="metric-unit">${escapeHtml(metric.unit || '')}</span>`;
    const trendLabel = ({
      increased: 'Increased',
      decreased: 'Decreased',
      neutral: 'Stable',
    })[metric.trend] || 'Stable';
    return `<article class="metric-card${statusClass}${metric.updating ? ' is-updating' : ''}" aria-busy="${metric.status === 'loading' ? 'true' : 'false'}">
      <div class="metric-card-head"><span>${escapeHtml(metric.label)}</span>${monitorStatusDot(metric.status === 'normal' ? 'online' : metric.status === 'critical' ? 'error' : metric.status, `${metric.label} ${metric.status}`, { pulse: metric.updating })}</div>
      <div class="metric-value">${value}</div>
      <div class="metric-meta"><span class="metric-trend ${escapeHtml(metric.trend)}">${escapeHtml(trendLabel)}</span><span>${escapeHtml(fmtTime(metric.lastUpdated))}</span></div>
    </article>`;
  }).join('');
}

function renderMonitorPanel(item) {
  const selectedItem = monitorSelectedKind === 'item' && monitorSelectedId === item.id;
  const expanded = monitorExpandedPanelId === item.id;
  const toneClass = ['warning', 'error', 'loading'].includes(item.status) ? ` status-${item.status}` : '';
  return `<article class="surveillance-panel${toneClass}${selectedItem ? ' is-selected' : ''}${expanded ? ' is-expanded' : ''}${item.status === 'loading' ? ' is-loading' : ''}" role="listitem" data-monitor-panel="${escapeHtml(item.id)}" aria-busy="${item.status === 'loading' ? 'true' : 'false'}">
    <button class="surveillance-main" type="button" data-monitor-select="item" data-monitor-id="${escapeHtml(item.id)}" aria-pressed="${selectedItem ? 'true' : 'false'}">
      <div class="surveillance-title">
        ${monitorStatusDot(item.status, `${item.name} ${monitorStatusLabel(item.status)}`)}
        <strong>${escapeHtml(item.name)}</strong>
      </div>
      <div class="surveillance-line"><b>${escapeHtml(monitorStatusLabel(item.status))}</b><span>${escapeHtml(item.health)}%</span><span>${escapeHtml(item.lastUpdated)}</span></div>
    </button>
    <span class="surveillance-hover-meta">${escapeHtml(sourceLabel(item.source))}</span>
    <button class="panel-expand" type="button" data-monitor-expand="${escapeHtml(item.id)}" aria-expanded="${expanded ? 'true' : 'false'}">${expanded ? 'Hide' : 'Inspect'}</button>
    <div class="surveillance-expanded">
      ${escapeHtml(sourceLabel(item.source))} / ${escapeHtml(item.location)} / ${escapeHtml(item.confidence)}% confidence
    </div>
  </article>`;
}

function renderMonitorPanels() {
  const rows = monitorFilteredItems();
  $('#monitorPanelSummary').textContent = rows.length ? `${rows.length} visible` : 'No matches';
  $('#monitorPanelGrid').innerHTML = rows.length
    ? rows.map(renderMonitorPanel).join('')
    : '<div class="signal-empty"><b>No matches</b><p>Adjust status or search.</p></div>';
}

function severityLabel(severity) {
  return severity === 'critical' ? 'Critical' : severity === 'warning' ? 'Warning' : 'Info';
}

function renderMonitorEvent(event) {
  const selectedEvent = monitorSelectedKind === 'event' && monitorSelectedId === event.id;
  const expanded = monitorExpandedEventId === event.id;
  const isRecent = monitorRecentEventId === event.id;
  const severityIcon = event.severity === 'critical' ? '!' : event.severity === 'warning' ? '!' : 'i';
  return `<div class="activity-feed-row severity-${escapeHtml(event.severity)}${selectedEvent ? ' is-selected' : ''}${isRecent ? ' is-new' : ''}" role="option" tabindex="0" aria-selected="${selectedEvent ? 'true' : 'false'}" data-monitor-event-id="${escapeHtml(event.id)}">
      <span>${escapeHtml(fmtTime(event.timestamp))}</span>
      <span class="severity-label ${escapeHtml(event.severity)}"><span aria-hidden="true">${severityIcon}</span>${escapeHtml(severityLabel(event.severity))}</span>
      <span>${escapeHtml(sourceLabel(event.source))}</span>
      <b>${escapeHtml(event.title)}</b>
      <button class="activity-expand" type="button" data-monitor-event-expand="${escapeHtml(event.id)}" aria-expanded="${expanded ? 'true' : 'false'}">${expanded ? 'Hide' : 'Details'}</button>
    </div>
    <div class="activity-detail-block${expanded ? ' is-expanded' : ''}">
      <div>${escapeHtml(event.description)}</div>
    </div>`;
}

function renderMonitorEvents() {
  const events = monitorFilteredEvents();
  $('#monitorFeedSummary').textContent = events.length ? `${events.length} visible` : 'No matches';
  $('#monitorActivityFeed').innerHTML = events.length
    ? events.map(renderMonitorEvent).join('')
    : '<div class="signal-empty"><b>No events</b><p>Clear search or broaden status.</p></div>';
}

function monitorSelectedRecord() {
  if (monitorSelectedKind === 'item') {
    return monitorItems.find((item) => item.id === monitorSelectedId) || null;
  }
  if (monitorSelectedKind === 'event') {
    return monitorAllEvents().find((event) => event.id === monitorSelectedId) || null;
  }
  return null;
}

function renderMonitorInspector() {
  const inspector = $('#monitorInspector');
  const record = monitorSelectedRecord();
  if (monitorInspectorLoading) {
    inspector.className = 'signal-inspector';
    inspector.setAttribute('aria-busy', 'true');
    inspector.innerHTML = `<div class="signal-inspector-head"><div><h3>Inspector</h3><p>Loading selection.</p></div><div class="button-spinner" aria-hidden="true"></div></div>`;
    return;
  }
  inspector.removeAttribute('aria-busy');
  if (!record) {
    inspector.className = 'signal-inspector';
    inspector.innerHTML = `<div class="signal-inspector-head"><div><h3>Inspector</h3><p>No selection.</p></div></div>`;
    return;
  }
  const isEvent = monitorSelectedKind === 'event';
  const state = record.status === 'error' || record.severity === 'critical' ? 'state-error'
    : record.status === 'warning' || record.severity === 'warning' ? 'state-warning' : '';
  const status = isEvent ? severityLabel(record.severity) : monitorStatusLabel(record.status);
  const timestamp = isEvent ? fmt(record.timestamp) : record.lastUpdated;
  const health = isEvent ? `${record.confidence}% confidence` : `${record.health}% health / ${record.confidence}% confidence`;
  const healthLabel = isEvent ? 'Confidence' : 'Health';
  const title = isEvent ? record.title : record.name;
  inspector.className = `signal-inspector ${state}`;
  inspector.innerHTML = `<div class="signal-inspector-head">
      <div>
        <h3>${escapeHtml(title)}</h3>
        <p>${escapeHtml(record.description)}</p>
      </div>
      <button class="system-button ghost" type="button" data-monitor-close-inspector>Close</button>
    </div>
    <div class="inspector-grid">
      <div class="inspector-field"><span>ID</span><b>${escapeHtml(record.id)}</b></div>
      <div class="inspector-field"><span>Status</span><b>${escapeHtml(status)}</b></div>
      <div class="inspector-field"><span>Source</span><b>${escapeHtml(sourceLabel(record.source))}</b></div>
      <div class="inspector-field"><span>Timestamp</span><b>${escapeHtml(timestamp)}</b></div>
      <div class="inspector-field"><span>${escapeHtml(healthLabel)}</span><b>${escapeHtml(health)}</b></div>
    </div>
    <div class="inspector-id">${escapeHtml(record.relatedMetric || '')}</div>`;
}

function updateMonitorSearchUi() {
  const search = $('#monitorSearch');
  const wrap = $('#monitorSearchWrap');
  const help = $('#monitorSearchHelp');
  if (!search || !wrap || !help) return;
  const state = monitorSearchState();
  wrap.dataset.state = state.state;
  help.textContent = state.message;
  search.disabled = state.state === 'disabled';
  search.setAttribute('aria-invalid', state.state === 'error' ? 'true' : 'false');
  if (search.value !== monitorSearchTerm) search.value = monitorSearchTerm;
}

function renderMonitor() {
  if (!$('#tab-monitor')) return;
  updateMonitorSearchUi();
  renderMonitorStatusFilters();
  renderMonitorMetrics();
  renderMonitorPanels();
  renderMonitorEvents();
  renderMonitorInspector();
  const updated = $('#monitorUpdated');
  if (updated) updated.textContent = `UPDATED ${fmtTime(monitorLastUpdated)}`;
  const refreshButton = $('#monitorRefresh');
  if (refreshButton) {
    refreshButton.disabled = monitorRefreshing;
    refreshButton.setAttribute('aria-busy', monitorRefreshing ? 'true' : 'false');
    refreshButton.innerHTML = monitorRefreshing ? '<span class="button-spinner" aria-hidden="true"></span>Refreshing' : 'Refresh';
  }
}

function selectMonitorRecord(kind, id) {
  monitorSelectedKind = kind;
  monitorSelectedId = id;
  monitorInspectorLoading = true;
  if (monitorInspectorTimer) clearTimeout(monitorInspectorTimer);
  renderMonitor();
  monitorInspectorTimer = setTimeout(() => {
    monitorInspectorLoading = false;
    renderMonitor();
  }, 220);
}

function clearMonitorSelection() {
  monitorSelectedKind = '';
  monitorSelectedId = '';
  monitorInspectorLoading = false;
  if (monitorInspectorTimer) clearTimeout(monitorInspectorTimer);
  renderMonitor();
}

function refreshMonitorSignals() {
  if (monitorRefreshing) return;
  monitorRefreshing = true;
  renderMonitor();
  setTimeout(() => {
    monitorRefreshing = false;
    monitorUpdateSequence += 1;
    monitorLastUpdated = new Date().toISOString();
    monitorRecentEventId = `evt-refresh-${monitorUpdateSequence}`;
    renderMonitor();
    markUpdated('SIGNALS UPDATED');
  }, 700);
}

function statusToneClass(tone) {
  if (tone === 'good') return 'secure';
  if (tone === 'warn') return 'warn';
  if (tone === 'bad') return 'critical';
  return 'live';
}

function statusChip(tone, label, detail, options = {}) {
  const chipTone = statusToneClass(tone);
  const lightTone = options.lightTone || chipTone;
  const light = options.light
    ? `<span class="status-light tone-${escapeHtml(lightTone)} ${options.live ? 'is-live' : ''}" aria-hidden="true"></span>`
    : '';
  return `<span class="pill ${escapeHtml(tone)} status-chip tone-${escapeHtml(chipTone)}" tabindex="0" role="button" data-status-detail="${escapeHtml(detail || label)}" data-tooltip="${escapeHtml(detail || label)}">${light}${escapeHtml(label)}</span>`;
}

function markUpdated(label = 'LAST UPDATED') {
  const el = $('#lastUpdated');
  if (!el) return;
  el.textContent = `${label} ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
}

function setBusy(selector, busy, label = 'SYNCING') {
  const el = $(selector);
  if (!el) return;
  el.classList.toggle('is-loading', !!busy);
  if (busy) el.dataset.loadingLabel = label;
  else delete el.dataset.loadingLabel;
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
    audit_log: 'Audit',
    approval_queue: 'Approval',
    policy: 'Policy',
    signal_console: 'Console',
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
  if (q.assignedGroup || q.assignedRole) chips.push(`<span class="chip status-chip tone-live" tabindex="0" role="button" data-status-detail="${escapeHtml(`Owner: ${workflowOwner(q)}\nPermission level: ${q.assignedRole ? roleLabel(q.assignedRole) : 'Unassigned'}`)}"><b>Owner</b> ${escapeHtml(workflowOwner(q))}</span>`);
  if (q.slaDueAt) chips.push(`<span class="chip status-chip ${isEscalated(q) ? 'category tone-warn' : 'tone-live'}" tabindex="0" role="button" data-status-detail="${escapeHtml(`SLA: ${fmt(q.slaDueAt)}\nState: ${isEscalated(q) ? 'DEGRADED' : 'SYNCED'}`)}"><b>SLA</b> ${escapeHtml(fmt(q.slaDueAt))}</span>`);
  if (q.escalationReason) chips.push(`<span class="chip category status-chip tone-warn" tabindex="0" role="button" data-status-detail="${escapeHtml(`Escalation reason: ${humanize(q.escalationReason)}`)}"><b>Escalated</b> ${escapeHtml(humanize(q.escalationReason))}</span>`);
  if (q.notificationStatus) chips.push(`<span class="chip status-chip tone-live" tabindex="0" role="button" data-status-detail="${escapeHtml(`Notification state: ${humanize(q.notificationStatus)}`)}"><b>Notify</b> ${escapeHtml(humanize(q.notificationStatus))}</span>`);
  if ((q.notificationChannels || []).length) chips.push(`<span class="chip status-chip tone-live" tabindex="0" role="button" data-status-detail="${escapeHtml(`Notification channels: ${(q.notificationChannels || []).join(', ')}`)}"><b>Channels</b> ${escapeHtml((q.notificationChannels || []).join(', '))}</span>`);
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

function boundedPromise(promise, timeoutMs, fallback) {
  return Promise.race([
    Promise.resolve(promise).catch(() => fallback),
    new Promise((resolve) => setTimeout(() => resolve(fallback), timeoutMs)),
  ]);
}

async function optionalDashboardJson(path, fallback = null, timeoutMs = 1800) {
  const response = await boundedPromise(api(path), timeoutMs, null);
  if (!response || !response.ok) return fallback;
  return boundedPromise(response.json(), timeoutMs, fallback);
}

async function loadCsrf() {
  const r = await api('/api/csrf');
  if (!r) return;
  const body = await r.json();
  csrfToken = body.csrfToken || '';
}

function placeFloating(el, target, gap = 8) {
  const rect = target.getBoundingClientRect();
  const width = el.offsetWidth || 280;
  const left = Math.min(Math.max(12, rect.left), Math.max(12, window.innerWidth - width - 12));
  const top = rect.bottom + gap + el.offsetHeight > window.innerHeight
    ? Math.max(12, rect.top - gap - el.offsetHeight)
    : rect.bottom + gap;
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
}

function closeStatusPopover() {
  if (statusPopover) statusPopover.remove();
  statusPopover = null;
}

function showStatusPopover(target) {
  hideTooltip();
  closeStatusPopover();
  const detail = target.dataset.statusDetail;
  if (!detail) return;
  statusPopover = document.createElement('div');
  statusPopover.className = 'meta-popover';
  statusPopover.innerHTML = `<b>Metadata</b><p>${escapeHtml(detail)}</p>`;
  document.body.appendChild(statusPopover);
  placeFloating(statusPopover, target);
}

function showTooltip(target) {
  const text = target.dataset.tooltip;
  if (!text || statusPopover) return;
  if (tooltipEl) tooltipEl.remove();
  tooltipEl = document.createElement('div');
  tooltipEl.className = 'ui-tooltip';
  tooltipEl.textContent = text;
  document.body.appendChild(tooltipEl);
  placeFloating(tooltipEl, target, 6);
}

function hideTooltip() {
  if (tooltipEl) tooltipEl.remove();
  tooltipEl = null;
}

function setupPanelChrome() {
  $$('.panel[data-collapsible="true"]').forEach((panel, index) => {
    if (panel.dataset.chromeReady) return;
    const head = $('.panel-head', panel);
    if (!head) return;
    const body = document.createElement('div');
    body.className = 'panel-body';
    body.id = panel.id ? `${panel.id}_body` : `panel_body_${index}`;
    while (head.nextSibling) body.appendChild(head.nextSibling);
    panel.appendChild(body);
    const toggle = document.createElement('button');
    toggle.className = 'panel-toggle';
    toggle.type = 'button';
    toggle.dataset.panelToggle = '';
    toggle.setAttribute('aria-expanded', 'true');
    toggle.setAttribute('aria-controls', body.id);
    toggle.textContent = 'HIDE';
    toggle.dataset.tooltip = 'Collapse or expand diagnostics';
    head.appendChild(toggle);
    panel.dataset.chromeReady = 'true';
  });
}

function setLiveState(state) {
  const live = $('.live');
  const chip = $('.live .status-chip');
  const light = $('.live .status-light');
  const label = state === 'reconnecting' ? 'SYNCING' : 'LIVE';
  const detail = state === 'reconnecting'
    ? 'SYNCING: session telemetry stream is reconnecting.'
    : 'LIVE: session telemetry stream is connected.';
  if ($('#liveTxt')) $('#liveTxt').textContent = label;
  if (live) live.dataset.statusDetail = detail;
  if (chip) {
    chip.classList.toggle('tone-warn', state === 'reconnecting');
    chip.classList.toggle('tone-live', state !== 'reconnecting');
  }
  if (light) {
    light.classList.toggle('tone-warn', state === 'reconnecting');
    light.classList.toggle('tone-live', state !== 'reconnecting');
  }
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
  setupPanelChrome();
  renderMonitor();
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
  setBusy('#stats', true, 'SYNCING');
  try {
    const [r, seatRes] = await Promise.all([api('/api/stats'), api('/api/billing/seats')]);
    if (!r) return;
    const s = await r.json();
    const seats = seatRes && seatRes.ok ? await seatRes.json() : null;
    const totalDecisions = (s.approved || 0) + (s.denied || 0);
    const approveRate = totalDecisions ? `${Math.round(((s.approved || 0) / totalDecisions) * 100)}%` : '-';
    const seatValue = seats && seats.seatLimit ? `${seats.seatsUsed}/${seats.seatLimit}` : (seats ? seats.seatsUsed : '-');
    const seatMeta = seats && seats.seatLimit ? `${seats.seatsRemaining} remaining` : 'billable users';
    const cards = [
      ['pending', s.pending, 'Pending approval', 'held for review', 'critical'],
      ['alert', s.todayBlocked, 'Blocked today', 'policy stops', 'warn'],
      ['good', s.approved, 'Approved', 'released by admin', 'secure'],
      ['', s.denied, 'Denied', 'never released', 'critical'],
      ['', approveRate, 'Approval rate', 'admin decisions', 'live'],
      [seats && seats.overLimit ? 'alert' : '', seatValue, seats && seats.saasMode ? 'Seats used' : 'Users observed', seatMeta, seats && seats.overLimit ? 'warn' : 'secure'],
    ];
    $('#stats').innerHTML = cards.map(([c, n, l, m, tone]) => `
      <div class="stat ${c}" data-tooltip="${escapeHtml(`${l}: ${m}`)}">
        <div class="l"><span class="status-light tone-${escapeHtml(tone)}" aria-hidden="true"></span>${escapeHtml(l)}</div>
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
    markUpdated();
  } finally {
    setBusy('#stats', false);
  }
}

function findingChips(findings, categories) {
  const fc = (findings || []).map((f) => `<span class="chip status-chip tone-warn" tabindex="0" role="button" data-status-detail="${escapeHtml(`Detected type: ${f.type}\nMasked value: ${f.masked || 'redacted'}`)}"><b>${escapeHtml(f.type)}</b> ${escapeHtml(f.masked || '')}</span>`).join('');
  const cc = (categories || []).map((c) => `<span class="chip category status-chip tone-warn" tabindex="0" role="button" data-status-detail="${escapeHtml(`Policy category: ${c}`)}"><b>${escapeHtml(c)}</b></span>`).join('');
  return fc + cc;
}

function pruneRevealedPrompts() {
  if (!revealedPrompts.size) return;
  const pendingIds = new Set(currentQueue.map((q) => q.id));
  for (const id of revealedPrompts.keys()) {
    if (!pendingIds.has(id)) revealedPrompts.delete(id);
  }
}

async function loadQueue() {
  setBusy('#tab-queue .panel', true, 'SYNCING');
  try {
    const r = await api('/api/queries?status=pending');
    if (!r) return;
    currentQueue = await r.json();
    pruneRevealedPrompts();
    if (currentQueue.length && !currentQueue.some((q) => q.id === selected)) selected = currentQueue[0].id;
    if (!currentQueue.length) selected = null;
    renderQueueView();
    markUpdated();
  } finally {
    setBusy('#tab-queue .panel', false);
  }
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
  const isRevealed = revealedPrompts.has(q.id);
  const revealedPrompt = revealedPrompts.get(q.id);
  const promptText = isRevealed ? revealedPrompt : q.redactedPrompt;
  const revealControl = canReveal(q)
    ? isRevealed
      ? `<button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button" disabled>Raw shown and logged</button>`
      : `<button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button">${icons.eye}Reveal gated</button>`
    : '';
  const controls = canAdminWrite()
    || canDecide(q)
    ? `<textarea class="note" id="note_${escapeHtml(q.id)}" placeholder="Decision note, recorded in audit log"></textarea>
    <div class="actions">
      <button class="btn approve" data-act="approve" data-id="${escapeHtml(q.id)}" type="button">${icons.check}Approve release</button>
      <button class="btn deny" data-act="deny" data-id="${escapeHtml(q.id)}" type="button">${icons.deny}Deny</button>
      ${revealControl}
    </div>`
    : `<div class="readonly-note">${escapeHtml(queueDecisionLabel(q))}</div>`;
  return `<article class="q ${selected === q.id ? 'selected' : ''}" data-id="${escapeHtml(q.id)}" tabindex="0">
    <div class="top risk-meta-row">
      <span class="select-dot" aria-hidden="true"></span>
      <span class="sev ${sev}">${escapeHtml(q.maxSeverityLabel || 'low')}</span>
      <span class="risk">Risk <b>${escapeHtml(q.riskScore ?? 0)}</b>/100</span>
    </div>
    <div class="queue-mainline">
      <strong>${escapeHtml(q.user || 'unknown user')}</strong>
      <span>${escapeHtml(sourceLabel(q.source))} -> ${escapeHtml(q.destination || 'unknown destination')}</span>
      <span>${escapeHtml(fmtTime(q.createdAt))}</span>
    </div>
    <div class="prompt ${isRevealed ? 'revealed' : ''}" id="p_${escapeHtml(q.id)}">${escapeHtml(promptText)}</div>
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
      <div class="risk-meta-row"><span class="sev ${sev}">${escapeHtml(q.maxSeverityLabel || 'low')}</span><span class="risk">Risk <b>${risk}</b>/100</span></div>
      <div class="risk-track"><i></i></div>
    </div>
    <div class="prompt">${escapeHtml(q.redactedPrompt)}</div>
    <div class="posture-list">${matches}</div>`;
}

document.addEventListener('click', async (e) => {
  const selectableQueueRow = e.target.closest('.q[data-id]');
  if (selectableQueueRow && !e.target.closest('textarea,input,button,select,a')) {
    selected = selectableQueueRow.dataset.id;
    renderQueueView();
    return;
  }
  const metadataTarget = e.target.closest('[data-status-detail]');
  if (metadataTarget) {
    e.preventDefault();
    e.stopPropagation();
    showStatusPopover(metadataTarget);
    return;
  }
  closeStatusPopover();
  const panelToggle = e.target.closest('[data-panel-toggle]');
  if (panelToggle) {
    const panel = panelToggle.closest('.panel');
    const collapsed = !panel.classList.contains('collapsed');
    panel.classList.toggle('collapsed', collapsed);
    panelToggle.setAttribute('aria-expanded', String(!collapsed));
    panelToggle.textContent = collapsed ? 'DETAILS' : 'HIDE';
    return;
  }
  const monitorStatusButton = e.target.closest('[data-monitor-status]');
  if (monitorStatusButton) {
    if (monitorStatusButton.disabled) return;
    monitorStatusFilter = monitorStatusButton.dataset.monitorStatus || 'all';
    renderMonitor();
    return;
  }
  const monitorSelect = e.target.closest('[data-monitor-select]');
  if (monitorSelect) {
    selectMonitorRecord(monitorSelect.dataset.monitorSelect, monitorSelect.dataset.monitorId);
    return;
  }
  const monitorExpand = e.target.closest('[data-monitor-expand]');
  if (monitorExpand) {
    monitorExpandedPanelId = monitorExpandedPanelId === monitorExpand.dataset.monitorExpand ? '' : monitorExpand.dataset.monitorExpand;
    renderMonitor();
    return;
  }
  const monitorEventExpand = e.target.closest('[data-monitor-event-expand]');
  if (monitorEventExpand) {
    monitorExpandedEventId = monitorExpandedEventId === monitorEventExpand.dataset.monitorEventExpand ? '' : monitorEventExpand.dataset.monitorEventExpand;
    renderMonitor();
    return;
  }
  const monitorClose = e.target.closest('[data-monitor-close-inspector]');
  if (monitorClose) {
    clearMonitorSelection();
    return;
  }
  const monitorEventRow = e.target.closest('.activity-feed-row[data-monitor-event-id]');
  if (monitorEventRow && !e.target.closest('button,a,input,select,textarea')) {
    selectMonitorRecord('event', monitorEventRow.dataset.monitorEventId);
    return;
  }
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
      revealedPrompts.set(id, body.rawPrompt || '');
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
      if (r && r.ok) {
        revealedPrompts.delete(id);
        await refreshAll();
      }
      else actionButton.disabled = false;
    }
    return;
  }
  const jump = e.target.closest('[data-tab-jump]');
  if (jump) {
    activateTab(jump.dataset.tabJump);
    return;
  }
  const activityRow = e.target.closest('.activity-row[data-activity-id]');
  if (activityRow && !e.target.closest('textarea,input,button,select,a')) {
    expandedActivityId = expandedActivityId === activityRow.dataset.activityId ? '' : activityRow.dataset.activityId;
    renderActivityRows(currentActivity);
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
  const metadataTarget = e.target.closest('[data-status-detail]');
  if (metadataTarget && ['Enter', ' '].includes(e.key)) {
    e.preventDefault();
    showStatusPopover(metadataTarget);
    return;
  }
  if (e.key === 'Escape') {
    closeStatusPopover();
    hideTooltip();
    if (document.body.dataset.activeTab === 'monitor' && (monitorSelectedId || monitorInspectorLoading)) {
      clearMonitorSelection();
      return;
    }
  }
  const monitorEventRow = e.target.closest('.activity-feed-row[data-monitor-event-id]');
  if (monitorEventRow && ['Enter', ' '].includes(e.key)) {
    e.preventDefault();
    selectMonitorRecord('event', monitorEventRow.dataset.monitorEventId);
    return;
  }
  const activityRow = e.target.closest('.activity-row[data-activity-id]');
  if (activityRow && ['Enter', ' '].includes(e.key)) {
    e.preventDefault();
    expandedActivityId = expandedActivityId === activityRow.dataset.activityId ? '' : activityRow.dataset.activityId;
    renderActivityRows(currentActivity);
    return;
  }
  const row = e.target.closest('.q[data-id]');
  if (!row || !['Enter', ' '].includes(e.key)) return;
  if (e.target.closest('textarea,input,button,select,a')) return;
  e.preventDefault();
  selected = row.dataset.id;
  renderQueueView();
});

document.addEventListener('pointerover', (e) => {
  const target = e.target.closest('[data-tooltip]');
  if (target) showTooltip(target);
});

document.addEventListener('pointerout', (e) => {
  if (e.target.closest('[data-tooltip]')) hideTooltip();
});

document.addEventListener('focusin', (e) => {
  const target = e.target.closest('[data-tooltip]');
  if (target) showTooltip(target);
});

document.addEventListener('focusout', (e) => {
  if (e.target.closest('[data-tooltip]')) hideTooltip();
});

async function loadActivity() {
  setBusy('#tab-activity .panel', true, 'SYNCING');
  try {
    const r = await api('/api/queries?limit=200');
    if (!r) return;
    currentActivity = await r.json();
    renderActivityRows(currentActivity);
    markUpdated();
  } finally {
    setBusy('#tab-activity .panel', false);
  }
}

function activitySeverityClass(q) {
  const tone = statusTone(q.status);
  if (tone === 'bad') return 'critical';
  if (tone === 'warn') return 'warning';
  return '';
}

function activityDetail(q) {
  const expanded = expandedActivityId === q.id;
  if (!expanded) return '<tr class="activity-detail-row hidden"><td colspan="9"></td></tr>';
  const detected = Object.keys(q.entityCounts || {}).join(', ') || (q.categories || []).join(', ') || '-';
  return `<tr class="activity-detail-row">
    <td colspan="9">
      <div class="activity-detail">
        <div class="activity-detail-grid">
          <div class="datum"><label>Object</label><b>${escapeHtml(q.id || '-')}</b></div>
          <div class="datum"><label>Status</label><b>${escapeHtml(humanize(q.status))}</b></div>
          <div class="datum"><label>Timestamp</label><b>${escapeHtml(fmt(q.createdAt))}</b></div>
          <div class="datum"><label>Source</label><b>${escapeHtml(sourceLabel(q.source))}</b></div>
          <div class="datum"><label>Owner</label><b>${escapeHtml(workflowOwner(q))}</b></div>
          <div class="datum"><label>Destination</label><b>${escapeHtml(q.destination || '-')}</b></div>
          <div class="datum"><label>Detected</label><b>${escapeHtml(detected)}</b></div>
          <div class="datum"><label>Risk</label><b>${escapeHtml(q.riskScore ?? 0)}/100</b></div>
        </div>
        <div class="activity-detail-actions">
          ${q.status === 'pending' ? '<button class="ghost mini" data-tab-jump="queue" type="button">INSPECT</button>' : ''}
          <button class="ghost mini" data-tab-jump="audit" type="button">VIEW AUDIT</button>
        </div>
      </div>
    </td>
  </tr>`;
}

function renderActivityRows(rows) {
  const filtered = (rows || []).filter(matchesSearch);
  $('#activityRows').innerHTML = filtered.map((q) => {
    const tone = statusTone(q.status);
    const detail = `Status: ${humanize(q.status)}\nSession ID: ${q.id || '-'}\nOwner: ${workflowOwner(q)}\nRisk: ${q.riskScore ?? 0}/100`;
    return `<tr class="activity-row ${activitySeverityClass(q)} ${expandedActivityId === q.id ? 'selected' : ''}" data-activity-id="${escapeHtml(q.id)}" tabindex="0">
    <td class="mono">${escapeHtml(fmt(q.createdAt))}</td>
    <td>${escapeHtml(sourceLabel(q.source))}</td>
    <td>${escapeHtml(q.user || '-')}</td>
    <td class="mono">${escapeHtml(q.destination || '-')}</td>
    <td>${escapeHtml(workflowOwner(q))}</td>
    <td><span class="sev ${sevClass(q.maxSeverityLabel)}">${escapeHtml(q.maxSeverityLabel || 'low')}</span></td>
    <td class="mono">${escapeHtml(q.riskScore ?? 0)}</td>
    <td>${escapeHtml(Object.keys(q.entityCounts || {}).join(', ') || '-')}</td>
    <td>${statusChip(tone, humanize(q.status), detail)}<span class="row-affordance">VIEW</span></td>
  </tr>${activityDetail(q)}`;
  }).join('') || '<tr><td colspan="9" class="empty">No matching activity</td></tr>';
}

async function loadCoverage() {
  setBusy('#tab-coverage .panel', true, 'RECONCILING');
  try {
    const r = await api('/api/coverage');
    if (!r) return;
    currentCoverage = await r.json();
    renderCoverage(currentCoverage);
    markUpdated();
  } finally {
    setBusy('#tab-coverage .panel', false);
  }
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
      <span>${escapeHtml(p.label)} ${statusChip(postureTone(p.state), p.state, `System health: ${p.label}\nState: ${p.state}\nDetail: ${p.detail}`)}</span>
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
    <td>${statusChip(fleetTone(row.state), row.state || 'unknown', `Verification state: ${row.state || 'unknown'}\nUser: ${row.user || 'unknown'}\nFailed checks: ${fleetFailedChecks(row)}\nLast seen: ${row.lastSeen ? fmt(row.lastSeen) : '-'}`)}</td>
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
        ${statusChip(endpointAiToolTone(tool.state), tool.state || 'unknown', `Endpoint tool: ${tool.label || tool.id || 'unknown'}\nPermission state: ${tool.state || 'unknown'}\nLast seen: ${tool.lastSeen ? fmt(tool.lastSeen) : '-'}`)}
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
        ${statusChip(destinationPolicyTone(d.policyState), destinationPolicyLabel(d.policyState), `Destination: ${d.destination}\nPolicy: ${destinationPolicyLabel(d.policyState)}\nSource count: ${d.users} users\nLast seen: ${d.lastSeen ? fmt(d.lastSeen) : '-'}`)}
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
  setBusy('#tab-identity .panel', true, 'VERIFYING');
  try {
    const r = await api(`/api/identity/setup-guide?${params.toString()}`);
    if (!r) return;
    currentIdentitySetup = await r.json();
    if (currentIdentitySetup.error) {
      $('#identitySummary').innerHTML = `<div class="empty"><div class="big">Identity setup unavailable</div>${escapeHtml(currentIdentitySetup.error)}</div>`;
      return;
    }
    renderIdentitySetup(currentIdentitySetup);
    markUpdated();
  } finally {
    setBusy('#tab-identity .panel', false);
  }
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
    <td>${statusChip('info', roleLabel(row.role), `Permission level: ${roleLabel(row.role)}\nGroups: ${(row.groups || []).join(', ') || '-'}`)}</td>
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
  setBusy('#tab-lineage .panel', true, 'ANALYZING');
  try {
    const r = await api('/api/lineage?limit=1000');
    if (!r) return;
    const body = await r.json();
    currentLineage = body.lineage || {};
    renderLineage(currentLineage);
    markUpdated();
  } finally {
    setBusy('#tab-lineage .panel', false);
  }
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
  setBusy('#tab-audit .panel', true, 'VERIFYING');
  try {
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
      <td>${statusChip(statusTone(a.action), humanize(a.action), `Audit action: ${humanize(a.action)}\nActor: ${a.actor || '-'}\nQuery: ${a.queryId || '-'}\nTimestamp: ${fmt(a.ts)}`)}</td>
      <td>${escapeHtml(a.actor || '-')}</td>
      <td class="mono">${escapeHtml(a.queryId || '-')}</td>
      <td>${escapeHtml(a.detail || '')}</td>
    </tr>`).join('');
    markUpdated();
  } finally {
    setBusy('#tab-audit .panel', false);
  }
}

async function exportEvidence(){
  const btn = $('#exportEvidence');
  const status = $('#exportStatus');
  btn.disabled = true;
  status.textContent = 'PROCESSING';
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
    status.textContent = 'DATA VERIFIED';
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
  return statusChip(tone, label, `Verification state: ${label}\nSystem health: ${stateLabel(state)}`);
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
      ${statusChip(checklist.done === checklist.total ? 'good' : 'warn', `${checklist.done}/${checklist.total} ready`, `System health: ${checklist.done}/${checklist.total} setup checks ready`)}
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
  setBusy('#tab-policy .config-shell', true, 'VERIFYING');
  try {
  const preflightPromise = optionalDashboardJson('/api/preflight');
  const coveragePromise = optionalDashboardJson('/api/coverage', currentCoverage);
  const [pRes, tRes] = await Promise.all([
    api('/api/policy'),
    api('/api/policy/templates'),
  ]);
  if (!pRes || !tRes) return;
  const p = await pRes.json();
  const tpls = await tRes.json();
  const [preflight, coverage] = await Promise.all([preflightPromise, coveragePromise]);
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
        <p>Block paste, drop, copy, or download actions on specific destinations before data leaves the browser.</p>
        ${readonly
    ? `<div class="chips">${(p.blockedBrowserActions || []).map((rule) => `<span class="chip"><b>${escapeHtml(rule.action || 'action')}</b> ${escapeHtml((rule.destinations || []).join(', '))}</span>`).join('') || '<span class="chip">no action blocks</span>'}</div>`
    : `<textarea id="pol_blocked_browser_actions" class="policy-textarea" spellcheck="false" style="min-height:130px;margin-top:12px" placeholder='[{"id":"block_paste_chatgpt","action":"paste","destinations":["chatgpt.com"],"reason":"clipboard_paste_blocked"},{"id":"block_drop_claude","action":"drop","destinations":["claude.ai"],"reason":"file_drop_blocked"},{"id":"block_copy_chatgpt","action":"copy","destinations":["chatgpt.com"],"reason":"response_copy_blocked"},{"id":"block_download_chatgpt","action":"download","destinations":["chatgpt.com"],"reason":"download_blocked"}]'>${escapeHtml(policyJsonText(p.blockedBrowserActions))}</textarea>`}
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
    status.textContent = 'VERIFYING';
    const [nextPreflight, nextCoverage] = await Promise.all([
      optionalDashboardJson('/api/preflight'),
      optionalDashboardJson('/api/coverage', currentCoverage),
    ]);
    if (nextCoverage) currentCoverage = nextCoverage;
    const nextHealth = configHealth(nextPreflight);
    const configStatus = $('#configurationStatus');
    if (configStatus) configStatus.innerHTML = statePill(nextHealth.state, `${nextHealth.score}/100 ready`);
    status.textContent = nextHealth.state === 'bad'
      ? `${nextHealth.failed} blocking check(s)`
      : `${nextHealth.failed} warning(s), ${nextHealth.ok}/${nextHealth.total || 0} checks ready`;
    setTimeout(() => { status.textContent = ''; }, 3600);
  };
  markUpdated();
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
  markUpdated();
  } finally {
    setBusy('#tab-policy .config-shell', false);
  }
}

const pageHeadings = {
  queue: {
    title: 'Security Console',
    body: 'Review held prompts, enforce AI-use policy, and export examiner-ready evidence from one control plane.',
  },
  monitor: {
    title: 'Signal Monitor',
    body: 'Live signal posture across PromptWall controls.',
  },
};

function renderPageHeading(name) {
  const copy = pageHeadings[name] || pageHeadings.queue;
  const title = $('.page-title h2');
  const body = $('.page-title p');
  if (title) title.textContent = copy.title;
  if (body) body.textContent = copy.body;
}

function activateTab(name) {
  document.body.dataset.activeTab = name;
  renderPageHeading(name);
  $$('.tab').forEach((x) => x.classList.toggle('active', x.dataset.tab === name));
  $$('section[id^=tab-]').forEach((s) => s.classList.add('hidden'));
  $(`#tab-${CSS.escape(name)}`).classList.remove('hidden');
  window.scrollTo(0, 0);
  if (name === 'monitor') renderMonitor();
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
$('#monitorRefresh').onclick = refreshMonitorSignals;
$('#monitorSearch').addEventListener('input', (e) => {
  monitorSearchTerm = String(e.target.value || '').trim();
  renderMonitor();
});
$('#monitorSearch').addEventListener('focus', () => {
  monitorSearchFocused = true;
  updateMonitorSearchUi();
});
$('#monitorSearch').addEventListener('blur', () => {
  monitorSearchFocused = false;
  updateMonitorSearchUi();
});

function connectStream() {
  const es = new EventSource('/api/stream');
  es.addEventListener('query', () => { loadStats(); loadQueue(); if (!$('#tab-coverage').classList.contains('hidden')) loadCoverage(); if (!$('#tab-lineage').classList.contains('hidden')) loadLineage(); flash(); });
  es.addEventListener('decision', () => { loadStats(); loadQueue(); loadActivity(); if (!$('#tab-lineage').classList.contains('hidden')) loadLineage(); });
  es.addEventListener('stats', () => loadStats());
  es.onerror = () => { setLiveState('reconnecting'); };
  es.onopen = () => { setLiveState('live'); };
}

function flash() {
  const d = document.querySelector('.live .status-light');
  if (!d) return;
  d.classList.remove('tone-live');
  d.classList.add('tone-warn');
  setTimeout(() => {
    d.classList.remove('tone-warn');
    d.classList.add('tone-live');
  }, 500);
}

init();
