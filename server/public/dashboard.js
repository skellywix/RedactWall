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
let currentPosture = null;
let currentAuditEntries = [];
let currentIdentitySetup = null;
let searchTerm = '';
let currentRole = 'auditor';
let currentUser = '';
let queueFilter = 'all';
let queueCategoryFilter = 'all';
let queueDestinationFilter = 'all';
let queueDensity = savedQueueDensity();
let colorTheme = savedColorTheme();
let revealedPrompts = new Map();
let expandedActivityId = '';
let activityPage = 1;
let auditPage = 1;
let lineagePages = {};
let statusPopover = null;
let tooltipEl = null;
let monitorStatusFilter = 'all';
let monitorSegmentFilter = 'all';
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
let currentSiemPackage = null;
let siemPackageProfile = 'all';
let siemPackageLoading = false;
let siemPackageError = '';
let currentSecurityPackage = null;
let securityPackageLoading = false;
let securityPackageError = '';
let policyStatusTimer = null;

const icons = {
  check: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5 12 4 4L19 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  deny: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" stroke="currentColor" stroke-width="1.7"/><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" stroke="currentColor" stroke-width="1.7"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 12a8 8 0 0 1-13.7 5.6M4 12A8 8 0 0 1 17.7 6.4M17.7 6.4H14M17.7 6.4V2.7M6.3 17.6H10M6.3 17.6v3.7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4l7 3v5c0 4.2-2.6 6.8-7 8-4.4-1.2-7-3.8-7-8V7l7-3Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3v12m0 0 4-4m-4 4-4-4M5 21h14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};
const LINEAGE_PAGE_SIZE = 10;
let activityPageSize = 10;
let auditPageSize = 10;
let activityRangeDays = 0; // 0 = all retained rows
let auditActionFilter = 'all';

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
    description: 'Connector payloads are redacted before model access; only masked findings and category metadata are recorded.',
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
    description: 'A governed chat destination triggered a hard-stop detector. AI Command Center records sanitized metadata; retained raw text stays behind Queue reveal.',
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
    description: 'Connector payload was transformed before model access; raw document text was not logged in AI Command Center.',
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
  const sourceEvents = currentPosture && Array.isArray(currentPosture.events) && currentPosture.events.length
    ? currentPosture.events
    : monitorEvents;
  if (!monitorUpdateSequence) return sourceEvents;
  const id = `evt-refresh-${monitorUpdateSequence}`;
  const refreshEvent = {
    id,
    timestamp: monitorLastUpdated,
    severity: 'info',
    source: 'signal_console',
    title: 'Signal refresh completed',
    description: 'Telemetry refresh updated sanitized metrics, timestamps, and recent activity.',
    confidence: 93,
    relatedMetric: 'Refresh cadence',
    status: 'online',
  };
  return [refreshEvent, ...sourceEvents];
}

function monitorItemsSource() {
  return currentPosture && Array.isArray(currentPosture.surfaces) && currentPosture.surfaces.length
    ? currentPosture.surfaces
    : monitorItems;
}

function monitorFilteredItems() {
  return monitorItemsSource().filter(monitorMatchesStatus).filter(monitorMatchesSearch);
}

function monitorFilteredEvents() {
  return monitorAllEvents().filter(monitorMatchesStatus).filter(monitorMatchesSearch);
}

function monitorStatusCounts() {
  const records = [...monitorItemsSource(), ...monitorAllEvents()];
  const counts = records.reduce((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1;
    if (item.severity === 'critical' && item.status !== 'error') acc.error = (acc.error || 0) + 1;
    if (item.severity === 'warning' && item.status !== 'warning') acc.warning = (acc.warning || 0) + 1;
    return acc;
  }, { all: records.length });
  return counts;
}

function monitorMetrics() {
  if (currentPosture && Array.isArray(currentPosture.metrics) && currentPosture.metrics.length) {
    return currentPosture.metrics.map((metric) => ({
      ...metric,
      updating: monitorRefreshing,
      lastUpdated: metric.lastUpdated || currentPosture.generatedAt || monitorLastUpdated,
    }));
  }
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

function segmentStateTone(state) {
  const value = String(state || 'ready');
  if (value === 'critical') return 'critical';
  if (value === 'attention') return 'warning';
  return 'ready';
}

function renderPostureSegments() {
  const segments = currentPosture && currentPosture.segments && typeof currentPosture.segments === 'object'
    ? currentPosture.segments
    : null;
  const bar = $('#postureSegmentBar');
  const summary = $('#postureSegmentSummary');
  const select = $('#postureSegmentSelect');
  const matrixTarget = $('#postureSegmentMatrix');
  if (!bar || !summary || !select || !matrixTarget) return;
  if (!segments) {
    bar.classList.add('is-empty');
    summary.textContent = 'Segments will appear after sanitized activity arrives.';
    select.innerHTML = '<option value="all">All segments</option>';
    matrixTarget.innerHTML = '';
    return;
  }
  bar.classList.remove('is-empty');
  const segSummary = segments.summary || {};
  const active = segments.active || null;
  const filters = Array.isArray(segments.filters) ? segments.filters : [];
  const matrix = Array.isArray(segments.matrix) ? segments.matrix : [];
  const selectedId = segSummary.selectedId || (active && active.id) || 'all';
  if (monitorSegmentFilter !== selectedId && (monitorSegmentFilter !== 'all' || selectedId !== 'all')) {
    monitorSegmentFilter = selectedId;
  }
  const activeLabel = active ? `${active.typeLabel || 'Segment'}: ${active.label || 'Unknown'}` : 'All segments';
  const privacy = segSummary.privacy || 'metadata only; prompt bodies excluded';
  summary.innerHTML = `<b>${escapeHtml(activeLabel)}</b><span>${escapeHtml(segSummary.visibleEvents || 0)} visible events / ${escapeHtml(segSummary.attention || 0)} attention / ${escapeHtml(privacy)}</span>`;
  const options = filters.length ? filters : [{ id: 'all', label: 'All segments', typeLabel: 'All' }];
  select.innerHTML = options.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === selectedId ? 'selected' : ''}>${escapeHtml(item.typeLabel || 'Segment')} - ${escapeHtml(item.label || item.id)}</option>`).join('');
  matrixTarget.innerHTML = matrix.length
    ? matrix.slice(0, 8).map((item) => {
      const tone = segmentStateTone(item.state);
      const selected = item.id === selectedId;
      return `<button class="segment-card ${escapeHtml(tone)}${selected ? ' is-selected' : ''}" type="button" data-posture-segment="${escapeHtml(item.id)}" aria-pressed="${selected ? 'true' : 'false'}">
        <span>${escapeHtml(item.typeLabel || 'Segment')}</span>
        <strong>${escapeHtml(item.label || 'Unknown')}</strong>
        <small>${escapeHtml(item.detail || '')}</small>
        <b>${escapeHtml(item.score || 0)}<em>/100</em></b>
      </button>`;
    }).join('')
    : '<div class="signal-empty"><b>No segments</b><p>Awaiting activity.</p></div>';
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

function renderHardeningMission() {
  const mission = currentPosture && currentPosture.hardening && currentPosture.hardening.mission
    ? currentPosture.hardening.mission
    : null;
  const target = $('#hardeningMission');
  if (!target) return;
  if (!mission) {
    target.innerHTML = '<div class="signal-empty"><b>No mission</b><p>Refresh posture.</p></div>';
    return;
  }
  const progress = mission.progress || {};
  const current = mission.current || null;
  const lanes = Array.isArray(mission.lanes) ? mission.lanes : [];
  const proofLedger = mission.proofLedger && typeof mission.proofLedger === 'object' ? mission.proofLedger : {};
  const proofCurrent = proofLedger.current && typeof proofLedger.current === 'object' ? proofLedger.current : null;
  const missionState = readinessTone(mission.state || 'attention');
  const title = current ? current.label : 'Deployment proof complete';
  const area = current ? current.areaLabel : 'Gateway, AI assets, and MCP agents';
  const detail = current ? current.detail : 'All hardening steps are proven from sanitized telemetry and policy state.';
  const command = current && current.command ? current.command : '';
  const validation = current && current.validation ? current.validation : 'Evidence export and SOC posture state are ready.';
  const proofSummary = proofLedger.total
    ? `${proofLedger.verified || 0} verified / ${proofLedger.attention || 0} attention / ${proofLedger.missing || 0} missing`
    : 'No proof items';
  target.innerHTML = `<div class="hardening-mission ${escapeHtml(missionState)}">
      <div class="mission-primary">
        <div class="mission-kicker">
          ${monitorStatusDot(mission.status || 'warning', `${mission.title || 'Hardening mission'} ${mission.state || 'attention'}`)}
          <span>${escapeHtml(mission.title || 'Hardening mission')}</span>
          <b>${escapeHtml(progress.percent || 0)}%</b>
        </div>
        <h3>${escapeHtml(title)}</h3>
        <p>${escapeHtml(area)} · ${escapeHtml(detail)}</p>
        ${command ? `<div class="mission-command"><code>${escapeHtml(command)}</code><button class="ghost mini" type="button" data-copy-command="${escapeHtml(command)}">Copy</button></div>` : ''}
        <small>${escapeHtml(validation)}</small>
        <div class="mission-proof-ledger">
          <b>Proof ledger</b>
          <span>${escapeHtml(proofSummary)}</span>
          ${proofCurrent ? `<small>${escapeHtml(proofCurrent.areaLabel || 'Readiness area')}: ${escapeHtml(proofCurrent.label || 'Evidence item')}</small>` : '<small>All proof rows are verified.</small>'}
        </div>
      </div>
      <div class="mission-progress" role="list" aria-label="Hardening mission lanes">
        ${lanes.map((lane) => {
    const laneTone = readinessTone(lane.state || 'attention');
    return `<button class="mission-lane ${escapeHtml(laneTone)}" type="button" data-tab-jump="${escapeHtml(lane.targetTab || 'coverage')}" role="listitem">
            <span>${escapeHtml(lane.label || 'Readiness area')}</span>
            <b>${escapeHtml(lane.done || 0)}/${escapeHtml(lane.total || 0)}</b>
            <small>${escapeHtml(lane.nextStep || 'Complete')}</small>
          </button>`;
  }).join('')}
      </div>
    </div>`;
}

function proofStatusLabel(status) {
  const value = String(status || 'missing');
  if (value === 'verified') return 'Verified';
  if (value === 'attention') return 'Attention';
  return 'Missing';
}

function actionWorkflowLabel(status) {
  const value = String(status || 'open');
  if (value === 'assigned') return 'Assigned';
  if (value === 'snoozed') return 'Snoozed';
  if (value === 'resolved') return 'Resolved';
  return 'Open';
}

function actionWorkflowTone(status) {
  const value = String(status || 'open');
  if (value === 'resolved') return 'resolved';
  if (value === 'snoozed') return 'snoozed';
  if (value === 'assigned') return 'assigned';
  return 'open';
}

function actionWorkflowMeta(item = {}) {
  const parts = [];
  if (item.workflowOwner) parts.push(item.workflowOwner);
  if (item.workflowSnoozeUntil && item.workflowStatus === 'snoozed') parts.push(`until ${fmtTime(item.workflowSnoozeUntil)}`);
  if (item.workflowProofState === 'proof_pending') parts.push('proof pending');
  if (item.workflowUpdatedAt) parts.push(fmtTime(item.workflowUpdatedAt));
  return parts.join(' / ');
}

function renderHardeningActionQueue() {
  const rows = currentPosture && Array.isArray(currentPosture.actionQueue) ? currentPosture.actionQueue : [];
  const summary = $('#hardeningActionSummary');
  const target = $('#hardeningActionQueue');
  if (!summary || !target) return;
  const critical = rows.filter((item) => item.severity === 'critical').length;
  const warning = rows.filter((item) => item.severity === 'warning').length;
  const assigned = rows.filter((item) => item.workflowStatus === 'assigned').length;
  const snoozed = rows.filter((item) => item.workflowStatus === 'snoozed').length;
  summary.textContent = rows.length ? `${rows.length} actions / ${critical} critical / ${warning} warning / ${assigned + snoozed} routed` : 'All clear';
  target.innerHTML = rows.length
    ? rows.map((item, index) => {
      const severity = ['critical', 'warning', 'info'].includes(item.severity) ? item.severity : 'warning';
      const command = item.command || '';
      const workflow = actionWorkflowTone(item.workflowStatus);
      const workflowMeta = actionWorkflowMeta(item);
      const disabled = canAdminWrite() ? '' : 'disabled aria-disabled="true"';
      return `<article class="action-row">
        <div class="action-rank">${escapeHtml(index + 1)}</div>
        <div class="action-main">
          <div class="action-kicker">
            <span>${escapeHtml(item.category || 'Hardening')}</span>
            <b class="action-severity ${escapeHtml(severity)}">${escapeHtml(severity)}</b>
            <b class="action-workflow-pill ${escapeHtml(workflow)}">${escapeHtml(actionWorkflowLabel(item.workflowStatus))}</b>
          </div>
          <strong>${escapeHtml(item.label || 'Review hardening action')}</strong>
          <small>${escapeHtml(item.detail || '')}</small>
          ${workflowMeta ? `<small class="action-workflow-meta">${escapeHtml(workflowMeta)}</small>` : ''}
        </div>
        <div class="action-controls">
          ${command ? `<code>${escapeHtml(command)}</code>` : ''}
          <button class="ghost mini" type="button" data-tab-jump="${escapeHtml(item.targetTab || 'coverage')}">${escapeHtml(item.action || 'Open')}</button>
          ${command ? `<button class="ghost mini" type="button" data-copy-command="${escapeHtml(command)}">Copy command</button>` : ''}
          <div class="action-workflow-controls">
            <button class="ghost mini" type="button" data-action-workflow="assigned" data-action-id="${escapeHtml(item.id)}" ${disabled}>Assign to me</button>
            <button class="ghost mini" type="button" data-action-workflow="snoozed" data-action-id="${escapeHtml(item.id)}" ${disabled}>Snooze</button>
            <button class="ghost mini" type="button" data-action-workflow="resolved" data-action-id="${escapeHtml(item.id)}" ${disabled}>Log resolved</button>
          </div>
        </div>
      </article>`;
    }).join('')
    : '<div class="signal-empty"><b>No action gaps</b><p>Hardening gaps are clear.</p></div>';
}

function renderPostureObjectives() {
  const objectives = currentPosture && Array.isArray(currentPosture.objectives) ? currentPosture.objectives : [];
  const summary = $('#postureObjectiveSummary');
  const target = $('#postureObjectives');
  if (!summary || !target) return;
  const covered = objectives.filter((item) => item.state === 'covered').length;
  summary.textContent = objectives.length ? `${covered}/${objectives.length} covered` : 'Waiting for data';
  target.innerHTML = objectives.length
    ? objectives.map((item) => {
      const tone = postureTone(item.state);
      return `<article class="objective-card ${escapeHtml(tone)}">
        <div class="objective-score"><b>${escapeHtml(item.score ?? 0)}</b><span>/100</span></div>
        <div class="objective-body">
          <div class="objective-title">${escapeHtml(item.label)}</div>
          <div class="objective-detail">${escapeHtml(item.detail)}</div>
          <button class="ghost mini" type="button" data-tab-jump="${escapeHtml(item.targetTab || 'policy')}">${escapeHtml(item.action || 'Open')}</button>
        </div>
      </article>`;
    }).join('')
    : '<div class="signal-empty"><b>No posture data</b><p>Refresh posture.</p></div>';
}

function inventoryStateLabel(state) {
  const value = String(state || 'unknown');
  if (value === 'sanctioned') return 'Sanctioned';
  if (value === 'unsanctioned') return 'Unsanctioned';
  if (value === 'shadow') return 'Shadow';
  if (value === 'local_approved') return 'Approved';
  if (value === 'local_unapproved') return 'Unapproved';
  return value.replace(/_/g, ' ');
}

function inventoryRiskLabel(level) {
  const value = String(level || 'low');
  if (value === 'critical') return 'Critical';
  if (value === 'high') return 'High';
  if (value === 'medium') return 'Medium';
  return 'Low';
}

function renderAiInventory() {
  const inventory = currentPosture && currentPosture.aiInventory && typeof currentPosture.aiInventory === 'object'
    ? currentPosture.aiInventory
    : null;
  const summary = $('#aiInventorySummary');
  const target = $('#aiInventoryRows');
  if (!summary || !target) return;
  const invSummary = inventory && inventory.summary && typeof inventory.summary === 'object' ? inventory.summary : {};
  const apps = inventory && Array.isArray(inventory.apps) ? inventory.apps : [];
  const tools = inventory && Array.isArray(inventory.tools) ? inventory.tools : [];
  const rows = [...apps, ...tools].slice(0, 12);
  summary.textContent = inventory
    ? `${invSummary.sanctioned || 0} sanctioned / ${invSummary.shadow || 0} shadow / ${invSummary.highRiskAssets || 0} high risk`
    : 'Waiting for data';
  target.innerHTML = rows.length
    ? rows.map((item) => {
      const status = item.status === 'online' || item.status === 'warning' ? item.status : 'idle';
      const state = item.state || 'unknown';
      const events = Number(item.events) || 0;
      const sideValue = item.kind === 'Endpoint tool'
        ? (state === 'local_unapproved' ? 'Review' : 'OK')
        : events;
      const riskLevel = ['critical', 'high', 'medium', 'low'].includes(item.riskLevel) ? item.riskLevel : 'low';
      const riskScore = Number(item.riskScore) || 0;
      return `<article class="ai-inventory-row ${escapeHtml(status)}">
        <div class="ai-inventory-main">
          <small>${escapeHtml(item.kind || 'AI app')} / ${escapeHtml(item.source || 'coverage')}</small>
          <strong>${escapeHtml(item.name || 'AI destination')}</strong>
          <span>${escapeHtml(item.detail || 'No sanitized detail.')}</span>
          <span class="ai-inventory-risk ${escapeHtml(riskLevel)}">${escapeHtml(inventoryRiskLabel(riskLevel))} risk / ${escapeHtml(riskScore)}/100${item.riskReason ? ` / ${escapeHtml(item.riskReason)}` : ''}</span>
        </div>
        <div class="ai-inventory-side">
          <span class="ai-inventory-state ${escapeHtml(state)}">${escapeHtml(inventoryStateLabel(state))}</span>
          <b>${escapeHtml(sideValue)}</b>
          <button class="ghost mini" type="button" data-tab-jump="${escapeHtml(item.targetTab || 'coverage')}">${escapeHtml(item.action || 'Open')}</button>
        </div>
      </article>`;
    }).join('')
    : '<div class="signal-empty"><b>No AI inventory</b><p>No governed, shadow, or endpoint AI tools observed.</p></div>';
}

function renderOperatorFlow(){window.PromptWallOperatorFlow&&window.PromptWallOperatorFlow.render(currentPosture,{$,escapeHtml});}
function renderAgenticMcp(){window.PromptWallAgenticMcp&&window.PromptWallAgenticMcp.render(currentPosture,{$,escapeHtml,inventoryStateLabel});}
function renderThreatGuardrails(){window.PromptWallThreatGuardrails&&window.PromptWallThreatGuardrails.render(currentPosture,{$,escapeHtml});}
function renderControlGraph(){window.PromptWallControlGraph&&window.PromptWallControlGraph.render(currentPosture,{$,escapeHtml});}
function renderBehaviorBaselines(){window.PromptWallBehaviorBaselines&&window.PromptWallBehaviorBaselines.render(currentPosture,{$,escapeHtml});}

function renderHardeningWorkbench() {
  const hardening = currentPosture && currentPosture.hardening && typeof currentPosture.hardening === 'object'
    ? currentPosture.hardening
    : null;
  const areas = hardening && Array.isArray(hardening.areas) ? hardening.areas : [];
  const summary = $('#hardeningReadinessSummary');
  const target = $('#hardeningReadinessBoard');
  if (!summary || !target) return;
  const sendButton = $('#sendPostureSnapshot');
  if (sendButton) {
    sendButton.disabled = !canAdminWrite();
    sendButton.title = canAdminWrite() ? 'Send sanitized posture snapshot' : 'Security Admin required';
  }
  const ready = areas.filter((area) => area.state === 'ready').length;
  summary.textContent = areas.length ? `${ready}/${areas.length} ready / ${hardening.score || 0} overall` : 'Waiting for data';
  target.innerHTML = areas.length
    ? areas.map((area) => {
      const tone = readinessTone(area.state);
      const evidence = (Array.isArray(area.evidence) ? area.evidence : []).slice(0, 3);
      const gaps = (Array.isArray(area.gaps) ? area.gaps : []).slice(0, 3);
      const playbook = (Array.isArray(area.playbook) ? area.playbook : []).slice(0, 5);
      const proofs = (Array.isArray(area.proofs) ? area.proofs : []).slice(0, 6);
      const proofLedger = area.proofLedger && typeof area.proofLedger === 'object' ? area.proofLedger : {};
      const status = area.state === 'ready' ? 'online' : area.state === 'blocked' ? 'error' : 'warning';
      const list = (label, items, fallback) => `<div class="hardening-list"><b>${escapeHtml(label)}</b><ul>${items.length
        ? items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
        : `<li>${escapeHtml(fallback)}</li>`}</ul></div>`;
      const proofRows = `<div class="hardening-proof-ledger">
        <div class="proof-ledger-head">
          <b>Evidence ledger</b>
          <span>${escapeHtml(proofLedger.verified || 0)} verified / ${escapeHtml(proofLedger.attention || 0)} attention / ${escapeHtml(proofLedger.missing || 0)} missing</span>
        </div>
        ${proofs.length ? proofs.map((proof) => `<div class="proof-row ${escapeHtml(proof.status || 'missing')}">
          <span>${escapeHtml(proofStatusLabel(proof.status))}</span>
          <div>
            <strong>${escapeHtml(proof.label || 'Evidence item')}</strong>
            <small>${escapeHtml(proof.detail || '')}${proof.evidenceAt ? ` / ${escapeHtml(fmt(proof.evidenceAt))}` : ''}</small>
          </div>
        </div>`).join('') : '<p class="hardening-step-empty">No proof rows published.</p>'}
      </div>`;
      const runbook = `<div class="hardening-runbook"><b>Runbook</b>${playbook.length
        ? playbook.map((step) => `<div class="hardening-step ${escapeHtml(step.status || 'todo')}">
          <div class="hardening-step-head">
            <span>${escapeHtml(step.status || 'todo')}</span>
            <strong>${escapeHtml(step.label || 'Remediation step')}</strong>
          </div>
          <p>${escapeHtml(step.detail || '')}</p>
          ${step.command ? `<code>${escapeHtml(step.command)}</code>` : ''}
          <small>${escapeHtml(step.validation || '')}</small>
        </div>`).join('')
        : '<p class="hardening-step-empty">No remediation steps published.</p>'}</div>`;
      return `<article class="hardening-card ${escapeHtml(tone)}">
        <div class="hardening-head">
          <div class="hardening-title">
            ${monitorStatusDot(status, `${area.label} ${area.state}`)}
            <strong>${escapeHtml(area.label)}</strong>
          </div>
          <div class="hardening-score">${escapeHtml(area.score || 0)}<span>/100</span></div>
        </div>
        <p class="hardening-desc">${escapeHtml(area.description || '')}</p>
        <div class="hardening-meta">
          <span>${escapeHtml(area.owner || 'security')}</span>
          <span>${escapeHtml(area.source || 'control')}</span>
        </div>
        <div class="hardening-lists">
          ${list('Proof', evidence, 'Awaiting proof')}
          ${list('Gaps', gaps, 'No open gaps')}
        </div>
        ${proofRows}
        ${runbook}
        <button class="ghost mini" type="button" data-tab-jump="${escapeHtml(area.targetTab || 'coverage')}">${escapeHtml(area.action || 'Open')}</button>
      </article>`;
    }).join('')
    : '<div class="signal-empty"><b>No hardening data</b><p>Refresh readiness.</p></div>';
}

function siemState(){return{currentSiemPackage,siemPackageProfile,siemPackageLoading,siemPackageError};}
function setSiemState(patch){if('currentSiemPackage'in patch)currentSiemPackage=patch.currentSiemPackage;if('siemPackageLoading'in patch)siemPackageLoading=patch.siemPackageLoading;if('siemPackageError'in patch)siemPackageError=patch.siemPackageError;}
function siemDeps(){return{$,api,apiErrorSummary,canAdminWrite,escapeHtml,humanize,markUpdated,renderSiemPackage,responseJsonObject,setState:setSiemState,statusChip};}
function renderSiemPackage(){const m=window.PromptWallSiemPackage;if(m)m.render(siemState(),siemDeps());}
async function loadSiemPackage(){const m=window.PromptWallSiemPackage;return m?m.load(siemState(),siemDeps()):null;}
async function downloadSiemPackage(){const m=window.PromptWallSiemPackage;return m?m.download(siemState(),siemDeps()):null;}
function securityPackageState(){return{currentSecurityPackage,securityPackageLoading,securityPackageError};}
function setSecurityPackageState(patch){if('currentSecurityPackage'in patch)currentSecurityPackage=patch.currentSecurityPackage;if('securityPackageLoading'in patch)securityPackageLoading=patch.securityPackageLoading;if('securityPackageError'in patch)securityPackageError=patch.securityPackageError;}
function securityPackageDeps(){return{$,api,apiErrorSummary,canAdminWrite,escapeHtml,humanize,icons,markUpdated,renderSecurityPackage,responseJsonObject,setState:setSecurityPackageState,statusChip};}
function renderSecurityPackage(){const m=window.PromptWallSecurityPackage;if(m)m.render(securityPackageState(),securityPackageDeps());}
async function loadSecurityPackage(){const m=window.PromptWallSecurityPackage;return m?m.load(securityPackageState(),securityPackageDeps()):null;}
async function downloadSecurityPackage(){const m=window.PromptWallSecurityPackage;return m?m.download(securityPackageState(),securityPackageDeps()):null;}

function renderPostureTrend() {
  const rows = currentPosture && Array.isArray(currentPosture.trend) ? currentPosture.trend : [];
  const target = $('#postureTrendChart');
  const summary = $('#postureTrendSummary');
  if (!target || !summary) return;
  const max = Math.max(1, ...rows.map((row) => Number(row.events) || 0));
  const total = rows.reduce((sum, row) => sum + (Number(row.events) || 0), 0);
  summary.textContent = rows.length ? `${total} events / ${rows.length} days` : 'Waiting for data';
  target.innerHTML = rows.length
    ? rows.map((row) => {
      const blocked = Number(row.blocked) || 0;
      const redacted = Number(row.redacted) || 0;
      const allowed = Number(row.allowed) || 0;
      const coached = Number(row.coached) || 0;
      const events = Number(row.events) || 0;
      const height = Math.max(5, Math.round((events / max) * 100));
      const detail = `${row.date}: ${events} events, ${blocked} blocked, ${redacted} redacted, ${coached} coached, ${allowed} allowed`;
      return `<div class="trend-day" tabindex="0" role="img" aria-label="${escapeHtml(detail)}" data-tooltip="${escapeHtml(detail)}">
        <div class="trend-stack" style="--h:${height}%">
          <i class="trend-blocked" style="--share:${events ? Math.max(4, Math.round((blocked / events) * height)) : 0}%"></i>
          <i class="trend-redacted" style="--share:${events ? Math.max(4, Math.round((redacted / events) * height)) : 0}%"></i>
          <i class="trend-coached" style="--share:${events ? Math.max(4, Math.round((coached / events) * height)) : 0}%"></i>
          <i class="trend-allowed" style="--share:${events ? Math.max(4, Math.round((allowed / events) * height)) : 0}%"></i>
        </div>
        <span>${escapeHtml(String(row.date || '').slice(5))}</span>
      </div>`;
    }).join('')
    : '<div class="signal-empty"><b>No trend data</b><p>Recent activity appears here.</p></div>';
}

function renderControlOutcomes() {
  const rows = currentPosture && Array.isArray(currentPosture.controls) ? currentPosture.controls : [];
  const target = $('#controlOutcomeRows');
  const summary = $('#controlOutcomeSummary');
  if (!target || !summary) return;
  const total = rows.reduce((sum, row) => sum + (Number(row.events) || 0), 0);
  summary.textContent = rows.length ? `${rows.length} control paths` : 'Waiting for data';
  target.innerHTML = rows.length
    ? rows.map((row) => {
      const events = Number(row.events) || 0;
      const controlled = (Number(row.blocked) || 0) + (Number(row.redacted) || 0) + (Number(row.coached) || 0);
      const width = total ? Math.max(5, Math.round((events / total) * 100)) : 0;
      return `<div class="control-row">
        <div><strong>${escapeHtml(row.label)}</strong><span>${escapeHtml(controlled)} controlled / ${escapeHtml(events)} events</span></div>
        <div class="control-bar" role="img" aria-label="${escapeHtml(row.label)} ${events} events"><i style="--w:${width}%"></i></div>
      </div>`;
    }).join('')
    : '<div class="signal-empty"><b>No outcomes</b><p>Awaiting controls.</p></div>';
}

function monitorSelectedRecord() {
  if (monitorSelectedKind === 'item') {
    return monitorItemsSource().find((item) => item.id === monitorSelectedId) || null;
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
  renderPostureSegments();
  renderMonitorMetrics();
  renderHardeningMission();
  renderOperatorFlow();
  renderHardeningActionQueue();
  renderPostureObjectives();
  renderAiInventory();
  renderAgenticMcp();
  renderThreatGuardrails();
  renderControlGraph();
  renderHardeningWorkbench();
  renderSiemPackage();
  renderPostureTrend();
  renderControlOutcomes();
  renderBehaviorBaselines();
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

async function loadPosture() {
  try {
    const segment = monitorSegmentFilter && monitorSegmentFilter !== 'all'
      ? `&segment=${encodeURIComponent(monitorSegmentFilter)}`
      : '';
    const r = await api('/api/posture?limit=5000' + segment);
    const body = await responseJsonObject(r, null);
    if (!body) return null;
    currentPosture = body;
    monitorLastUpdated = body.generatedAt || new Date().toISOString();
    const live = $('#monitorLiveSummary');
    if (live) {
      const critical = (body.surfaces || []).some((item) => item.status === 'error')
        || (body.events || []).some((item) => item.severity === 'critical');
      live.innerHTML = `${monitorStatusDot(critical ? 'error' : 'online', critical ? 'Command center has critical signals' : 'Command center online', { pulse: true })}${critical ? 'ATTENTION' : 'LIVE'}`;
    }
    renderMonitor();
    return body;
  } catch {
    return null;
  }
}

async function refreshMonitorSignals() {
  if (monitorRefreshing) return;
  monitorRefreshing = true;
  renderMonitor();
  try {
    await Promise.all([loadPosture(), loadSiemPackage()]);
    monitorRefreshing = false;
    monitorUpdateSequence += 1;
    monitorLastUpdated = (currentPosture && currentPosture.generatedAt) || new Date().toISOString();
    monitorRecentEventId = `evt-refresh-${monitorUpdateSequence}`;
    renderMonitor();
    markUpdated('SIGNALS UPDATED');
  } catch {
    monitorRefreshing = false;
    renderMonitor();
  }
}

function workflowPatchFor(status) {
  const now = new Date();
  if (status === 'assigned') {
    return { status, owner: currentUser || 'security_admin', note: 'assigned_from_command_center' };
  }
  if (status === 'snoozed') {
    const until = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    return { status, snoozeUntil: until, note: 'snoozed_24h_from_command_center' };
  }
  if (status === 'resolved') {
    return { status, note: 'remediation_logged_waiting_for_proof' };
  }
  return { status: 'open', note: 'reopened_from_command_center' };
}

async function updatePostureActionWorkflow(id, status, button) {
  if (!canAdminWrite()) {
    alert('Request not allowed for this session.');
    return;
  }
  if (!id) return;
  const payload = { id, ...workflowPatchFor(status) };
  if (button) button.disabled = true;
  const response = await api('/api/posture/actions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (response && response.ok) {
    await loadPosture();
    markUpdated('ACTION UPDATED');
    return;
  }
  if (button) button.disabled = false;
  if (response) alert(await apiErrorSummary(response, 'Action update failed'));
}

async function sendPostureSnapshot() {
  if (!canAdminWrite()) return;
  const button = $('#sendPostureSnapshot');
  const status = $('#postureSnapshotStatus');
  if (button) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    button.innerHTML = '<span class="button-spinner" aria-hidden="true"></span>Sending';
  }
  if (status) status.textContent = 'SENDING';
  try {
    const response = await api('/api/posture/notify', { method: 'POST' });
    const body = await responseJsonBody(response, {});
    if (response && response.ok && body.sent) {
      if (status) status.textContent = 'SENT TO SOC';
      await loadAudit();
      return;
    }
    const reason = body && body.reason ? humanize(body.reason) : 'not configured';
    if (status) status.textContent = `NOT SENT - ${reason}`.slice(0, 80);
  } catch {
    if (status) status.textContent = 'SEND FAILED';
  } finally {
    if (button) {
      button.removeAttribute('aria-busy');
      button.innerHTML = 'Send SOC snapshot';
    }
    renderHardeningWorkbench();
  }
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
    setPolicyStatus(`Added scoped rule ${rule.id}`);
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
    setPolicyStatus(`Added exception ${rule.id}`);
  }
}

function setPolicyStatus(message, clearAfterMs = 0) {
  const status = $('#polSaved');
  if (!status) return;
  if (policyStatusTimer) {
    clearTimeout(policyStatusTimer);
    policyStatusTimer = null;
  }
  status.textContent = message;
  if (clearAfterMs > 0) {
    policyStatusTimer = setTimeout(() => {
      if (status.textContent === message) status.textContent = '';
      policyStatusTimer = null;
    }, clearAfterMs);
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
  return String(state || '').toLowerCase() === 'covered' ? 'good' : 'warn';
}

function readinessTone(state) {
  const s = String(state || '').toLowerCase();
  if (s === 'ready') return 'ready';
  if (s === 'blocked') return 'blocked';
  return 'attention';
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

function samePrincipal(left, right) {
  return String(left || '').trim().toLowerCase() === String(right || '').trim().toLowerCase();
}

function canDecide(q = {}) {
  if (currentRole === 'security_admin') return true;
  if (currentRole !== 'approver') return false;
  return q.assignedRole === 'approver' && (!q.assignedUser || samePrincipal(q.assignedUser, currentUser));
}

function canReveal(q = {}) {
  return currentRole === 'security_admin' && !!q && q.rawRetained === true;
}

function savedQueueDensity() {
  try {
    return localStorage.getItem('promptwall.queueDensity') === 'compact' ? 'compact' : 'comfortable';
  } catch {
    return 'comfortable';
  }
}

function saveQueueDensity(value) {
  try {
    localStorage.setItem('promptwall.queueDensity', value);
  } catch {}
}

function normalizeColorTheme(value) {
  return value === 'light' ? 'light' : 'dark';
}

function savedColorTheme() {
  try {
    return normalizeColorTheme(localStorage.getItem('promptwall.theme'));
  } catch {
    return 'dark';
  }
}

function saveColorTheme(value) {
  try {
    localStorage.setItem('promptwall.theme', normalizeColorTheme(value));
  } catch {}
}

function updateColorThemeControls() {
  $$('[data-theme-choice]').forEach((button) => {
    const selectedTheme = button.dataset.themeChoice === colorTheme;
    button.classList.toggle('active', selectedTheme);
    button.setAttribute('aria-pressed', String(selectedTheme));
  });
}

function applyColorTheme(value, options = {}) {
  colorTheme = normalizeColorTheme(value);
  document.body.dataset.theme = colorTheme;
  document.documentElement.style.colorScheme = colorTheme;
  updateColorThemeControls();
  if (options.persist !== false) saveColorTheme(colorTheme);
}

function applyQueueDensity() {
  const compact = queueDensity === 'compact';
  document.body.classList.toggle('queue-density-compact', compact);
  const button = $('#toggleQueueDensity');
  if (!button) return;
  button.classList.toggle('active', compact);
  button.setAttribute('aria-pressed', String(compact));
  const label = $('span', button);
  if (label) label.textContent = compact ? 'Comfort view' : 'Compact view';
  button.dataset.tooltip = compact ? 'Show full queue details' : 'Fit more queue items';
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
  if (queueFilter === 'mine') return q.assignedRole === currentRole || samePrincipal(q.assignedUser, currentUser);
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

function auditText(entry = {}) {
  return [
    entry.id,
    entry.ts,
    entry.action,
    entry.actor,
    entry.queryId,
    entry.detail,
  ].join(' ').toLowerCase();
}

function matchesAudit(entry) {
  return !searchTerm || auditText(entry || {}).includes(searchTerm);
}

function withinRangeDays(ts, days) {
  if (!days) return true;
  const t = Date.parse(ts);
  return !Number.isFinite(t) || t >= Date.now() - days * 86400000;
}

function filteredActivityRows(rows) {
  return (rows || []).filter((q) => withinRangeDays(q.createdAt, activityRangeDays) && matchesSearch(q));
}

function filteredAuditEntries(entries) {
  return (entries || []).filter((a) => (auditActionFilter === 'all' || a.action === auditActionFilter) && matchesAudit(a));
}

function csvCell(value) {
  const s = String(value ?? '');
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function downloadCsv(name, header, rows) {
  const body = [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\n');
  const url = URL.createObjectURL(new Blob([body], { type: 'text/csv' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function csvStamp() {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}

function exportActivityCsv() {
  const rows = filteredActivityRows(currentActivity).map((q) => [
    fmt(q.createdAt), sourceLabel(q.source), q.user || '', q.destination || '', workflowOwner(q),
    q.maxSeverityLabel || 'low', q.riskScore ?? 0, Object.keys(q.entityCounts || {}).join('; '), humanize(q.status),
  ]);
  downloadCsv(`promptwall-activity-${csvStamp()}.csv`,
    ['Time', 'Source', 'User', 'Destination', 'Owner', 'Severity', 'Risk', 'Detected', 'Status'], rows);
}

function exportAuditCsv() {
  const rows = filteredAuditEntries(currentAuditEntries).map((a) => [
    fmt(a.ts), a.action || '', a.actor || '', a.queryId || '', a.detail || '',
  ]);
  downloadCsv(`promptwall-audit-${csvStamp()}.csv`,
    ['Timestamp', 'Action', 'Actor', 'Query', 'Detail'], rows);
}

function resetTablePages() {
  activityPage = 1;
  auditPage = 1;
  lineagePages = {};
}

function paginatedRows(rows, page, pageSize) {
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, Number(page) || 1), totalPages);
  const start = (safePage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  return {
    rows: rows.slice(start, end),
    page: safePage,
    total,
    totalPages,
    start,
    end,
  };
}

function renderTablePager(selector, { target, page, total, totalPages, start, end }) {
  const el = $(selector);
  if (!el) return;
  if (!total) {
    el.innerHTML = '<span>No rows</span>';
    return;
  }
  const prevPage = Math.max(1, page - 1);
  const nextPage = Math.min(totalPages, page + 1);
  el.innerHTML = `<span>Showing ${start + 1}-${end} of ${total}</span>
    <div class="pager-controls" aria-label="Pagination controls">
      <button class="ghost mini pager-button" type="button" data-pager-target="${escapeHtml(target)}" data-pager-page="${prevPage}" ${page === 1 ? 'disabled' : ''} aria-label="Previous page">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m15 6-6 6 6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>
      <span class="pager-page">Page ${page} of ${totalPages}</span>
      <button class="ghost mini pager-button" type="button" data-pager-target="${escapeHtml(target)}" data-pager-page="${nextPage}" ${page === totalPages ? 'disabled' : ''} aria-label="Next page">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m9 6 6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>
    </div>`;
}

function updateSearch(value) {
  const next = String(value || '').trim().toLowerCase();
  if (next !== searchTerm) resetTablePages();
  searchTerm = next;
  renderQueueView();
  renderActivityRows(currentActivity);
  renderLineage(currentLineage);
  renderAuditRows(currentAuditEntries);
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

async function apiErrorSummary(response, fallback) {
  try {
    const body = await response.clone().json();
    if (Array.isArray(body.fields) && body.fields.length) return `${fallback}: ${body.fields.join(', ')}`;
    if (body.error) return `${fallback}: ${body.error}`;
  } catch {}
  return fallback;
}

async function responseJsonBody(response, fallback = null) {
  if (!response) return fallback;
  try {
    return await response.json();
  } catch {
    return fallback;
  }
}

async function responseJson(response, fallback = null) {
  if (!response || !response.ok) return fallback;
  return responseJsonBody(response, fallback);
}

async function responseJsonObject(response, fallback = null) {
  const body = await responseJson(response, null);
  return body && typeof body === 'object' && !Array.isArray(body) ? body : fallback;
}

async function responseJsonObjectBody(response, fallback = null) {
  const body = await responseJsonBody(response, null);
  return body && typeof body === 'object' && !Array.isArray(body) ? body : fallback;
}

async function responseJsonArray(response, fallback = []) {
  const body = await responseJson(response, null);
  return Array.isArray(body) ? body : fallback;
}

function boundedPromise(promise, timeoutMs, fallback) {
  return Promise.race([
    Promise.resolve(promise).catch(() => fallback),
    new Promise((resolve) => setTimeout(() => resolve(fallback), timeoutMs)),
  ]);
}

async function optionalDashboardJson(path, fallback = null, timeoutMs = 1800) {
  const response = await boundedPromise(api(path), timeoutMs, null);
  return boundedPromise(responseJson(response, fallback), timeoutMs, fallback);
}

async function dashboardJsonWithTimeout(path, timeoutMs = 1800) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await api(path, { signal: controller.signal });
    return await responseJson(response, null);
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function pendingQueueRows() {
  const directRows = await dashboardJsonWithTimeout('/api/queries?status=pending', 2200);
  if (Array.isArray(directRows)) return directRows;

  const activityRows = await dashboardJsonWithTimeout('/api/queries?limit=200', 2200);
  if (Array.isArray(activityRows)) return activityRows.filter((q) => q.status === 'pending');

  if (Array.isArray(currentActivity) && currentActivity.length) {
    return currentActivity.filter((q) => q.status === 'pending');
  }

  return [];
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

function uniqueDialogId(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function askStepUpPassword({ title, message, confirmText, icon = '', buttonClass = 'reveal' }) {
  return new Promise((resolve) => {
    const dialog = document.createElement('dialog');
    const titleId = uniqueDialogId('stepup_title');
    const descriptionId = uniqueDialogId('stepup_description');
    dialog.className = 'stepup-dialog';
    dialog.setAttribute('aria-labelledby', titleId);
    dialog.setAttribute('aria-describedby', descriptionId);
    dialog.innerHTML = `
      <form method="dialog" class="stepup-panel">
        <div>
          <h2 id="${titleId}">${escapeHtml(title)}</h2>
          <p id="${descriptionId}">${escapeHtml(message)}</p>
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
    const titleId = uniqueDialogId('destination_review_title');
    const descriptionId = uniqueDialogId('destination_review_description');
    dialog.className = 'stepup-dialog';
    dialog.setAttribute('aria-labelledby', titleId);
    dialog.setAttribute('aria-describedby', descriptionId);
    dialog.innerHTML = `
      <form method="dialog" class="stepup-panel">
        <div>
          <h2 id="${titleId}">Record destination reason</h2>
          <p id="${descriptionId}">${escapeHtml(labels[decision] || 'review')} ${escapeHtml(destination)} with a short examiner-facing reason.</p>
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
  applyQueueDensity();
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
  activateTab(tabNameFromLocation(), { replaceHistory: true });
  connectStream();
}

async function refreshAll() {
  await Promise.all([loadStats(), loadQueue(), loadActivity(), loadPosture(), loadSiemPackage()]);
}

async function loadStats() {
  setBusy('#stats', true, 'SYNCING');
  try {
    const [r, seatRes] = await Promise.all([
      api('/api/stats'),
      canAdminWrite() ? api('/api/billing/seats') : Promise.resolve(null),
    ]);
    const s = await responseJsonObject(r, null);
    if (!s) return;
    const seats = await responseJsonObject(seatRes, null);
    const topEntities = Array.isArray(s.topEntities) ? s.topEntities : [];
    const totalDecisions = (s.approved || 0) + (s.denied || 0);
    const approveRate = totalDecisions ? `${Math.round(((s.approved || 0) / totalDecisions) * 100)}%` : '-';
    const invalidSeatConfig = !!(seats && seats.saasMode && seats.seatLimitValid === false);
    const hasSeatLimit = !!(seats && seats.seatLimit);
    const seatValue = invalidSeatConfig ? 'Invalid' : (hasSeatLimit ? `${seats.seatsUsed}/${seats.seatLimit}` : (seats ? seats.seatsUsed : '-'));
    const seatMeta = invalidSeatConfig ? 'set paid seat limit' : (hasSeatLimit ? `${seats.seatsRemaining} remaining` : 'billable users');
    const seatLabel = invalidSeatConfig ? 'Seat config' : (seats && seats.saasMode ? 'Seats used' : 'Users observed');
    const seatTone = invalidSeatConfig || (seats && seats.overLimit) ? 'warn' : 'secure';
    const cards = [
      ['pending', s.pending, 'Pending approval', 'held for review', 'critical'],
      ['alert', s.todayBlocked, 'Blocked today', 'policy stops', 'warn'],
      ['good', s.approved, 'Approved', 'released by admin', 'secure'],
      ['', s.denied, 'Denied', 'never released', 'critical'],
      ['', approveRate, 'Approval rate', 'admin decisions', 'live'],
      [invalidSeatConfig || (seats && seats.overLimit) ? 'alert' : '', seatValue, seatLabel, seatMeta, seatTone],
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
    $('#topEntities').innerHTML = topEntities.map(([k, v]) => {
      const max = topEntities[0][1] || 1;
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

function revealedPromptState(id) {
  const value = revealedPrompts.get(id);
  if (!value) return null;
  if (typeof value === 'string') return { text: value, rawRetained: true, rawDiffersFromRedacted: true };
  return {
    text: String(value.text || ''),
    rawRetained: value.rawRetained === true,
    rawDiffersFromRedacted: typeof value.rawDiffersFromRedacted === 'boolean'
      ? value.rawDiffersFromRedacted
      : null,
  };
}

function revealDisplayState(q, revealState) {
  if (!revealState) return null;
  const rawRetained = revealState.rawRetained === true;
  const rawDiffersFromRedacted = rawRetained && (typeof revealState.rawDiffersFromRedacted === 'boolean'
    ? revealState.rawDiffersFromRedacted
    : String(revealState.text || '') !== String((q || {}).redactedPrompt || ''));
  if (rawRetained && rawDiffersFromRedacted) {
    return {
      kind: 'raw',
      promptClass: 'revealed',
      buttonLabel: 'Raw shown and logged',
      statusLabel: 'Raw prompt revealed',
      statusDetail: 'Audit logged',
    };
  }
  if (rawRetained) {
    return {
      kind: 'retained',
      promptClass: 'retained',
      buttonLabel: 'Retained copy shown',
      statusLabel: 'Retained copy matches preview',
      statusDetail: 'Audit logged',
    };
  }
  return {
    kind: 'unavailable',
    promptClass: 'unavailable',
    buttonLabel: 'Raw unavailable, event logged',
    statusLabel: 'Raw unavailable',
    statusDetail: 'Redacted preview shown',
  };
}

function revealControlFor(q, revealState) {
  if (currentRole !== 'security_admin') return '';
  if (revealState) {
    const displayState = revealDisplayState(q, revealState);
    return `<button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button" disabled>${escapeHtml(displayState.buttonLabel)}</button>`;
  }
  if (q.rawRetained !== true) {
    return `<button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button" disabled>Raw not retained</button>`;
  }
  return `<button class="btn reveal" data-act="reveal" data-id="${escapeHtml(q.id)}" type="button">${icons.eye}Reveal raw</button>`;
}

async function loadQueue() {
  setBusy('#tab-queue .panel', true, 'SYNCING');
  try {
    currentQueue = await pendingQueueRows();
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
    const active = button.dataset.queueFilter === queueFilter;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
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
  const isSelected = selected === q.id;
  const sev = sevClass(q.maxSeverityLabel);
  const detected = Object.keys(q.entityCounts || {}).join(', ') || (q.categories || []).join(', ') || 'policy match';
  const revealState = revealedPromptState(q.id);
  const revealDisplay = revealDisplayState(q, revealState);
  const promptText = revealState ? revealState.text : q.redactedPrompt;
  const revealControl = revealControlFor(q, revealState);
  const rowLabel = `${q.user || 'unknown user'} ${sourceLabel(q.source)} to ${q.destination || 'unknown destination'}, ${q.maxSeverityLabel || 'low'} severity, risk ${q.riskScore ?? 0}`;
  const revealStatus = revealDisplay
    ? `<div class="prompt-reveal-status ${escapeHtml(revealDisplay.kind)}"><b>${escapeHtml(revealDisplay.statusLabel)}</b><span>${escapeHtml(revealDisplay.statusDetail)}</span></div>`
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
  return `<article class="q ${isSelected ? 'selected' : ''}" data-id="${escapeHtml(q.id)}" tabindex="0" role="listitem" ${isSelected ? 'aria-current="true"' : ''} aria-controls="incidentDetail" aria-label="${escapeHtml(rowLabel)}">
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
    ${revealStatus}
    <div class="prompt ${revealDisplay ? escapeHtml(revealDisplay.promptClass) : ''}" id="p_${escapeHtml(q.id)}">${escapeHtml(promptText)}</div>
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
  const copyCommand = e.target.closest('[data-copy-command]');
  if (copyCommand) {
    e.preventDefault();
    e.stopPropagation();
    const command = copyCommand.dataset.copyCommand || '';
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(command);
      copyCommand.textContent = 'Copied';
    } catch {
      copyCommand.textContent = 'Copy failed';
    }
    setTimeout(() => {
      copyCommand.textContent = 'Copy';
    }, 1600);
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
  const selectableQueueRow = e.target.closest('.q[data-id]');
  if (selectableQueueRow && !e.target.closest('textarea,input,button,select,a')) {
    selected = selectableQueueRow.dataset.id;
    renderQueueView();
    return;
  }
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
  const postureSegmentButton = e.target.closest('[data-posture-segment]');
  if (postureSegmentButton) {
    monitorSegmentFilter = postureSegmentButton.dataset.postureSegment || 'all';
    await loadPosture();
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
  const copySha = e.target.closest('[data-copy-sha]');
  if (copySha && navigator.clipboard) {
    navigator.clipboard.writeText(copySha.dataset.copySha).then(() => {
      const original = copySha.innerHTML;
      copySha.innerHTML = '<b>SHA-256</b> copied to clipboard';
      setTimeout(() => { copySha.innerHTML = original; }, 1400);
    }).catch(() => {});
    return;
  }
  const pagerButton = e.target.closest('[data-pager-target][data-pager-page]');
  if (pagerButton) {
    const page = Number(pagerButton.dataset.pagerPage) || 1;
    const target = pagerButton.dataset.pagerTarget || '';
    if (target === 'activity') {
      activityPage = page;
      renderActivityRows(currentActivity);
      return;
    }
    if (target === 'audit') {
      auditPage = page;
      renderAuditRows(currentAuditEntries);
      return;
    }
    if (target.startsWith('lineage')) {
      lineagePages[target] = page;
      renderLineage(currentLineage);
      return;
    }
  }
  const densityButton = e.target.closest('#toggleQueueDensity');
  if (densityButton) {
    queueDensity = queueDensity === 'compact' ? 'comfortable' : 'compact';
    saveQueueDensity(queueDensity);
    hideTooltip();
    applyQueueDensity();
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
        alert(q.rawRetained === false
          ? 'Raw prompt was not retained for this item.'
          : 'Request not allowed for this session. Use a Security Admin account.');
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
      const rawRetained = body.rawRetained === true;
      const rawPrompt = String(body.rawPrompt || '');
      const rawDiffersFromRedacted = typeof body.rawDiffersFromRedacted === 'boolean'
        ? body.rawDiffersFromRedacted
        : (rawRetained && rawPrompt !== String(q.redactedPrompt || ''));
      revealedPrompts.set(id, {
        text: rawPrompt,
        rawRetained,
        rawDiffersFromRedacted,
      });
      selected = id;
      renderQueueView();
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
  const workflowButton = e.target.closest('[data-action-workflow][data-action-id]');
  if (workflowButton) {
    await updatePostureActionWorkflow(
      workflowButton.dataset.actionId,
      workflowButton.dataset.actionWorkflow,
      workflowButton,
    );
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
  if (e.target.matches('#activityRange')) {
    activityRangeDays = Number(e.target.value) || 0;
    activityPage = 1;
    renderActivityRows(currentActivity);
    return;
  }
  if (e.target.matches('#activityPageSize')) {
    activityPageSize = Number(e.target.value) || 10;
    activityPage = 1;
    renderActivityRows(currentActivity);
    return;
  }
  if (e.target.matches('#auditActionFilter')) {
    auditActionFilter = e.target.value || 'all';
    auditPage = 1;
    renderAuditRows(currentAuditEntries);
    return;
  }
  if (e.target.matches('#auditPageSize')) {
    auditPageSize = Number(e.target.value) || 10;
    auditPage = 1;
    renderAuditRows(currentAuditEntries);
    return;
  }
  if (e.target.matches('#queueCategoryFilter')) {
    queueCategoryFilter = e.target.value || 'all';
    renderQueueView();
    return;
  }
  if (e.target.matches('#queueDestinationFilter')) {
    queueDestinationFilter = e.target.value || 'all';
    renderQueueView();
    return;
  }
  if (e.target.matches('#postureSegmentSelect')) {
    monitorSegmentFilter = e.target.value || 'all';
    loadPosture().catch(() => {});
    return;
  }
  if (e.target.matches('#siemPackageProfile')) {
    siemPackageProfile = e.target.value || 'all';
    loadSiemPackage().catch(() => {});
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
    const rows = await responseJsonArray(r, null);
    if (!rows) return;
    currentActivity = rows;
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
  const filtered = filteredActivityRows(rows);
  const page = paginatedRows(filtered, activityPage, activityPageSize);
  activityPage = page.page;
  $('#activityRows').innerHTML = page.rows.map((q) => {
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
  renderTablePager('#activityPager', { target: 'activity', ...page });
}

let currentInsights = null;
let insightsWindowDays = 30;

const INSIGHTS_DECISION_META = {
  allowed: { label: 'Allowed', tone: '#3fb27f' },
  redacted: { label: 'Redacted', tone: '#3f8cff' },
  warned: { label: 'Warned', tone: '#e0a23b' },
  flagged: { label: 'Flagged', tone: '#c98b2e' },
  blocked: { label: 'Blocked', tone: '#e0555f' },
  shadow: { label: 'Shadow AI', tone: '#a15de0' },
};
const INSIGHTS_RISK_TONE = { none: '#6b7686', low: '#3fb27f', medium: '#e0a23b', high: '#e07a3b', critical: '#e0555f' };

async function loadInsights() {
  const sel = $('#insightsWindow');
  if (sel) insightsWindowDays = Number(sel.value) || 30;
  setBusy('#tab-insights .panel', true, 'AGGREGATING');
  try {
    const r = await api(`/api/insights?windowDays=${encodeURIComponent(insightsWindowDays)}`);
    const next = await responseJsonObject(r, null);
    if (!next) return;
    currentInsights = next;
    renderInsights(next);
    markUpdated();
  } finally {
    setBusy('#tab-insights .panel', false);
  }
}

function insightsKpi(label, value, hint) {
  return `<div class="insights-kpi"><span class="insights-kpi-value">${escapeHtml(String(value))}</span>`
    + `<span class="insights-kpi-label">${escapeHtml(label)}</span>`
    + (hint ? `<span class="insights-kpi-hint">${escapeHtml(hint)}</span>` : '') + '</div>';
}

// Dependency-free stacked-area time series as inline SVG (CSP-safe).
function insightsSeriesSvg(series) {
  const w = 720, h = 200, pad = 24;
  const days = series.length || 1;
  const max = Math.max(1, ...series.map((d) => d.total));
  const order = ['allowed', 'redacted', 'warned', 'flagged', 'blocked', 'shadow'];
  const x = (i) => pad + (i * (w - pad * 2)) / Math.max(1, days - 1);
  const y = (v) => h - pad - (v / max) * (h - pad * 2);
  let bars = '';
  const bw = Math.max(3, (w - pad * 2) / days - 4);
  series.forEach((d, i) => {
    let acc = 0;
    const cx = x(i) - bw / 2;
    for (const k of order) {
      const v = d[k] || 0;
      if (!v) continue;
      const yTop = y(acc + v);
      const seg = ((v / max) * (h - pad * 2));
      bars += `<rect x="${cx.toFixed(1)}" y="${yTop.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(1, seg).toFixed(1)}" fill="${INSIGHTS_DECISION_META[k].tone}" rx="1"><title>${escapeHtml(d.date)} · ${INSIGHTS_DECISION_META[k].label}: ${v}</title></rect>`;
      acc += v;
    }
  });
  const ticks = [0, Math.round(max / 2), max].map((v) => `<text x="4" y="${(y(v) + 3).toFixed(1)}" class="insights-axis">${v}</text>`).join('');
  const firstLabel = series.length ? `<text x="${pad}" y="${h - 6}" class="insights-axis">${escapeHtml(series[0].date.slice(5))}</text>` : '';
  const lastLabel = series.length ? `<text x="${w - pad}" y="${h - 6}" text-anchor="end" class="insights-axis">${escapeHtml(series[series.length - 1].date.slice(5))}</text>` : '';
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="AI activity over time">${ticks}${bars}${firstLabel}${lastLabel}</svg>`;
}

// Donut of the decision mix.
function insightsDonutSvg(decisions) {
  const total = decisions.reduce((s, d) => s + d.count, 0);
  const size = 180, r = 64, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
  if (!total) return '<div class="insights-empty">No activity in this window.</div>';
  let offset = 0;
  const arcs = decisions.filter((d) => d.count).map((d) => {
    const frac = d.count / total;
    const dash = `${(frac * C).toFixed(2)} ${(C - frac * C).toFixed(2)}`;
    const seg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${INSIGHTS_DECISION_META[d.id].tone}" stroke-width="20" stroke-dasharray="${dash}" stroke-dashoffset="${(-offset * C).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"><title>${INSIGHTS_DECISION_META[d.id].label}: ${d.count}</title></circle>`;
    offset += frac;
    return seg;
  }).join('');
  const legend = decisions.filter((d) => d.count).map((d) =>
    `<span class="insights-swatch"><i style="background:${INSIGHTS_DECISION_META[d.id].tone}"></i>${INSIGHTS_DECISION_META[d.id].label} <b>${d.count}</b></span>`).join('');
  return `<svg viewBox="0 0 ${size} ${size}" class="insights-donut" role="img" aria-label="Decision mix">${arcs}`
    + `<text x="${cx}" y="${cy - 2}" text-anchor="middle" class="insights-donut-total">${total}</text>`
    + `<text x="${cx}" y="${cy + 16}" text-anchor="middle" class="insights-donut-sub">events</text></svg>`
    + `<div class="insights-legend">${legend}</div>`;
}

function insightsRiskSvg(bands) {
  const max = Math.max(1, ...bands.map((b) => b.count));
  return '<div class="insights-riskbars">' + bands.map((b) => {
    const pct = Math.round((b.count / max) * 100);
    return `<div class="insights-riskbar"><span class="insights-riskbar-label">${escapeHtml(b.label)}</span>`
      + `<span class="insights-riskbar-track"><span class="insights-riskbar-fill" style="width:${pct}%;background:${INSIGHTS_RISK_TONE[b.id]}"></span></span>`
      + `<span class="insights-riskbar-count">${b.count}</span></div>`;
  }).join('') + '</div>';
}

function insightsHBars(items, keyName) {
  if (!items || !items.length) return '<div class="insights-empty">None recorded.</div>';
  const max = Math.max(1, ...items.map((i) => i.count));
  return items.map((i) => {
    const pct = Math.round((i.count / max) * 100);
    return `<div class="insights-hbar"><span class="insights-hbar-label" title="${escapeHtml(i[keyName])}">${escapeHtml(i[keyName])}</span>`
      + `<span class="insights-hbar-track"><span class="insights-hbar-fill" style="width:${pct}%"></span></span>`
      + `<span class="insights-hbar-count">${i.count}</span></div>`;
  }).join('');
}

function insightsRiskChip(risk) {
  if (!risk) return '<span class="insights-chip tone-neutral">Unrated</span>';
  const tone = risk.riskTier >= 4 ? 'tone-critical' : risk.riskTier === 3 ? 'tone-high' : risk.riskTier === 2 ? 'tone-medium' : 'tone-low';
  return `<span class="insights-chip ${tone}">${escapeHtml(risk.riskTierLabel || 'unknown')}</span>`;
}

function insightsFlagLabels(flags) {
  const map = { trains_on_data: 'Trains on data', personal_account_tier: 'Personal tier', data_residency_cn: 'Data in CN', data_residency_eu: 'Data in EU' };
  return (flags || []).map((f) => `<span class="insights-attr">${escapeHtml(map[f] || f)}</span>`).join(' ');
}

function renderInsights(d) {
  if (!d) return;
  const t = d.totals || {};
  $('#insightsKpis').innerHTML = [
    insightsKpi('AI interactions', t.considered || 0, `last ${d.windowDays} days`),
    insightsKpi('Avg exposure risk', t.avgRisk || 0, 'of 100'),
    insightsKpi('Blocked', t.blocked || 0, 'held or denied'),
    insightsKpi('Redacted', t.redacted || 0, 'tokenized & sent'),
    insightsKpi('Shadow-AI hits', t.shadow || 0, 'ungoverned tools'),
  ].join('');
  $('#insightsSeries').innerHTML = insightsSeriesSvg(d.series || []);
  $('#insightsSeriesLegend').innerHTML = (d.decisions || []).filter((x) => INSIGHTS_DECISION_META[x.id])
    .map((x) => `<span class="insights-swatch"><i style="background:${INSIGHTS_DECISION_META[x.id].tone}"></i>${INSIGHTS_DECISION_META[x.id].label}</span>`).join('');
  $('#insightsDecisions').innerHTML = insightsDonutSvg(d.decisions || []);
  $('#insightsRisk').innerHTML = insightsRiskSvg(d.riskBands || []);
  $('#insightsDetectors').innerHTML = insightsHBars(d.topDetectors || [], 'key');
  $('#insightsCategories').innerHTML = insightsHBars(d.topCategories || [], 'key');
  $('#insightsShadow').innerHTML = insightsHBars(d.shadowByProvider || [], 'key');
  $('#insightsDestinations').innerHTML = (d.topDestinations || []).map((row) =>
    `<tr><td>${escapeHtml(row.destination)}</td><td>${escapeHtml(row.risk ? row.risk.provider : '—')}</td>`
    + `<td>${insightsRiskChip(row.risk)}</td><td>${row.risk ? insightsFlagLabels(row.risk.flags) : '<span class="insights-attr-muted">—</span>'}</td>`
    + `<td>${row.count}</td></tr>`).join('') || '<tr><td colspan="5" class="insights-empty">No destinations recorded.</td></tr>';
  $('#insightsUsers').innerHTML = (d.topUsers || []).map((u) =>
    `<tr><td>${escapeHtml(u.user)}</td><td>${u.events}</td><td>${u.blocked}</td><td>${u.avgRisk}</td></tr>`).join('')
    || '<tr><td colspan="4" class="insights-empty">No user activity recorded.</td></tr>';
}

// ---- App Catalog ------------------------------------------------------------
const CATALOG_RISK_TONE = { critical: 'tone-critical', high: 'tone-high', moderate: 'tone-medium', low: 'tone-low', minimal: 'tone-low', unrated: 'tone-neutral' };
const CATALOG_STATUS_TONE = { blocked: 'tone-critical', unsanctioned: 'tone-high', under_review: 'tone-neutral', tolerated: 'tone-medium', sanctioned: 'tone-low' };
const CATALOG_ATTR_LABEL = { trains_on_data: 'Trains on data', personal_account_tier: 'Personal tier', data_residency_cn: 'Data in CN', data_residency_eu: 'Data in EU' };

async function loadCatalog() {
  setBusy('#tab-catalog .panel', true, 'DISCOVERING');
  try {
    const r = await api('/api/catalog');
    const body = await responseJsonObject(r, null);
    if (!body) return;
    renderCatalog(body.apps || []);
    markUpdated();
  } finally {
    setBusy('#tab-catalog .panel', false);
  }
}

function catalogAttrs(app) {
  const flags = (app.riskAttributes && app.riskAttributes.flags) || [];
  return flags.map((f) => `<span class="insights-attr">${escapeHtml(CATALOG_ATTR_LABEL[f] || f)}</span>`).join(' ') || '<span class="insights-attr-muted">—</span>';
}

function renderCatalog(apps) {
  const total = apps.length;
  const shadow = apps.filter((a) => a.sanctionedStatus === 'under_review').length;
  const high = apps.filter((a) => a.riskTier === 'critical' || a.riskTier === 'high').length;
  const governed = apps.filter((a) => ['sanctioned', 'tolerated', 'blocked'].includes(a.sanctionedStatus)).length;
  $('#catalogKpis').innerHTML = [
    insightsKpi('AI apps discovered', total, 'across all sources'),
    insightsKpi('Awaiting review', shadow, 'shadow AI'),
    insightsKpi('Elevated / high risk', high, 'by risk tier'),
    insightsKpi('Governed', governed, 'allow / govern / block'),
  ].join('');
  $('#catalogRows').innerHTML = apps.map((a) => `
    <tr>
      <td>${escapeHtml(a.appName || a.destination)}<div class="catalog-host">${escapeHtml(a.destination)}</div></td>
      <td>${escapeHtml(a.provider || '—')}</td>
      <td><span class="insights-chip ${CATALOG_RISK_TONE[a.riskTier] || 'tone-neutral'}">${escapeHtml(a.riskTier)}</span> <span class="catalog-score">${a.riskScore == null ? '' : a.riskScore}</span></td>
      <td>${catalogAttrs(a)}</td>
      <td><span class="insights-chip ${CATALOG_STATUS_TONE[a.sanctionedStatus] || 'tone-neutral'}">${escapeHtml(a.sanctionedStatus.replace(/_/g, ' '))}</span></td>
      <td>${a.eventCount || 0}</td>
      <td class="catalog-sources">${escapeHtml(Object.keys(a.sources || {}).join(', ') || '—')}</td>
      <td class="catalog-actions">
        <button class="ghost mini" data-catalog-review="${escapeHtml(a.destination)}" data-decision="allow" type="button">Allow</button>
        <button class="ghost mini" data-catalog-review="${escapeHtml(a.destination)}" data-decision="govern" type="button">Govern</button>
        <button class="ghost mini danger" data-catalog-review="${escapeHtml(a.destination)}" data-decision="block" type="button">Block</button>
      </td>
    </tr>`).join('') || '<tr><td colspan="8" class="insights-empty">No AI apps discovered yet. Import a proxy/DNS log or wait for sensor sightings.</td></tr>';
  $$('#catalogRows [data-catalog-review]').forEach((btn) => {
    btn.onclick = () => reviewCatalogApp(btn.dataset.catalogReview, btn.dataset.decision);
  });
}

async function reviewCatalogApp(host, decision) {
  const reason = prompt(`Reason for "${decision}" on ${host}:`, `${decision} decision from console`);
  if (reason == null) return;
  const r = await api(`/api/catalog/${encodeURIComponent(host)}/review`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ decision, reason }) });
  if (r && r.ok) loadCatalog();
}

async function importCatalogCsv() {
  const csv = prompt('Paste AI hostnames (one per line, or host,count from a proxy/DNS log):', '');
  if (!csv) return;
  const r = await api('/api/catalog/import', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ csv }) });
  if (r && r.ok) { const b = await r.json(); alert(`Imported ${b.imported} app(s), skipped ${b.skipped}.`); loadCatalog(); }
}

async function addCatalogApp() {
  const destination = prompt('AI app host to add (e.g. internal-llm.corp):', '');
  if (!destination) return;
  const appName = prompt('Display name (optional):', destination) || undefined;
  const r = await api('/api/catalog', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ destination, appName }) });
  if (r && r.ok) loadCatalog();
}

// ---- Compliance framework coverage ------------------------------------------
const COMPLIANCE_STATE_TONE = { covered: 'tone-low', attention: 'tone-high', not_provided: 'tone-neutral' };

async function loadCompliance() {
  setBusy('#tab-compliance .panel', true, 'MAPPING');
  try {
    const r = await api('/api/compliance');
    const body = await responseJsonObject(r, null);
    if (!body) return;
    renderCompliance(body.controlMappings || []);
    markUpdated();
  } finally {
    setBusy('#tab-compliance .panel', false);
  }
}

function renderCompliance(controls) {
  const covered = controls.filter((c) => c.state === 'covered').length;
  const attention = controls.filter((c) => c.state === 'attention').length;
  const pct = controls.length ? Math.round((covered / controls.length) * 100) : 0;
  $('#complianceKpis').innerHTML = [
    insightsKpi('Controls covered', `${covered}/${controls.length}`, `${pct}% coverage`),
    insightsKpi('Needs attention', attention, 'action required'),
    insightsKpi('AI frameworks', '5', 'NIST/ISO 42001/EU AI Act/OWASP/ATLAS'),
    insightsKpi('Evidence', 'prompt-free', 'hashes & metadata only'),
  ].join('');
  // Framework roll-up: a control "belongs" to a framework if any control family names it.
  const FRAMEWORKS = [
    { key: 'NIST AI RMF', match: /NIST AI RMF/i },
    { key: 'ISO/IEC 42001', match: /ISO\/IEC 42001|ISO 42001/i },
    { key: 'EU AI Act', match: /EU AI Act/i },
    { key: 'OWASP LLM Top 10', match: /OWASP LLM/i },
    { key: 'MITRE ATLAS', match: /MITRE ATLAS/i },
    { key: 'GLBA / NCUA', match: /GLBA|NCUA/i },
    { key: 'HIPAA', match: /HIPAA/i },
    { key: 'PCI DSS', match: /PCI/i },
  ];
  $('#complianceFrameworks').innerHTML = FRAMEWORKS.map((fw) => {
    const rel = controls.filter((c) => (c.controlFamilies || []).some((f) => fw.match.test(f)));
    if (!rel.length) return '';
    const cov = rel.filter((c) => c.state === 'covered').length;
    const p = Math.round((cov / rel.length) * 100);
    const tone = p >= 100 ? 'tone-low' : p >= 50 ? 'tone-medium' : 'tone-high';
    return `<div class="compliance-fw"><div class="compliance-fw-head"><span>${escapeHtml(fw.key)}</span><span class="insights-chip ${tone}">${cov}/${rel.length}</span></div>`
      + `<span class="insights-riskbar-track"><span class="insights-riskbar-fill" style="width:${p}%;background:var(--blue)"></span></span></div>`;
  }).join('');
  $('#complianceControls').innerHTML = controls.map((c) => `
    <div class="panel">
      <div class="panel-head"><div><h2>${escapeHtml(c.title)}</h2><span>${escapeHtml((c.evidence || []).slice(0, 3).join(', '))}</span></div>
        <span class="insights-chip ${COMPLIANCE_STATE_TONE[c.state] || 'tone-neutral'}">${escapeHtml((c.state || '').replace('_', ' '))}</span></div>
      <div class="compliance-body">
        <p class="compliance-summary">${escapeHtml(c.summary || '')}</p>
        <div class="compliance-families">${(c.controlFamilies || []).map((f) => `<span class="insights-attr">${escapeHtml(f)}</span>`).join(' ')}</div>
      </div>
    </div>`).join('');
}

// ---- Integrations & delivery ------------------------------------------------
const DELIVERY_TONE = { delivered: 'tone-low', failed: 'tone-critical', deduped: 'tone-neutral' };

async function loadIntegrations() {
  setBusy('#tab-integrations .panel', true, 'SYNCING');
  try {
    const [subsR, delR] = await Promise.all([api('/api/subscriptions'), api('/api/subscriptions/deliveries')]);
    const subs = await responseJsonObject(subsR, { destinations: [], supportedTypes: [] });
    const del = await responseJsonObject(delR, { deliveries: [] });
    renderIntegrations(subs, del.deliveries || []);
    markUpdated();
  } finally {
    setBusy('#tab-integrations .panel', false);
  }
}

function renderIntegrations(subs, deliveries) {
  const dests = subs.destinations || [];
  const delivered = deliveries.filter((d) => d.status === 'delivered').length;
  const failed = deliveries.filter((d) => d.status === 'failed').length;
  $('#integrationsKpis').innerHTML = [
    insightsKpi('Subscriptions', dests.length, 'named destinations'),
    insightsKpi('Delivered', delivered, 'recent events'),
    insightsKpi('Failed', failed, 'needs attention'),
    insightsKpi('Supported', (subs.supportedTypes || []).length, 'SIEM/SOAR types'),
  ].join('');
  $('#subscriptionRows').innerHTML = dests.map((d) => `
    <div class="sub-row">
      <div class="sub-meta"><b>${escapeHtml(d.name)}</b><span class="insights-attr">${escapeHtml(d.type)}</span>
        <span class="sub-host">${escapeHtml(d.urlHost || '—')}</span>
        <span class="sub-filter">risk≥${d.minRisk} · sev≥${d.minSeverity}${d.eventTypes ? ' · ' + escapeHtml(d.eventTypes.join(',')) : ''}</span></div>
      ${subTestBadge(d.id)}
      <button class="ghost mini" data-sub-test="${escapeHtml(d.id)}" type="button">Send test</button>
    </div>`).join('') || '<div class="insights-empty">No subscriptions configured. Add destinations in config/subscriptions.json.</div>';
  $$('#subscriptionRows [data-sub-test]').forEach((btn) => { btn.onclick = () => testSubscription(btn.dataset.subTest, btn); });
  $('#deliveryRows').innerHTML = deliveries.map((d) => `
    <tr><td>${fmtTime(d.ts)}</td><td>${escapeHtml(d.destName || d.destId)}</td><td>${escapeHtml(d.type || '')}</td>
      <td><span class="insights-chip ${DELIVERY_TONE[d.status] || 'tone-neutral'}">${escapeHtml(d.status)}</span></td>
      <td>${d.attempts || 0}</td><td>${d.httpStatus || '—'}</td></tr>`).join('')
    || '<tr><td colspan="6" class="insights-empty">No deliveries yet.</td></tr>';
}

const subTestResults = {};

function subTestBadge(id) {
  const t = subTestResults[id];
  if (!t) return '';
  const ok = t.status === 'delivered';
  return `<span class="sub-test-result ${ok ? 'ok' : 'bad'}">Last test: ${escapeHtml(t.status)} · ${t.attempts} attempt(s) · ${escapeHtml(t.at)}</span>`;
}

async function testSubscription(id, btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  const r = await api(`/api/subscriptions/${encodeURIComponent(id)}/test`, { method: 'POST' });
  const b = r && r.ok ? await r.json().catch(() => null) : null;
  subTestResults[id] = b && b.result
    ? { status: b.result.status, attempts: b.result.attempts || 0, at: new Date().toLocaleTimeString() }
    : { status: 'failed', attempts: 0, at: new Date().toLocaleTimeString() };
  loadIntegrations();
}

async function loadCoverage() {
  setBusy('#tab-coverage .panel', true, 'RECONCILING');
  try {
    const r = await api('/api/coverage');
    const nextCoverage = await responseJsonObject(r, null);
    if (!nextCoverage) return;
    currentCoverage = nextCoverage;
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
      <div class="mini-kpi"><b>${escapeHtml(totals.freshDiscoveryFeeds || 0)}/${escapeHtml(totals.discoveryFeeds || 0)}</b><span>Feeds fresh</span></div>
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
  }).join('') || '<div class="empty"><div class="big">No endpoint AI tools</div>No endpoint AI inventory reported.</div>';
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
      <div><strong>${escapeHtml(d.destination)}</strong><span>${escapeHtml(d.users)} users / ${escapeHtml((d.sources || []).join(', ') || d.source || 'source unknown')} / last ${escapeHtml(d.lastSeen ? fmt(d.lastSeen) : '-')}</span></div>
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
    </div>`).join('') || '<div class="empty"><div class="big">No shadow AI</div>No ungoverned AI tools reported.</div>';
  dispatchEvent(new CustomEvent('pw:c',{detail:c}));
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
    const nextSetup = r && r.ok
      ? await responseJsonObject(r, null)
      : await responseJsonObjectBody(r, null);
    if (!nextSetup) return;
    currentIdentitySetup = nextSetup;
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
    const body = await responseJsonObject(r, null);
    if (!body) return;
    currentLineage = body.lineage || {};
    renderLineage(currentLineage);
    markUpdated();
  } finally {
    setBusy('#tab-lineage .panel', false);
  }
}

function renderLineageRows(tbodyId, rows, emptyLabel) {
  const filtered = (rows || []).filter(matchesLineage);
  const page = paginatedRows(filtered, lineagePages[tbodyId] || 1, LINEAGE_PAGE_SIZE);
  lineagePages[tbodyId] = page.page;
  $(`#${tbodyId}`).innerHTML = page.rows.map((row) => `<tr>
    <td class="mono">${escapeHtml(row.key || '-')}</td>
    <td class="mono">${escapeHtml(row.events || 0)}</td>
    <td class="mono">${escapeHtml(row.blocked || 0)}</td>
    <td class="mono">${escapeHtml(row.redacted || 0)}</td>
    <td class="mono">${escapeHtml(row.maxRiskScore || 0)}</td>
  </tr>`).join('') || `<tr><td colspan="5" class="empty">${escapeHtml(emptyLabel)}</td></tr>`;
  renderTablePager(`#${tbodyId}Pager`, { target: tbodyId, ...page });
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
  renderLineageRows('lineageUsers', lineage.byUser, 'No user lineage yet.');
  renderLineageRows('lineageDestinations', lineage.byDestination, 'No destination lineage yet.');
  renderLineageRows('lineageSensors', lineage.bySensor, 'No sensor lineage yet.');
  renderLineageRows('lineageCategories', lineage.byCategory, 'No category lineage yet.');
  renderLineageRows('lineageChannels', lineage.byChannel, 'No channel lineage yet.');
  renderLineageRows('lineageDecisions', lineage.byDecision, 'No decision lineage yet.');
}

async function loadAudit() {
  setBusy('#tab-audit .panel', true, 'VERIFYING');
  try {
    loadSecurityPackage();
    const r = await api('/api/audit');
    const d = await responseJsonObject(r, null);
    if (!d || !d.integrity || !Array.isArray(d.entries)) return;
    const ig = d.integrity;
    $('#integrity').className = `integrity ${ig.ok ? 'ok' : 'bad'}`;
    $('#integrity').innerHTML = ig.ok
      ? `${icons.shield}<span>Chain verified: ${escapeHtml(ig.count)} cryptographically linked entries.</span>`
      : `${icons.shield}<span>Integrity check failed at ${escapeHtml(ig.brokenAt)}.</span>`;
    currentAuditEntries = d.entries;
    renderAuditRows(currentAuditEntries);
    markUpdated();
  } finally {
    setBusy('#tab-audit .panel', false);
  }
}

function refreshAuditActionOptions(entries) {
  const sel = $('#auditActionFilter');
  if (!sel) return;
  const actions = [...new Set((entries || []).map((a) => a.action).filter(Boolean))].sort();
  const want = 'all,' + actions.join(',');
  if (sel.dataset.options === want) return;
  sel.dataset.options = want;
  sel.innerHTML = '<option value="all">All actions</option>'
    + actions.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(humanize(a))}</option>`).join('');
  if (actions.includes(auditActionFilter)) sel.value = auditActionFilter;
  else { sel.value = 'all'; auditActionFilter = 'all'; }
}

function renderAuditRows(entries) {
  refreshAuditActionOptions(entries);
  const filtered = filteredAuditEntries(entries);
  const page = paginatedRows(filtered, auditPage, auditPageSize);
  auditPage = page.page;
  $('#auditRows').innerHTML = page.rows.map((a) => `<tr>
      <td class="mono">${escapeHtml(fmt(a.ts))}</td>
      <td>${statusChip(statusTone(a.action), humanize(a.action), `Audit action: ${humanize(a.action)}\nActor: ${a.actor || '-'}\nQuery: ${a.queryId || '-'}\nTimestamp: ${fmt(a.ts)}`)}</td>
      <td>${escapeHtml(a.actor || '-')}</td>
      <td class="mono">${escapeHtml(a.queryId || '-')}</td>
      <td>${escapeHtml(a.detail || '')}</td>
    </tr>`).join('') || `<tr><td colspan="5" class="empty">${searchTerm || auditActionFilter !== 'all' ? 'No matching audit entries' : 'No audit entries yet'}</td></tr>`;
  renderTablePager('#auditPager', { target: 'audit', ...page });
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

function policyFormBody(p) {
  const approvalRoutingRules = parsePolicyJsonArray($('#pol_approval_routing_rules').value, 'Approval routing rules');
  if (approvalRoutingRules == null) return null;
  const blockedBrowserActions = parsePolicyJsonArray($('#pol_blocked_browser_actions').value, 'Browser action controls');
  if (blockedBrowserActions == null) return null;
  const policyScopes = parsePolicyJsonArray($('#pol_policy_scopes').value, 'Scoped enforcement rules');
  if (policyScopes == null) return null;
  const policyExceptions = parsePolicyJsonArray($('#pol_policy_exceptions').value, 'Time-bound exceptions');
  if (policyExceptions == null) return null;
  return {
    enforcementMode: (document.querySelector('input[name=mode]:checked') || {}).value || p.enforcementMode,
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
    mcpAllowedTools: parsePolicyList($('#pol_mcp_allowed_tools').value),
    mcpBlockedTools: parsePolicyList($('#pol_mcp_blocked_tools').value),
    mcpApprovalRequiredTools: parsePolicyList($('#pol_mcp_approval_required_tools').value),
    blockUnapprovedAiDestinations: $('#pol_block_unapproved_ai').checked,
    responseScanMode: $('#pol_response_scan_mode').value,
  };
}

function renderPolicyImpactPreview(result) {
  if (window.PromptWallPolicyImpact && typeof window.PromptWallPolicyImpact.render === 'function') {
    window.PromptWallPolicyImpact.render(result);
  }
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
  const p = await responseJsonObject(pRes, null);
  const tpls = await responseJsonArray(tRes, null);
  if (!p || !tpls) return;
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
    <div class="config-card pad policy-impact-card" id="policyImpactPreview" aria-live="polite">
      <div class="sensor-head"><div><h3>Policy Impact Preview</h3><p>Test a draft policy against recent sanitized evidence before saving.</p></div>${statePill('warn', 'Not run')}</div>
      <div class="policy-impact-empty">Run Test configuration to preview changed outcomes. Prompt bodies are excluded.</div>
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
      <h3>MCP Tool Governance</h3>
      <p>Restrict agent tools before execution and require review for high-impact connectors.</p>
      <div class="policy-list-grid" style="margin-top:14px">
        <label class="policy-list-field">Allowed MCP tools
          ${readonly
    ? `<div class="chips">${(p.mcpAllowedTools || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">all tools unless blocked</span>'}</div>`
    : `<textarea id="pol_mcp_allowed_tools" class="policy-textarea" spellcheck="false" placeholder="sharepoint.fetch*&#10;drive.read*">${escapeHtml(policyListText(p.mcpAllowedTools))}</textarea>`}
        </label>
        <label class="policy-list-field">Blocked MCP tools
          ${readonly
    ? `<div class="chips">${(p.mcpBlockedTools || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_mcp_blocked_tools" class="policy-textarea" spellcheck="false" placeholder="*.delete*&#10;database.write*">${escapeHtml(policyListText(p.mcpBlockedTools))}</textarea>`}
        </label>
        <label class="policy-list-field">Approval-required MCP tools
          ${readonly
    ? `<div class="chips">${(p.mcpApprovalRequiredTools || []).map((x) => `<span class="chip">${escapeHtml(x)}</span>`).join('') || '<span class="chip">none</span>'}</div>`
    : `<textarea id="pol_mcp_approval_required_tools" class="policy-textarea" spellcheck="false" placeholder="sharepoint.export*&#10;drive.share*">${escapeHtml(policyListText(p.mcpApprovalRequiredTools))}</textarea>`}
        </label>
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
    setPolicyStatus('VERIFYING');
    const body = readonly ? null : policyFormBody(p);
    if (!readonly && !body) return;
    const [nextPreflight, nextCoverage, impactRes] = await Promise.all([
      optionalDashboardJson('/api/preflight'),
      optionalDashboardJson('/api/coverage', currentCoverage),
      body ? api('/api/policy/impact?limit=1000', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }) : Promise.resolve(null),
    ]);
    if (nextCoverage) currentCoverage = nextCoverage;
    let impact;
    if (impactRes) {
      if (!impactRes.ok) {
        setPolicyStatus(await apiErrorSummary(impactRes, 'Could not preview impact'));
        return;
      }
      impact = await impactRes.json();
      renderPolicyImpactPreview(impact);
    }
    const nextHealth = configHealth(nextPreflight);
    const configStatus = $('#configurationStatus');
    if (configStatus) configStatus.innerHTML = statePill(nextHealth.state, `${nextHealth.score}/100 ready`);
    const impactText = impact && impact.summary ? ` / ${impact.summary.changed || 0} policy impact change(s)` : '';
    setPolicyStatus((nextHealth.state === 'bad'
      ? `${nextHealth.failed} blocking check(s)`
      : `${nextHealth.failed} warning(s), ${nextHealth.ok}/${nextHealth.total || 0} checks ready`) + impactText, 3600);
  };
  markUpdated();
  if (readonly) return;
  $('#addScopeRule').onclick = appendGuidedScopeRule;
  $('#addExceptionRule').onclick = appendGuidedExceptionRule;
  $('#savePolicy').onclick = async () => {
    const body = policyFormBody(p);
    if (!body) return;
    setPolicyStatus('Saving');
    const r = await api('/api/policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r) return;
    if (!r.ok) {
      setPolicyStatus(await apiErrorSummary(r, 'Could not save'));
      return;
    }
    setPolicyStatus('Saved', 4000);
  };
  $('#runRetentionPurge').onclick = async () => {
    const r = await api('/api/retention/purge', { method: 'POST' });
    if (!r || !r.ok) return;
    const body = await r.json();
    setPolicyStatus(`Purged ${body.purged || 0} record(s)`, 4000);
  };
  $$('.ps-tpl').forEach((b) => {
    b.onclick = async () => {
      const r = await api('/api/policy/apply-template', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: b.dataset.tpl }) });
      if (!r || !r.ok) {
        setPolicyStatus(r ? await apiErrorSummary(r, 'Could not apply template') : 'Could not apply template');
        return;
      }
      await loadPolicy();
    };
  });
  markUpdated();
  } finally {
    setBusy('#tab-policy .config-shell', false);
  }
}

function installModeLabel(mode) {
  return ({
    'npm-ci-omit-dev': 'Install runtime dependencies',
    'npm-ci': 'Install all dependencies',
    skip: 'Skip dependency install',
  })[mode] || humanize(mode);
}

function updateStatusState(status = {}) {
  if (status.inProgress) return ['warn', 'Running'];
  if (status.error) return ['bad', 'Needs setup'];
  const safety = status.safety || {};
  if (!safety.githubRemote || !safety.sourceTreeClean || safety.configuredBranch === false || (safety.auditIntegrity && safety.auditIntegrity.ok === false)) return ['bad', 'Blocked'];
  const last = status.lastRun || {};
  if (last.status === 'failed' || last.status === 'restart-failed') return ['bad', 'Failed'];
  if (last.restartRequired) return ['warn', 'Restart required'];
  return ['good', 'Ready'];
}

function updateShortCommit(value) {
  return String(value || '').slice(0, 12) || '-';
}

function updateLogRow(label, value) {
  return `<div class="update-log-row"><span>${escapeHtml(label)}</span><b>${escapeHtml(value || '-')}</b></div>`;
}

function updateSafetyRow(label, ok, detail) {
  return `<div class="posture-item"><span>${escapeHtml(label)}</span><b>${statePill(ok ? 'good' : 'bad', detail || (ok ? 'Ready' : 'Blocked'))}</b></div>`;
}

function renderUpdateLastRun(last = {}) {
  if (!last || !last.status) {
    return '<div class="empty"><div class="big">No update runs</div>Check GitHub before the first production update.</div>';
  }
  return `<div class="update-log">
    ${updateLogRow('Status', humanize(last.status))}
    ${updateLogRow('Stage', humanize(last.stage || 'complete'))}
    ${updateLogRow('Started', fmt(last.startedAt))}
    ${updateLogRow('Completed', fmt(last.completedAt))}
    ${updateLogRow('From', updateShortCommit(last.fromCommit))}
    ${updateLogRow('To', updateShortCommit(last.toCommit))}
    ${updateLogRow('Backup', last.backup && last.backup.manifestFile ? last.backup.manifestFile : '')}
    ${last.error ? updateLogRow('Error', last.error) : ''}
  </div>`;
}

function renderUpdateConfigForm(config = {}, disabled = false) {
  const installMode = config.installMode || 'npm-ci-omit-dev';
  return `<div class="config-card pad">
    <h3>Update Configuration</h3>
    <p>Fill these once for the production host. Settings are stored beside the active evidence database, not in source.</p>
    <div class="field-grid" style="margin-top:14px">
      <label for="updateRemoteName">Git remote</label>
      <input id="updateRemoteName" type="text" maxlength="80" value="${escapeHtml(config.remoteName || 'origin')}" ${disabled ? 'disabled' : ''}/>
      <label for="updateBranch">GitHub branch</label>
      <input id="updateBranch" type="text" maxlength="128" value="${escapeHtml(config.branch || 'main')}" ${disabled ? 'disabled' : ''}/>
      <label for="updateInstallMode">Dependency step</label>
      <select id="updateInstallMode" ${disabled ? 'disabled' : ''}>
        ${[
    ['npm-ci-omit-dev', 'npm ci --omit=dev'],
    ['npm-ci', 'npm ci'],
    ['skip', 'Skip install'],
  ].map(([value, label]) => `<option value="${value}" ${installMode === value ? 'selected' : ''}>${label}</option>`).join('')}
      </select>
      <label for="updateRestartCommand">Restart command</label>
      <input id="updateRestartCommand" type="text" maxlength="256" placeholder="systemctl restart promptwall" value="${escapeHtml(config.restartCommand || '')}" ${disabled ? 'disabled' : ''}/>
      <label for="updateRestartAfter">Auto-run restart command</label>
      <input id="updateRestartAfter" type="checkbox" ${config.restartAfterUpdate ? 'checked' : ''} ${disabled ? 'disabled' : ''}/>
    </div>
    <p class="config-subtitle">Backend restart execution requires PROMPTWALL_UPDATE_RESTART_ENABLED=true on the host.</p>
    <div class="update-action-row">
      <button class="btn approve" id="saveUpdateConfig" type="button" ${disabled ? 'disabled' : ''}>${icons.check}Save configuration</button>
      <span class="save-status" id="updateSaveStatus"></span>
    </div>
  </div>`;
}

function renderUpdates(status = {}) {
  const box = $('#updateBox');
  const [state, label] = updateStatusState(status);
  const repo = status.repo || {};
  const config = status.config || {};
  const safety = status.safety || {};
  const last = status.lastRun || {};
  const dirtyFiles = repo.dirtyFiles || [];
  const blocked = state === 'bad' || status.inProgress;
  const restartConfigured = !!config.restartCommand || config.restartCommandSource === 'env';
  const restartExecutable = !!config.restartEnabled && restartConfigured;
  const restartRequired = !!(last && last.restartRequired);
  const dirtyDetail = dirtyFiles.length
    ? `${dirtyFiles.length} source change(s): ${dirtyFiles.slice(0, 3).map((item) => item.path).join(', ')}`
    : 'Clean';
  const updateDisabled = blocked || (safety.auditIntegrity && safety.auditIntegrity.ok === false);
  $('#updateConsoleStatus').innerHTML = statePill(state, label);
  box.innerHTML = `<div class="update-grid">
    <div class="config-card pad wide-panel">
      <div class="sensor-head">
        <div><h3>GitHub Update</h3><p>Fast-forward source from the configured GitHub branch after a verified evidence-store backup.</p></div>
        ${statePill(state, label)}
      </div>
      <div class="update-log">
        ${updateLogRow('Remote', repo.remoteUrl || `${config.remoteName || 'origin'} (not verified)`)}
        ${updateLogRow('Branch', `${repo.branch || '-'} -> ${config.remoteName || 'origin'}/${config.branch || 'main'}`)}
        ${updateLogRow('Current', updateShortCommit(repo.head))}
        ${updateLogRow('Install', installModeLabel(config.installMode))}
        ${updateLogRow('Config path', config.configPath)}
      </div>
      <div class="update-action-row">
        <button class="ghost" id="checkUpdate" type="button" ${blocked ? 'disabled' : ''}>${icons.refresh}Check GitHub</button>
        <button class="btn approve" id="runUpdate" type="button" ${updateDisabled ? 'disabled' : ''}>${icons.refresh}Update from GitHub</button>
        <button class="ghost" id="restartUpdate" type="button" ${(!restartExecutable || !restartRequired || status.inProgress) ? 'disabled' : ''}>Restart service</button>
      </div>
      ${status.error ? `<div class="readonly-note">${escapeHtml(status.error)}</div>` : ''}
    </div>

    <div class="config-card pad">
      <h3>Preservation Checks</h3>
      <p>Runtime state is protected before source files move.</p>
      <div class="posture-list">
        ${updateSafetyRow('GitHub remote', !!safety.githubRemote, safety.githubRemote ? 'GitHub' : 'Not GitHub')}
        ${updateSafetyRow('Checked-out branch', safety.configuredBranch !== false, safety.configuredBranch === false ? `${repo.branch || '-'} does not match ${config.branch || 'main'}` : (repo.branch || config.branch || 'main'))}
        ${updateSafetyRow('Source tree', !!safety.sourceTreeClean, dirtyDetail)}
        ${updateSafetyRow('Audit chain', !!(safety.auditIntegrity && safety.auditIntegrity.ok), safety.auditIntegrity && safety.auditIntegrity.ok ? `${safety.auditIntegrity.count} entries` : 'Failed')}
        ${updateSafetyRow('Backup target', !!safety.backupDir, safety.backupDir || config.backupDir || '-')}
        ${updateSafetyRow('Backend restart', true, config.restartEnabled ? `Enabled via ${config.restartCommandSource}` : 'Manual restart')}
      </div>
    </div>

    ${renderUpdateConfigForm(config, status.inProgress)}

    <div class="config-card pad">
      <h3>Last Run</h3>
      <p>Update activity is also written to the tamper-evident audit log.</p>
      ${renderUpdateLastRun(last)}
    </div>
  </div>`;
  wireUpdateButtons();
}

async function loadUpdates() {
  const box = $('#updateBox');
  if (!box) return;
  if (!canAdminWrite()) {
    $('#updateConsoleStatus').innerHTML = statePill('warn', 'Admin only');
    box.innerHTML = '<div class="readonly-note">Use a Security Admin account to configure and run application updates.</div>';
    return;
  }
  setBusy('#tab-updates .config-shell', true, 'CHECKING');
  try {
    const r = await api('/api/update/status');
    const body = await responseJsonObjectBody(r, null);
    if (!r || !r.ok || !body) {
      $('#updateConsoleStatus').innerHTML = statePill('bad', 'Unavailable');
      box.innerHTML = `<div class="readonly-note">${escapeHtml(body && body.error ? body.error : 'Update status unavailable.')}</div>`;
      return;
    }
    renderUpdates(body);
    markUpdated();
  } finally {
    setBusy('#tab-updates .config-shell', false);
  }
}

function collectUpdateConfig() {
  return {
    remoteName: ($('#updateRemoteName') || {}).value || 'origin',
    branch: ($('#updateBranch') || {}).value || 'main',
    installMode: ($('#updateInstallMode') || {}).value || 'npm-ci-omit-dev',
    restartCommand: ($('#updateRestartCommand') || {}).value || '',
    restartAfterUpdate: !!(($('#updateRestartAfter') || {}).checked),
  };
}

async function saveUpdateConfig() {
  const status = $('#updateSaveStatus');
  if (status) status.textContent = 'Saving';
  const r = await api('/api/update/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(collectUpdateConfig()),
  });
  if (!r || !r.ok) {
    if (status) status.textContent = r ? await apiErrorSummary(r, 'Could not save') : 'Could not save';
    return;
  }
  const body = await r.json();
  renderUpdates(body);
  if ($('#updateSaveStatus')) $('#updateSaveStatus').textContent = 'Saved';
}

async function checkUpdate() {
  $('#updateConsoleStatus').innerHTML = statePill('warn', 'Checking');
  const r = await api('/api/update/check', { method: 'POST' });
  if (!r || !r.ok) {
    $('#updateConsoleStatus').innerHTML = statePill('bad', 'Check failed');
    alert(r ? await apiErrorSummary(r, 'Could not check GitHub') : 'Could not check GitHub');
    await loadUpdates();
    return;
  }
  const result = await r.json();
  $('#updateConsoleStatus').innerHTML = statePill(result.updateAvailable ? 'warn' : 'good', result.updateAvailable ? 'Update available' : 'Current');
  await loadUpdates();
}

async function runUpdate() {
  const proceed = confirm('PromptWall will verify the audit chain, create a database backup, fast-forward source from GitHub, and install dependencies. Continue?');
  if (!proceed) return;
  $('#updateConsoleStatus').innerHTML = statePill('warn', 'Updating');
  const r = await api('/api/update/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ confirmBackup: true }),
  });
  if (!r || !r.ok) {
    $('#updateConsoleStatus').innerHTML = statePill('bad', 'Update failed');
    alert(r ? await apiErrorSummary(r, 'Update failed') : 'Update failed');
    await loadUpdates();
    return;
  }
  await loadUpdates();
}

async function restartUpdatedService() {
  const proceed = confirm('Run the configured restart command now? The dashboard may briefly disconnect.');
  if (!proceed) return;
  const r = await api('/api/update/restart', { method: 'POST' });
  if (!r || !r.ok) {
    alert(r ? await apiErrorSummary(r, 'Restart failed') : 'Restart failed');
    return;
  }
  $('#updateConsoleStatus').innerHTML = statePill('warn', 'Restarting');
}

function wireUpdateButtons() {
  const save = $('#saveUpdateConfig');
  const check = $('#checkUpdate');
  const run = $('#runUpdate');
  const restart = $('#restartUpdate');
  if (save) save.onclick = saveUpdateConfig;
  if (check) check.onclick = checkUpdate;
  if (run) run.onclick = runUpdate;
  if (restart) restart.onclick = restartUpdatedService;
}


function deploySize(bytes) {
  if (!Number.isFinite(bytes)) return 'size on build';
  return bytes < 1024 * 1024 ? Math.round(bytes / 1024) + ' KB' : (bytes / 1024 / 1024).toFixed(1) + ' MB';
}

async function loadDeploy() {
  const rows = $('#deployRows');
  if (!rows) return;
  try {
    const res = await fetch('/api/deploy/artifacts');
    if (!res.ok) throw new Error('http_' + res.status);
    const data = await res.json();
    rows.innerHTML = data.artifacts.map((item) => item.error ? `
      <div class="q" style="cursor:default"><div class="queue-mainline">
        <strong>${escapeHtml(item.label)}</strong><span>packaging unavailable</span><span></span>
      </div></div>` : `
      <div class="q" style="cursor:default">
        <div class="queue-mainline">
          <strong>${escapeHtml(item.label)}</strong>
          <span>${escapeHtml(item.fileName)}</span>
          <a class="btn" href="/api/deploy/download/${escapeHtml(item.id)}" download>Download .zip</a>
        </div>
        <div class="chips">
          <span class="chip"><b>ZIP</b> ${escapeHtml(deploySize(item.sizeBytes))}</span>
          <span class="chip"><b>v${escapeHtml(item.version)}</b></span>
          ${item.fileCount ? `<span class="chip">${item.fileCount} files</span>` : ''}
          ${item.requires ? `<span class="chip"><b>Runs on</b> ${escapeHtml(item.requires)}</span>` : ''}
          ${item.sha256 ? `<button class="chip mono" type="button" data-copy-sha="${escapeHtml(item.sha256)}" title="Copy full SHA-256 for installer verification"><b>SHA-256</b> ${escapeHtml(item.sha256.slice(0, 16))}&hellip; &#x2398;</button>` : ''}
          <span class="chip"><b>Guide</b> ${escapeHtml(item.guide)}</span>
        </div>
        ${item.install ? `<div class="deploy-install"><b>Rollout</b> ${escapeHtml(item.install)}</div>` : ''}
      </div>`).join('');
    const history = $('#deployHistory');
    if (history) {
      history.innerHTML = (data.history || []).length
        ? data.history.map((h) => `
          <div class="inspector-field"><span>${escapeHtml(new Date(h.ts).toLocaleString())}</span><b>${escapeHtml(h.actor)} - ${escapeHtml(h.detail)}</b></div>`).join('')
        : '<div class="empty">No downloads recorded yet. Every download is written to the audit chain.</div>';
    }
  } catch {
    rows.innerHTML = '<div class="empty">Deploy packages need the operator or security admin role.</div>';
  }
}

// ---- Overview: the always-up control room; every element jumps to its tab ----
function overviewTile(jump, cls, value, label, meta, tone) {
  return `<button class="stat ${cls}" type="button" data-tab-jump="${escapeHtml(jump)}" data-tooltip="${escapeHtml(`${label}: ${meta}. Click to open.`)}">
      <div class="l"><span class="status-light tone-${escapeHtml(tone)}" aria-hidden="true"></span>${escapeHtml(label)}</div>
      <div class="n">${escapeHtml(String(value))}</div>
      <div class="m">${escapeHtml(meta)}</div>
      <div class="stat-rule"></div>
    </button>`;
}

function renderOverviewTiles({ stats, coverage, deliveries, audit }) {
  const failed = deliveries ? deliveries.filter((d) => d.status === 'failed').length : null;
  const chainOk = !!(audit && audit.integrity && audit.integrity.ok);
  const tiles = [
    stats && overviewTile('queue', stats.pending > 0 ? 'pending' : '', stats.pending, 'Pending approval', 'waiting on a decision', stats.pending > 0 ? 'warn' : 'secure'),
    stats && overviewTile('activity', stats.todayBlocked > 0 ? 'alert' : '', stats.todayBlocked, 'Blocked today', 'policy stops', stats.todayBlocked > 0 ? 'critical' : 'secure'),
    coverage && Number.isFinite(coverage.score) && overviewTile('coverage', '', `${coverage.score}/100`, 'Sensor coverage', 'fleet reporting score', coverage.score >= 70 ? 'secure' : 'warn'),
    failed !== null && overviewTile('integrations', failed ? 'alert' : '', failed, 'Failed deliveries', 'SIEM and webhook sends', failed ? 'warn' : 'secure'),
    audit && overviewTile('audit', '', chainOk ? 'Verified' : 'Check', 'Audit log', chainOk ? `${audit.integrity.count} linked entries` : 'integrity needs review', chainOk ? 'secure' : 'warn'),
  ].filter(Boolean);
  $('#overviewTiles').innerHTML = tiles.join('') || '<div class="empty">Waiting for the first data from your sensors.</div>';
}

function overviewRow(q, jump) {
  const sev = q.maxSeverityLabel || 'low';
  const tone = statusTone(q.status);
  return `<button class="overview-row" type="button" data-tab-jump="${escapeHtml(jump)}">
      <span class="ovr-when">${escapeHtml(fmtTime(q.createdAt))}</span>
      <span class="sev ${sevClass(sev)}">${escapeHtml(sev)}</span>
      <span class="ovr-what"><b>${escapeHtml(q.user || 'unknown')}</b> &rarr; ${escapeHtml(q.destination || '-')}</span>
      <span class="pill ${escapeHtml(tone)} status-chip tone-${escapeHtml(statusToneClass(tone))}">${escapeHtml(humanize(q.status))}</span>
    </button>`;
}

function renderOverviewLists(rows) {
  if (!Array.isArray(rows)) return;
  const pending = rows.filter((q) => q.status === 'pending').slice(0, 6);
  $('#overviewQueue').innerHTML = pending.map((q) => overviewRow(q, 'queue')).join('')
    || '<div class="empty">Nothing is waiting. New held prompts appear here the moment a sensor blocks one.</div>';
  $('#overviewFeed').innerHTML = rows.slice(0, 8).map((q) => overviewRow(q, 'activity')).join('')
    || '<div class="empty">No gated prompts yet. Activity streams in live once sensors report.</div>';
}

async function loadOverview() {
  const [stats, rows, audit, deliveries, coverage] = await Promise.all([
    dashboardJsonWithTimeout('/api/stats', 2200),
    dashboardJsonWithTimeout('/api/queries?limit=50', 2200),
    dashboardJsonWithTimeout('/api/audit?limit=10', 2200),
    dashboardJsonWithTimeout('/api/subscriptions/deliveries?limit=50', 2200),
    dashboardJsonWithTimeout('/api/coverage', 2600),
  ]);
  renderOverviewTiles({ stats, coverage, deliveries: deliveries && deliveries.deliveries, audit });
  renderOverviewLists(rows);
  const updated = $('#overviewUpdated');
  if (updated) updated.textContent = 'UPDATED ' + new Date().toLocaleTimeString();
}

function refreshOverviewIfVisible() {
  if (!$('#tab-overview').classList.contains('hidden')) loadOverview().catch(() => {});
}
setInterval(refreshOverviewIfVisible, 30000);

function knownTabNames() {
  return $$('.tab[data-tab]')
    .map((tab) => tab.dataset.tab)
    .filter((name, index, names) => name && names.indexOf(name) === index && $(`#tab-${CSS.escape(name)}`));
}

function normalizeTabName(name) {
  const candidate = String(name || '').trim().toLowerCase();
  return knownTabNames().includes(candidate) ? candidate : 'overview';
}

function tabNameFromLocation() {
  const url = new URL(window.location.href);
  const queryTab = url.searchParams.get('tab');
  const hashTab = (url.hash || '').replace(/^#\/?/, '');
  return normalizeTabName(queryTab || hashTab || 'overview');
}

function syncTabUrl(name, { replace = false } = {}) {
  const url = new URL(window.location.href);
  if (name === 'overview') url.searchParams.delete('tab');
  else url.searchParams.set('tab', name);
  url.hash = '';
  if (url.href === window.location.href) return;
  const method = replace ? 'replaceState' : 'pushState';
  window.history[method]({ tab: name }, '', url);
}

function activateTab(name, options = {}) {
  const targetName = normalizeTabName(name);
  const panel = $(`#tab-${CSS.escape(targetName)}`);
  if (!panel) return;
  document.body.dataset.activeTab = targetName;
  $$('.tab').forEach((x) => {
    const active = x.dataset.tab === targetName;
    x.classList.toggle('active', active);
    if (active) x.setAttribute('aria-current', 'page');
    else x.removeAttribute('aria-current');
  });
  $$('section[id^=tab-]').forEach((s) => s.classList.add('hidden'));
  panel.classList.remove('hidden');
  window.scrollTo(0, 0);
  if (!options.skipHistory) syncTabUrl(targetName, { replace: options.replaceHistory });
  if (targetName === 'overview') loadOverview();
  if (targetName === 'monitor') { renderMonitor(); loadPosture().catch(() => {}); loadSiemPackage().catch(() => {}); }
  if (targetName === 'audit') loadAudit();
  if (targetName === 'policy') loadPolicy();
  if (targetName === 'activity') loadActivity();
  if (targetName === 'insights') loadInsights();
  if (targetName === 'coverage') loadCoverage();
  if (targetName === 'catalog') loadCatalog();
  if (targetName === 'compliance') loadCompliance();
  if (targetName === 'integrations') loadIntegrations();
  if (targetName === 'identity') loadIdentitySetup();
  if (targetName === 'lineage') loadLineage();
  if (targetName === 'deploy') loadDeploy();
  if (targetName === 'updates') loadUpdates();
}

$$('.tab').forEach((t) => {
  t.onclick = () => activateTab(t.dataset.tab);
});

window.addEventListener('popstate', () => {
  activateTab(tabNameFromLocation(), { skipHistory: true });
});

$$('[data-theme-choice]').forEach((button) => {
  button.onclick = () => applyColorTheme(button.dataset.themeChoice);
});
applyColorTheme(colorTheme, { persist: false });

$('#refreshQueue').onclick = loadQueue;
$('#refreshCoverage').onclick = loadCoverage;
if ($('#refreshInsights')) $('#refreshInsights').onclick = loadInsights;
if ($('#insightsWindow')) $('#insightsWindow').addEventListener('change', loadInsights);
if ($('#exportActivityCsv')) $('#exportActivityCsv').addEventListener('click', exportActivityCsv);
if ($('#exportAuditCsv')) $('#exportAuditCsv').addEventListener('click', exportAuditCsv);
if ($('#refreshCatalog')) $('#refreshCatalog').onclick = loadCatalog;
if ($('#catalogImportBtn')) $('#catalogImportBtn').onclick = importCatalogCsv;
if ($('#catalogAddBtn')) $('#catalogAddBtn').onclick = addCatalogApp;
if ($('#refreshCompliance')) $('#refreshCompliance').onclick = loadCompliance;
if ($('#complianceExportBtn')) $('#complianceExportBtn').onclick = () => { window.open('/api/export/evidence', '_blank'); };
if ($('#refreshIntegrations')) $('#refreshIntegrations').onclick = loadIntegrations;
$('#refreshIdentity').onclick = loadIdentitySetup;
$('#identityProvider').addEventListener('change', loadIdentitySetup);
$('#identityTenant').addEventListener('change', loadIdentitySetup);
$('#refreshLineage').onclick = loadLineage;
$('#logout').onclick = async () => { await api('/api/logout', { method: 'POST' }); location.href = '/login.html'; };
$('#exportEvidence').onclick = exportEvidence;
$('#downloadSecurityPackage').onclick = downloadSecurityPackage;
$('#globalSearch').addEventListener('input', (e) => updateSearch(e.target.value));
$('#monitorRefresh').onclick = refreshMonitorSignals;
$('#sendPostureSnapshot').onclick = sendPostureSnapshot;
$('#downloadSiemPackage').onclick = downloadSiemPackage;
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
  es.addEventListener('query', () => { loadStats(); loadQueue(); loadPosture().catch(() => {}); refreshOverviewIfVisible(); if (!$('#tab-coverage').classList.contains('hidden')) loadCoverage(); if (!$('#tab-lineage').classList.contains('hidden')) loadLineage(); if (!$('#tab-insights').classList.contains('hidden')) loadInsights(); flash(); });
  es.addEventListener('decision', () => { loadStats(); loadQueue(); loadActivity(); loadPosture().catch(() => {}); refreshOverviewIfVisible(); if (!$('#tab-lineage').classList.contains('hidden')) loadLineage(); });
  es.addEventListener('stats', () => { loadStats(); refreshOverviewIfVisible(); if (!$('#tab-monitor').classList.contains('hidden')) loadPosture().catch(() => {}); });
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

// ---- Command palette (Ctrl/Cmd+K): jump to any tab or run a console action ----
const cmdk = { overlay: null, items: [], selected: 0, restoreFocus: null };

function cmdkEntries() {
  const seen = new Set();
  const tabs = $$('.rail .tab[data-tab]').filter((tab) => {
    if (seen.has(tab.dataset.tab)) return false;
    seen.add(tab.dataset.tab);
    return true;
  }).map((tab) => {
    const badge = tab.querySelector('.badge');
    const label = tab.textContent.replace(badge ? badge.textContent : '', '').trim();
    return {
      group: 'Navigate',
      label,
      icon: (tab.querySelector('.tab-icon') || {}).innerHTML || '',
      run: () => activateTab(tab.dataset.tab),
    };
  });
  const actions = [
    {
      group: 'Actions',
      label: 'Toggle color theme',
      icon: '',
      run: () => {
        const dark = document.body.dataset.theme === 'dark';
        const target = $(dark ? '#themeLight' : '#themeDark');
        if (target) target.click();
      },
    },
    { group: 'Actions', label: 'Focus search', icon: '', run: () => { const s = $('#globalSearch'); if (s) s.focus(); } },
    { group: 'Actions', label: 'Sign out', icon: '', run: () => { const b = $('#logout'); if (b) b.click(); } },
  ];
  return tabs.concat(actions);
}

function cmdkRender(filterText) {
  const list = cmdk.overlay.querySelector('.cmdk-list');
  const needle = String(filterText || '').trim().toLowerCase();
  cmdk.items = cmdkEntries().filter((item) => !needle || item.label.toLowerCase().includes(needle));
  cmdk.selected = Math.min(cmdk.selected, Math.max(0, cmdk.items.length - 1));
  if (!cmdk.items.length) {
    list.innerHTML = '<div class="cmdk-empty">No matching destination or action</div>';
    return;
  }
  let group = '';
  list.innerHTML = cmdk.items.map((item, index) => {
    const header = item.group !== group ? `<div class="cmdk-group">${escapeHtml(item.group)}</div>` : '';
    group = item.group;
    return `${header}<button type="button" class="cmdk-item${index === cmdk.selected ? ' is-selected' : ''}" data-cmdk-index="${index}">
      <span class="tab-icon" aria-hidden="true">${item.icon}</span>${escapeHtml(item.label)}
      ${index === cmdk.selected ? '<kbd>enter</kbd>' : ''}
    </button>`;
  }).join('');
}

function cmdkClose() {
  if (!cmdk.overlay) return;
  cmdk.overlay.remove();
  cmdk.overlay = null;
  if (cmdk.restoreFocus && document.contains(cmdk.restoreFocus)) cmdk.restoreFocus.focus();
}

function cmdkOpen() {
  if (cmdk.overlay) return cmdkClose();
  cmdk.restoreFocus = document.activeElement;
  cmdk.selected = 0;
  const overlay = document.createElement('div');
  overlay.className = 'cmdk-overlay';
  overlay.innerHTML = `<div class="cmdk" role="dialog" aria-modal="true" aria-label="Command palette">
    <input type="text" placeholder="Jump to a tab or run an action" aria-label="Command palette filter" />
    <div class="cmdk-list" role="listbox"></div>
  </div>`;
  document.body.appendChild(overlay);
  cmdk.overlay = overlay;
  const input = overlay.querySelector('input');
  cmdkRender('');
  input.focus();
  input.addEventListener('input', () => { cmdk.selected = 0; cmdkRender(input.value); });
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) cmdkClose(); });
  overlay.addEventListener('click', (e) => {
    const item = e.target.closest('[data-cmdk-index]');
    if (!item) return;
    const entry = cmdk.items[Number(item.dataset.cmdkIndex)];
    cmdkClose();
    if (entry) entry.run();
  });
  overlay.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); cmdkClose(); return; }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const step = e.key === 'ArrowDown' ? 1 : -1;
      cmdk.selected = (cmdk.selected + step + cmdk.items.length) % Math.max(1, cmdk.items.length);
      cmdkRender(input.value);
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      const entry = cmdk.items[cmdk.selected];
      cmdkClose();
      if (entry) entry.run();
    }
  });
}

document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && String(e.key).toLowerCase() === 'k') {
    e.preventDefault();
    cmdkOpen();
  }
}, true);
const cmdkHint = document.getElementById('cmdkHint');
if (cmdkHint) {
  cmdkHint.style.cursor = 'pointer';
  cmdkHint.addEventListener('click', (e) => { e.preventDefault(); cmdkOpen(); });
}
