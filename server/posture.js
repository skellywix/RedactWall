'use strict';

const coverage = require('./coverage');
const controlReadiness = require('./control-readiness');
const detectionQuality = require('./detection-quality');
const {
  CONNECTOR_PROFILES,
} = require('../sensors/mcp-guard/connector-registry');

const WINDOW_DAYS = 7;

const BLOCKED_STATUSES = new Set([
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'action_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'response_flagged',
  'response_blocked',
  'seat_limit_blocked',
]);
const REDACTED_STATUSES = new Set(['redacted', 'response_redacted']);
const ALLOWED_STATUSES = new Set(['allowed', 'approved']);
const HELD_STATUSES = new Set(['pending', 'pending_justification']);
const COACHING_STATUSES = new Set(['warned', 'justified', 'pending_justification', 'blocked_by_user', 'paste_flagged']);
// These statuses record an explicit policy decision that permits the sanitized
// flow to continue. This is not delivery confirmation: it intentionally
// excludes warnings that have not been accepted, local paste coaching,
// observations, shadow sightings, and unknown outcomes.
const CONTINUED_STATUSES = new Set([
  ...ALLOWED_STATUSES,
  'redacted',
  'warned_sent',
  'justified',
]);
const EVENTLESS_STATUSES = new Set(['sensor_heartbeat']);
// SSNs (contiguous, dashed, or space-grouped), PANs (contiguous or space/dash
// grouped), and common secret-key prefixes. One shared predicate so every
// metadata redaction path — baseline labels and segment labels — stays in sync.
const METADATA_SSN_RE = /\b\d{3}[-_ .:]?\d{2}[-_ .:]?\d{4}\b/;
const METADATA_PAN_RE = /\b(?:\d[ -]?){12,19}\b/;
const METADATA_SECRET_RE = /\b(?:sk|pk|rk|ghp|gho|github_pat|xox[baprs])[-_a-z0-9]{8,}\b/i;
function containsSensitiveMetadata(text) {
  return METADATA_SSN_RE.test(text) || METADATA_PAN_RE.test(text) || METADATA_SECRET_RE.test(text);
}

const SOURCE_LABELS = {
  browser_extension: 'Browser',
  endpoint_agent: 'Endpoint',
  mcp_guard: 'MCP',
  proxy: 'Proxy',
  api: 'API',
};
const NON_AI_INVENTORY_DESTINATIONS = new Set(['endpoint-install', 'unknown']);
const OWNER_VIEW_TEMPLATES = Object.freeze([
  {
    id: 'owner:security',
    label: 'Security Ops',
    ownerGroup: 'Security',
    reviewerRole: 'security_admin',
    segmentCandidates: ['workflow:security', 'workflow:member-services', 'source:browser'],
    assignmentHint: 'Review critical DLP attempts, default-deny events, and proof gaps.',
  },
  {
    id: 'owner:lending',
    label: 'Lending',
    ownerGroup: 'Lending',
    reviewerRole: 'approver',
    segmentCandidates: ['group:redactwall-lending', 'org:cu-lending', 'workflow:lending'],
    assignmentHint: 'Own loan-file and member-data prompts from lending teams.',
  },
  {
    id: 'owner:call-center',
    label: 'Call Center',
    ownerGroup: 'Member Services',
    reviewerRole: 'approver',
    segmentCandidates: ['group:redactwall-call-center', 'group:call-center', 'workflow:member-services'],
    assignmentHint: 'Watch member-service queues and coached paste activity.',
  },
  {
    id: 'owner:it',
    label: 'IT',
    ownerGroup: 'IT',
    reviewerRole: 'operator',
    segmentCandidates: ['source:endpoint', 'source:mcp', 'source:proxy'],
    assignmentHint: 'Own endpoint, MCP, and gateway sensor rollout gaps.',
  },
  {
    id: 'owner:executive',
    label: 'Executive Office',
    ownerGroup: 'Executive',
    reviewerRole: 'auditor',
    segmentCandidates: ['all'],
    assignmentHint: 'Track aggregate control rate, shadow AI, and examiner readiness.',
  },
]);

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function eventWeight(q) {
  const value = Number(q && q.discoveryEvents);
  if (!Number.isFinite(value)) return 1;
  return Math.max(1, Math.min(100000, Math.trunc(value)));
}

function pct(value, total) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

function bound(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n(value))));
}

function safeText(value, fallback = 'unknown', limit = 140) {
  const text = String(value || '').trim();
  return (text || fallback).slice(0, limit);
}

function safeMetadataLabel(value, fallback = 'unknown', limit = 140) {
  const text = safeText(value, fallback, limit);
  return containsSensitiveMetadata(text) ? 'redacted_label' : text;
}

function dayKey(date) {
  const parsed = date instanceof Date ? date : new Date(date);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString().slice(0, 10) : null;
}

function addDays(date, delta) {
  const d = new Date(date);
  d.setUTCDate(d.getUTCDate() + delta);
  return d;
}

function statusDecision(status) {
  const value = String(status || 'unknown');
  if (BLOCKED_STATUSES.has(value)) return 'blocked';
  if (REDACTED_STATUSES.has(value)) return 'redacted';
  if (ALLOWED_STATUSES.has(value)) return 'allowed';
  if (COACHING_STATUSES.has(value)) return 'coached';
  return value;
}

function isBlocked(q) {
  return BLOCKED_STATUSES.has(String(q && q.status || ''));
}

function isRedacted(q) {
  return REDACTED_STATUSES.has(String(q && q.status || ''));
}

function isAllowed(q) {
  return ALLOWED_STATUSES.has(String(q && q.status || ''));
}

function isContinued(q) {
  return CONTINUED_STATUSES.has(String(q && q.status || ''));
}

function isHeld(q) {
  return HELD_STATUSES.has(String(q && q.status || ''));
}

function categoryLabels(q) {
  const labels = [];
  for (const finding of q.findings || []) {
    if (finding && finding.type) labels.push(String(finding.type));
  }
  for (const category of q.categories || []) {
    if (typeof category === 'string') labels.push(category);
    else if (category && category.category) labels.push(String(category.category));
  }
  for (const key of Object.keys(q.entityCounts || {})) labels.push(key);
  return [...new Set(labels.map((item) => safeText(item, '', 80)).filter(Boolean))];
}

function hasFindings(q) {
  return categoryLabels(q).length > 0;
}

function isSensitive(q) {
  if (!q || EVENTLESS_STATUSES.has(q.status)) return false;
  return hasFindings(q)
    || n(q.riskScore) > 0
    || n(q.maxSeverity) > 0
    || isBlocked(q)
    || isRedacted(q)
    || COACHING_STATUSES.has(String(q.status || ''));
}

function isShadowAi(q) {
  return q && (q.status === 'shadow_ai' || (q.status === 'destination_blocked' && q.channel === 'shadow_ai'));
}

function isEscalated(q, nowMs) {
  if (!q) return false;
  if (q.escalatedAt) return true;
  const due = Date.parse(q.slaDueAt || '');
  return Number.isFinite(due) && due < nowMs;
}

function sourceLabel(source) {
  return SOURCE_LABELS[source] || safeText(source || 'api', 'API', 40);
}

function severityForQuery(q) {
  if (n(q.riskScore) >= 70 || n(q.maxSeverity) >= 4 || q.status === 'injection_blocked') return 'critical';
  if (isBlocked(q) || isRedacted(q) || isShadowAi(q) || n(q.riskScore) >= 30 || n(q.maxSeverity) >= 2) return 'warning';
  return 'info';
}

function signalStatusForQuery(q) {
  if (q.status === 'allowed' || q.status === 'approved') return 'online';
  if (q.status === 'denied' || q.status === 'blocked_by_user') return 'idle';
  if (severityForQuery(q) === 'critical') return 'error';
  if (severityForQuery(q) === 'warning') return 'warning';
  return 'online';
}

function titleForQuery(q) {
  if (q && q.source === 'mcp_guard' && q.status === 'action_blocked') return 'MCP tool blocked';
  return ({
    pending: 'Prompt held for approval',
    pending_justification: 'Business justification required',
    redacted: 'Sensitive values tokenized',
    response_redacted: 'Sensitive response tokenized',
    response_blocked: 'Sensitive AI response blocked',
    response_flagged: 'Sensitive AI response flagged',
    destination_blocked: isShadowAi(q) ? 'Shadow AI destination blocked' : 'AI destination blocked',
    file_upload_blocked: 'File upload blocked',
    action_blocked: 'Browser action blocked',
    injection_blocked: 'Prompt injection blocked',
    shadow_ai: 'Shadow AI sighting logged',
    proxy_observed: 'Network proxy observed AI traffic',
    paste_flagged: 'Sensitive paste coached',
    allowed: 'AI prompt allowed',
    approved: 'Held prompt approved',
    denied: 'Held prompt denied',
  })[q.status] || `${sourceLabel(q.source)} activity recorded`;
}

function descriptionForQuery(q) {
  const labels = categoryLabels(q).slice(0, 3);
  const parts = [
    sourceLabel(q.source),
    safeText(q.channel || 'event', 'event', 40),
    coverage.normalizeDestination(q.destination || 'unknown'),
  ];
  if (labels.length) parts.push(labels.join(', '));
  parts.push('raw content excluded');
  return parts.join(' / ');
}

function confidenceForQuery(q) {
  if (hasFindings(q)) return 96;
  if (isBlocked(q) || isRedacted(q)) return 91;
  if (isShadowAi(q)) return 84;
  return 75;
}

function recentEvents(rows, nowMs) {
  return (rows || [])
    .filter((q) => q && !EVENTLESS_STATUSES.has(q.status))
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
    .slice(0, 20)
    .map((q) => ({
      id: q.id,
      timestamp: q.createdAt || new Date(nowMs).toISOString(),
      severity: severityForQuery(q),
      source: q.source || 'api',
      title: titleForQuery(q),
      description: descriptionForQuery(q),
      confidence: confidenceForQuery(q),
      relatedMetric: statusDecision(q.status),
      status: signalStatusForQuery(q),
    }));
}

function emptyTrend(keys) {
  const map = new Map();
  for (const key of keys) {
    map.set(key, { date: key, events: 0, blocked: 0, redacted: 0, allowed: 0, coached: 0, shadow: 0, maxRiskScore: 0 });
  }
  return map;
}

function riskTrend(rows, now = new Date(), days = WINDOW_DAYS) {
  const keys = [];
  const end = new Date(now);
  for (let i = days - 1; i >= 0; i -= 1) keys.push(dayKey(addDays(end, -i)));
  const map = emptyTrend(keys.filter(Boolean));
  for (const q of rows || []) {
    const key = dayKey(q.createdAt);
    const bucket = map.get(key);
    if (!bucket || EVENTLESS_STATUSES.has(q.status)) continue;
    const events = eventWeight(q);
    bucket.events += events;
    if (isBlocked(q)) bucket.blocked += events;
    else if (isRedacted(q)) bucket.redacted += events;
    else if (isAllowed(q)) bucket.allowed += events;
    else if (COACHING_STATUSES.has(q.status)) bucket.coached += events;
    if (isShadowAi(q)) bucket.shadow += events;
    bucket.maxRiskScore = Math.max(bucket.maxRiskScore, n(q.riskScore));
  }
  return [...map.values()];
}

function rowTimestamp(row = {}) {
  const parsed = Date.parse(row.createdAt || row.timestamp || '');
  return Number.isFinite(parsed) ? parsed : 0;
}

function controlledByPolicy(row = {}) {
  return isBlocked(row) || isRedacted(row) || COACHING_STATUSES.has(row.status) || row.status === 'approved' || row.status === 'denied';
}

function baselineState(score) {
  if (score >= 80) return 'critical';
  if (score >= 50) return 'warning';
  return 'normal';
}

function baselineStatus(state) {
  if (state === 'critical') return 'error';
  if (state === 'warning') return 'warning';
  return 'normal';
}

function baselineDimensionMeta(kind) {
  return ({
    user: { title: 'User Activity', action: 'Review user lineage', targetTab: 'lineage', source: 'identity' },
    destination: { title: 'Destination Activity', action: 'Review destination', targetTab: 'coverage', source: 'coverage' },
    source: { title: 'Sensor Surface', action: 'Inspect surface', targetTab: 'coverage', source: 'coverage' },
    detector: { title: 'Detector Pattern', action: 'Review detections', targetTab: 'activity', source: 'detector' },
  })[kind] || { title: 'Behavior Baseline', action: 'Review activity', targetTab: 'monitor', source: 'posture' };
}

function baselineDimensionId(kind, label) {
  return `baseline:${kind}:${safeMetadataLabel(label, 'unknown', 90).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 70) || 'unknown'}`;
}

function addBaselineObservation(map, kind, label, row, recent, baselineDays) {
  const cleanLabel = safeMetadataLabel(label, 'unknown', 120);
  if (!cleanLabel || cleanLabel === 'unknown') return;
  const key = `${kind}:${cleanLabel.toLowerCase()}`;
  const item = map.get(key) || {
    id: baselineDimensionId(kind, cleanLabel),
    kind,
    label: cleanLabel,
    recentEvents: 0,
    previousEvents: 0,
    recentSensitive: 0,
    previousSensitive: 0,
    recentControlled: 0,
    maxRiskScore: 0,
    maxSeverity: 0,
    baselineDays,
    latestAt: '',
  };
  const events = eventWeight(row);
  if (recent) {
    item.recentEvents += events;
    if (isSensitive(row)) item.recentSensitive += events;
    if (controlledByPolicy(row)) item.recentControlled += events;
    item.maxRiskScore = Math.max(item.maxRiskScore, n(row.riskScore));
    item.maxSeverity = Math.max(item.maxSeverity, n(row.maxSeverity));
    if (String(row.createdAt || '') > String(item.latestAt || '')) item.latestAt = safeText(row.createdAt, '', 80);
  } else {
    item.previousEvents += events;
    if (isSensitive(row)) item.previousSensitive += events;
  }
  map.set(key, item);
}

function baselineRows(rows, nowMs, options = {}) {
  const recentMs = Math.max(1, n(options.recentHours || 24)) * 60 * 60 * 1000;
  const baselineDays = Math.max(1, n(options.baselineDays || WINDOW_DAYS - 1));
  const baselineMs = baselineDays * 24 * 60 * 60 * 1000;
  const recentStart = nowMs - recentMs;
  const baselineStart = recentStart - baselineMs;
  const map = new Map();
  for (const row of rows || []) {
    if (!row || EVENTLESS_STATUSES.has(row.status)) continue;
    const ts = rowTimestamp(row);
    if (!ts || ts < baselineStart || ts > nowMs) continue;
    const recent = ts >= recentStart;
    const destination = coverage.normalizeDestination(row.destination || 'unknown');
    const labels = categoryLabels(row);
    const observations = [
      ['user', row.user || 'unknown'],
      ['destination', destination],
      ['source', row.source || 'unknown'],
      ...labels.map((label) => ['detector', label]),
    ];
    for (const [kind, label] of observations) addBaselineObservation(map, kind, label, row, recent, baselineDays);
  }
  return [...map.values()].filter((item) => item.recentEvents > 0).map((item) => {
    const baselineDaily = Number((item.previousEvents / item.baselineDays).toFixed(2));
    const surgeRatio = item.previousEvents ? Number((item.recentEvents / Math.max(1, baselineDaily)).toFixed(1)) : item.recentEvents ? 99 : 0;
    const uncontrolled = Math.max(0, item.recentSensitive - item.recentControlled);
    const newPattern = item.previousEvents === 0 && item.recentEvents > 0;
    const score = bound(
      (newPattern ? 20 : 0)
      + (surgeRatio >= 3 ? 25 : surgeRatio >= 2 ? 15 : 0)
      + Math.min(25, item.recentEvents * 6)
      + Math.min(30, item.maxRiskScore * 0.3)
      + (item.maxSeverity >= 4 ? 12 : item.maxSeverity >= 3 ? 8 : 0)
      + Math.min(25, uncontrolled * 12)
    );
    const state = baselineState(score);
    const meta = baselineDimensionMeta(item.kind);
    const reason = newPattern ? 'new metadata pattern'
      : surgeRatio >= 3 ? `${surgeRatio}x baseline activity`
      : uncontrolled ? `${uncontrolled} sensitive event${uncontrolled === 1 ? '' : 's'} not fully controlled`
      : item.maxRiskScore >= 70 ? `risk score ${item.maxRiskScore}`
      : 'activity above normal watch threshold';
    return {
      id: item.id,
      kind: item.kind,
      label: item.label,
      title: meta.title,
      state,
      status: baselineStatus(state),
      score,
      recentEvents: item.recentEvents,
      previousEvents: item.previousEvents,
      baselineDaily,
      surgeRatio,
      recentSensitive: item.recentSensitive,
      recentControlled: item.recentControlled,
      maxRiskScore: item.maxRiskScore,
      maxSeverity: item.maxSeverity,
      latestAt: item.latestAt || null,
      detail: `${reason}; ${item.recentEvents} recent event${item.recentEvents === 1 ? '' : 's'} vs ${baselineDaily}/day baseline`,
      action: meta.action,
      targetTab: meta.targetTab,
      source: meta.source,
    };
  }).filter((item) => item.state !== 'normal' || item.score >= 45 || item.recentEvents >= 3)
    .sort((a, b) => b.score - a.score || b.recentEvents - a.recentEvents || a.label.localeCompare(b.label))
    .slice(0, 12);
}

function behaviorBaselines({ rows = [], nowMs = Date.now() } = {}) {
  const activeRows = (Array.isArray(rows) ? rows : []).filter((row) => row && !EVENTLESS_STATUSES.has(row.status));
  const dimensions = baselineRows(rows, nowMs);
  const critical = dimensions.filter((item) => item.state === 'critical').length;
  const warning = dimensions.filter((item) => item.state === 'warning').length;
  const score = activeRows.length ? bound(100 - (critical * 24) - (warning * 10)) : 0;
  const state = !activeRows.length ? 'gap' : critical ? 'critical' : warning ? 'warning' : 'ready';
  const playbook = dimensions.slice(0, 5).map((item, index) => ({
    id: `behavior:${item.id}`,
    priority: index + 1,
    severity: item.state === 'critical' ? 'critical' : 'warning',
    label: `Review ${item.title.toLowerCase()}`,
    detail: `${item.label}: ${item.detail}`,
    action: item.action,
    targetTab: item.targetTab,
    score: item.score,
  }));
  return {
    generatedAt: new Date(nowMs).toISOString(),
    privacy: 'metadata only; prompt bodies excluded',
    summary: {
      score,
      state,
      status: state === 'critical' ? 'error' : state === 'warning' ? 'warning' : state === 'ready' ? 'normal' : 'idle',
      anomalies: dimensions.length,
      activeEvents: activeRows.length,
      critical,
      warning,
      baselineDays: WINDOW_DAYS - 1,
      recentWindowHours: 24,
    },
    dimensions,
    playbook,
  };
}

function controlKey(q) {
  if (q.status === 'response_blocked' || q.status === 'response_redacted' || q.status === 'response_flagged' || q.channel === 'ai_response') return 'AI response';
  if (q.status === 'file_upload_blocked' || q.channel === 'file_upload') return 'File upload';
  if (q.source === 'mcp_guard') return 'MCP tool data';
  if (q.status === 'action_blocked') return 'Browser action';
  if (q.status === 'shadow_ai' || q.channel === 'shadow_ai') return 'Shadow AI';
  if (q.status === 'proxy_observed' || q.source === 'proxy') return 'Network proxy';
  if (COACHING_STATUSES.has(q.status)) return 'User coaching';
  return 'Prompt submit';
}

function controlOutcomes(rows) {
  const map = new Map();
  for (const q of rows || []) {
    if (!q || EVENTLESS_STATUSES.has(q.status)) continue;
    const key = controlKey(q);
    const events = eventWeight(q);
    const row = map.get(key) || { label: key, events: 0, blocked: 0, redacted: 0, allowed: 0, coached: 0, shadow: 0 };
    row.events += events;
    if (isBlocked(q)) row.blocked += events;
    else if (isRedacted(q)) row.redacted += events;
    else if (isAllowed(q)) row.allowed += events;
    else if (COACHING_STATUSES.has(q.status)) row.coached += events;
    if (isShadowAi(q)) row.shadow += events;
    map.set(key, row);
  }
  return [...map.values()].sort((a, b) => b.events - a.events || a.label.localeCompare(b.label)).slice(0, 8);
}

function qualityState(score) {
  if (score >= 85) return 'ready';
  if (score >= 60) return 'attention';
  return 'blocked';
}

function qualityStatus(state) {
  return state === 'ready' ? 'normal' : state === 'attention' ? 'warning' : 'critical';
}

function decisionHotspotId(kind, label) {
  return `${kind}:${safeText(label, 'unknown', 80).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'unknown'}`;
}

function addDecisionHotspot(map, kind, label, q, nowMs) {
  const cleanLabel = safeText(label, 'unknown', 80);
  const id = decisionHotspotId(kind, cleanLabel);
  const events = eventWeight(q);
  const row = map.get(id) || {
    id,
    kind,
    label: cleanLabel,
    events: 0,
    sensitive: 0,
    blocked: 0,
    redacted: 0,
    allowed: 0,
    coached: 0,
    pending: 0,
    escalated: 0,
    maxRiskScore: 0,
    lastSeen: null,
  };
  row.events += events;
  if (isSensitive(q)) row.sensitive += events;
  if (isBlocked(q)) row.blocked += events;
  else if (isRedacted(q)) row.redacted += events;
  else if (isAllowed(q)) row.allowed += events;
  else if (COACHING_STATUSES.has(q.status)) row.coached += events;
  if (isHeld(q)) row.pending += events;
  if (isEscalated(q, nowMs)) row.escalated += events;
  row.maxRiskScore = Math.max(row.maxRiskScore, n(q.riskScore));
  if (!row.lastSeen || String(q.createdAt || '') > row.lastSeen) row.lastSeen = q.createdAt || null;
  map.set(id, row);
}

function decisionQuality(rows, nowMs) {
  const active = (rows || []).filter((q) => q && !EVENTLESS_STATUSES.has(q.status));
  const sensitive = active.filter(isSensitive);
  const pending = active.filter(isHeld);
  const approvals = active.filter((q) => q.status === 'approved');
  const denials = active.filter((q) => q.status === 'denied');
  const justified = active.filter((q) => q.status === 'justified');
  const blockedByUser = active.filter((q) => q.status === 'blocked_by_user');
  const coaching = active.filter((q) => COACHING_STATUSES.has(q.status));
  const coachingComplete = justified.length + blockedByUser.length;
  const escalated = pending.filter((q) => isEscalated(q, nowMs));
  const slaTracked = active.filter((q) => q.slaDueAt);
  const slaOverdue = slaTracked.filter((q) => isEscalated(q, nowMs));
  const controlled = sensitive.filter((q) => isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(q.status) || q.status === 'approved' || q.status === 'denied');
  const riskyAllows = sensitive.filter((q) => isAllowed(q) || q.status === 'justified');
  const allowedSensitive = active.filter((q) => q.status === 'allowed' && isSensitive(q));
  const overrideWatch = approvals.length + justified.length + allowedSensitive.length;
  const slaScore = slaTracked.length ? pct(slaTracked.length - slaOverdue.length, slaTracked.length) : (pending.length ? 75 : 100);
  const coachingScore = coaching.length ? pct(coachingComplete, coaching.length) : 100;
  const overrideScore = sensitive.length ? bound(100 - Math.round((riskyAllows.length / sensitive.length) * 100)) : 100;
  const controlScore = sensitive.length ? pct(controlled.length, sensitive.length) : 100;
  const hotspotMap = new Map();
  for (const q of active) {
    addDecisionHotspot(hotspotMap, 'destination', coverage.normalizeDestination(q.destination || 'unknown'), q, nowMs);
    const labels = categoryLabels(q);
    if (labels.length) {
      for (const label of labels.slice(0, 3)) addDecisionHotspot(hotspotMap, 'category', label, q, nowMs);
    } else {
      addDecisionHotspot(hotspotMap, 'control', controlKey(q), q, nowMs);
    }
  }
  const hotspots = [...hotspotMap.values()]
    .map((row) => {
      const friction = row.pending + row.escalated + row.allowed + row.coached;
      const state = row.escalated || row.allowed ? 'attention' : row.blocked || row.redacted ? 'ready' : 'review';
      return {
        ...row,
        state,
        detail: `${row.sensitive} sensitive / ${friction} review or coaching signals`,
      };
    })
    .sort((a, b) => (b.escalated + b.allowed + b.pending + b.coached) - (a.escalated + a.allowed + a.pending + a.coached)
      || b.maxRiskScore - a.maxRiskScore
      || b.events - a.events
      || a.label.localeCompare(b.label))
    .slice(0, 8);
  const cards = [
    {
      id: 'approval_sla',
      label: 'Approval SLA',
      score: slaScore,
      state: qualityState(slaScore),
      status: qualityStatus(qualityState(slaScore)),
      value: `${slaTracked.length - slaOverdue.length}/${slaTracked.length || 0}`,
      detail: slaTracked.length ? `${slaOverdue.length} overdue of ${slaTracked.length} SLA-tracked reviews` : `${pending.length} pending reviews without SLA timers`,
      action: 'Open queue',
      targetTab: 'queue',
    },
    {
      id: 'coaching_completion',
      label: 'Coaching Completion',
      score: coachingScore,
      state: qualityState(coachingScore),
      status: qualityStatus(qualityState(coachingScore)),
      value: `${coachingComplete}/${coaching.length || 0}`,
      detail: coaching.length ? `${justified.length} justified / ${blockedByUser.length} stopped by user` : 'No coaching prompts in this window',
      action: 'Review activity',
      targetTab: 'activity',
    },
    {
      id: 'override_watch',
      label: 'Override Watch',
      score: overrideScore,
      state: qualityState(overrideScore),
      status: qualityStatus(qualityState(overrideScore)),
      value: overrideWatch,
      detail: `${riskyAllows.length} sensitive releases or allowed outcomes need trend review`,
      action: 'Inspect lineage',
      targetTab: 'lineage',
    },
    {
      id: 'sensitive_control_quality',
      label: 'Sensitive Control Quality',
      score: controlScore,
      state: qualityState(controlScore),
      status: qualityStatus(qualityState(controlScore)),
      value: `${controlled.length}/${sensitive.length || 0}`,
      detail: `${controlled.length} of ${sensitive.length} sensitive events had a control outcome`,
      action: 'Review controls',
      targetTab: 'monitor',
    },
  ];
  return {
    generatedAt: new Date(nowMs).toISOString(),
    summary: {
      events: active.length,
      sensitiveEvents: sensitive.length,
      pendingReviews: pending.length,
      escalatedReviews: escalated.length,
      approved: approvals.length,
      denied: denials.length,
      coachingEvents: coaching.length,
      coachingCompleted: coachingComplete,
      overrideWatch,
      riskyAllows: riskyAllows.length,
      controlRate: controlScore,
      slaHealthyRate: slaScore,
      privacy: 'metadata only; prompt bodies excluded',
    },
    cards,
    hotspots,
  };
}

const THREAT_GUARDRAIL_DEFS = Object.freeze([
  {
    id: 'prompt_injection',
    label: 'Prompt injection',
    framework: 'OWASP LLM01',
    atlas: 'MITRE ATLAS: prompt injection',
    control: 'Browser injection sensor',
    targetTab: 'activity',
    detail: 'Hidden instructions, jailbreak attempts, and adversarial prompt content blocked before submission.',
  },
  {
    id: 'sensitive_disclosure',
    label: 'Sensitive disclosure',
    framework: 'OWASP LLM02',
    atlas: 'MITRE ATLAS: data disclosure',
    control: 'DLP detectors',
    targetTab: 'queue',
    detail: 'PII, secrets, confidential business context, or regulated data detected before AI egress.',
  },
  {
    id: 'unsafe_output',
    label: 'Unsafe output',
    framework: 'OWASP LLM05',
    atlas: 'MITRE ATLAS: unsafe model response',
    control: 'AI response scanning',
    targetTab: 'activity',
    detail: 'AI response scanning flagged, blocked, or redacted risky model output.',
  },
  {
    id: 'excessive_agency',
    label: 'Excessive agency',
    framework: 'OWASP LLM06',
    atlas: 'MITRE ATLAS: agent action abuse',
    control: 'MCP tool policy',
    targetTab: 'policy',
    detail: 'Agent or tool actions exceeded the allowed registry or approval policy.',
  },
  {
    id: 'shadow_ai',
    label: 'Shadow AI',
    framework: 'AI governance',
    atlas: 'MITRE ATLAS: untrusted AI service',
    control: 'Default-deny destinations',
    targetTab: 'coverage',
    detail: 'Unapproved AI destinations or unsanctioned local tools need review.',
  },
  {
    id: 'unscanned_content',
    label: 'Unscanned content',
    framework: 'OWASP LLM02',
    atlas: 'MITRE ATLAS: uninspected data path',
    control: 'Upload/OCR gate',
    targetTab: 'coverage',
    detail: 'Files that could not be scanned were held until OCR or manual review is available.',
  },
  {
    id: 'personal_account',
    label: 'Personal AI account',
    framework: 'AI governance',
    atlas: 'GLBA Safeguards: identity controls',
    control: 'Account identity detection',
    targetTab: 'insights',
    detail: 'AI activity on personal (non-corporate) accounts — the leading data-leakage vector.',
  },
]);

function threatText(q = {}) {
  return [
    q.status,
    q.channel,
    q.source,
    q.note,
    ...(Array.isArray(q.reasons) ? q.reasons : []),
    ...categoryLabels(q),
  ].filter(Boolean).join(' ').toLowerCase();
}

function isSensitiveDisclosureThreat(q = {}) {
  const status = String(q.status || '');
  if (['injection_blocked', 'action_blocked', 'destination_blocked', 'shadow_ai', 'file_blocked_unscanned', 'ocr_required'].includes(status)) return false;
  if (q.channel === 'mcp_tool') return false;
  return hasFindings(q) || isRedacted(q) || status === 'pending' || status === 'pending_justification' || status === 'file_upload_blocked' || status === 'response_blocked' || status === 'response_flagged';
}

function threatGuardrailMatches(def, q = {}) {
  const status = String(q.status || '');
  const text = threatText(q);
  if (def.id === 'prompt_injection') return status === 'injection_blocked' || /\b(prompt injection|jailbreak)\b/.test(text);
  if (def.id === 'sensitive_disclosure') return isSensitiveDisclosureThreat(q);
  if (def.id === 'unsafe_output') return q.channel === 'ai_response' || status === 'response_redacted' || status === 'response_blocked' || status === 'response_flagged' || /\b(unsafe output|harmful response)\b/.test(text);
  if (def.id === 'excessive_agency') return q.source === 'mcp_guard' && (q.channel === 'mcp_tool' || status === 'action_blocked' || /\btool blocked\b/.test(text));
  if (def.id === 'shadow_ai') return isShadowAi(q);
  if (def.id === 'unscanned_content') return status === 'file_blocked_unscanned' || status === 'ocr_required' || /\b(ocr required|unscanned)\b/.test(text);
  if (def.id === 'personal_account') return q.accountType === 'personal';
  return false;
}

function threatState(row = {}) {
  if (n(row.critical) || n(row.blocked)) return 'critical';
  if (n(row.redacted) || n(row.events)) return 'attention';
  return 'ready';
}

function threatStatus(state) {
  if (state === 'critical') return 'error';
  if (state === 'attention') return 'warning';
  return 'online';
}

function threatControlState({ ready, attention }) {
  return ready ? 'ready' : attention ? 'attention' : 'missing';
}

function threatControls(policy = {}, rows = []) {
  const requiredSensors = Array.isArray(policy.requiredSensors) ? policy.requiredSensors : [];
  const mcpRules = [
    ...mcpPolicyList(policy, 'mcpAllowedTools'),
    ...mcpPolicyList(policy, 'mcpBlockedTools'),
    ...mcpPolicyList(policy, 'mcpApprovalRequiredTools'),
  ];
  const injectionObserved = rows.some((q) => q && q.status === 'injection_blocked');
  const responseMode = String(policy.responseScanMode || 'allow');
  return [
    {
      id: 'prompt_injection_sensor',
      label: 'Prompt injection block',
      state: threatControlState({ ready: requiredSensors.includes('browser_extension') || injectionObserved, attention: true }),
      detail: injectionObserved ? 'Injection attempts have been blocked in this window.' : 'Browser sensor is expected to report injection_blocked outcomes.',
      targetTab: 'coverage',
    },
    {
      id: 'response_scanning',
      label: 'Response scanning',
      state: threatControlState({ ready: responseMode !== 'allow', attention: true }),
      detail: `AI response mode: ${responseMode}`,
      targetTab: 'policy',
    },
    {
      id: 'mcp_tool_policy',
      label: 'Agent tool policy',
      state: threatControlState({ ready: mcpRules.length > 0, attention: true }),
      detail: mcpRules.length ? `${mcpRules.length} MCP allow/block/approval rules configured.` : 'Add MCP allow, block, or approval-required rules.',
      targetTab: 'policy',
    },
    {
      id: 'shadow_ai_default_deny',
      label: 'Shadow AI default deny',
      state: threatControlState({ ready: policy.blockUnapprovedAiDestinations === true, attention: true }),
      detail: policy.blockUnapprovedAiDestinations === true ? 'Unapproved AI destinations are blocked by default.' : 'Enable default deny for unapproved AI destinations.',
      targetTab: 'policy',
    },
  ];
}

function threatGuardrails({ rows = [], policy = {} } = {}) {
  const ruleRows = THREAT_GUARDRAIL_DEFS.map((def) => ({ ...def, events: 0, blocked: 0, redacted: 0, critical: 0, lastSeen: null }));
  const byId = new Map(ruleRows.map((row) => [row.id, row]));
  const eventMap = new Map();

  for (const q of rows || []) {
    if (!q || EVENTLESS_STATUSES.has(q.status)) continue;
    const matches = THREAT_GUARDRAIL_DEFS.filter((def) => threatGuardrailMatches(def, q));
    if (!matches.length) continue;
    const events = eventWeight(q);
    const key = safeText(q.id || `${q.createdAt || ''}:${q.source || ''}:${q.status || ''}`, 'event', 120);
    const existing = eventMap.get(key) || { row: q, labels: new Set(), events };
    existing.events = Math.max(existing.events, events);
    for (const def of matches) {
      const row = byId.get(def.id);
      row.events += events;
      row.blocked += isBlocked(q) ? events : 0;
      row.redacted += isRedacted(q) ? events : 0;
      row.critical += severityForQuery(q) === 'critical' ? events : 0;
      if (q.createdAt && (!row.lastSeen || String(q.createdAt) > String(row.lastSeen))) row.lastSeen = q.createdAt;
      existing.labels.add(def.label);
    }
    eventMap.set(key, existing);
  }

  const rules = ruleRows.map((row) => {
    const state = threatState(row);
    return {
      ...row,
      state,
      status: threatStatus(state),
      lastSeen: row.lastSeen || null,
      action: row.events ? `Review ${row.control}` : `Verify ${row.control}`,
    };
  }).sort((a, b) => b.events - a.events || a.label.localeCompare(b.label));

  const unique = [...eventMap.values()];
  const countByRule = (id) => n(byId.get(id) && byId.get(id).events);
  return {
    summary: {
      events: unique.reduce((sum, item) => sum + n(item.events), 0),
      detections: rules.reduce((sum, item) => sum + n(item.events), 0),
      activeRules: rules.filter((item) => n(item.events) > 0).length,
      blocked: unique.reduce((sum, item) => sum + (isBlocked(item.row) ? n(item.events) : 0), 0),
      redacted: unique.reduce((sum, item) => sum + (isRedacted(item.row) ? n(item.events) : 0), 0),
      critical: unique.reduce((sum, item) => sum + (severityForQuery(item.row) === 'critical' ? n(item.events) : 0), 0),
      promptInjection: countByRule('prompt_injection'),
      sensitiveDisclosure: countByRule('sensitive_disclosure'),
      unsafeOutput: countByRule('unsafe_output'),
      agentActions: countByRule('excessive_agency'),
      shadowAi: countByRule('shadow_ai'),
      unscannedContent: countByRule('unscanned_content'),
      privacy: 'prompt bodies excluded',
    },
    rules,
    controls: threatControls(policy, rows),
    recent: unique
      .sort((a, b) => String(b.row.createdAt || '').localeCompare(String(a.row.createdAt || '')))
      .slice(0, 8)
      .map((item) => ({
        id: item.row.id,
        timestamp: item.row.createdAt || null,
        source: item.row.source || 'api',
        destination: coverage.normalizeDestination(item.row.destination || 'unknown'),
        severity: severityForQuery(item.row),
        status: signalStatusForQuery(item.row),
        decision: statusDecision(item.row.status),
        title: titleForQuery(item.row),
        threats: [...item.labels].slice(0, 3),
        detail: `${sourceLabel(item.row.source)} / ${controlKey(item.row)} / raw content excluded`,
      })),
  };
}

function inventoryStateForDestination(bucket = {}, fallback = 'sanctioned') {
  // A reviewed-and-governed destination is sanctioned even if it was first seen
  // as shadow AI; check governed before the shadow fallback so the coverage
  // review actually clears the shadow/critical state here too.
  if (bucket.governed === true) return 'sanctioned';
  if (fallback === 'shadow') return 'shadow';
  return 'unsanctioned';
}

function inventoryStatus(state) {
  if (state === 'sanctioned' || state === 'local_approved') return 'online';
  if (state === 'shadow' || state === 'unsanctioned' || state === 'local_unapproved') return 'warning';
  return 'idle';
}

function inventoryAction(state) {
  if (state === 'sanctioned') return 'Inspect coverage';
  if (state === 'local_approved') return 'Inspect endpoint';
  if (state === 'local_unapproved') return 'Review local tool';
  return 'Review destination';
}

function inventoryRiskLevel(score) {
  const value = bound(score);
  if (value >= 80) return 'critical';
  if (value >= 55) return 'high';
  if (value >= 30) return 'medium';
  return 'low';
}

function inventoryRiskForAsset(item = {}) {
  let score = item.state === 'shadow' ? 82
    : item.state === 'unsanctioned' ? 64
      : item.state === 'local_unapproved' ? 70
        : item.state === 'local_approved' ? 20
          : 16;
  score += Math.min(12, n(item.users) * 3);
  score += Math.min(10, n(item.blocked) * 3);
  score += Math.min(8, n(item.redacted) * 2);
  score += Math.min(8, n(item.events));
  const riskScore = bound(score);
  const reasons = [];
  if (item.state === 'shadow') reasons.push('shadow AI');
  if (item.state === 'unsanctioned') reasons.push('unsanctioned');
  if (item.state === 'local_unapproved') reasons.push('unapproved local tool');
  if (n(item.blocked)) reasons.push(`${n(item.blocked)} blocked`);
  if (n(item.redacted)) reasons.push(`${n(item.redacted)} redacted`);
  if (n(item.users)) reasons.push(`${n(item.users)} user${n(item.users) === 1 ? '' : 's'}`);
  return {
    riskScore,
    riskLevel: inventoryRiskLevel(riskScore),
    riskReason: reasons.slice(0, 3).join(' / ') || 'cataloged',
  };
}

function mcpPolicyList(policy = {}, key) {
  return (Array.isArray(policy[key]) ? policy[key] : [])
    .map((item) => safeText(item, '', 160))
    .filter(Boolean)
    .slice(0, 50);
}

// Compile one policy pattern into a reusable matcher so the wildcard RegExp is
// built once, not once per MCP row on every /api/posture request.
function compileMcpPattern(pattern) {
  const rule = safeText(pattern, '', 160).toLowerCase();
  if (!rule) return null;
  if (rule === '*') return { all: true };
  if (rule.includes('*')) {
    const escaped = rule.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    return { re: new RegExp(`^${escaped}$`) };
  }
  return { exact: rule };
}

function compileMcpList(policy, key) {
  return mcpPolicyList(policy, key).map(compileMcpPattern).filter(Boolean);
}

// Prepare the three policy matcher lists once; reuse across every row.
function prepareMcpPolicy(policy = {}) {
  return {
    allowed: compileMcpList(policy, 'mcpAllowedTools'),
    blocked: compileMcpList(policy, 'mcpBlockedTools'),
    approvalRequired: compileMcpList(policy, 'mcpApprovalRequiredTools'),
  };
}

function matchesCompiled(target, matchers) {
  return matchers.some((m) => m.all || (m.re ? m.re.test(target) : m.exact === target));
}

function mcpToolPolicyState(tool, prepared) {
  const target = safeText(tool, 'mcp-tool', 160).toLowerCase();
  if (matchesCompiled(target, prepared.blocked)) return 'blocked';
  if (matchesCompiled(target, prepared.approvalRequired)) return 'approval_required';
  if (prepared.allowed.length && matchesCompiled(target, prepared.allowed)) return 'allowed_registry';
  if (prepared.allowed.length) return 'outside_registry';
  return 'observed';
}

function mcpPolicyLabel(state) {
  return ({
    allowed_registry: 'Allowed registry',
    approval_required: 'Approval required',
    outside_registry: 'Outside registry',
    blocked: 'Blocked',
    observed: 'Observed',
  })[state] || 'Observed';
}

function mcpStatusForState(state, item = {}) {
  if (state === 'blocked' || state === 'outside_registry' || n(item.riskScore) >= 80) return 'error';
  if (state === 'approval_required' || n(item.blocked) > 0 || n(item.redacted) > 0 || n(item.riskScore) >= 45) return 'warning';
  if (state === 'allowed_registry' || n(item.events) > 0) return 'online';
  return 'idle';
}

function mcpRiskForItem(item = {}) {
  const state = String(item.state || 'observed');
  let score = state === 'outside_registry' ? 72
    : state === 'blocked' ? 68
      : state === 'approval_required' ? 54
        : state === 'allowed_registry' ? 20
          : 32;
  score += Math.min(14, n(item.events));
  score += Math.min(16, n(item.blocked) * 4);
  score += Math.min(12, n(item.redacted) * 3);
  score += Math.min(10, n(item.users || item.agents) * 2);
  score = Math.max(score, n(item.riskScore));
  const riskScore = bound(score);
  const reasons = [];
  if (state === 'outside_registry') reasons.push('outside registry');
  if (state === 'blocked') reasons.push('blocked policy');
  if (state === 'approval_required') reasons.push('approval gate');
  if (n(item.blocked)) reasons.push(`${n(item.blocked)} blocked`);
  if (n(item.redacted)) reasons.push(`${n(item.redacted)} redacted`);
  if (n(item.users || item.agents)) reasons.push(`${n(item.users || item.agents)} actor${n(item.users || item.agents) === 1 ? '' : 's'}`);
  return {
    riskScore,
    riskLevel: inventoryRiskLevel(riskScore),
    riskReason: reasons.slice(0, 3).join(' / ') || mcpPolicyLabel(state).toLowerCase(),
  };
}

function mcpRowTool(q = {}) {
  return safeText(q.destination || q.tool || 'mcp-tool', 'mcp-tool', 160);
}

function mcpRowAgent(q = {}) {
  return safeText(q.user || q.agent || 'mcp-agent', 'mcp-agent', 120);
}

function mcpPolicySummary(policy = {}) {
  const allowed = mcpPolicyList(policy, 'mcpAllowedTools');
  const blocked = mcpPolicyList(policy, 'mcpBlockedTools');
  const approvalRequired = mcpPolicyList(policy, 'mcpApprovalRequiredTools');
  return {
    allowed: { count: allowed.length, examples: allowed.slice(0, 6) },
    blocked: { count: blocked.length, examples: blocked.slice(0, 6) },
    approvalRequired: { count: approvalRequired.length, examples: approvalRequired.slice(0, 6) },
    registryMode: allowed.length ? 'allowlist' : 'observe_with_blocks',
  };
}

function connectorProfileLookup() {
  const map = new Map();
  for (const profile of CONNECTOR_PROFILES || []) {
    map.set(profile.id, {
      id: safeText(profile.id, 'unknown', 80),
      label: safeText(profile.label, 'Connector', 80),
      stage: profile.stage === 'shipped' ? 'shipped' : 'template',
      category: safeText(profile.category, 'connector', 80),
      operations: (profile.operations || []).map((item) => safeText(item, '', 80)).filter(Boolean).slice(0, 6),
      scopeCount: Array.isArray(profile.defaultScopes) ? profile.defaultScopes.length : 0,
      detail: safeText(profile.detail, 'metadata-only connector profile', 180),
    });
  }
  return map;
}

function connectorStatusField(detail = '', field = 'status') {
  const pattern = new RegExp(`${field}:([a-z0-9_:-]+)`, 'i');
  const match = String(detail || '').match(pattern);
  return match ? match[1].toLowerCase() : '';
}

function connectorRegistryPosture(rows = []) {
  const lookup = connectorProfileLookup();
  const profiles = new Map();
  for (const profile of lookup.values()) {
    profiles.set(profile.id, {
      ...profile,
      status: profile.stage === 'shipped' ? 'profile_registered' : 'profile_template',
      runtimePresent: false,
      configured: false,
      installProof: false,
      ok: true,
      state: profile.stage === 'shipped' ? 'registered' : 'template',
    });
  }

  let registrySeen = false;
  let registryOk = false;
  let failedChecks = 0;
  for (const row of rows || []) {
    if (!row || row.source !== 'mcp_guard' || row.status !== 'sensor_heartbeat') continue;
    for (const item of Array.isArray(row.installChecks) ? row.installChecks : []) {
      const id = safeText(item && item.id, '', 80);
      if (!id) continue;
      if (id === 'mcp_connector_registry') {
        registrySeen = true;
        registryOk = registryOk || item.ok === true;
        if (item.ok !== true) failedChecks += 1;
        continue;
      }
      if (!id.startsWith('mcp_connector_profile_')) continue;
      const profileId = id.replace(/^mcp_connector_profile_/, '');
      const base = profiles.get(profileId) || {
        id: profileId,
        label: profileId.split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' '),
        stage: 'template',
        category: 'connector',
        operations: [],
        scopeCount: 0,
        detail: 'metadata-only connector profile',
      };
      const detail = safeText(item.detail, '', 160);
      const stage = connectorStatusField(detail, 'stage') || base.stage;
      const status = connectorStatusField(detail, 'status') || base.status || 'profile_template';
      const scopeMatch = String(detail || '').match(/scopes:(\d+)/i);
      const runtimePresent = ['runtime_present', 'configured'].includes(status);
      const configured = ['configured', 'template_credentials_seen'].includes(status);
      const ok = item.ok === true;
      if (!ok) failedChecks += 1;
      profiles.set(profileId, {
        ...base,
        stage: stage === 'shipped' ? 'shipped' : 'template',
        status,
        runtimePresent,
        configured,
        installProof: true,
        ok,
        state: ok
          ? (stage === 'shipped' ? (runtimePresent ? 'shipped' : 'registered') : 'template')
          : 'attention',
        scopeCount: scopeMatch ? n(scopeMatch[1]) : n(base.scopeCount),
      });
    }
  }

  const nextConnector = ([...profiles.values()].find((profile) => profile.stage === 'template') || {}).id || 'none';
  const profileRows = [...profiles.values()]
    .sort((a, b) => (a.stage === b.stage ? a.label.localeCompare(b.label) : (a.stage === 'shipped' ? -1 : 1)))
    .slice(0, 10);
  const shipped = profileRows.filter((profile) => profile.stage === 'shipped');
  const templates = profileRows.filter((profile) => profile.stage === 'template');
  const installed = profileRows.filter((profile) => profile.installProof);
  return {
    summary: {
      profiles: profileRows.length,
      shipped: shipped.length,
      shippedRuntimePresent: shipped.filter((profile) => profile.runtimePresent).length,
      profileTemplates: templates.length,
      configuredProfiles: profileRows.filter((profile) => profile.configured).length,
      installProof: registrySeen && registryOk,
      healthChecks: installed.length + (registrySeen ? 1 : 0),
      failedChecks,
      nextConnector,
      privacy: 'metadata only; tokens and document IDs excluded',
    },
    profiles: profileRows.map((profile) => ({
      id: profile.id,
      label: profile.label,
      stage: profile.stage,
      category: profile.category,
      state: profile.state,
      status: profile.ok === false ? 'warning' : (profile.stage === 'shipped' && profile.runtimePresent ? 'online' : 'idle'),
      runtimePresent: profile.runtimePresent,
      configured: profile.configured,
      installProof: profile.installProof,
      operations: profile.operations,
      scopeCount: n(profile.scopeCount),
      detail: profile.detail,
    })),
  };
}

function agenticMcpPosture({ rows = [], policy = {} } = {}) {
  const mcpRows = (rows || []).filter((row) => row && row.source === 'mcp_guard' && !EVENTLESS_STATUSES.has(row.status));
  const agents = new Map();
  const tools = new Map();
  const policySummary = mcpPolicySummary(policy);
  const preparedPolicy = prepareMcpPolicy(policy);
  const connectorRegistry = connectorRegistryPosture(rows);
  const requestCounts = {
    toolData: 0,
    toolPolicy: 0,
    response: 0,
    blocked: 0,
    redacted: 0,
    allowed: 0,
  };

  for (const q of mcpRows) {
    const events = eventWeight(q);
    const agent = mcpRowAgent(q);
    const tool = mcpRowTool(q);
    const toolState = mcpToolPolicyState(tool, preparedPolicy);
    const blocked = isBlocked(q) ? events : 0;
    const redacted = isRedacted(q) ? events : 0;
    const allowed = isAllowed(q) ? events : 0;
    if (q.channel === 'mcp_tool' || q.status === 'action_blocked') requestCounts.toolPolicy += events;
    else if (q.channel === 'ai_response' || q.status === 'response_redacted' || q.status === 'response_blocked') requestCounts.response += events;
    else requestCounts.toolData += events;
    requestCounts.blocked += blocked;
    requestCounts.redacted += redacted;
    requestCounts.allowed += allowed;

    const agentRow = agents.get(agent) || {
      id: `mcp-agent-${graphSlug(agent)}`,
      name: agent,
      events: 0,
      blocked: 0,
      redacted: 0,
      tools: new Set(),
      lastSeen: '',
      riskScore: 0,
    };
    agentRow.events += events;
    agentRow.blocked += blocked;
    agentRow.redacted += redacted;
    agentRow.tools.add(tool);
    if (q.createdAt && (!agentRow.lastSeen || String(q.createdAt) > agentRow.lastSeen)) agentRow.lastSeen = String(q.createdAt);
    agentRow.riskScore = Math.max(n(agentRow.riskScore), n(q.riskScore), n(q.maxSeverity) >= 4 ? 82 : 0);
    agents.set(agent, agentRow);

    const toolRow = tools.get(tool) || {
      id: `mcp-tool-${graphSlug(tool)}`,
      name: tool,
      kind: 'MCP tool',
      source: 'mcp_guard',
      state: toolState,
      events: 0,
      blocked: 0,
      redacted: 0,
      agents: new Set(),
      lastSeen: '',
      riskScore: 0,
      targetTab: 'policy',
      action: 'Review MCP policy',
    };
    const rank = { blocked: 0, outside_registry: 1, approval_required: 2, observed: 3, allowed_registry: 4 };
    if ((rank[toolState] ?? 9) < (rank[toolRow.state] ?? 9)) toolRow.state = toolState;
    toolRow.events += events;
    toolRow.blocked += blocked;
    toolRow.redacted += redacted;
    toolRow.agents.add(agent);
    if (q.createdAt && (!toolRow.lastSeen || String(q.createdAt) > toolRow.lastSeen)) toolRow.lastSeen = String(q.createdAt);
    toolRow.riskScore = Math.max(n(toolRow.riskScore), n(q.riskScore), n(q.maxSeverity) >= 4 ? 82 : 0);
    tools.set(tool, toolRow);
  }

  const agentRows = [...agents.values()]
    .map((agent) => {
      const risk = mcpRiskForItem({
        ...agent,
        state: agent.blocked ? 'blocked' : agent.redacted ? 'approval_required' : 'observed',
        users: agent.tools.size,
      });
      const state = agent.blocked ? 'blocked' : agent.redacted ? 'redacted' : 'observed';
      return {
        id: agent.id,
        name: agent.name,
        events: n(agent.events),
        blocked: n(agent.blocked),
        redacted: n(agent.redacted),
        tools: agent.tools.size,
        lastSeen: agent.lastSeen || null,
        state,
        status: mcpStatusForState(state, { ...agent, ...risk }),
        detail: `${n(agent.events)} event${n(agent.events) === 1 ? '' : 's'} / ${agent.tools.size} tool${agent.tools.size === 1 ? '' : 's'} / ${n(agent.blocked)} blocked`,
        ...risk,
      };
    })
    .sort((a, b) => n(b.riskScore) - n(a.riskScore) || n(b.events) - n(a.events) || a.name.localeCompare(b.name))
    .slice(0, 8);

  const toolRows = [...tools.values()]
    .map((tool) => {
      const risk = mcpRiskForItem({ ...tool, agents: tool.agents.size });
      return {
        id: tool.id,
        name: tool.name,
        kind: tool.kind,
        source: tool.source,
        state: tool.state,
        status: mcpStatusForState(tool.state, { ...tool, ...risk }),
        events: n(tool.events),
        blocked: n(tool.blocked),
        redacted: n(tool.redacted),
        agents: tool.agents.size,
        users: tool.agents.size,
        lastSeen: tool.lastSeen || null,
        detail: `${mcpPolicyLabel(tool.state)} / ${n(tool.events)} event${n(tool.events) === 1 ? '' : 's'} / ${tool.agents.size} agent${tool.agents.size === 1 ? '' : 's'}`,
        targetTab: tool.targetTab,
        action: tool.action,
        ...risk,
      };
    })
    .sort((a, b) => n(b.riskScore) - n(a.riskScore) || n(b.events) - n(a.events) || a.name.localeCompare(b.name))
    .slice(0, 10);

  const outsideRegistry = toolRows.filter((tool) => tool.state === 'outside_registry').length;
  const approvalRequired = toolRows.filter((tool) => tool.state === 'approval_required').length;
  const blockedTools = toolRows.filter((tool) => tool.state === 'blocked').length;
  const controlled = requestCounts.blocked + requestCounts.redacted;
  return {
    summary: {
      events: mcpRows.reduce((sum, row) => sum + eventWeight(row), 0),
      activeAgents: agentRows.length,
      activeTools: toolRows.length,
      controlled,
      blocked: requestCounts.blocked,
      redacted: requestCounts.redacted,
      approvalRequired,
      outsideRegistry,
      blockedTools,
      registryMode: policySummary.registryMode,
      privacy: 'prompt bodies excluded',
    },
    agents: agentRows,
    tools: toolRows,
    connectorRegistry,
    requests: [
      { id: 'mcp-tool-data', label: 'Tool data', events: requestCounts.toolData, state: requestCounts.redacted ? 'redacted' : 'observed' },
      { id: 'mcp-tool-policy', label: 'Tool policy', events: requestCounts.toolPolicy, state: requestCounts.blocked ? 'blocked' : 'observed' },
      { id: 'mcp-response', label: 'AI response', events: requestCounts.response, state: requestCounts.response ? 'observed' : 'idle' },
    ],
    policy: policySummary,
  };
}

function inventoryUpsert(map, row = {}, fallback = 'sanctioned') {
  const destination = coverage.normalizeDestination(row.destination || 'unknown');
  if (!destination || NON_AI_INVENTORY_DESTINATIONS.has(destination)) return;
  const state = inventoryStateForDestination(row, fallback);
  const observedSource = safeText(row.source || (Array.isArray(row.sources) && row.sources[0]) || (fallback === 'shadow' ? 'shadow_ai' : 'coverage'), fallback === 'shadow' ? 'shadow_ai' : 'coverage', 80);
  const current = map.get(destination) || {
    id: `ai-app-${destination.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase() || 'unknown'}`,
    name: destination,
    kind: 'AI app',
    state,
    status: inventoryStatus(state),
    events: 0,
    blocked: 0,
    redacted: 0,
    shadow: 0,
    users: 0,
    lastSeen: null,
    source: observedSource,
    action: inventoryAction(state),
    targetTab: state === 'sanctioned' ? 'coverage' : 'coverage',
  };
  const rank = { shadow: 0, unsanctioned: 1, sanctioned: 2 };
  const nextState = (rank[state] ?? 3) < (rank[current.state] ?? 3) ? state : current.state;
  current.state = nextState;
  current.status = inventoryStatus(nextState);
  current.action = inventoryAction(nextState);
  if (current.source === 'coverage' || current.source === 'shadow_ai') current.source = observedSource;
  current.events += n(row.events);
  current.blocked += n(row.blocked);
  current.redacted += n(row.redacted);
  current.shadow += n(row.shadow);
  current.users = Math.max(current.users, n(row.users));
  if (row.lastSeen && (!current.lastSeen || String(row.lastSeen) > String(current.lastSeen))) current.lastSeen = row.lastSeen;
  current.detail = `${current.events} event${current.events === 1 ? '' : 's'} / ${current.blocked} blocked / ${current.users} user${current.users === 1 ? '' : 's'}`;
  Object.assign(current, inventoryRiskForAsset(current));
  map.set(destination, current);
}

function aiInventory({ coverageReport, agenticMcp = null }) {
  const report = coverageReport || {};
  const totals = report.totals || {};
  const appsByDestination = new Map();
  for (const row of report.governedDestinations || []) inventoryUpsert(appsByDestination, row, 'sanctioned');
  for (const row of report.ungovernedDestinations || []) {
    if (n(row && row.shadow)) continue;
    inventoryUpsert(appsByDestination, row, 'unsanctioned');
  }
  for (const row of report.shadowDestinations || []) inventoryUpsert(appsByDestination, row, 'shadow');
  const apps = [...appsByDestination.values()]
    .sort((a, b) => {
      const rank = { shadow: 0, unsanctioned: 1, sanctioned: 2 };
      return (rank[a.state] ?? 3) - (rank[b.state] ?? 3)
        || b.events - a.events
        || a.name.localeCompare(b.name);
    })
    .slice(0, 12);
  const tools = (Array.isArray(report.endpointAiTools) ? report.endpointAiTools : []).slice(0, 8).map((tool) => {
    const approved = tool && tool.approved === true;
    const state = approved ? 'local_approved' : 'local_unapproved';
    return {
      id: safeText(tool && tool.id, 'local-ai-tool', 80),
      name: safeText(tool && (tool.label || tool.id), 'Local AI tool', 120),
      kind: 'Endpoint tool',
      state,
      status: inventoryStatus(state),
      source: 'endpoint_agent',
      user: safeText(tool && tool.user, 'unknown', 80),
      orgId: tool && tool.orgId ? safeText(tool.orgId, '', 80) : null,
      lastSeen: safeText(tool && tool.lastSeen, '', 80),
      detail: safeText(tool && tool.detail, approved ? 'Approved local AI tool' : 'Unapproved local AI tool', 160),
      action: inventoryAction(state),
      targetTab: 'coverage',
      ...inventoryRiskForAsset({
        state,
        events: 1,
        users: tool && tool.user ? 1 : 0,
      }),
    };
  });
  const mcpTools = agenticMcp && Array.isArray(agenticMcp.tools)
    ? agenticMcp.tools.slice(0, 8).map((tool) => ({
      id: safeText(tool.id, 'mcp-tool', 100),
      name: safeText(tool.name, 'MCP tool', 160),
      kind: 'MCP tool',
      state: safeText(tool.state, 'observed', 40),
      status: safeText(tool.status, 'idle', 40),
      source: 'mcp_guard',
      events: n(tool.events),
      blocked: n(tool.blocked),
      redacted: n(tool.redacted),
      users: n(tool.agents || tool.users),
      lastSeen: tool.lastSeen ? safeText(tool.lastSeen, '', 80) : null,
      detail: safeText(tool.detail, 'MCP tool observed through the guard', 180),
      action: 'Review MCP policy',
      targetTab: 'policy',
      riskScore: bound(tool.riskScore),
      riskLevel: safeText(tool.riskLevel, 'low', 40),
      riskReason: safeText(tool.riskReason, 'MCP policy state', 120),
    }))
    : [];
  const allTools = [...tools, ...mcpTools];
  const highRiskAssets = [...apps, ...allTools].filter((item) => ['critical', 'high'].includes(item.riskLevel)).length;
  return {
    summary: {
      sanctioned: apps.filter((item) => item.state === 'sanctioned').length,
      unsanctioned: apps.filter((item) => item.state === 'unsanctioned').length,
      shadow: apps.filter((item) => item.state === 'shadow').length,
      localTools: tools.length,
      mcpTools: mcpTools.length,
      unapprovedLocalTools: n(totals.endpointAiToolUnapproved),
      activeDestinations: apps.filter((item) => item.events > 0).length,
      totalEvents: apps.reduce((sum, item) => sum + n(item.events), 0),
      highRiskAssets,
    },
    apps,
    tools: allTools,
  };
}

function queueSeverity(state) {
  if (state === 'blocked' || state === 'missing' || state === 'shadow' || state === 'local_unapproved') return 'critical';
  if (state === 'attention' || state === 'unsanctioned') return 'warning';
  return 'info';
}

function queueAction(input = {}) {
  return {
    id: safeText(input.id, 'action', 100),
    priority: bound(input.priority || 99, 1, 99),
    severity: safeText(input.severity || 'warning', 'warning', 40),
    category: safeText(input.category || 'Hardening', 'Hardening', 80),
    label: safeText(input.label, 'Review hardening action', 140),
    detail: safeText(input.detail, 'Open the recommended control surface.', 240),
    owner: safeText(input.owner, 'security', 80),
    source: safeText(input.source, 'control', 80),
    action: safeText(input.action, 'Open', 80),
    targetTab: safeText(input.targetTab, 'coverage', 40),
    command: input.command ? safeText(input.command, '', 240) : '',
  };
}

function workflowStatus(state = {}) {
  const value = String(state.status || 'open');
  if (!['open', 'assigned', 'snoozed', 'resolved'].includes(value)) return 'open';
  if (value === 'snoozed' && state.snoozeUntil && Date.parse(state.snoozeUntil) <= Date.now()) return 'open';
  return value;
}

function applyWorkflowState(action, actionStates = {}) {
  const state = actionStates && actionStates[action.id] ? actionStates[action.id] : {};
  const status = workflowStatus(state);
  return {
    ...action,
    workflowStatus: status,
    workflowOwner: safeText(state.owner, '', 120),
    workflowActor: safeText(state.actor, '', 120),
    workflowNote: safeText(state.note, '', 240),
    workflowSnoozeUntil: state.snoozeUntil ? safeText(state.snoozeUntil, '', 80) : '',
    workflowUpdatedAt: state.updatedAt ? safeText(state.updatedAt, '', 80) : '',
    workflowProofState: status === 'resolved' && action.severity !== 'info' ? 'proof_pending' : status,
  };
}

function hardeningActionQueue({ hardening = {}, inventory = {}, behavior = {}, actionStates = {} } = {}) {
  const actions = [];
  const seen = new Set();
  const add = (item) => {
    const action = queueAction(item);
    if (!action.id || seen.has(action.id)) return;
    seen.add(action.id);
    actions.push(action);
  };
  const mission = hardening.mission && typeof hardening.mission === 'object' ? hardening.mission : {};
  const current = mission.current && typeof mission.current === 'object' ? mission.current : null;
  if (current) {
    add({
      id: `mission:${current.id || current.areaId || current.label}`,
      priority: 1,
      severity: queueSeverity(current.areaState),
      category: 'Current mission',
      label: current.label,
      detail: `${safeText(current.areaLabel, 'Readiness area', 120)}: ${safeText(current.detail, 'Follow the hardening runbook', 200)}`,
      owner: current.owner,
      source: current.source,
      action: 'Run step',
      targetTab: current.targetTab,
      command: current.command,
    });
  }
  const proofLedger = mission.proofLedger && typeof mission.proofLedger === 'object'
    ? mission.proofLedger
    : hardening.proofLedger && typeof hardening.proofLedger === 'object' ? hardening.proofLedger : {};
  const proof = proofLedger.current && typeof proofLedger.current === 'object' ? proofLedger.current : null;
  if (proof) {
    add({
      id: `proof:${proof.id || proof.areaId || proof.label}`,
      priority: current ? 2 : 1,
      severity: queueSeverity(proof.status),
      category: 'Evidence proof',
      label: proof.label,
      detail: `${safeText(proof.areaLabel, 'Readiness area', 120)}: ${safeText(proof.detail, 'Collect sanitized proof', 200)}`,
      owner: 'security',
      source: proof.source,
      action: proof.action || 'Collect proof',
      targetTab: proof.targetTab,
    });
  }
  const nextActions = Array.isArray(hardening.nextActions) ? hardening.nextActions : [];
  nextActions.slice(0, 4).forEach((item, index) => add({
    id: `readiness:${item.id || item.action || index}`,
    priority: 3 + index,
    severity: 'warning',
    category: 'Readiness gap',
    label: item.action || item.label,
    detail: item.detail || item.label,
    owner: item.label || 'security',
    source: 'hardening',
    action: item.action || 'Review',
    targetTab: item.targetTab,
  }));
  const behaviorActions = Array.isArray(behavior.playbook) ? behavior.playbook : [];
  behaviorActions.slice(0, 2).forEach((item, index) => add({
    id: item.id || `behavior:${index}`,
    priority: 6 + index,
    severity: item.severity || 'warning',
    category: 'Behavior baseline',
    label: item.label || 'Review behavior anomaly',
    detail: item.detail || 'Metadata baseline changed',
    owner: 'security analytics',
    source: 'behavior_baseline',
    action: item.action || 'Review baseline',
    targetTab: item.targetTab || 'monitor',
  }));
  const apps = Array.isArray(inventory.apps) ? inventory.apps : [];
  apps
    .filter((item) => item && (item.state === 'shadow' || item.state === 'unsanctioned'))
    .slice(0, 3)
    .forEach((item, index) => add({
      id: `inventory:${item.id || item.name}`,
      priority: 7 + index,
      severity: queueSeverity(item.state),
      category: item.state === 'shadow' ? 'Shadow AI' : 'Unsanctioned AI',
      label: item.state === 'shadow' ? 'Review shadow AI destination' : 'Review unsanctioned AI destination',
      detail: `${safeText(item.name, 'AI destination', 120)}: ${safeText(item.detail, 'Destination needs review', 180)}`,
      owner: 'security operations',
      source: item.source || 'coverage',
      action: item.action || 'Review destination',
      targetTab: item.targetTab || 'coverage',
    }));
  const tools = Array.isArray(inventory.tools) ? inventory.tools : [];
  tools
    .filter((item) => item && item.state === 'local_unapproved')
    .slice(0, 3)
    .forEach((item, index) => add({
      id: `tool:${item.id || item.name}`,
      priority: 10 + index,
      severity: 'warning',
      category: 'Endpoint AI tool',
      label: 'Review unapproved local AI tool',
      detail: `${safeText(item.name, 'Local AI tool', 120)}: ${safeText(item.detail, 'Endpoint inventory needs review', 180)}`,
      owner: 'endpoint engineering',
      source: item.source || 'endpoint_agent',
      action: item.action || 'Review local tool',
      targetTab: item.targetTab || 'coverage',
    }));
  return actions
    .sort((a, b) => a.priority - b.priority || a.label.localeCompare(b.label))
    .slice(0, 8)
    .map((item, index) => applyWorkflowState({ ...item, priority: index + 1 }, actionStates));
}

function configuredActionControls(policy = {}) {
  return {
    blockUnapprovedAiDestinations: policy.blockUnapprovedAiDestinations !== false,
    blockedFileUploads: Array.isArray(policy.blockedFileUploadDestinations) && policy.blockedFileUploadDestinations.length > 0,
    blockedBrowserActions: Array.isArray(policy.blockedBrowserActions) && policy.blockedBrowserActions.length > 0,
    responseScanning: policy.responseScanMode && policy.responseScanMode !== 'allow',
  };
}

function objective(id, label, score, detail, action, targetTab = 'policy') {
  const bounded = bound(score);
  return {
    id,
    label,
    score: bounded,
    state: bounded >= 90 ? 'covered' : 'attention',
    detail,
    action,
    targetTab,
  };
}

function hardeningObjectives(hardening = {}) {
  return (Array.isArray(hardening.areas) ? hardening.areas : []).map((area) => objective(
    `harden_${area.id}`,
    area.label,
    area.score,
    area.gaps && area.gaps.length ? `${area.gaps.length} readiness gap${area.gaps.length === 1 ? '' : 's'} / ${area.evidence.length} proof points` : `${area.evidence.length} proof points ready`,
    area.gaps && area.gaps.length ? area.action : 'Inspect proof',
    area.targetTab || 'coverage',
  ));
}

function objectives({ rows, policy, coverageReport, auditIntegrity, nowMs, hardening }) {
  const sensitiveRows = rows.filter(isSensitive);
  const controlledSensitive = sensitiveRows.filter((q) => isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(q.status) || q.status === 'denied' || q.status === 'approved').length;
  const highRiskAllowThreshold = Math.max(50, n(policy.blockRiskScore || 0));
  const highRiskAllowed = sensitiveRows.filter((q) => isAllowed(q) && (n(q.riskScore) >= highRiskAllowThreshold || n(q.maxSeverity) >= 3)).length;
  const preventScore = sensitiveRows.length ? Math.max(0, pct(controlledSensitive, sensitiveRows.length) - (highRiskAllowed * 20)) : 100;
  const totals = (coverageReport && coverageReport.totals) || {};
  const unresolvedShadow = n(totals.unresolvedShadowDestinations);
  const controlConfig = configuredActionControls(policy);
  const actionScore = pct(Object.values(controlConfig).filter(Boolean).length, Object.keys(controlConfig).length);
  const pendingRows = rows.filter(isHeld);
  const escalated = pendingRows.filter((q) => isEscalated(q, nowMs)).length;
  const pending = pendingRows.length;
  const workflowScore = pending ? Math.max(0, 100 - (escalated * 35)) : 100;

  return [
    objective(
      'prevent_sensitive_ai_egress',
      'Prevent sensitive AI egress',
      preventScore,
      `${controlledSensitive}/${sensitiveRows.length || 0} sensitive events controlled${highRiskAllowed ? ` / ${highRiskAllowed} high-risk allowed` : ''}`,
      highRiskAllowed ? 'Review allow paths' : 'Review lineage',
      'lineage',
    ),
    objective(
      'close_shadow_ai_gaps',
      'Close shadow-AI gaps',
      unresolvedShadow ? Math.max(0, 100 - (unresolvedShadow * 25)) : 100,
      `${unresolvedShadow} unreviewed destinations / ${n(totals.shadowEvents)} sightings`,
      unresolvedShadow ? 'Review destinations' : 'Keep watchlist current',
      'coverage',
    ),
    objective(
      'prove_three_sensor_coverage',
      'Prove three-sensor coverage',
      n(coverageReport && coverageReport.score),
      `${n(totals.activeRequiredSensors)}/${n(totals.requiredSensors)} required sensors active / ${n(totals.fleetAttention)} fleet gaps`,
      'Open coverage',
      'coverage',
    ),
    ...hardeningObjectives(hardening),
    attributionObjective(totals),
    objective(
      'govern_ai_actions',
      'Govern AI actions',
      actionScore,
      `${Object.values(controlConfig).filter(Boolean).length}/4 action-control families configured`,
      actionScore >= 90 ? 'Inspect policy' : 'Configure controls',
      'policy',
    ),
    objective(
      'examiner_ready_evidence',
      'Examiner-ready evidence',
      auditIntegrity && auditIntegrity.ok ? 100 : 0,
      auditIntegrity && auditIntegrity.ok ? `${n(auditIntegrity.count)} linked audit entries` : 'audit chain needs review',
      'Open audit log',
      'audit',
    ),
    objective(
      'approval_sla_control',
      'Approval SLA control',
      workflowScore,
      `${pending} pending / ${escalated} escalated`,
      escalated ? 'Triage queue' : 'Inspect queue',
      'queue',
    ),
  ];
}

function attributionObjective(totals = {}) {
  const unattributed = n(totals.unattributedEvents);
  const rate = Number(totals.unattributedRate) || 0;
  const mode = totals.unmanagedInstallMode || 'allow';
  const score = unattributed
    ? Math.max(0, 100 - Math.round(rate * 100) - (mode === 'allow' ? 15 : 0))
    : 100;
  return objective(
    'guarantee_user_attribution',
    'Guarantee per-user attribution',
    score,
    `${unattributed} unattributed events / unmanaged installs ${mode}`,
    unattributed || mode === 'allow' ? 'Set unmanagedInstalls to flag or block' : 'Keep managed identity enforced',
    'coverage',
  );
}

function sensorStatus(sensor = {}) {
  if (!sensor.events) return 'offline';
  if (sensor.versionHealth && sensor.versionHealth !== 'current') return 'warning';
  if (sensor.installHealth && sensor.installHealth.state === 'attention') return 'warning';
  return 'online';
}

function sensorHealth(sensor = {}) {
  if (!sensor.events) return 0;
  let score = 100;
  if (sensor.versionHealth && sensor.versionHealth !== 'current') score -= 25;
  if (sensor.installHealth && sensor.installHealth.state === 'attention') score -= 25;
  score -= Math.min(30, ((sensor.installHealth && sensor.installHealth.failedChecks || []).length) * 8);
  return bound(score);
}

function lastSeenText(iso, nowMs) {
  const ts = Date.parse(iso || '');
  if (!Number.isFinite(ts)) return 'not seen';
  const seconds = Math.max(0, Math.round((nowMs - ts) / 1000));
  if (seconds < 60) return `${seconds || 1} sec ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hr ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function surfaceFromSensor(source, coverageReport, nowMs) {
  const sensor = ((coverageReport && coverageReport.sensors) || []).find((item) => item.source === source) || {
    source,
    label: SOURCE_LABELS[source] || source,
    events: 0,
  };
  const status = sensorStatus(sensor);
  const health = sensorHealth(sensor);
  return {
    id: `surface-${source}`,
    name: sensor.label || SOURCE_LABELS[source] || source,
    type: source === 'browser_extension' ? 'browser extension' : source === 'endpoint_agent' ? 'endpoint agent' : source === 'mcp_guard' ? 'agent guard' : 'network control',
    status,
    source,
    location: source === 'browser_extension' ? 'Managed browser fleet'
      : source === 'endpoint_agent' ? 'Endpoint and desktop collectors'
        : source === 'mcp_guard' ? 'MCP tool/data path'
          : 'Proxy and API paths',
    health,
    confidence: sensor.events ? Math.max(70, health - 4) : 45,
    relatedMetric: sensor.required ? 'Required sensor' : 'Observed source',
    lastUpdated: lastSeenText(sensor.lastSeen, nowMs),
    description: sensor.events
      ? `${sensor.events} events${sensor.latestVersion ? ` / v${sensor.latestVersion}` : ''}${sensor.versionHealth === 'outdated' ? ' / version gap' : ''}`
      : 'No install-health or traffic evidence in the current report.',
  };
}

function surfaces({ rows, coverageReport, policy, auditIntegrity, nowMs, hardening }) {
  const totals = (coverageReport && coverageReport.totals) || {};
  const required = new Set(((coverageReport && coverageReport.sensors) || []).filter((sensor) => sensor.required).map((sensor) => sensor.source));
  for (const source of ['browser_extension', 'endpoint_agent', 'mcp_guard']) required.add(source);
  if (((coverageReport && coverageReport.sensors) || []).some((sensor) => sensor.source === 'proxy')) required.add('proxy');
  const pendingRows = rows.filter(isHeld);
  const pending = pendingRows.length;
  const escalated = pendingRows.filter((q) => isEscalated(q, nowMs)).length;
  const policyControls = configuredActionControls(policy);
  const configuredControls = Object.values(policyControls).filter(Boolean).length;
  const shadowAttention = n(totals.unresolvedShadowDestinations);
  const result = [...required].map((source) => surfaceFromSensor(source, coverageReport, nowMs));
  result.push({
    id: 'surface-approval-workflow',
    name: 'Approval Workflow',
    type: 'workflow',
    status: escalated ? 'error' : pending ? 'warning' : 'idle',
    source: 'approval_queue',
    location: 'Security admin console',
    health: escalated ? 55 : pending ? 78 : 96,
    confidence: 90,
    relatedMetric: 'Pending queue',
    lastUpdated: 'live',
    description: `${pending} pending review${escalated ? ` / ${escalated} escalated` : ''}.`,
  });
  result.push({
    id: 'surface-shadow-ai',
    name: 'Shadow AI Inventory',
    type: 'AI observability',
    status: shadowAttention ? 'warning' : 'online',
    source: 'endpoint_agent',
    location: 'Browser, endpoint, and proxy sightings',
    health: shadowAttention ? 70 : 96,
    confidence: 86,
    relatedMetric: 'Shadow AI review',
    lastUpdated: (coverageReport && coverageReport.generatedAt) ? lastSeenText(coverageReport.generatedAt, nowMs) : 'live',
    description: `${n(totals.shadowEvents)} sightings / ${shadowAttention} unreviewed destinations.`,
  });
  result.push({
    id: 'surface-policy-guardrails',
    name: 'Policy Guardrails',
    type: 'policy engine',
    status: configuredControls >= 3 ? 'online' : 'warning',
    source: 'policy',
    location: 'Prompt, file, response, and destination controls',
    health: pct(configuredControls, 4),
    confidence: 88,
    relatedMetric: 'Control coverage',
    lastUpdated: 'live',
    description: `${configuredControls}/4 AI action-control families configured.`,
  });
  result.push({
    id: 'surface-audit-evidence',
    name: 'Audit Evidence',
    type: 'evidence',
    status: auditIntegrity && auditIntegrity.ok ? 'online' : 'error',
    source: 'audit_log',
    location: 'Hash-chained SQLite store',
    health: auditIntegrity && auditIntegrity.ok ? 100 : 25,
    confidence: 99,
    relatedMetric: 'Examiner evidence',
    lastUpdated: 'live',
    description: auditIntegrity && auditIntegrity.ok ? `${n(auditIntegrity.count)} linked entries verified.` : 'Audit integrity requires review.',
  });
  for (const area of (hardening && hardening.areas) || []) {
    result.push({
      id: `surface-${area.id}`,
      name: area.label,
      type: 'competitive hardening',
      status: area.status,
      source: area.source,
      location: area.location,
      health: area.score,
      confidence: area.state === 'ready' ? 96 : 88,
      relatedMetric: 'Hardening readiness',
      lastUpdated: 'live',
      description: area.description,
    });
  }
  return result;
}

function graphSlug(value) {
  return safeText(value, 'unknown', 120)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'unknown';
}

function graphId(kind, value) {
  return `${kind}-${graphSlug(value)}`;
}

function graphStatusFromCounts(item = {}) {
  const status = String(item.status || '');
  if (n(item.riskScore) >= 80 || n(item.critical) > 0) return 'error';
  if (status === 'error') return 'error';
  if (n(item.shadow) > 0 || n(item.blocked) > 0 || n(item.redacted) > 0 || n(item.coached) > 0 || n(item.riskScore) >= 40) return 'warning';
  if (status === 'warning') return 'warning';
  if (status === 'online') return 'online';
  if (n(item.events) > 0 || n(item.score) >= 90) return 'online';
  return 'idle';
}

function graphDetail(item = {}) {
  const parts = [];
  if (n(item.events)) parts.push(`${n(item.events)} event${n(item.events) === 1 ? '' : 's'}`);
  if (n(item.controlled)) parts.push(`${n(item.controlled)} controlled`);
  if (n(item.shadow)) parts.push(`${n(item.shadow)} shadow`);
  if (n(item.riskScore)) parts.push(`max risk ${bound(item.riskScore)}`);
  if (n(item.score)) parts.push(`${bound(item.score)}/100 ready`);
  return parts.slice(0, 4).join(' / ') || safeText(item.detail, 'Awaiting sanitized evidence', 180);
}

function controlGraph({ rows = [], inventory = {}, surfaces: surfaceRows = [], controls = [], hardening = {} } = {}) {
  const nodes = new Map();
  const edges = new Map();
  const assetNames = new Set();
  const controlNames = new Set();
  const laneDefs = [
    { id: 'people', label: 'People', detail: 'Users and actors reaching AI paths', limit: 6 },
    { id: 'gateways', label: 'Gateways', detail: 'Browser, endpoint, proxy, and MCP controls', limit: 6 },
    { id: 'assets', label: 'AI assets', detail: 'Apps, models, agents, and local tools', limit: 8 },
    { id: 'controls', label: 'Controls', detail: 'Policy outcomes and enforcement points', limit: 7 },
    { id: 'hardening', label: 'Hardening', detail: 'Competitive readiness areas', limit: 3 },
  ];
  const laneLimits = new Map(laneDefs.map((lane) => [lane.id, lane.limit]));

  const addNode = (base = {}, metrics = {}) => {
    if (!base.id) return null;
    const current = nodes.get(base.id) || {
      id: safeText(base.id, 'node', 100),
      lane: safeText(base.lane, 'assets', 40),
      kind: safeText(base.kind, 'node', 40),
      label: safeText(base.label, 'Unknown', 120),
      source: safeText(base.source, 'posture', 80),
      targetTab: safeText(base.targetTab, 'monitor', 40),
      action: safeText(base.action, 'Inspect', 80),
      detail: safeText(base.detail, '', 180),
      events: 0,
      controlled: 0,
      blocked: 0,
      redacted: 0,
      coached: 0,
      shadow: 0,
      critical: 0,
      riskScore: 0,
      score: 0,
    };
    current.events += n(metrics.events);
    current.controlled += n(metrics.controlled);
    current.blocked += n(metrics.blocked);
    current.redacted += n(metrics.redacted);
    current.coached += n(metrics.coached);
    current.shadow += n(metrics.shadow);
    current.critical += n(metrics.critical);
    current.riskScore = Math.max(n(current.riskScore), n(metrics.riskScore), n(base.riskScore));
    current.score = Math.max(n(current.score), n(metrics.score), n(base.score));
    current.status = metrics.status || base.status || graphStatusFromCounts(current);
    current.detail = graphDetail(current);
    nodes.set(current.id, current);
    return current.id;
  };

  const addEdge = (from, to, label, q = {}) => {
    if (!from || !to || from === to) return;
    const events = eventWeight(q);
    const id = `${from}->${to}`;
    const current = edges.get(id) || {
      id,
      from,
      to,
      label: safeText(label, 'flow', 80),
      source: safeText(q.source, 'posture', 80),
      events: 0,
      controlled: 0,
      blocked: 0,
      redacted: 0,
      coached: 0,
      shadow: 0,
      critical: 0,
      riskScore: 0,
    };
    current.events += events;
    current.blocked += isBlocked(q) ? events : 0;
    current.redacted += isRedacted(q) ? events : 0;
    current.coached += COACHING_STATUSES.has(String(q.status || '')) ? events : 0;
    current.shadow += isShadowAi(q) ? events : 0;
    current.critical += severityForQuery(q) === 'critical' ? events : 0;
    current.controlled += (isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(String(q.status || '')) || q.status === 'approved' || q.status === 'denied') ? events : 0;
    current.riskScore = Math.max(n(current.riskScore), n(q.riskScore), n(q.maxSeverity) >= 4 ? 80 : 0);
    current.status = graphStatusFromCounts(current);
    current.detail = graphDetail(current);
    edges.set(id, current);
  };

  for (const surface of surfaceRows || []) {
    if (!surface || !surface.id) continue;
    const source = surface.source || surface.id;
    addNode({
      id: graphId('gateway', source),
      lane: 'gateways',
      kind: surface.type || 'gateway',
      label: surface.name || source,
      source,
      targetTab: 'coverage',
      action: 'Inspect surface',
      score: surface.health,
      status: surface.status,
    }, {
      events: source === 'policy' || source === 'audit_log' ? 0 : 1,
      score: surface.health,
    });
  }

  for (const item of [...(inventory.apps || []), ...(inventory.tools || [])]) {
    if (!item || !item.name) continue;
    const isEndpointTool = item.kind === 'Endpoint tool';
    assetNames.add(coverage.normalizeDestination(item.name));
    addNode({
      id: graphId('asset', item.name),
      lane: 'assets',
      kind: item.kind || 'AI asset',
      label: item.name,
      source: item.source || 'inventory',
      targetTab: item.targetTab || 'coverage',
      action: item.action || 'Inspect asset',
      riskScore: item.riskScore,
      status: item.status,
    }, {
      events: isEndpointTool ? (n(item.events) || 1) : 0,
      blocked: isEndpointTool ? n(item.blocked) : 0,
      redacted: isEndpointTool ? n(item.redacted) : 0,
      shadow: isEndpointTool && item.state === 'shadow' ? 1 : 0,
      riskScore: item.riskScore,
    });
  }

  for (const control of controls || []) {
    if (!control || !control.label) continue;
    controlNames.add(control.label);
    addNode({
      id: graphId('control', control.label),
      lane: 'controls',
      kind: 'control outcome',
      label: control.label,
      source: 'policy',
      targetTab: 'monitor',
      action: 'Inspect outcome',
    }, {
      events: control.events,
      blocked: control.blocked,
      redacted: control.redacted,
      coached: control.coached,
      shadow: control.shadow,
      controlled: n(control.blocked) + n(control.redacted) + n(control.coached),
    });
  }

  for (const area of (hardening && hardening.areas) || []) {
    if (!area || !area.id) continue;
    addNode({
      id: graphId('hardening', area.id),
      lane: 'hardening',
      kind: 'readiness area',
      label: area.label,
      source: area.source || 'hardening',
      targetTab: area.targetTab || 'coverage',
      action: area.action || 'Inspect readiness',
      score: area.score,
      status: area.status,
    }, {
      score: area.score,
      critical: area.state === 'blocked' ? 1 : 0,
    });
  }

  for (const q of rows || []) {
    if (!q || EVENTLESS_STATUSES.has(q.status)) continue;
    const events = eventWeight(q);
    const user = safeText(q.user, 'unknown user', 100);
    const source = safeText(q.source, 'api', 80);
    const destination = coverage.normalizeDestination(q.destination || 'unknown');
    const control = controlKey(q);
    const controlled = isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(String(q.status || '')) || q.status === 'approved' || q.status === 'denied';
    const userId = addNode({
      id: graphId('person', user),
      lane: 'people',
      kind: 'user',
      label: user,
      source: 'identity',
      targetTab: 'lineage',
      action: 'Open lineage',
    }, {
      events,
      controlled: controlled ? events : 0,
      blocked: isBlocked(q) ? events : 0,
      redacted: isRedacted(q) ? events : 0,
      coached: COACHING_STATUSES.has(String(q.status || '')) ? events : 0,
      shadow: isShadowAi(q) ? events : 0,
      critical: severityForQuery(q) === 'critical' ? events : 0,
      riskScore: q.riskScore,
    });
    const gatewayId = addNode({
      id: graphId('gateway', source),
      lane: 'gateways',
      kind: source === 'mcp_guard' ? 'agent gateway' : source === 'endpoint_agent' ? 'endpoint sensor' : source === 'proxy' ? 'network gateway' : 'browser gateway',
      label: sourceLabel(source),
      source,
      targetTab: 'coverage',
      action: 'Inspect sensor',
    }, {
      events,
      controlled: controlled ? events : 0,
      blocked: isBlocked(q) ? events : 0,
      redacted: isRedacted(q) ? events : 0,
      shadow: isShadowAi(q) ? events : 0,
      critical: severityForQuery(q) === 'critical' ? events : 0,
      riskScore: q.riskScore,
    });
    let assetId = null;
    if (destination && !NON_AI_INVENTORY_DESTINATIONS.has(destination)) {
      assetNames.add(destination);
      assetId = addNode({
        id: graphId('asset', destination),
        lane: 'assets',
        kind: source === 'mcp_guard' ? 'agent tool/model path' : 'AI destination',
        label: destination,
        source,
        targetTab: 'coverage',
        action: isShadowAi(q) ? 'Review destination' : 'Inspect asset',
      }, {
        events,
        controlled: controlled ? events : 0,
        blocked: isBlocked(q) ? events : 0,
        redacted: isRedacted(q) ? events : 0,
        shadow: isShadowAi(q) ? events : 0,
        critical: severityForQuery(q) === 'critical' ? events : 0,
        riskScore: q.riskScore,
      });
    }
    controlNames.add(control);
    const controlId = addNode({
      id: graphId('control', control),
      lane: 'controls',
      kind: 'control outcome',
      label: control,
      source: 'policy',
      targetTab: 'monitor',
      action: 'Inspect outcome',
    }, {
      events,
      controlled: controlled ? events : 0,
      blocked: isBlocked(q) ? events : 0,
      redacted: isRedacted(q) ? events : 0,
      coached: COACHING_STATUSES.has(String(q.status || '')) ? events : 0,
      shadow: isShadowAi(q) ? events : 0,
      critical: severityForQuery(q) === 'critical' ? events : 0,
      riskScore: q.riskScore,
    });
    addEdge(userId, gatewayId, 'uses', q);
    addEdge(gatewayId, assetId, source === 'mcp_guard' ? 'guards tool' : 'inspects', q);
    addEdge(assetId || gatewayId, controlId, controlled ? 'controlled by' : 'observed by', q);
  }

  const selectedNodes = [];
  const selected = new Set();
  for (const lane of laneDefs) {
    const rowsInLane = [...nodes.values()]
      .filter((node) => node.lane === lane.id)
      .sort((a, b) => n(b.riskScore) - n(a.riskScore) || n(b.events) - n(a.events) || String(a.label).localeCompare(String(b.label)))
      .slice(0, laneLimits.get(lane.id) || 6)
      .map((node) => {
        const clean = {
          id: node.id,
          lane: node.lane,
          kind: node.kind,
          label: node.label,
          status: graphStatusFromCounts(node),
          source: node.source,
          targetTab: node.targetTab,
          action: node.action,
          detail: graphDetail(node),
          events: n(node.events),
          riskScore: bound(node.riskScore),
          score: bound(node.score),
        };
        selected.add(clean.id);
        return clean;
      });
    selectedNodes.push(...rowsInLane);
  }

  const selectedEdges = [...edges.values()]
    .filter((edge) => selected.has(edge.from) && selected.has(edge.to))
    .sort((a, b) => n(b.riskScore) - n(a.riskScore) || n(b.events) - n(a.events) || String(a.label).localeCompare(String(b.label)))
    .slice(0, 24)
    .map((edge) => ({
      id: edge.id,
      from: edge.from,
      to: edge.to,
      label: edge.label,
      status: graphStatusFromCounts(edge),
      source: edge.source,
      detail: graphDetail(edge),
      events: n(edge.events),
      controlled: n(edge.controlled),
      riskScore: bound(edge.riskScore),
    }));

  const laneSummaries = laneDefs.map((lane) => {
    const laneNodes = selectedNodes.filter((node) => node.lane === lane.id);
    const attention = laneNodes.filter((node) => node.status === 'warning' || node.status === 'error').length;
    return {
      id: lane.id,
      label: lane.label,
      detail: lane.detail,
      count: laneNodes.length,
      attention,
    };
  });

  return {
    summary: {
      nodes: selectedNodes.length,
      edges: selectedEdges.length,
      highRiskAssets: n(inventory && inventory.summary && inventory.summary.highRiskAssets),
      shadowAssets: selectedNodes.filter((node) => node.lane === 'assets' && /shadow/.test(String(node.detail).toLowerCase())).length,
      mcpLinks: selectedEdges.filter((edge) => edge.source === 'mcp_guard').length,
      controlledLinks: selectedEdges.filter((edge) => n(edge.controlled) > 0).length,
      privacy: 'prompt bodies excluded',
    },
    lanes: laneSummaries,
    nodes: selectedNodes,
    edges: selectedEdges,
    catalog: {
      assets: [...assetNames].filter(Boolean).sort().slice(0, 20),
      controls: [...controlNames].filter(Boolean).sort().slice(0, 12),
    },
  };
}

const SEGMENT_TYPES = {
  org: 'Organization',
  group: 'Identity group',
  workflow: 'Review queue',
  source: 'Surface',
};

function segmentSafeLabel(value, fallback = '') {
  const text = safeText(value, fallback, 100);
  if (!text || text === fallback) return text;
  if (containsSensitiveMetadata(text)) return '';
  return text;
}

function segmentId(type, label) {
  const safeType = Object.prototype.hasOwnProperty.call(SEGMENT_TYPES, type) ? type : 'source';
  const safeLabel = segmentSafeLabel(label, '');
  if (!safeLabel) return '';
  return `${safeType}:${graphSlug(safeLabel)}`;
}

function normalizedSegmentId(value) {
  const text = String(value || '').trim().toLowerCase();
  return /^(org|group|workflow|source):[a-z0-9][a-z0-9-]{0,79}$/.test(text) ? text : '';
}

function identityGroupMap(identityGroups = {}) {
  if (identityGroups instanceof Map) return identityGroups;
  const map = new Map();
  if (!identityGroups || typeof identityGroups !== 'object') return map;
  for (const [user, groups] of Object.entries(identityGroups)) {
    const key = String(user || '').trim().toLowerCase();
    if (!key || !Array.isArray(groups)) continue;
    map.set(key, groups.map((group) => segmentSafeLabel(group, '')).filter(Boolean).slice(0, 8));
  }
  return map;
}

function rowIdentityGroups(row = {}, groupsByUser = new Map()) {
  const user = String(row.user || '').trim().toLowerCase();
  return user ? (groupsByUser.get(user) || []) : [];
}

function rowSegments(row = {}, identityGroups = {}) {
  const groupsByUser = identityGroups instanceof Map ? identityGroups : identityGroupMap(identityGroups);
  const segments = [];
  const add = (type, label) => {
    const cleanLabel = segmentSafeLabel(label, '');
    const id = segmentId(type, cleanLabel);
    if (!id || segments.some((item) => item.id === id)) return;
    segments.push({
      id,
      type,
      typeLabel: SEGMENT_TYPES[type] || 'Segment',
      label: cleanLabel,
    });
  };
  if (row.orgId) add('org', row.orgId);
  for (const group of rowIdentityGroups(row, groupsByUser)) add('group', group);
  if (row.assignedGroup) add('workflow', row.assignedGroup);
  if (row.source) add('source', sourceLabel(row.source));
  return segments;
}

function rowMatchesSegment(row = {}, segment, identityGroups = {}) {
  const id = normalizedSegmentId(segment);
  if (!id) return false;
  return rowSegments(row, identityGroups).some((item) => item.id === id);
}

function filterRowsBySegment(rows = [], segment, identityGroups = {}) {
  const id = normalizedSegmentId(segment);
  if (!id) return Array.isArray(rows) ? rows : [];
  return (Array.isArray(rows) ? rows : []).filter((row) => rowMatchesSegment(row, id, identityGroups));
}

function segmentState(row = {}) {
  if (n(row.pending) || n(row.maxRiskScore) >= 80) return 'critical';
  if (n(row.shadow) || n(row.sensitive) > n(row.controlled) || n(row.maxRiskScore) >= 40) return 'attention';
  return 'ready';
}

function finalizeSegment(row = {}) {
  const users = row.users instanceof Set ? row.users.size : n(row.users);
  const destinations = row.destinations instanceof Set ? row.destinations.size : n(row.destinations);
  const hasEvidence = n(row.events) > 0;
  const controlRate = n(row.sensitive) ? pct(row.controlled, row.sensitive) : hasEvidence ? 100 : 0;
  const score = hasEvidence ? bound(
    controlRate
      - Math.min(35, Math.round(n(row.maxRiskScore) / 3))
      - Math.min(25, n(row.shadow) * 5)
      - Math.min(30, n(row.pending) * 10),
  ) : 0;
  const state = hasEvidence ? segmentState({ ...row, score, controlRate }) : 'attention';
  return {
    id: row.id,
    type: row.type,
    typeLabel: row.typeLabel,
    label: row.label,
    state,
    score,
    events: n(row.events),
    sensitive: n(row.sensitive),
    controlled: n(row.controlled),
    blocked: n(row.blocked),
    redacted: n(row.redacted),
    coached: n(row.coached),
    pending: n(row.pending),
    shadow: n(row.shadow),
    controlRate,
    maxRiskScore: bound(row.maxRiskScore),
    users,
    destinations,
    lastSeen: row.lastSeen || null,
    detail: hasEvidence
      ? `${n(row.controlled)}/${n(row.sensitive)} sensitive controlled / ${users} user${users === 1 ? '' : 's'} / ${destinations} AI destination${destinations === 1 ? '' : 's'}`
      : 'Verified empty aggregate; no readiness score is available',
  };
}

function savedOwnerViews(matrix = [], selectedId = '', aggregate = finalizeSegment({
  id: 'all', type: 'all', typeLabel: 'All', label: 'All activity',
})) {
  const byId = new Map(matrix.map((item) => [item.id, item]));
  return OWNER_VIEW_TEMPLATES.map((template) => {
    const match = template.segmentCandidates.includes('all')
      ? aggregate
      : template.segmentCandidates.map((id) => byId.get(id)).find(Boolean);
    const fallbackSegmentId = template.segmentCandidates.map(normalizedSegmentId).find(Boolean) || 'all';
    const segmentId = match && match.id ? match.id : fallbackSegmentId;
    const hasSegment = !!(match && match.id && segmentId !== 'all');
    const hasAggregate = !!(match && match.id === 'all');
    return {
      id: template.id,
      segmentId,
      label: template.label,
      ownerGroup: template.ownerGroup,
      reviewerRole: template.reviewerRole,
      assignmentHint: template.assignmentHint,
      selected: segmentId === selectedId || (!selectedId && segmentId === 'all'),
      state: match ? match.state : 'attention',
      score: match ? match.score : 0,
      events: match ? match.events : 0,
      sensitive: match ? match.sensitive : 0,
      controlled: match ? match.controlled : 0,
      blocked: match ? match.blocked : 0,
      redacted: match ? match.redacted : 0,
      coached: match ? match.coached : 0,
      pending: match ? match.pending : 0,
      shadow: match ? match.shadow : 0,
      controlRate: match ? match.controlRate : 0,
      maxRiskScore: match ? match.maxRiskScore : 0,
      users: match ? match.users : 0,
      destinations: match ? match.destinations : 0,
      attention: match ? n(match.pending) + n(match.shadow) : 0,
      detail: hasSegment
        ? `${template.ownerGroup} / ${template.reviewerRole} / ${match.detail}`
        : hasAggregate
          ? `${template.ownerGroup} / ${template.reviewerRole} / ${match.detail}`
          : `${template.ownerGroup} / ${template.reviewerRole} / no matching segment yet`,
    };
  });
}

function ownerViewCards(views = []) {
  return views.map((view) => ({
    id: normalizedSegmentId(view.segmentId) || 'all',
    type: 'owner',
    typeLabel: 'Owner View',
    label: view.label,
    state: view.state,
    score: view.score,
    events: view.events,
    sensitive: view.sensitive,
    controlled: view.controlled,
    blocked: view.blocked,
    redacted: view.redacted,
    coached: view.coached,
    pending: view.pending,
    shadow: view.shadow,
    controlRate: view.controlRate,
    maxRiskScore: view.maxRiskScore,
    users: view.users,
    destinations: view.destinations,
    ownerViewId: view.id,
    ownerGroup: view.ownerGroup,
    reviewerRole: view.reviewerRole,
    assignmentHint: view.assignmentHint,
    detail: view.detail,
  }));
}

function emptySegmentBucket(extra = {}) {
  return {
    events: 0,
    sensitive: 0,
    controlled: 0,
    blocked: 0,
    redacted: 0,
    coached: 0,
    pending: 0,
    shadow: 0,
    maxRiskScore: 0,
    users: new Set(),
    destinations: new Set(),
    lastSeen: null,
    ...extra,
  };
}

function tallySegmentBucket(bucket, row, events) {
  const sensitive = isSensitive(row);
  const controlled = sensitive && (isBlocked(row) || isRedacted(row)
    || COACHING_STATUSES.has(row.status) || row.status === 'approved' || row.status === 'denied');
  bucket.events += events;
  bucket.sensitive += sensitive ? events : 0;
  bucket.controlled += controlled ? events : 0;
  bucket.blocked += isBlocked(row) ? events : 0;
  bucket.redacted += isRedacted(row) ? events : 0;
  bucket.coached += COACHING_STATUSES.has(row.status) ? events : 0;
  bucket.pending += isHeld(row) ? events : 0;
  bucket.shadow += isShadowAi(row) ? events : 0;
  bucket.maxRiskScore = Math.max(bucket.maxRiskScore, n(row.riskScore), n(row.maxSeverity) >= 4 ? 80 : 0);
  if (row.user && row.user !== 'unknown') bucket.users.add(safeText(row.user, '', 120));
  const destination = coverage.normalizeDestination(row.destination || '');
  if (destination && !NON_AI_INVENTORY_DESTINATIONS.has(destination)) bucket.destinations.add(destination);
  if (row.createdAt && (!bucket.lastSeen || String(row.createdAt) > String(bucket.lastSeen))) bucket.lastSeen = row.createdAt;
}

function postureSegments({ rows = [], selectedRows = [], segment = '', identityGroups = {} } = {}) {
  const groupsByUser = identityGroupMap(identityGroups);
  const buckets = new Map();
  const aggregateBucket = emptySegmentBucket({ id: 'all', type: 'all', typeLabel: 'All', label: 'All activity' });
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || EVENTLESS_STATUSES.has(row.status)) continue;
    const segments = rowSegments(row, groupsByUser);
    const events = eventWeight(row);
    tallySegmentBucket(aggregateBucket, row, events);
    for (const item of segments) {
      const bucket = buckets.get(item.id) || emptySegmentBucket(item);
      tallySegmentBucket(bucket, row, events);
      buckets.set(item.id, bucket);
    }
  }
  const fullMatrix = [...buckets.values()]
    .map(finalizeSegment)
    .sort((a, b) => {
      const rank = { critical: 0, attention: 1, ready: 2 };
      return (rank[a.state] ?? 3) - (rank[b.state] ?? 3)
        || b.maxRiskScore - a.maxRiskScore
        || b.events - a.events
        || a.label.localeCompare(b.label);
    });
  const selectedId = normalizedSegmentId(segment);
  const aggregate = finalizeSegment(aggregateBucket);
  const views = savedOwnerViews(fullMatrix, selectedId || 'all', aggregate);
  // Two owner templates can resolve to the same segment (or both fall back to
  // 'all'), so dedupe the owner cards by resolved id before concatenating —
  // otherwise the matrix carries duplicate ids and the console renders
  // duplicate React keys / double-selected cards.
  const seenCardIds = new Set();
  const ownerCards = ownerViewCards(views).filter((card) => {
    if (seenCardIds.has(card.id)) return false;
    seenCardIds.add(card.id);
    return true;
  });
  const displayMatrix = [
    ...ownerCards,
    ...fullMatrix.filter((item) => !seenCardIds.has(item.id)),
  ].slice(0, 16);
  const active = selectedId ? fullMatrix.find((item) => item.id === selectedId) || {
    id: selectedId,
    type: selectedId.split(':')[0],
    typeLabel: SEGMENT_TYPES[selectedId.split(':')[0]] || 'Segment',
    label: 'No matching segment',
    state: 'attention',
    score: 0,
    events: 0,
    sensitive: 0,
    controlled: 0,
    blocked: 0,
    redacted: 0,
    coached: 0,
    pending: 0,
    shadow: 0,
    controlRate: 0,
    maxRiskScore: 0,
    users: 0,
    destinations: 0,
    detail: 'Verified empty: no sanitized evidence matched this segment. This is not a readiness score.',
  } : null;
  const matrix = active && !displayMatrix.some((item) => item.id === active.id)
    ? [active, ...displayMatrix].slice(0, 16)
    : displayMatrix;
  const leadingFilters = fullMatrix.slice(0, 16);
  const filterSegments = active && !leadingFilters.some((item) => item.id === active.id)
    ? [active, ...leadingFilters].slice(0, 16)
    : leadingFilters;
  const filters = [
    {
      id: 'all',
      type: 'all',
      typeLabel: 'All',
      label: 'All segments',
      state: aggregate.state,
    },
    ...filterSegments,
  ].map((item) => ({
    id: item.id,
    type: item.type,
    typeLabel: item.typeLabel,
    label: item.label,
    state: item.state,
    events: item.events,
    controlRate: item.controlRate,
  }));
  return {
    active,
    filters,
    views,
    matrix,
    summary: {
      total: fullMatrix.length,
      ownerViews: views.length,
      critical: fullMatrix.filter((item) => item.state === 'critical').length,
      attention: fullMatrix.filter((item) => item.state === 'attention').length,
      ready: fullMatrix.filter((item) => item.state === 'ready').length,
      ownerCritical: views.filter((item) => item.state === 'critical').length,
      ownerAttention: views.filter((item) => item.state === 'attention').length,
      ownerReady: views.filter((item) => item.state === 'ready').length,
      selectedAttention: active && active.state !== 'ready' ? 1 : 0,
      selectedId: selectedId || 'all',
      selectedLabel: active ? active.label : 'All segments',
      visibleEvents: (Array.isArray(selectedRows) ? selectedRows : []).filter((row) => row && !EVENTLESS_STATUSES.has(row.status)).length,
      privacy: 'metadata only; prompt bodies excluded',
    },
  };
}

const LEAK_MAP_LIMITS = Object.freeze({ segments: 6, destinations: 8, edges: 18, categories: 6 });

function leakSegmentFor(row, groupsByUser) {
  const segments = rowSegments(row, groupsByUser);
  return segments.find((item) => item.type === 'group')
    || segments.find((item) => item.type === 'org')
    || { id: 'org:unassigned', type: 'org', typeLabel: SEGMENT_TYPES.org, label: 'Unassigned' };
}

function leakBucket(extra = {}) {
  return {
    events: 0, sensitive: 0, controlled: 0, blocked: 0, redacted: 0, coached: 0,
    pending: 0, shadow: 0, uncontrolled: 0, continued: 0, uncontrolledContinued: 0,
    maxRiskScore: 0, lastSeen: null, ...extra,
  };
}

function leakTally(bucket, row, events) {
  const sensitive = isSensitive(row);
  const controlled = sensitive && (isBlocked(row) || isRedacted(row) || COACHING_STATUSES.has(String(row.status || '')) || row.status === 'approved' || row.status === 'denied');
  const uncontrolled = sensitive && !controlled && !isHeld(row);
  bucket.events += events;
  bucket.sensitive += sensitive ? events : 0;
  bucket.controlled += controlled ? events : 0;
  bucket.blocked += isBlocked(row) ? events : 0;
  bucket.redacted += isRedacted(row) ? events : 0;
  bucket.coached += COACHING_STATUSES.has(String(row.status || '')) ? events : 0;
  bucket.pending += isHeld(row) ? events : 0;
  bucket.shadow += isShadowAi(row) ? events : 0;
  bucket.uncontrolled += uncontrolled ? events : 0;
  bucket.continued += isContinued(row) ? events : 0;
  bucket.uncontrolledContinued += uncontrolled && isContinued(row) ? events : 0;
  bucket.maxRiskScore = Math.max(n(bucket.maxRiskScore), n(row.riskScore), n(row.maxSeverity) >= 4 ? 80 : 0);
  if (row.createdAt && (!bucket.lastSeen || String(row.createdAt) > String(bucket.lastSeen))) bucket.lastSeen = row.createdAt;
}

function leakStatus(item) {
  if (n(item.uncontrolled) > 0 || n(item.shadow) > 0 || n(item.maxRiskScore) >= 80) return 'error';
  if (n(item.pending) > 0 || n(item.maxRiskScore) >= 40) return 'warning';
  if (n(item.events) > 0) return 'online';
  return 'idle';
}

function leakNode(bucket) {
  const users = bucket.users instanceof Set ? bucket.users.size : n(bucket.users);
  const { users: _users, via: _via, categories: _categories, ...rest } = bucket;
  return {
    ...rest,
    users,
    maxRiskScore: bound(bucket.maxRiskScore),
    controlRate: n(bucket.sensitive) ? pct(bucket.controlled, bucket.sensitive) : 100,
    status: leakStatus(bucket),
  };
}

function leakRank(a, b) {
  return (n(b.uncontrolled) + n(b.shadow)) - (n(a.uncontrolled) + n(a.shadow))
    || n(b.sensitive) - n(a.sensitive)
    || n(b.events) - n(a.events)
    || String(a.label || a.id).localeCompare(String(b.label || b.id));
}

function leakEdgeFinalize(edge) {
  const via = [...edge.via.entries()].sort((a, b) => b[1] - a[1]);
  const categories = [...edge.categories.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([label, events]) => ({ label, events }));
  const node = leakNode(edge);
  return {
    ...node,
    via: via.length ? via[0][0] : 'api',
    viaLabel: via.length ? sourceLabel(via[0][0]) : sourceLabel('api'),
    categories,
  };
}

function leakMapGraph({ rows = [], identityGroups = {}, inventory = {} } = {}) {
  const groupsByUser = identityGroupMap(identityGroups);
  const appState = new Map((inventory.apps || []).map((app) => [coverage.normalizeDestination(app.name), app.state]));
  const segments = new Map();
  const channels = new Map();
  const destinations = new Map();
  const edges = new Map();
  const categoryTotals = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    // This map is intentionally request-directional. AI response inspection
    // belongs to the response control surfaces, not a team-to-provider path.
    if (!row || EVENTLESS_STATUSES.has(row.status) || row.channel === 'ai_response' || String(row.status || '').startsWith('response_')) continue;
    const destination = coverage.normalizeDestination(row.destination || '');
    if (!destination || NON_AI_INVENTORY_DESTINATIONS.has(destination)) continue;
    const events = eventWeight(row);
    const seg = leakSegmentFor(row, groupsByUser);
    const source = safeText(row.source || 'api', 'api', 40);
    const segBucket = segments.get(seg.id)
      || leakBucket({ id: seg.id, label: seg.label || 'Unassigned', typeLabel: seg.typeLabel, users: new Set() });
    leakTally(segBucket, row, events);
    if (row.user && row.user !== 'unknown') segBucket.users.add(String(row.user).toLowerCase());
    segments.set(seg.id, segBucket);
    const chBucket = channels.get(source) || leakBucket({ id: source, label: sourceLabel(source) });
    leakTally(chBucket, row, events);
    channels.set(source, chBucket);
    const destBucket = destinations.get(destination)
      || leakBucket({ id: destination, label: destination, state: appState.get(destination) || 'observed' });
    if (isShadowAi(row) && !appState.get(destination)) destBucket.state = 'shadow';
    leakTally(destBucket, row, events);
    destinations.set(destination, destBucket);
    const edgeKey = `${seg.id}->${destination}`;
    const edge = edges.get(edgeKey)
      || leakBucket({ id: edgeKey, from: seg.id, to: destination, via: new Map(), categories: new Map() });
    leakTally(edge, row, events);
    edge.via.set(source, (edge.via.get(source) || 0) + events);
    for (const label of categoryLabels(row).slice(0, 4)) {
      edge.categories.set(label, (edge.categories.get(label) || 0) + events);
      categoryTotals.set(label, (categoryTotals.get(label) || 0) + events);
    }
    edges.set(edgeKey, edge);
  }
  const segmentRows = [...segments.values()].map(leakNode).sort(leakRank).slice(0, LEAK_MAP_LIMITS.segments);
  const destinationRows = [...destinations.values()].map(leakNode).sort(leakRank).slice(0, LEAK_MAP_LIMITS.destinations);
  const channelRows = [...channels.values()].map(leakNode).sort((a, b) => n(b.events) - n(a.events));
  const keptSegments = new Set(segmentRows.map((item) => item.id));
  const keptDestinations = new Set(destinationRows.map((item) => item.id));
  const edgeRows = [...edges.values()]
    .filter((edge) => keptSegments.has(edge.from) && keptDestinations.has(edge.to))
    .map(leakEdgeFinalize)
    .sort(leakRank)
    .slice(0, LEAK_MAP_LIMITS.edges);
  const categories = [...categoryTotals.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, LEAK_MAP_LIMITS.categories)
    .map(([label, events]) => ({ label, events }));
  const totals = leakNode([...edges.values()].reduce((acc, edge) => {
    for (const key of ['events', 'sensitive', 'controlled', 'blocked', 'redacted', 'coached', 'pending', 'shadow', 'uncontrolled', 'continued', 'uncontrolledContinued']) acc[key] += n(edge[key]);
    return acc;
  }, leakBucket({ id: 'all', label: 'All flows' })));
  return {
    segments: segmentRows,
    channels: channelRows,
    destinations: destinationRows,
    edges: edgeRows,
    categories,
    summary: {
      segments: segments.size,
      destinations: destinations.size,
      edges: edges.size,
      shownEdges: edgeRows.length,
      events: totals.events,
      sensitive: totals.sensitive,
      controlled: totals.controlled,
      uncontrolled: totals.uncontrolled,
      continued: totals.continued,
      uncontrolledContinued: totals.uncontrolledContinued,
      pending: totals.pending,
      shadow: totals.shadow,
      controlRate: totals.controlRate,
      status: totals.status,
      privacy: 'prompt bodies excluded',
    },
  };
}

function competitiveState(score) {
  const value = bound(score);
  if (value >= 90) return 'leader';
  if (value >= 75) return 'pilot_ready';
  if (value >= 55) return 'close_gap';
  return 'gap';
}

function competitiveStatus(state) {
  if (state === 'leader' || state === 'pilot_ready') return 'online';
  if (state === 'close_gap') return 'warning';
  return 'error';
}

function competitiveRow({
  id,
  label,
  marketBar,
  score,
  evidence = [],
  gaps = [],
  action = 'Review',
  targetTab = 'monitor',
  source = 'posture',
}) {
  const cleanEvidence = evidence.filter(Boolean).map((item) => safeText(item, '', 180)).filter(Boolean).slice(0, 4);
  const cleanGaps = gaps.filter(Boolean).map((item) => safeText(item, '', 180)).filter(Boolean).slice(0, 4);
  const state = competitiveState(score);
  return {
    id,
    label,
    marketBar: safeText(marketBar, 'market readiness', 220),
    score: bound(score),
    state,
    status: competitiveStatus(state),
    evidence: cleanEvidence,
    gaps: cleanGaps,
    action: safeText(action, 'Review', 80),
    targetTab: safeText(targetTab, 'monitor', 40),
    source: safeText(source, 'posture', 80),
    detail: cleanGaps.length
      ? `${cleanGaps.length} gap${cleanGaps.length === 1 ? '' : 's'} to close`
      : `${cleanEvidence.length} proof point${cleanEvidence.length === 1 ? '' : 's'} ready`,
  };
}

function competitiveReadiness({
  rows = [],
  policy = {},
  coverageReport = {},
  auditIntegrity = null,
  hardening = {},
  inventory = {},
  agenticMcp = {},
  threatReport = {},
  postureSummary = {},
  segments = {},
  behavior = {},
  env = process.env,
} = {}) {
  const totals = (coverageReport && coverageReport.totals) || {};
  const controlConfig = configuredActionControls(policy);
  const actionFamilyCount = Object.values(controlConfig).filter(Boolean).length;
  const requiredSensors = n(totals.requiredSensors);
  const activeRequiredSensors = n(totals.activeRequiredSensors);
  const sensorScore = requiredSensors ? pct(activeRequiredSensors, requiredSensors) : 0;
  const inventorySummary = (inventory && inventory.summary) || {};
  const mcpSummary = (agenticMcp && agenticMcp.summary) || {};
  const mcpPolicy = (agenticMcp && agenticMcp.policy) || {};
  const threatSummary = (threatReport && threatReport.summary) || {};
  const behaviorSummary = (behavior && behavior.summary) || {};
  const defaultDeny = policy.blockUnapprovedAiDestinations === true;
  const responseScan = policy.responseScanMode && policy.responseScanMode !== 'allow';
  const governedTotal = n(totals.governedDestinations);
  const shadowEvents = n(totals.shadowEvents);
  const unresolvedShadow = n(totals.unresolvedShadowDestinations);
  const endpointInventories = n(totals.endpointAiInventoryReports);
  const endpointToolsUnapproved = n(totals.endpointAiToolUnapproved);
  const fileFlowProfiles = n(totals.endpointFileFlowProfiles);
  const fileFlowAttention = n(totals.endpointFileFlowAttention);
  const desktop = controlReadiness.desktopReadiness({ policy, coverageReport });
  const soc = controlReadiness.socReadiness({ policy, auditIntegrity, env, postureFeedSupported: true });
  const hardeningAreas = Array.isArray(hardening.areas) ? hardening.areas : [];
  const gatewayArea = hardeningAreas.find((area) => area.id === 'ai_gateway_enforcement') || {};

  const dlpScore = bound(
    (n(postureSummary.controlRate) * 0.45)
    + (pct(actionFamilyCount, 4) * 0.25)
    + (responseScan ? 15 : 0)
    + (n(threatSummary.sensitiveDisclosure) || n(postureSummary.sensitiveEvents) ? 15 : 0)
  );
  const visibilityScore = bound(
    (sensorScore * 0.35)
    + (governedTotal ? 20 : 0)
    + (endpointInventories ? 15 : 0)
    + ((shadowEvents || n(inventorySummary.shadow)) ? 15 : 0)
    + (segments && segments.summary && n(segments.summary.total) ? 15 : 0)
  );
  const shadowScore = bound(
    (defaultDeny ? 35 : 0)
    + ((shadowEvents || n(inventorySummary.shadow)) ? 20 : 0)
    + (unresolvedShadow ? Math.max(0, 30 - unresolvedShadow * 12) : 30)
    + (governedTotal ? 15 : 0)
  );
  const mcpPolicyCount = n(mcpPolicy.allowed && mcpPolicy.allowed.count)
    + n(mcpPolicy.blocked && mcpPolicy.blocked.count)
    + n(mcpPolicy.approvalRequired && mcpPolicy.approvalRequired.count);
  const mcpScore = bound(
    (mcpSummary.events ? 25 : 0)
    + (mcpPolicyCount ? 30 : 0)
    + (mcpSummary.controlled ? 20 : 0)
    + (responseScan ? 15 : 0)
    + (mcpSummary.outsideRegistry ? 0 : 10)
  );
  const desktopScore = bound(
    (desktop.score * 0.8)
    + (fileFlowProfiles && !fileFlowAttention ? 12 : fileFlowProfiles ? 6 : 0)
    + (endpointToolsUnapproved ? 0 : endpointInventories ? 8 : 0)
  );
  const socScore = bound(
    (soc.score * 0.78)
    + (auditIntegrity && auditIntegrity.ok ? 10 : 0)
    + 12
  );

  const matrix = [
    competitiveRow({
      id: 'real_time_dlp',
      label: 'Real-time AI DLP',
      marketBar: 'Pre-submit prompt, file, response, and browser-action controls with user coaching.',
      score: dlpScore,
      evidence: [
        `${n(postureSummary.controlRate)}% sensitive-event control rate`,
        `${actionFamilyCount}/4 action-control families configured`,
        responseScan && `Response scan mode: ${safeText(policy.responseScanMode, 'configured', 40)}`,
        n(threatSummary.sensitiveDisclosure) && `${n(threatSummary.sensitiveDisclosure)} sensitive-disclosure detections`,
      ],
      gaps: [
        n(postureSummary.controlRate) < 100 && 'Investigate sensitive events that were not blocked, redacted, coached, approved, or denied',
        actionFamilyCount < 4 && 'Configure all prompt, file, response, and browser-action control families',
        !responseScan && 'Enable AI response scanning before broad pilot rollout',
      ],
      action: actionFamilyCount < 4 || !responseScan ? 'Configure controls' : 'Review lineage',
      targetTab: actionFamilyCount < 4 || !responseScan ? 'policy' : 'lineage',
      source: 'policy',
    }),
    competitiveRow({
      id: 'ai_usage_visibility',
      label: 'AI Usage Visibility',
      marketBar: 'Unified view of users, AI apps, local tools, sensors, trends, and segments.',
      score: visibilityScore,
      evidence: [
        `${activeRequiredSensors}/${requiredSensors || 0} required sensors active`,
        governedTotal && `${governedTotal} governed AI destinations`,
        endpointInventories && `${endpointInventories} endpoint AI inventory heartbeat${endpointInventories === 1 ? '' : 's'}`,
        segments && segments.summary && n(segments.summary.total) && `${n(segments.summary.total)} metadata segments`,
      ],
      gaps: [
        requiredSensors && activeRequiredSensors < requiredSensors && 'Bring every required sensor online',
        !governedTotal && 'Seed the governed AI destination catalog',
        !endpointInventories && 'Enable endpoint AI tool inventory heartbeat',
        !(segments && segments.summary && n(segments.summary.total)) && 'Connect identity or workflow metadata for owner views',
      ],
      action: 'Open coverage',
      targetTab: 'coverage',
      source: 'coverage',
    }),
    competitiveRow({
      id: 'shadow_ai_governance',
      label: 'Shadow-AI Governance',
      marketBar: 'Discover unapproved AI destinations and convert them into allow, govern, or block decisions.',
      score: shadowScore,
      evidence: [
        defaultDeny && 'Default-deny for unapproved AI destinations is enabled',
        shadowEvents && `${shadowEvents} shadow-AI sighting${shadowEvents === 1 ? '' : 's'} recorded`,
        !unresolvedShadow && 'No unresolved shadow-AI destinations',
        governedTotal && `${governedTotal} destinations already governed`,
      ],
      gaps: [
        !defaultDeny && 'Enable default-deny for unapproved AI destinations',
        unresolvedShadow && `Review ${unresolvedShadow} unresolved shadow-AI destination${unresolvedShadow === 1 ? '' : 's'}`,
        !governedTotal && 'Add sanctioned AI destinations before allowing broad AI usage',
      ],
      action: unresolvedShadow ? 'Review destinations' : 'Keep watchlist current',
      targetTab: 'coverage',
      source: 'shadow_ai',
    }),
    competitiveRow({
      id: 'behavior_anomaly_baselines',
      label: 'Behavioral Anomaly Baselines',
      marketBar: 'Detect unusual AI usage spikes by user, destination, sensor surface, and detector family before incidents become normal.',
      score: n(behaviorSummary.score),
      evidence: [
        n(behaviorSummary.anomalies) ? `${n(behaviorSummary.anomalies)} metadata baseline anomaly${n(behaviorSummary.anomalies) === 1 ? '' : 'ies'} detected` : 'No open baseline anomalies',
        `${n(behaviorSummary.recentWindowHours) || 24}h recent window compared with ${n(behaviorSummary.baselineDays) || WINDOW_DAYS - 1} baseline day${(n(behaviorSummary.baselineDays) || WINDOW_DAYS - 1) === 1 ? '' : 's'}`,
        behavior && behavior.privacy,
      ],
      gaps: [
        behaviorSummary.state === 'gap' && 'Run live sensor traffic before behavioral baselines can learn normal activity',
        n(behaviorSummary.critical) && `Investigate ${n(behaviorSummary.critical)} critical behavior baseline anomaly${n(behaviorSummary.critical) === 1 ? '' : 'ies'}`,
        n(behaviorSummary.warning) && `Review ${n(behaviorSummary.warning)} warning behavior baseline anomaly${n(behaviorSummary.warning) === 1 ? '' : 'ies'}`,
      ],
      action: n(behaviorSummary.anomalies) ? 'Review baselines' : 'Inspect posture',
      targetTab: 'monitor',
      source: 'behavior_baseline',
    }),
    competitiveRow({
      id: 'agent_mcp_governance',
      label: 'Agent And MCP Governance',
      marketBar: 'Control agent tool calls, tool-output redaction, response scanning, and registry drift.',
      score: mcpScore,
      evidence: [
        mcpSummary.events && `${n(mcpSummary.events)} MCP or agent event${n(mcpSummary.events) === 1 ? '' : 's'}`,
        mcpPolicyCount && `${mcpPolicyCount} MCP registry rule${mcpPolicyCount === 1 ? '' : 's'}`,
        mcpSummary.controlled && `${n(mcpSummary.controlled)} MCP outputs blocked or redacted`,
        responseScan && 'Agent output response scanning is active',
      ],
      gaps: [
        !mcpSummary.events && 'Run an MCP guard smoke through a real client or connector',
        !mcpPolicyCount && 'Define MCP allow, block, or approval-required tool rules',
        !responseScan && 'Scan AI responses and agent outputs before release',
        mcpSummary.outsideRegistry && `Review ${n(mcpSummary.outsideRegistry)} outside-registry tool${n(mcpSummary.outsideRegistry) === 1 ? '' : 's'}`,
      ],
      action: mcpPolicyCount ? 'Inspect MCP' : 'Configure MCP',
      targetTab: mcpPolicyCount ? 'monitor' : 'policy',
      source: 'mcp_guard',
    }),
    competitiveRow({
      id: 'desktop_file_flow',
      label: 'Desktop And File-Flow Coverage',
      marketBar: 'Govern desktop AI apps, local tool inventory, protected uploads, clipboard, Git, and watched folders.',
      score: desktopScore,
      evidence: [
        ...(desktop.evidence || []).slice(0, 2),
        fileFlowProfiles && `${fileFlowProfiles} named file-flow profile${fileFlowProfiles === 1 ? '' : 's'}`,
        endpointInventories && !endpointToolsUnapproved && 'Endpoint AI tool inventory is clean',
      ],
      gaps: [
        ...(desktop.gaps || []).slice(0, 2),
        !fileFlowProfiles && 'Configure named endpoint file-flow watcher profiles',
        fileFlowAttention && `Fix ${fileFlowAttention} file-flow profile path check${fileFlowAttention === 1 ? '' : 's'}`,
        endpointToolsUnapproved && `Review ${endpointToolsUnapproved} unapproved endpoint AI tool${endpointToolsUnapproved === 1 ? '' : 's'}`,
      ],
      action: desktop.action || 'Open coverage',
      targetTab: desktop.targetTab || 'coverage',
      source: 'endpoint_agent',
    }),
    competitiveRow({
      id: 'soc_compliance_handoff',
      label: 'SOC And Examiner Handoff',
      marketBar: 'SOC package, posture feed, approval workflow routing, evidence export, and audit-chain proof.',
      score: socScore,
      evidence: [
        'Offline SOC integration ZIP is available',
        ...(soc.evidence || []).slice(0, 3),
        gatewayArea.score >= 90 && 'Gateway hardening proof is ready',
      ],
      gaps: [
        ...(soc.gaps || []).slice(0, 3),
        gatewayArea.score < 90 && 'Complete AI gateway enforcement proof before production SOC handoff',
      ],
      action: soc.action || 'Open audit',
      targetTab: soc.targetTab || 'audit',
      source: 'siem',
    }),
  ];
  const ready = matrix.filter((row) => row.state === 'leader' || row.state === 'pilot_ready').length;
  const score = matrix.length ? bound(matrix.reduce((sum, row) => sum + row.score, 0) / matrix.length) : 0;
  const state = competitiveState(score);
  return {
    generatedAt: new Date().toISOString(),
    summary: {
      score,
      state,
      status: competitiveStatus(state),
      ready,
      attention: matrix.filter((row) => row.state === 'close_gap').length,
      gaps: matrix.filter((row) => row.state === 'gap').length,
      total: matrix.length,
      privacy: 'metadata only; prompt bodies excluded',
    },
    matrix,
    differentiators: [
      'Local-first detection and redaction before AI egress',
      'Browser, endpoint, gateway, and MCP coverage from one policy',
      'Examiner-ready evidence without raw prompt retention by default',
    ],
    nextGaps: matrix
      .filter((row) => row.gaps.length)
      .sort((a, b) => a.score - b.score || a.label.localeCompare(b.label))
      .slice(0, 4)
      .map((row, index) => ({
        id: row.id,
        priority: index + 1,
        label: row.label,
        detail: row.gaps[0],
        action: row.action,
        targetTab: row.targetTab,
        score: row.score,
      })),
  };
}

function competitiveById(readiness = {}) {
  const map = new Map();
  for (const row of Array.isArray(readiness.matrix) ? readiness.matrix : []) {
    if (row && row.id) map.set(row.id, row);
  }
  return map;
}

function focusLane({
  id,
  label,
  marketBar,
  score,
  evidence = [],
  gaps = [],
  action,
  targetTab,
  anchor,
}) {
  const state = competitiveState(score);
  return {
    id,
    label: safeText(label, 'Control focus', 140),
    marketBar: safeText(marketBar, 'control focus area', 240),
    score: bound(score),
    state,
    status: competitiveStatus(state),
    evidence: evidence.filter(Boolean).map((item) => safeText(item, '', 180)).filter(Boolean).slice(0, 5),
    gaps: gaps.filter(Boolean).map((item) => safeText(item, '', 180)).filter(Boolean).slice(0, 5),
    action: safeText(action, 'Open work area', 80),
    targetTab: safeText(targetTab, 'monitor', 40),
    anchor: safeText(anchor, '', 80),
  };
}

function competitiveFocus({
  competitiveReadiness: readiness = {},
  coverageReport = {},
  inventory = {},
  agenticMcp = {},
  threatReport = {},
  detectorFeedbackReport = {},
  detectionQualityReport = {},
  policy = {},
} = {}) {
  const matrix = competitiveById(readiness);
  const totals = (coverageReport && coverageReport.totals) || {};
  const sensors = Array.isArray(coverageReport && coverageReport.sensors) ? coverageReport.sensors : [];
  const discoveryFeeds = Array.isArray(coverageReport && coverageReport.discoveryFeeds) ? coverageReport.discoveryFeeds : [];
  const inventorySummary = (inventory && inventory.summary) || {};
  const mcpSummary = (agenticMcp && agenticMcp.summary) || {};
  const mcpPolicy = (agenticMcp && agenticMcp.policy) || {};
  const mcpRegistry = (agenticMcp && agenticMcp.connectorRegistry && agenticMcp.connectorRegistry.summary) || {};
  const threatSummary = (threatReport && threatReport.summary) || {};
  const feedbackSummary = (detectorFeedbackReport && detectorFeedbackReport.summary) || {};
  const qualitySummary = (detectionQualityReport && detectionQualityReport.summary) || {};
  const feedbackDetectors = Array.isArray(detectorFeedbackReport && detectorFeedbackReport.detectors)
    ? detectorFeedbackReport.detectors
    : [];
  const reviewQueue = Array.isArray(detectorFeedbackReport && detectorFeedbackReport.reviewQueue)
    ? detectorFeedbackReport.reviewQueue
    : [];
  const sourceNames = sensors
    .filter((sensor) => n(sensor && sensor.events))
    .map((sensor) => safeText(sensor.source, '', 80))
    .filter(Boolean);
  const hasProxyDiscovery = sourceNames.includes('proxy') || n(totals.shadowEvents) > 0;
  const freshDiscoveryFeeds = n(totals.freshDiscoveryFeeds);
  const staleDiscoveryFeeds = n(totals.staleDiscoveryFeeds);
  const defaultDeny = policy.blockUnapprovedAiDestinations === true;
  const mcpPolicyCount = n(mcpPolicy.allowed && mcpPolicy.allowed.count)
    + n(mcpPolicy.blocked && mcpPolicy.blocked.count)
    + n(mcpPolicy.approvalRequired && mcpPolicy.approvalRequired.count);
  const reviewedDetectors = n(feedbackSummary.total);
  const validated = n(feedbackSummary.valid);
  const noisy = n(feedbackSummary.noisy) + n(feedbackSummary.missed);
  const feedbackCoverage = reviewedDetectors
    ? Math.max(20, Math.min(90, (validated * 12) + Math.max(0, 30 - noisy * 8)))
    : (reviewQueue.length ? 25 : 0);
  const detectionQualityScore = bound(
    ((matrix.get('real_time_dlp') && matrix.get('real_time_dlp').score) || 0) * 0.4
    + (n(threatSummary.activeRules) ? 20 : 0)
    + (n(threatSummary.sensitiveDisclosure) || n(threatSummary.detections) ? 15 : 0)
    + (feedbackCoverage * 0.2)
    + (n(qualitySummary.score) * 0.2)
  );

  const lanes = [
    focusLane({
      id: 'continuous_shadow_ai_discovery',
      label: 'Continuous Shadow-AI Discovery',
      marketBar: 'Show every AI app, user, sensor, and unapproved destination before data leaves the environment.',
      score: bound((((matrix.get('ai_usage_visibility') && matrix.get('ai_usage_visibility').score) || 0)
        + ((matrix.get('shadow_ai_governance') && matrix.get('shadow_ai_governance').score) || 0)) / 2),
      evidence: [
        defaultDeny && 'Default-deny for unapproved AI destinations',
        `${n(totals.shadowEvents)} shadow-AI sighting${n(totals.shadowEvents) === 1 ? '' : 's'}`,
        discoveryFeeds.length && `${freshDiscoveryFeeds}/${discoveryFeeds.length} fresh discovery feed${discoveryFeeds.length === 1 ? '' : 's'}`,
        totals.lastDiscoveryAt && `Last discovery import ${String(totals.lastDiscoveryAt).slice(0, 10)}`,
        `${n(totals.unresolvedShadowDestinations)} unresolved shadow destination${n(totals.unresolvedShadowDestinations) === 1 ? '' : 's'}`,
        sourceNames.length && `Active discovery sources: ${sourceNames.slice(0, 4).join(', ')}`,
        n(inventorySummary.highRiskAssets) && `${n(inventorySummary.highRiskAssets)} high-risk AI asset${n(inventorySummary.highRiskAssets) === 1 ? '' : 's'}`,
      ],
      gaps: [
        !hasProxyDiscovery && 'Import proxy, SSE, firewall, or browser-isolation AI sightings continuously',
        !discoveryFeeds.length && 'Schedule a recurring host-only discovery import feed',
        staleDiscoveryFeeds && `Refresh ${staleDiscoveryFeeds} stale discovery feed${staleDiscoveryFeeds === 1 ? '' : 's'}`,
        !defaultDeny && 'Turn on default-deny for unapproved AI destinations',
        n(totals.unresolvedShadowDestinations) && `Review ${n(totals.unresolvedShadowDestinations)} shadow-AI destination${n(totals.unresolvedShadowDestinations) === 1 ? '' : 's'}`,
        !sourceNames.length && 'Bring browser, endpoint, MCP, or proxy sensors online',
      ],
      action: n(totals.unresolvedShadowDestinations) ? 'Review shadow AI' : 'Import discovery feed',
      targetTab: 'coverage',
      anchor: 'shadowRows',
    }),
    focusLane({
      id: 'mcp_saas_connector_coverage',
      label: 'MCP And SaaS Connector Coverage',
      marketBar: 'Wrap SaaS and MCP tool responses with allow/block policy, redaction, connector health, and registry drift proof.',
      score: bound(
        (((matrix.get('agent_mcp_governance') && matrix.get('agent_mcp_governance').score) || 0) * 0.72)
        + (n(mcpSummary.activeTools) >= 3 ? 10 : n(mcpSummary.activeTools) ? 5 : 0)
        + (mcpPolicyCount ? 10 : 0)
        + (n(mcpSummary.controlled) ? 8 : 0)
        + (n(mcpRegistry.shipped) >= 6 ? 8 : n(mcpRegistry.shipped) ? 4 : 0)
        + (n(mcpRegistry.shippedRuntimePresent) >= n(mcpRegistry.shipped) && n(mcpRegistry.shipped) ? 4 : 0)
        + (mcpRegistry.installProof ? 2 : 0)
      ),
      evidence: [
        `${n(mcpSummary.activeAgents)} active MCP agent${n(mcpSummary.activeAgents) === 1 ? '' : 's'}`,
        `${n(mcpSummary.activeTools)} active MCP tool${n(mcpSummary.activeTools) === 1 ? '' : 's'}`,
        n(mcpRegistry.shipped) && `${n(mcpRegistry.shipped)} shipped connector profile${n(mcpRegistry.shipped) === 1 ? '' : 's'}`,
        n(mcpRegistry.shippedRuntimePresent) && `${n(mcpRegistry.shippedRuntimePresent)} connector runtime${n(mcpRegistry.shippedRuntimePresent) === 1 ? '' : 's'} packaged`,
        mcpRegistry.installProof && 'MCP install heartbeat includes connector registry proof',
        !n(mcpRegistry.profileTemplates) && n(mcpRegistry.shipped) && 'Connector catalog has no template-only profiles',
        mcpPolicyCount && `${mcpPolicyCount} allow/block/approval registry rule${mcpPolicyCount === 1 ? '' : 's'}`,
        n(mcpSummary.controlled) && `${n(mcpSummary.controlled)} MCP output${n(mcpSummary.controlled) === 1 ? '' : 's'} blocked or redacted`,
      ],
      gaps: [
        !n(mcpSummary.events) && 'Run real MCP guard traffic from at least one SaaS connector',
        !mcpRegistry.installProof && 'Run MCP install check with connector registry heartbeat proof',
        n(mcpRegistry.shippedRuntimePresent) < 1 && 'Package at least one shipped MCP connector runtime',
        n(mcpRegistry.shippedRuntimePresent) < n(mcpRegistry.shipped) && 'Package every shipped connector runtime in the MCP guard artifact',
        n(mcpRegistry.profileTemplates) && 'Convert remaining template-only connector profiles into runtime connectors',
        n(mcpSummary.activeTools) < 3 && 'Add connector coverage beyond the first Microsoft 365-style path',
        !mcpPolicyCount && 'Define MCP allow, block, or approval-required tool rules',
        n(mcpSummary.outsideRegistry) && `Review ${n(mcpSummary.outsideRegistry)} outside-registry MCP tool${n(mcpSummary.outsideRegistry) === 1 ? '' : 's'}`,
      ],
      action: mcpPolicyCount ? 'Inspect MCP control' : 'Configure MCP rules',
      targetTab: mcpPolicyCount ? 'monitor' : 'policy',
      anchor: 'agenticMcpRows',
    }),
    focusLane({
      id: 'detection_quality_proof',
      label: 'Detection Quality Proof',
      marketBar: 'Prove sensitive-data, prompt-injection, response, and custom-detector accuracy with reviewed tuning signals.',
      score: detectionQualityScore,
      evidence: [
        `${n(threatSummary.activeRules)} active threat guardrail${n(threatSummary.activeRules) === 1 ? '' : 's'}`,
        `${n(threatSummary.detections)} detection${n(threatSummary.detections) === 1 ? '' : 's'} in posture window`,
        qualitySummary.floorsMet && `Held-out eval floors met at ${n(qualitySummary.score)}/100`,
        reviewedDetectors && `${reviewedDetectors} reviewed detector signal${reviewedDetectors === 1 ? '' : 's'}`,
        validated && `${validated} validated detection${validated === 1 ? '' : 's'}`,
        n(qualitySummary.semanticRecall) && `Semantic recall ${n(qualitySummary.semanticRecall)}%`,
        n(qualitySummary.structuredRecall) && `Structured recall ${n(qualitySummary.structuredRecall)}%`,
        feedbackDetectors.length && `${feedbackDetectors.length} detector${feedbackDetectors.length === 1 ? '' : 's'} with tuning history`,
      ],
      gaps: [
        qualitySummary.floorsMet === false && 'Fix held-out eval floor failures before claiming detection quality',
        n(qualitySummary.benignFalsePositives) && `Fix ${n(qualitySummary.benignFalsePositives)} benign eval false positive${n(qualitySummary.benignFalsePositives) === 1 ? '' : 's'}`,
        n(qualitySummary.baitFalsePositives) && `Fix ${n(qualitySummary.baitFalsePositives)} structured bait false positive${n(qualitySummary.baitFalsePositives) === 1 ? '' : 's'}`,
        !reviewedDetectors && 'Review detector candidates as valid, noisy, too sensitive, or missed',
        reviewQueue.length && `Work ${reviewQueue.length} detector review candidate${reviewQueue.length === 1 ? '' : 's'}`,
        !n(threatSummary.promptInjection) && 'Add prompt-injection evaluation proof to the current posture window',
        !n(threatSummary.sensitiveDisclosure) && 'Add sensitive-disclosure proof to the current posture window',
      ],
      action: reviewedDetectors ? 'Inspect feedback' : 'Review detections',
      targetTab: 'monitor',
      anchor: 'detectorFeedbackRows',
    }),
  ];
  const ready = lanes.filter((lane) => lane.state === 'leader' || lane.state === 'pilot_ready').length;
  const score = lanes.length ? bound(lanes.reduce((sum, lane) => sum + lane.score, 0) / lanes.length) : 0;
  const next = lanes
    .filter((lane) => lane.gaps.length)
    .sort((a, b) => a.score - b.score || a.label.localeCompare(b.label))[0] || lanes[0] || null;
  return {
    summary: {
      score,
      state: competitiveState(score),
      status: competitiveStatus(competitiveState(score)),
      ready,
      total: lanes.length,
      nextAction: next ? next.action : 'Keep monitoring',
      nextLane: next ? next.label : 'All lanes ready',
      objective: 'Close the highest-impact control gaps across discovery, connector coverage, and detection proof',
      privacy: 'metadata only; prompt bodies excluded',
    },
    lanes,
    playbook: lanes.map((lane, index) => ({
      id: `market-step-${lane.id}`,
      priority: index + 1,
      label: lane.action,
      detail: lane.gaps[0] || `${lane.label} has enough pilot proof`,
      targetTab: lane.targetTab,
      anchor: lane.anchor,
      validation: lane.id === 'continuous_shadow_ai_discovery'
        ? 'Coverage and Shadow AI panels show imported host-only sightings'
        : lane.id === 'mcp_saas_connector_coverage'
          ? 'Agentic MCP Control shows tools, registry state, and blocked/redacted counts'
          : 'Detection Feedback shows reviewed detector signals without prompt bodies',
    })),
  };
}

function metrics({ rows, coverageReport, auditIntegrity, nowMs }) {
  const totals = (coverageReport && coverageReport.totals) || {};
  const sensitiveRows = rows.filter(isSensitive);
  const blocked = rows.filter(isBlocked).length;
  const redacted = rows.filter(isRedacted).length;
  const controlled = sensitiveRows.filter((q) => isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(q.status) || q.status === 'approved' || q.status === 'denied').length;
  const avgRisk = sensitiveRows.length
    ? Math.round(sensitiveRows.reduce((sum, q) => sum + n(q.riskScore), 0) / sensitiveRows.length)
    : 0;
  const pending = rows.filter(isHeld).length;
  return [
    {
      id: 'active-sensors',
      label: 'Active sensors',
      value: `${n(totals.activeRequiredSensors)}/${n(totals.requiredSensors)}`,
      unit: '',
      trend: n(totals.fleetAttention) ? 'decreased' : 'neutral',
      status: n(totals.activeRequiredSensors) >= n(totals.requiredSensors) && !n(totals.fleetAttention) ? 'normal' : 'warning',
      lastUpdated: new Date(nowMs).toISOString(),
    },
    {
      id: 'controlled-sensitive',
      label: 'Control rate',
      value: sensitiveRows.length ? pct(controlled, sensitiveRows.length) : 100,
      unit: '%',
      trend: 'neutral',
      status: sensitiveRows.length && controlled < sensitiveRows.length ? 'warning' : 'normal',
      lastUpdated: new Date(nowMs).toISOString(),
    },
    {
      id: 'risk-pressure',
      label: 'Risk pressure',
      value: avgRisk,
      unit: '/100',
      trend: avgRisk > 50 ? 'increased' : 'neutral',
      status: avgRisk >= 70 ? 'critical' : avgRisk >= 35 ? 'warning' : 'normal',
      lastUpdated: new Date(nowMs).toISOString(),
    },
    {
      id: 'critical-holds',
      label: 'Active holds',
      value: pending,
      unit: '',
      trend: pending ? 'increased' : 'neutral',
      status: pending ? 'critical' : 'normal',
      lastUpdated: new Date(nowMs).toISOString(),
    },
    {
      id: 'guardrail-actions',
      label: 'Guardrail actions',
      value: blocked + redacted,
      unit: '',
      trend: blocked + redacted ? 'increased' : 'neutral',
      status: blocked + redacted ? 'warning' : 'normal',
      lastUpdated: new Date(nowMs).toISOString(),
    },
    {
      id: 'audit-chain',
      label: 'Audit chain',
      value: auditIntegrity && auditIntegrity.ok ? n(auditIntegrity.count) : 'Fail',
      unit: '',
      trend: auditIntegrity && auditIntegrity.ok ? 'neutral' : 'decreased',
      status: auditIntegrity && auditIntegrity.ok ? 'normal' : 'critical',
      lastUpdated: new Date(nowMs).toISOString(),
    },
  ];
}

function summarize({
  rows = [],
  policy = {},
  coverageReport = null,
  auditIntegrity = null,
  actionStates = {},
  now = new Date(),
  env = process.env,
  segmentId = '',
  identityGroups = {},
  detectorFeedbackReport = null,
  detectionQualityReport = null,
} = {}) {
  const nowDate = now instanceof Date ? now : new Date(now);
  const nowMs = Number.isFinite(nowDate.getTime()) ? nowDate.getTime() : Date.now();
  const sourceRows = Array.isArray(rows) ? rows : [];
  const selectedSegmentId = normalizedSegmentId(segmentId);
  const groupsByUser = identityGroupMap(identityGroups);
  const cleanRows = selectedSegmentId ? filterRowsBySegment(sourceRows, selectedSegmentId, groupsByUser) : sourceRows;
  const report = coverageReport && !selectedSegmentId ? coverageReport : coverage.summarize(cleanRows, policy);
  const hardening = controlReadiness.summarize({
    rows: cleanRows,
    policy,
    coverageReport: report,
    auditIntegrity,
    env,
  });
  const sensitiveRows = cleanRows.filter(isSensitive);
  const blockedRows = cleanRows.filter(isBlocked);
  const redactedRows = cleanRows.filter(isRedacted);
  const coachedRows = cleanRows.filter((q) => COACHING_STATUSES.has(q.status));
  const pendingRows = cleanRows.filter(isHeld);
  const agenticMcp = agenticMcpPosture({ rows: cleanRows, policy });
  const inventory = aiInventory({ coverageReport: report, agenticMcp });
  const threatReport = threatGuardrails({ rows: cleanRows, policy });
  const behavior = behaviorBaselines({ rows: cleanRows, nowMs });
  const qualityReport = detectionQualityReport || detectionQuality.report({
    generatedAt: new Date(nowMs).toISOString(),
  });
  const actionQueue = hardeningActionQueue({ hardening, inventory, behavior, actionStates });
  const controlRows = controlOutcomes(cleanRows);
  const decisionQualityReport = decisionQuality(cleanRows, nowMs);
  const surfaceRows = surfaces({ rows: cleanRows, coverageReport: report, policy, auditIntegrity, nowMs, hardening });
  const segmentReport = postureSegments({
    rows: sourceRows,
    selectedRows: cleanRows,
    segment: selectedSegmentId,
    identityGroups: groupsByUser,
  });
  const postureSummary = {
    events: cleanRows.filter((q) => !EVENTLESS_STATUSES.has(q.status)).length,
    sensitiveEvents: sensitiveRows.length,
    controlRate: sensitiveRows.length ? pct(
      sensitiveRows.filter((q) => isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(q.status) || q.status === 'approved' || q.status === 'denied').length,
      sensitiveRows.length,
    ) : 100,
  };
  const competitive = competitiveReadiness({
    rows: cleanRows,
    policy,
    coverageReport: report,
    auditIntegrity,
    hardening,
    inventory,
    agenticMcp,
    threatReport,
    postureSummary,
    segments: segmentReport,
    behavior,
    env,
  });
  const marketFocus = competitiveFocus({
    competitiveReadiness: competitive,
    coverageReport: report,
    inventory,
    agenticMcp,
    threatReport,
    detectorFeedbackReport,
    detectionQualityReport: qualityReport,
    policy,
  });
  return {
    generatedAt: new Date(nowMs).toISOString(),
    windowDays: WINDOW_DAYS,
    summary: {
      events: cleanRows.filter((q) => !EVENTLESS_STATUSES.has(q.status)).length,
      sensitiveEvents: sensitiveRows.length,
      blocked: blockedRows.length,
      redacted: redactedRows.length,
      coached: coachedRows.length,
      pending: pendingRows.length,
      approvalEscalated: pendingRows.filter((q) => isEscalated(q, nowMs)).length,
      shadowEvents: n(report && report.totals && report.totals.shadowEvents),
      unresolvedShadowDestinations: n(report && report.totals && report.totals.unresolvedShadowDestinations),
      requiredSensors: n(report && report.totals && report.totals.requiredSensors),
      activeRequiredSensors: n(report && report.totals && report.totals.activeRequiredSensors),
      fleetAttention: n(report && report.totals && report.totals.fleetAttention),
      controlRate: sensitiveRows.length ? pct(
        sensitiveRows.filter((q) => isBlocked(q) || isRedacted(q) || COACHING_STATUSES.has(q.status) || q.status === 'approved' || q.status === 'denied').length,
        sensitiveRows.length,
      ) : 100,
    },
    metrics: metrics({ rows: cleanRows, coverageReport: report, auditIntegrity, nowMs }),
    objectives: objectives({ rows: cleanRows, policy, coverageReport: report, auditIntegrity, nowMs, hardening }),
    hardening,
    segments: segmentReport,
    competitiveReadiness: competitive,
    competitiveFocus: marketFocus,
    behaviorBaselines: behavior,
    agenticMcp,
    threatGuardrails: threatReport,
    aiInventory: inventory,
    actionQueue,
    decisionQuality: decisionQualityReport,
    detectionQuality: qualityReport,
    controlGraph: controlGraph({
      rows: cleanRows,
      inventory,
      surfaces: surfaceRows,
      controls: controlRows,
      hardening,
    }),
    leakMap: leakMapGraph({ rows: cleanRows, identityGroups: groupsByUser, inventory }),
    surfaces: surfaceRows,
    events: recentEvents(cleanRows, nowMs),
    trend: riskTrend(cleanRows, new Date(nowMs), WINDOW_DAYS),
    controls: controlRows,
  };
}

module.exports = {
  containsSensitiveMetadata,
  summarize,
  riskTrend,
  controlOutcomes,
  controlGraph,
  leakMapGraph,
  aiInventory,
  agenticMcpPosture,
  threatGuardrails,
  competitiveReadiness,
  competitiveFocus,
  behaviorBaselines,
  decisionQuality,
  hardeningActionQueue,
  postureSegments,
  rowSegments,
  filterRowsBySegment,
  normalizedSegmentId,
  categoryLabels,
  statusDecision,
  isSensitive,
};
