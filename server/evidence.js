'use strict';
/**
 * Examiner export pack builder.
 *
 * Exports operational evidence without prompt bodies, token vaults, raw retained
 * prompts, or free-form audit details that may contain sensitive context.
 */
const crypto = require('crypto');
const { safeSensor } = require('./sensor-metadata');

const POLICY_AUDIT_ACTIONS = new Set(['POLICY_UPDATED', 'POLICY_TEMPLATE_APPLIED', 'DESTINATION_REVIEWED']);
const POLICY_AUDIT_FIELDS = new Set([
  'enforcementMode',
  'blockMinSeverity',
  'blockRiskScore',
  'alwaysBlock',
  'storeRawForApproval',
  'rawRetentionDays',
  'ignore',
  'disabledDetectors',
  'governedDestinations',
  'allowedDestinations',
  'blockedDestinations',
  'blockedFileUploadDestinations',
  'scanner',
]);

const BLOCKED_STATUSES = new Set([
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'response_flagged',
  'seat_limit_blocked',
]);

const REDACTED_STATUSES = new Set(['redacted']);
const ALLOWED_STATUSES = new Set(['allowed', 'approved']);
const WARNED_STATUSES = new Set(['warned', 'justified']);
const LINEAGE_LIMIT = 25;

function hashText(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function safeFinding(f) {
  return {
    type: f.type,
    severity: f.severity,
    score: f.score,
    masked: f.masked,
  };
}

function safeQuery(q) {
  return {
    id: q.id,
    createdAt: q.createdAt,
    status: q.status,
    mode: q.mode || null,
    user: q.user || 'unknown',
    orgId: q.orgId || null,
    source: q.source || 'unknown',
    channel: q.channel || 'unknown',
    sensor: safeSensor(q.sensor),
    destination: q.destination || 'unknown',
    riskScore: q.riskScore || 0,
    maxSeverity: q.maxSeverity || 0,
    maxSeverityLabel: q.maxSeverityLabel || 'none',
    findings: (q.findings || []).map(safeFinding),
    categories: q.categories || [],
    entityCounts: q.entityCounts || {},
    reasons: q.reasons || [],
    promptHash: hashText(q.redactedPrompt || q.tokenizedPrompt || ''),
    decidedBy: q.decidedBy || null,
    decidedAt: q.decidedAt || null,
    retentionPurgedAt: q.retentionPurgedAt || null,
    retentionPurgedFields: (q.retentionPurgedFields || []).filter((field) => ['rawPrompt', 'tokenVault'].includes(field)),
  };
}

function safePolicyValue(value) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.slice(0, 80).map(safePolicyValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().slice(0, 80).map((key) => [key, safePolicyValue(value[key])]));
  }
  return null;
}

function safePolicyChange(a) {
  if (!POLICY_AUDIT_ACTIONS.has(a.action) || !a.detail) return null;
  let parsed;
  try { parsed = JSON.parse(a.detail); } catch { return null; }
  if (!parsed || parsed.type !== 'policy_change' || !Array.isArray(parsed.changed)) return null;
  const changed = parsed.changed
    .filter((item) => item && POLICY_AUDIT_FIELDS.has(item.field))
    .map((item) => ({
      field: item.field,
      before: safePolicyValue(item.before),
      after: safePolicyValue(item.after),
    }));
  return {
    ...(parsed.templateId ? { templateId: String(parsed.templateId) } : {}),
    changed,
  };
}

function safeAuditEntry(a) {
  const safe = {
    id: a.id,
    ts: a.ts,
    action: a.action,
    queryId: a.queryId || null,
    actor: a.actor || null,
    prevHash: a.prevHash,
    hash: a.hash,
    detailHash: hashText(a.detail || ''),
  };
  const policyChange = safePolicyChange(a);
  if (policyChange) safe.policyChange = policyChange;
  return safe;
}

function safeCoverageNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function safeCoverageText(value) {
  return typeof value === 'string' ? value : null;
}

function safeCoverageTotals(totals = {}) {
  return {
    events: safeCoverageNumber(totals.events),
    governedDestinations: safeCoverageNumber(totals.governedDestinations),
    governedActive: safeCoverageNumber(totals.governedActive),
    shadowEvents: safeCoverageNumber(totals.shadowEvents),
    blocked: safeCoverageNumber(totals.blocked),
  };
}

function safeCoverageVersions(versions = []) {
  return (Array.isArray(versions) ? versions : []).slice(0, 25).map((item) => ({
    version: safeCoverageText(item && item.version),
    events: safeCoverageNumber(item && item.events),
    lastSeen: safeCoverageText(item && item.lastSeen),
  }));
}

function safeCoverageSensors(sensors = []) {
  return (Array.isArray(sensors) ? sensors : []).slice(0, 25).map((sensor) => ({
    source: safeCoverageText(sensor && sensor.source),
    label: safeCoverageText(sensor && sensor.label),
    events: safeCoverageNumber(sensor && sensor.events),
    lastSeen: safeCoverageText(sensor && sensor.lastSeen),
    latestVersion: safeCoverageText(sensor && sensor.latestVersion),
    versionHealth: safeCoverageText(sensor && sensor.versionHealth),
    versions: safeCoverageVersions(sensor && sensor.versions),
    platforms: (Array.isArray(sensor && sensor.platforms) ? sensor.platforms : [])
      .filter((item) => typeof item === 'string')
      .slice(0, 25),
  }));
}

function safeCoverageDestinations(destinations = []) {
  return (Array.isArray(destinations) ? destinations : []).slice(0, 50).map((destination) => ({
    destination: safeCoverageText(destination && destination.destination),
    events: safeCoverageNumber(destination && destination.events),
    blocked: safeCoverageNumber(destination && destination.blocked),
    redacted: safeCoverageNumber(destination && destination.redacted),
    shadow: safeCoverageNumber(destination && destination.shadow),
    users: safeCoverageNumber(destination && destination.users),
    lastSeen: safeCoverageText(destination && destination.lastSeen),
    governed: destination && destination.governed === true,
  }));
}

function safeCoveragePosture(posture = []) {
  return (Array.isArray(posture) ? posture : []).slice(0, 25).map((item) => ({
    id: safeCoverageText(item && item.id),
    label: safeCoverageText(item && item.label),
    state: safeCoverageText(item && item.state),
    detail: safeCoverageText(item && item.detail),
  }));
}

function safeCoverage(report) {
  if (!report || typeof report !== 'object') return null;
  return {
    generatedAt: safeCoverageText(report.generatedAt),
    score: safeCoverageNumber(report.score),
    totals: safeCoverageTotals(report.totals),
    sensors: safeCoverageSensors(report.sensors),
    governedDestinations: safeCoverageDestinations(report.governedDestinations),
    ungovernedDestinations: safeCoverageDestinations(report.ungovernedDestinations),
    shadowDestinations: safeCoverageDestinations(report.shadowDestinations),
    posture: safeCoveragePosture(report.posture),
  };
}

function decisionForStatus(status) {
  const value = String(status || 'unknown');
  if (BLOCKED_STATUSES.has(value)) return 'blocked';
  if (REDACTED_STATUSES.has(value)) return 'redacted';
  if (ALLOWED_STATUSES.has(value)) return 'allowed';
  if (WARNED_STATUSES.has(value)) return 'warned';
  return value;
}

function emptyLineageBucket(key) {
  return {
    key,
    events: 0,
    blocked: 0,
    redacted: 0,
    allowed: 0,
    warned: 0,
    maxRiskScore: 0,
    users: new Set(),
    destinations: new Set(),
    sources: new Set(),
    categories: new Set(),
    lastSeen: null,
  };
}

function categoryLabels(q) {
  const labels = [];
  for (const finding of q.findings || []) {
    if (finding && finding.type) labels.push(finding.type);
  }
  for (const category of q.categories || []) {
    if (typeof category === 'string') labels.push(category);
    else if (category && category.category) labels.push(category.category);
  }
  return [...new Set(labels)];
}

function bumpLineageBucket(bucket, q) {
  bucket.events += 1;
  const decision = decisionForStatus(q.status);
  if (decision === 'blocked') bucket.blocked += 1;
  else if (decision === 'redacted') bucket.redacted += 1;
  else if (decision === 'allowed') bucket.allowed += 1;
  else if (decision === 'warned') bucket.warned += 1;
  bucket.maxRiskScore = Math.max(bucket.maxRiskScore, Number(q.riskScore) || 0);
  if (q.user) bucket.users.add(q.user);
  if (q.destination) bucket.destinations.add(q.destination);
  if (q.source) bucket.sources.add(q.source);
  for (const label of categoryLabels(q)) bucket.categories.add(label);
  if (!bucket.lastSeen || String(q.createdAt || '') > bucket.lastSeen) bucket.lastSeen = q.createdAt || null;
}

function publicLineageBucket(bucket) {
  return {
    key: bucket.key,
    events: bucket.events,
    blocked: bucket.blocked,
    redacted: bucket.redacted,
    allowed: bucket.allowed,
    warned: bucket.warned,
    maxRiskScore: bucket.maxRiskScore,
    users: bucket.users.size,
    destinations: bucket.destinations.size,
    sources: bucket.sources.size,
    categories: [...bucket.categories].sort().slice(0, 12),
    lastSeen: bucket.lastSeen,
  };
}

function normalizeLineageKey(value, fallback = 'unknown') {
  const text = String(value || '').trim();
  return text || fallback;
}

function aggregateLineage(rows, keyFn) {
  const buckets = new Map();
  for (const q of rows || []) {
    const keys = keyFn(q);
    const list = Array.isArray(keys) ? keys : [keys];
    for (const key of list.map((item) => normalizeLineageKey(item)).filter(Boolean)) {
      const bucket = buckets.get(key) || emptyLineageBucket(key);
      bumpLineageBucket(bucket, q);
      buckets.set(key, bucket);
    }
  }
  return [...buckets.values()]
    .map(publicLineageBucket)
    .sort((a, b) => b.events - a.events || b.maxRiskScore - a.maxRiskScore || a.key.localeCompare(b.key))
    .slice(0, LINEAGE_LIMIT);
}

function buildLineage(rows) {
  return {
    byUser: aggregateLineage(rows, (q) => q.user || 'unknown'),
    byDestination: aggregateLineage(rows, (q) => q.destination || 'unknown'),
    bySensor: aggregateLineage(rows, (q) => q.source || 'unknown'),
    byChannel: aggregateLineage(rows, (q) => q.channel || 'unknown'),
    byCategory: aggregateLineage(rows, (q) => categoryLabels(q).length ? categoryLabels(q) : ['none']),
    byDecision: aggregateLineage(rows, (q) => decisionForStatus(q.status)),
  };
}

function buildEvidencePack(input) {
  const now = input.generatedAt || new Date().toISOString();
  const queries = input.queries || [];
  return {
    schemaVersion: 1,
    generatedAt: now,
    service: {
      name: 'PromptWall',
      version: input.version || 'unknown',
    },
    scope: {
      queryLimit: input.queryLimit,
      auditLimit: input.auditLimit,
      rawPromptBodiesIncluded: false,
      auditDetailsIncluded: false,
    },
    policy: input.policy,
    stats: input.stats,
    auditIntegrity: input.auditIntegrity,
    coverage: safeCoverage(input.coverage),
    lineage: buildLineage(queries),
    detectors: input.detectors || [],
    queries: queries.map(safeQuery),
    audit: (input.audit || []).map(safeAuditEntry),
  };
}

module.exports = {
  buildEvidencePack,
  safeQuery,
  safeAuditEntry,
  safePolicyChange,
  safeCoverage,
  buildLineage,
  hashText,
};
