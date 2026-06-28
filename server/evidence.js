'use strict';
/**
 * Examiner export pack builder.
 *
 * Exports operational evidence without prompt bodies, token vaults, raw retained
 * prompts, or free-form audit details that may contain sensitive context.
 */
const crypto = require('crypto');
const controlMap = require('./control-map');
const { safeSensor } = require('./sensor-metadata');
const routing = require('./routing');

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
  'blockedBrowserActions',
  'blockUnapprovedAiDestinations',
  'responseScanMode',
  'approvalRoutingRules',
  'policyScopes',
  'policyExceptions',
  'requiredSensors',
  'desiredSensorVersions',
  'scanner',
]);

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

function safeInstallChecks(checks = []) {
  return (Array.isArray(checks) ? checks : []).slice(0, 40).map((check) => {
    if (!check || typeof check !== 'object') return null;
    const id = typeof check.id === 'string' ? check.id.slice(0, 80) : null;
    if (!id) return null;
    const detail = typeof check.detail === 'string' && check.detail.trim()
      ? check.detail.trim().slice(0, 160)
      : null;
    return {
      id,
      ok: check.ok === true,
      ...(detail ? { detail } : {}),
    };
  }).filter(Boolean);
}

function safeQuery(q) {
  const workflow = routing.publicWorkflow(q);
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
    installChecks: safeInstallChecks(q.installChecks),
    policyScopeIds: (Array.isArray(q.policyScopeIds) ? q.policyScopeIds : [])
      .filter((item) => typeof item === 'string')
      .slice(0, 20),
    policyExceptionId: typeof q.policyExceptionId === 'string' ? q.policyExceptionId : null,
    workflow,
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
    ...(parsed.reason ? { reason: String(parsed.reason).slice(0, 240) } : {}),
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

function safeBoundedText(value, limit = 160) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text ? text.slice(0, limit) : null;
}

function safeFileName(value) {
  const text = safeBoundedText(value, 240);
  if (!text) return null;
  return text.replace(/\\/g, '/').split('/').pop().slice(0, 160);
}

function safeSha256(value) {
  const text = typeof value === 'string' ? value.trim() : '';
  return /^[a-f0-9]{64}$/i.test(text) ? text.toLowerCase() : null;
}

function safeIntegrity(result) {
  if (!result || typeof result !== 'object') return null;
  return {
    ok: result.ok === true,
    count: safeCoverageNumber(result.count),
    brokenAt: safeBoundedText(result.brokenAt, 80),
    reason: safeBoundedText(result.reason, 120),
    queryId: safeBoundedText(result.queryId, 80),
  };
}

function safeBackupEvidence(input) {
  if (!input || typeof input !== 'object') return null;
  const manifest = input.manifest && typeof input.manifest === 'object' ? input.manifest : {};
  const auditIntegrity = input.auditIntegrity || input.backupIntegrity || manifest.backupIntegrity;
  const sourceIntegrity = input.sourceIntegrity || manifest.sourceIntegrity;
  const backupSha256 = safeSha256(input.backupSha256 || manifest.backupSha256);
  return {
    ok: input.ok === true,
    checkedAt: safeBoundedText(input.checkedAt || input.verifiedAt || input.createdAt || manifest.createdAt, 80),
    backupFile: safeFileName(input.backupFile || input.file || manifest.backupFile),
    backupBytes: safeCoverageNumber(input.backupBytes || input.bytes || manifest.backupBytes),
    backupSha256,
    manifestOk: input.manifestOk !== false,
    auditIntegrity: safeIntegrity(auditIntegrity),
    sourceIntegrity: safeIntegrity(sourceIntegrity),
    rawPromptBodiesIncluded: false,
  };
}

function safeRestoreDrillEvidence(input) {
  if (!input || typeof input !== 'object') return null;
  return {
    ok: input.ok === true,
    checkedAt: safeBoundedText(input.checkedAt || input.verifiedAt || input.drilledAt, 80),
    restoredFile: safeFileName(input.restoredTo || input.file),
    backupSha256: safeSha256(input.backupSha256),
    manifestOk: input.manifestOk !== false,
    auditIntegrity: safeIntegrity(input.auditIntegrity),
    rawPromptBodiesIncluded: false,
  };
}

function safeReportSchedule(schedule) {
  if (!schedule || typeof schedule !== 'object') return null;
  return {
    id: safeBoundedText(schedule.id, 80),
    enabled: schedule.enabled !== false,
    cadence: safeBoundedText(schedule.cadence, 40),
    nextRunAt: safeBoundedText(schedule.nextRunAt, 80),
    retentionDays: safeCoverageNumber(schedule.retentionDays),
  };
}

function safeReport(input, generatedAt) {
  const report = input && typeof input === 'object' ? input : {};
  return {
    id: safeBoundedText(report.id, 120) || `promptwall-evidence-${generatedAt.slice(0, 10)}`,
    generatedAt,
    generatedBy: safeBoundedText(report.generatedBy, 80) || 'system',
    periodStart: safeBoundedText(report.periodStart, 80),
    periodEnd: safeBoundedText(report.periodEnd, 80),
    scheduled: report.scheduled === true,
    schedule: safeReportSchedule(report.schedule),
  };
}

function safeCoverageTotals(totals = {}) {
  return {
    events: safeCoverageNumber(totals.events),
    governedDestinations: safeCoverageNumber(totals.governedDestinations),
    governedActive: safeCoverageNumber(totals.governedActive),
    shadowEvents: safeCoverageNumber(totals.shadowEvents),
    blocked: safeCoverageNumber(totals.blocked),
    requiredSensors: safeCoverageNumber(totals.requiredSensors),
    activeRequiredSensors: safeCoverageNumber(totals.activeRequiredSensors),
    activeSensorVersionGaps: safeCoverageNumber(totals.activeSensorVersionGaps),
    activeSensorHealthWarnings: safeCoverageNumber(totals.activeSensorHealthWarnings),
    fleetRows: safeCoverageNumber(totals.fleetRows),
    fleetCovered: safeCoverageNumber(totals.fleetCovered),
    fleetAttention: safeCoverageNumber(totals.fleetAttention),
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
    required: sensor && sensor.required === true,
    events: safeCoverageNumber(sensor && sensor.events),
    lastSeen: safeCoverageText(sensor && sensor.lastSeen),
    latestVersion: safeCoverageText(sensor && sensor.latestVersion),
    desiredVersion: safeCoverageText(sensor && sensor.desiredVersion),
    versionHealth: safeCoverageText(sensor && sensor.versionHealth),
    versions: safeCoverageVersions(sensor && sensor.versions),
    platforms: (Array.isArray(sensor && sensor.platforms) ? sensor.platforms : [])
      .filter((item) => typeof item === 'string')
      .slice(0, 25),
    installHealth: safeCoverageInstallHealth(sensor && sensor.installHealth),
  }));
}

function safeCoverageFleet(fleet = []) {
  return (Array.isArray(fleet) ? fleet : []).slice(0, 150).map((row) => ({
    source: safeCoverageText(row && row.source),
    label: safeCoverageText(row && row.label),
    user: safeCoverageText(row && row.user),
    orgId: safeCoverageText(row && row.orgId),
    required: row && row.required === true,
    state: safeCoverageText(row && row.state),
    events: safeCoverageNumber(row && row.events),
    lastSeen: safeCoverageText(row && row.lastSeen),
    latestVersion: safeCoverageText(row && row.latestVersion),
    desiredVersion: safeCoverageText(row && row.desiredVersion),
    versionHealth: safeCoverageText(row && row.versionHealth),
    platforms: (Array.isArray(row && row.platforms) ? row.platforms : [])
      .filter((item) => typeof item === 'string')
      .slice(0, 25),
    installHealth: safeCoverageInstallHealth(row && row.installHealth),
  }));
}

function safeCoverageInstallHealth(health) {
  if (!health || typeof health !== 'object') return null;
  const failedChecks = (Array.isArray(health.failedChecks) ? health.failedChecks : [])
    .filter((item) => typeof item === 'string')
    .slice(0, 40);
  return {
    at: safeCoverageText(health.at),
    state: safeCoverageText(health.state),
    failedChecks,
    checks: safeInstallChecks(health.checks),
  };
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
    fleet: safeCoverageFleet(report.fleet),
    governedDestinations: safeCoverageDestinations(report.governedDestinations),
    ungovernedDestinations: safeCoverageDestinations(report.ungovernedDestinations),
    shadowDestinations: safeCoverageDestinations(report.shadowDestinations),
    posture: safeCoveragePosture(report.posture),
  };
}

function safePolicyExceptionReview(report) {
  if (!report || typeof report !== 'object') return null;
  const items = (Array.isArray(report.items) ? report.items : []).slice(0, 40).map((item) => ({
    id: safeCoverageText(item && item.id),
    enabled: item && item.enabled !== false,
    action: safeCoverageText(item && item.action),
    expiresAt: safeCoverageText(item && item.expiresAt),
    ownerGroup: safeCoverageText(item && item.ownerGroup),
    reviewerRole: safeCoverageText(item && item.reviewerRole),
    reviewAfter: safeCoverageText(item && item.reviewAfter),
    status: safeCoverageText(item && item.status),
  }));
  return {
    generatedAt: safeCoverageText(report.generatedAt),
    reviewWindowDays: safeCoverageNumber(report.reviewWindowDays),
    total: safeCoverageNumber(report.total),
    active: safeCoverageNumber(report.active),
    disabled: safeCoverageNumber(report.disabled),
    expired: safeCoverageNumber(report.expired),
    reviewDue: safeCoverageNumber(report.reviewDue),
    expiringSoon: safeCoverageNumber(report.expiringSoon),
    items,
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
  const queries = Array.isArray(input.queries) ? input.queries : [];
  const lineageQueries = Array.isArray(input.lineageQueries)
    ? input.lineageQueries
    : (Array.isArray(input.summaryQueries) ? input.summaryQueries : queries);
  const coverageReport = safeCoverage(input.coverage);
  const policyExceptionReview = safePolicyExceptionReview(input.policyExceptionReview);
  const backup = safeBackupEvidence(input.backup);
  const restoreDrill = safeRestoreDrillEvidence(input.restoreDrill);
  const scope = {
    queryLimit: input.queryLimit,
    auditLimit: input.auditLimit,
    summaryRowsIncluded: safeCoverageNumber(input.summaryRowsIncluded == null ? lineageQueries.length : input.summaryRowsIncluded),
    summariesUseFullHistory: input.summariesUseFullHistory === true,
    rawPromptBodiesIncluded: false,
    auditDetailsIncluded: false,
    backupEvidenceIncluded: !!backup,
    restoreDrillEvidenceIncluded: !!restoreDrill,
  };
  return {
    schemaVersion: 2,
    generatedAt: now,
    report: safeReport(input.report, now),
    service: {
      name: 'PromptWall',
      version: input.version || 'unknown',
    },
    scope,
    policy: input.policy,
    stats: input.stats,
    auditIntegrity: input.auditIntegrity,
    coverage: coverageReport,
    policyExceptionReview,
    backup,
    restoreDrill,
    controlMappings: controlMap.buildControlMappings({
      generatedAt: now,
      scope,
      policy: input.policy,
      detectors: input.detectors || [],
      auditIntegrity: input.auditIntegrity,
      coverage: coverageReport,
      backup,
      restoreDrill,
    }),
    lineage: buildLineage(lineageQueries),
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
  safeInstallChecks,
  safeBackupEvidence,
  safeRestoreDrillEvidence,
  safeReport,
  buildLineage,
  hashText,
};
