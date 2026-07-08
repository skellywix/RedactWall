'use strict';
/**
 * Examiner export pack builder.
 *
 * Exports operational evidence without prompt bodies, token vaults, raw retained
 * prompts, or free-form audit details that may contain sensitive context.
 */
const crypto = require('crypto');
const controlMap = require('./control-map');
const ncuaReadiness = require('./ncua-readiness');
const { safeSensor } = require('./sensor-metadata');
const routing = require('./routing');
const { containsSensitiveMetadata } = require('./posture');

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
  'mcpAllowedTools',
  'mcpBlockedTools',
  'mcpApprovalRequiredTools',
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
  return (Array.isArray(checks) ? checks : []).slice(0, 80).map((check) => {
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
    accountType: ['personal', 'corporate', 'unknown'].includes(q.accountType) ? q.accountType : 'unknown',
    originApp: typeof q.originApp === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(q.originApp) ? q.originApp : null,
    riskScore: q.riskScore || 0,
    maxSeverity: q.maxSeverity || 0,
    maxSeverityLabel: q.maxSeverityLabel || 'none',
    findings: (q.findings || []).map(safeFinding),
    // Bound and scrub categories/reasons so a future detector that ever embedded
    // a matched value in a reason/category string cannot leak it into the
    // examiner pack (defense-in-depth; today these are label-shaped).
    categories: (q.categories || []).slice(0, 40).map((c) => safeThreatText(typeof c === 'string' ? c : (c && c.category) || '', 80)),
    entityCounts: q.entityCounts || {},
    reasons: (q.reasons || []).slice(0, 20).map((r) => safeThreatText(r, 200)),
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

// Use-case inventory records for the examiner pack. EVERY string field —
// not only the free-text ones — passes safeThreatText (bounded plus
// SSN/card/secret pattern redaction) at this export boundary, on top of the
// create-time validation, so a record written by any path can never carry
// member PII out.
function safeUseCaseRecord(record) {
  if (!record || typeof record !== 'object') return null;
  return {
    id: safeThreatText(record.id, 80),
    destination: safeThreatText(record.canonicalHost, 253),
    department: safeThreatText(record.department, 80),
    owner: safeThreatText(record.owner, 160),
    approvedUse: safeThreatText(record.approvedUse, 240),
    allowedDataClasses: (Array.isArray(record.allowedDataClasses) ? record.allowedDataClasses : [])
      .slice(0, 24).map((idText) => safeThreatText(idText, 80)),
    reviewStatus: safeThreatText(record.reviewStatus, 40),
    vendorStatus: safeThreatText(record.vendorStatus, 40) || 'not_reviewed',
    nextReviewAt: safeThreatText(record.nextReviewAt, 80),
    policyScopeId: safeThreatText(record.policyScopeId, 64),
    createdAt: safeThreatText(record.createdAt, 80),
    updatedAt: safeThreatText(record.updatedAt, 80),
  };
}

// Incident records for the examiner pack: pattern-redacted metadata plus the
// derived prompt-free timeline (built from safeQuery-shaped rows only).
function safeIncidentRecord(record, timeline) {
  if (!record || typeof record !== 'object') return null;
  return {
    id: safeThreatText(record.id, 80),
    title: safeThreatText(record.title, 120),
    notes: safeThreatText(record.notes, 240),
    status: safeThreatText(record.status, 40),
    detectedAt: safeThreatText(record.detectedAt, 80),
    deadlineAt: safeThreatText(record.deadlineAt, 80),
    reportedAt: safeThreatText(record.reportedAt, 80),
    queryCount: (Array.isArray(record.queryIds) ? record.queryIds : []).length,
    timeline: Array.isArray(timeline) ? timeline.slice(0, 50) : [],
  };
}

// EDM watchlist status for examiner review: counts and thresholds only. The
// salt and fingerprint list never leave server/exact-match.js.
function safeEdmSummary(edm) {
  if (!edm || typeof edm !== 'object') return null;
  return {
    enabled: edm.enabled === true,
    fingerprints: safeCoverageNumber(edm.fingerprints),
    minLength: safeCoverageNumber(edm.minLength),
    maxWords: safeCoverageNumber(edm.maxWords),
    severity: safeCoverageNumber(edm.severity),
  };
}

function safeRestoreDrillEvidence(input) {
  if (!input || typeof input !== 'object') return null;
  // A restore drill proves recoverability + chain integrity of the RESTORED
  // database. The restored copy carries no sibling manifest (that hash binds the
  // original backup, checked separately), so success keys off the restored
  // audit chain, not manifest presence.
  const auditOk = !!(input.auditIntegrity && input.auditIntegrity.ok);
  return {
    ok: input.ok === true || auditOk,
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
    id: safeBoundedText(report.id, 120) || `redactwall-evidence-${generatedAt.slice(0, 10)}`,
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
    endpointAiInventoryReports: safeCoverageNumber(totals.endpointAiInventoryReports),
    endpointAiToolDetections: safeCoverageNumber(totals.endpointAiToolDetections),
    endpointAiToolUnapproved: safeCoverageNumber(totals.endpointAiToolUnapproved),
    discoveryFeeds: safeCoverageNumber(totals.discoveryFeeds),
    freshDiscoveryFeeds: safeCoverageNumber(totals.freshDiscoveryFeeds),
    staleDiscoveryFeeds: safeCoverageNumber(totals.staleDiscoveryFeeds),
    lastDiscoveryAt: safeCoverageText(totals.lastDiscoveryAt),
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

function safeCoverageAiToolInventory(inventory) {
  if (!inventory || typeof inventory !== 'object') return null;
  return {
    detected: safeCoverageNumber(inventory.detected),
    reported: safeCoverageNumber(inventory.reported),
    unapproved: safeCoverageNumber(inventory.unapproved),
    truncated: inventory.truncated === true,
    state: safeCoverageText(inventory.state),
    tools: (Array.isArray(inventory.tools) ? inventory.tools : []).slice(0, 25).map((tool) => ({
      id: safeCoverageText(tool && tool.id),
      label: safeCoverageText(tool && tool.label),
      approved: tool && tool.approved === true,
      state: safeCoverageText(tool && tool.state),
      detail: safeCoverageText(tool && tool.detail),
    })),
  };
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
    aiToolInventory: safeCoverageAiToolInventory(health.aiToolInventory),
  };
}

function safeEndpointAiTools(tools = []) {
  return (Array.isArray(tools) ? tools : []).slice(0, 100).map((tool) => ({
    id: safeCoverageText(tool && tool.id),
    label: safeCoverageText(tool && tool.label),
    approved: tool && tool.approved === true,
    state: safeCoverageText(tool && tool.state),
    detail: safeCoverageText(tool && tool.detail),
    user: safeCoverageText(tool && tool.user),
    orgId: safeCoverageText(tool && tool.orgId),
    lastSeen: safeCoverageText(tool && tool.lastSeen),
    platforms: (Array.isArray(tool && tool.platforms) ? tool.platforms : [])
      .filter((item) => typeof item === 'string')
      .slice(0, 5),
  }));
}

function safeEndpointFileFlowProfiles(profiles = []) {
  return (Array.isArray(profiles) ? profiles : []).slice(0, 120).map((profile) => ({
    id: safeCoverageText(profile && profile.id),
    state: safeCoverageText(profile && profile.state),
    detail: safeCoverageText(profile && profile.detail),
    user: safeCoverageText(profile && profile.user),
    orgId: safeCoverageText(profile && profile.orgId),
    lastSeen: safeCoverageText(profile && profile.lastSeen),
    platforms: (Array.isArray(profile && profile.platforms) ? profile.platforms : [])
      .filter((item) => typeof item === 'string')
      .slice(0, 5),
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

function safeCoverageDiscoveryFeeds(feeds = []) {
  return (Array.isArray(feeds) ? feeds : []).slice(0, 12).map((feed) => ({
    source: safeCoverageText(feed && feed.source),
    state: safeCoverageText(feed && feed.state),
    observations: safeCoverageNumber(feed && feed.observations),
    destinations: safeCoverageNumber(feed && feed.destinations),
    users: safeCoverageNumber(feed && feed.users),
    categories: (Array.isArray(feed && feed.categories) ? feed.categories : []).slice(0, 6).map((item) => safeCoverageText(item)),
    lastSeen: safeCoverageText(feed && feed.lastSeen),
    ageHours: feed && feed.ageHours == null ? null : safeCoverageNumber(feed && feed.ageHours),
    privacy: safeCoverageText(feed && feed.privacy),
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
    endpointAiTools: safeEndpointAiTools(report.endpointAiTools),
    endpointFileFlowProfiles: safeEndpointFileFlowProfiles(report.endpointFileFlowProfiles),
    discoveryFeeds: safeCoverageDiscoveryFeeds(report.discoveryFeeds),
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

function safePostureText(value, limit = 160) {
  // Operator-authored posture fields (workflowNote, owner, detail, ...) reach the
  // examiner pack, so scrub PII patterns at the export boundary, not just bound
  // length: a space-grouped SSN in a note must never ship. Uses the same
  // redaction as threat text.
  return safeThreatText(value, limit);
}

function safePostureItems(items = [], fields = []) {
  return (Array.isArray(items) ? items : []).slice(0, 50).map((item) => {
    const row = {};
    for (const field of fields) {
      const value = item && item[field];
      if (typeof value === 'number' || typeof value === 'boolean') row[field] = value;
      else if (typeof value === 'string') row[field] = safePostureText(value, field === 'description' || field === 'detail' ? 240 : 120);
      else if (Array.isArray(value)) row[field] = value.slice(0, 20).map((entry) => (typeof entry === 'string' ? safeThreatText(entry, 120) : safePolicyValue(entry)));
      else if (value && typeof value === 'object') row[field] = safePolicyValue(value);
      else row[field] = null;
    }
    return row;
  });
}

function safePostureHardening(hardening) {
  if (!hardening || typeof hardening !== 'object') return null;
  return {
    generatedAt: safePostureText(hardening.generatedAt, 80),
    score: safeCoverageNumber(hardening.score),
    state: safePostureText(hardening.state, 80),
    status: safePostureText(hardening.status, 80),
    summary: safePolicyValue(hardening.summary || {}),
    areas: safePostureItems(hardening.areas, [
      'id',
      'label',
      'description',
      'score',
      'state',
      'status',
      'evidence',
      'gaps',
      'action',
      'targetTab',
      'owner',
      'source',
      'location',
      'proofs',
      'proofLedger',
      'playbook',
    ]),
    proofLedger: safePolicyValue(hardening.proofLedger || {}),
    mission: safePolicyValue(hardening.mission || {}),
    nextActions: safePostureItems(hardening.nextActions, ['id', 'label', 'action', 'detail', 'targetTab', 'priority']),
  };
}

function safeThreatText(value, limit = 160) {
  const text = safeBoundedText(value, limit);
  if (!text) return text;
  // Canonical SSN/PAN/secret predicate shared with posture.js, so the export
  // boundary's redaction can never be narrower than the create boundary's (a
  // space-grouped SSN like '123 45 6789' was missed by the old hyphen-only regex).
  if (containsSensitiveMetadata(text)) return '[redacted]';
  return text;
}

function safeThreatItems(items = [], fields = []) {
  return (Array.isArray(items) ? items : []).slice(0, 50).map((item) => {
    const row = {};
    for (const field of fields) {
      const value = item && item[field];
      if (typeof value === 'number' || typeof value === 'boolean') row[field] = value;
      else if (typeof value === 'string') row[field] = safeThreatText(value, field === 'description' || field === 'detail' ? 240 : 120);
      else if (Array.isArray(value)) row[field] = value.slice(0, 20).map((entry) => (typeof entry === 'string' ? safeThreatText(entry, 120) : safePolicyValue(entry)));
      else if (value && typeof value === 'object') row[field] = safePolicyValue(value);
      else row[field] = null;
    }
    return row;
  });
}

function safePostureThreatGuardrails(threats) {
  if (!threats || typeof threats !== 'object') return null;
  return {
    summary: safePolicyValue(threats.summary || {}),
    rules: safeThreatItems(threats.rules, ['id', 'label', 'framework', 'atlas', 'control', 'events', 'blocked', 'redacted', 'critical', 'lastSeen', 'state', 'status', 'detail', 'action', 'targetTab']),
    controls: safeThreatItems(threats.controls, ['id', 'label', 'state', 'detail', 'targetTab']),
    recent: safeThreatItems(threats.recent, ['id', 'timestamp', 'source', 'destination', 'severity', 'status', 'decision', 'title', 'threats', 'detail']),
  };
}

function safePostureCompetitiveReadiness(readiness) {
  if (!readiness || typeof readiness !== 'object') return null;
  return {
    generatedAt: safePostureText(readiness.generatedAt, 80),
    summary: safePolicyValue(readiness.summary || {}),
    matrix: safeThreatItems(readiness.matrix, ['id', 'label', 'marketBar', 'score', 'state', 'status', 'evidence', 'gaps', 'action', 'targetTab', 'source', 'detail']),
    differentiators: (Array.isArray(readiness.differentiators) ? readiness.differentiators : [])
      .slice(0, 10)
      .map((item) => safeThreatText(item, 180)),
    nextGaps: safeThreatItems(readiness.nextGaps, ['id', 'priority', 'label', 'detail', 'action', 'targetTab', 'score']),
  };
}

function safePostureBehaviorBaselines(baselines) {
  if (!baselines || typeof baselines !== 'object') return null;
  return {
    generatedAt: safeThreatText(baselines.generatedAt, 80),
    privacy: safeThreatText(baselines.privacy, 120),
    summary: safePolicyValue(baselines.summary || {}),
    dimensions: safeThreatItems(baselines.dimensions, [
      'id',
      'kind',
      'label',
      'title',
      'state',
      'status',
      'score',
      'recentEvents',
      'previousEvents',
      'baselineDaily',
      'surgeRatio',
      'recentSensitive',
      'recentControlled',
      'maxRiskScore',
      'maxSeverity',
      'latestAt',
      'detail',
      'action',
      'targetTab',
      'source',
    ]),
    playbook: safeThreatItems(baselines.playbook, ['id', 'priority', 'severity', 'label', 'detail', 'action', 'targetTab', 'score']),
  };
}

function safePostureCompetitiveFocus(focus) {
  if (!focus || typeof focus !== 'object') return null;
  return {
    summary: safePolicyValue(focus.summary || {}),
    lanes: safeThreatItems(focus.lanes, ['id', 'label', 'competitors', 'marketBar', 'score', 'state', 'status', 'evidence', 'gaps', 'action', 'targetTab', 'anchor']),
    playbook: safeThreatItems(focus.playbook, ['id', 'priority', 'label', 'detail', 'targetTab', 'anchor', 'validation']),
  };
}

function safePostureDecisionQuality(quality) {
  if (!quality || typeof quality !== 'object') return null;
  const summary = quality.summary || {};
  return {
    generatedAt: safeThreatText(quality.generatedAt, 80),
    summary: {
      events: safeCoverageNumber(summary.events),
      sensitiveEvents: safeCoverageNumber(summary.sensitiveEvents),
      pendingReviews: safeCoverageNumber(summary.pendingReviews),
      escalatedReviews: safeCoverageNumber(summary.escalatedReviews),
      approved: safeCoverageNumber(summary.approved),
      denied: safeCoverageNumber(summary.denied),
      coachingEvents: safeCoverageNumber(summary.coachingEvents),
      coachingCompleted: safeCoverageNumber(summary.coachingCompleted),
      overrideWatch: safeCoverageNumber(summary.overrideWatch),
      riskyAllows: safeCoverageNumber(summary.riskyAllows),
      controlRate: safeCoverageNumber(summary.controlRate),
      slaHealthyRate: safeCoverageNumber(summary.slaHealthyRate),
      privacy: safeThreatText(summary.privacy, 120),
    },
    cards: safeThreatItems(quality.cards, ['id', 'label', 'score', 'state', 'status', 'value', 'detail', 'action', 'targetTab']),
    hotspots: safeThreatItems(quality.hotspots, ['id', 'kind', 'label', 'events', 'sensitive', 'blocked', 'redacted', 'allowed', 'coached', 'pending', 'escalated', 'maxRiskScore', 'lastSeen', 'state', 'detail']),
  };
}

function safePostureDetectionQuality(quality) {
  if (!quality || typeof quality !== 'object') return null;
  return {
    generatedAt: safeThreatText(quality.generatedAt, 80),
    summary: safePolicyValue(quality.summary || {}),
    gates: safeThreatItems(quality.gates, ['id', 'label', 'value', 'floor', 'state']),
    semantic: safeThreatItems(quality.semantic, ['id', 'kind', 'precision', 'recall', 'f1', 'tp', 'fp', 'fn', 'state', 'status', 'detail']),
    structured: safeThreatItems(quality.structured, ['id', 'kind', 'precision', 'recall', 'f1', 'tp', 'fp', 'fn', 'state', 'status', 'detail']),
    failures: (Array.isArray(quality.failures) ? quality.failures : []).slice(0, 12).map((item) => safeThreatText(item, 160)),
  };
}

function safeDetectorFeedbackReport(report) {
  if (!report || typeof report !== 'object') return null;
  return {
    generatedAt: safeThreatText(report.generatedAt, 80),
    summary: safePolicyValue(report.summary || {}),
    detectors: safeThreatItems(report.detectors, ['detectorId', 'label', 'total', 'valid', 'falsePositive', 'tooSensitive', 'missed', 'affectedQueries', 'maxRiskScore', 'lastSeen', 'state', 'detail']),
    reviewQueue: safeThreatItems(report.reviewQueue, ['queryId', 'createdAt', 'detectorId', 'detectorIds', 'destination', 'source', 'channel', 'status', 'riskScore', 'maxSeverity', 'feedbackCount', 'reviewed']),
    recent: safeThreatItems(report.recent, ['id', 'createdAt', 'queryId', 'detectorId', 'verdict', 'verdictLabel', 'actor', 'role', 'source', 'channel', 'destination', 'queryStatus', 'riskScore', 'maxSeverity']),
  };
}

function safePosture(report) {
  if (!report || typeof report !== 'object') return null;
  return {
    generatedAt: safePostureText(report.generatedAt, 80),
    windowDays: safeCoverageNumber(report.windowDays),
    summary: safePolicyValue(report.summary || {}),
    metrics: safePostureItems(report.metrics, ['id', 'label', 'value', 'unit', 'trend', 'status']),
    objectives: safePostureItems(report.objectives, ['id', 'label', 'score', 'state', 'detail', 'action', 'targetTab']),
    aiInventory: safePolicyValue(report.aiInventory || {}),
    threatGuardrails: safePostureThreatGuardrails(report.threatGuardrails),
    behaviorBaselines: safePostureBehaviorBaselines(report.behaviorBaselines),
    competitiveReadiness: safePostureCompetitiveReadiness(report.competitiveReadiness),
    competitiveFocus: safePostureCompetitiveFocus(report.competitiveFocus),
    decisionQuality: safePostureDecisionQuality(report.decisionQuality),
    detectionQuality: safePostureDetectionQuality(report.detectionQuality),
    actionQueue: safePostureItems(report.actionQueue, ['id', 'priority', 'severity', 'category', 'label', 'detail', 'owner', 'source', 'action', 'targetTab', 'command', 'workflowStatus', 'workflowOwner', 'workflowActor', 'workflowNote', 'workflowSnoozeUntil', 'workflowUpdatedAt', 'workflowProofState']),
    surfaces: safePostureItems(report.surfaces, ['id', 'name', 'type', 'status', 'source', 'location', 'health', 'confidence', 'relatedMetric', 'lastUpdated', 'description']),
    trend: safePostureItems(report.trend, ['date', 'events', 'blocked', 'redacted', 'allowed', 'coached', 'shadow', 'maxRiskScore']),
    controls: safePostureItems(report.controls, ['label', 'events', 'blocked', 'redacted', 'allowed', 'coached', 'shadow']),
    hardening: safePostureHardening(report.hardening),
    events: safePostureItems(report.events, ['id', 'timestamp', 'severity', 'source', 'title', 'description', 'confidence', 'relatedMetric', 'status']),
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
    byAccountType: aggregateLineage(rows, (q) => q.accountType || 'unknown'),
    byOriginApp: aggregateLineage(rows, (q) => q.originApp || 'unknown'),
  };
}

function buildIncidentSection(summary, incidentRows, lineageQueries) {
  const queryMap = new Map(lineageQueries.map((q) => [q.id, q]));
  return {
    summary,
    records: (incidentRows || []).slice(0, 100).map((record) => {
      const resolved = (Array.isArray(record.queryIds) ? record.queryIds : [])
        .map((queryId) => queryMap.get(queryId)).filter(Boolean).map(safeQuery);
      return safeIncidentRecord(record, ncuaReadiness.incidentTimeline(record, resolved));
    }).filter(Boolean),
  };
}

function buildEvidencePack(input) {
  const now = input.generatedAt || new Date().toISOString();
  const queries = Array.isArray(input.queries) ? input.queries : [];
  const lineageQueries = Array.isArray(input.lineageQueries)
    ? input.lineageQueries
    : (Array.isArray(input.summaryQueries) ? input.summaryQueries : queries);
  const coverageReport = safeCoverage(input.coverage);
  const postureReport = safePosture(input.posture);
  const detectorFeedbackReport = safeDetectorFeedbackReport(input.detectorFeedback);
  const policyExceptionReview = safePolicyExceptionReview(input.policyExceptionReview);
  const backup = safeBackupEvidence(input.backup);
  const restoreDrill = safeRestoreDrillEvidence(input.restoreDrill);
  const examinerProfile = ncuaReadiness.isProfile(input.examinerProfile) ? input.examinerProfile : null;
  const edm = safeEdmSummary(input.edm);
  const useCaseRows = Array.isArray(input.useCases) ? input.useCases : null;
  const useCases = ncuaReadiness.useCasesSummary(useCaseRows, now);
  const incidentRows = Array.isArray(input.incidents) ? input.incidents : null;
  const incidents = ncuaReadiness.incidentsSummary(incidentRows, now);
  const scope = {
    queryLimit: input.queryLimit,
    auditLimit: input.auditLimit,
    summaryRowsIncluded: safeCoverageNumber(input.summaryRowsIncluded == null ? lineageQueries.length : input.summaryRowsIncluded),
    summariesUseFullHistory: input.summariesUseFullHistory === true,
    rawPromptBodiesIncluded: false,
    auditDetailsIncluded: false,
    backupEvidenceIncluded: !!backup,
    restoreDrillEvidenceIncluded: !!restoreDrill,
    ...(examinerProfile ? { examinerProfile } : {}),
  };
  const controlMappings = controlMap.buildControlMappings({
    generatedAt: now,
    scope,
    policy: input.policy,
    detectors: input.detectors || [],
    auditIntegrity: input.auditIntegrity,
    coverage: coverageReport,
    backup,
    restoreDrill,
    edm,
    useCases,
    incidents,
    boardPacket: input.boardPacket,
  });
  const report = safeReport(input.report, now);
  return {
    // Default packs stay schemaVersion 2 (consumers pin it); only
    // examiner-profile packs stamp 3.
    schemaVersion: examinerProfile ? 3 : 2,
    generatedAt: now,
    report,
    service: {
      name: 'RedactWall',
      version: input.version || 'unknown',
    },
    scope,
    policy: input.policy,
    stats: input.stats,
    auditIntegrity: input.auditIntegrity,
    coverage: coverageReport,
    posture: postureReport,
    detectorFeedback: detectorFeedbackReport,
    policyExceptionReview,
    backup,
    restoreDrill,
    edm,
    controlMappings,
    ...(examinerProfile ? {
      ncuaReadiness: ncuaReadiness.summarize({
        generatedAt: now,
        examinerProfile,
        controls: controlMappings,
        auditIntegrity: input.auditIntegrity,
        policyExceptionReview,
        edm,
        catalog: input.catalog,
        queries: lineageQueries,
        useCases,
        incidents,
        // The whitelisted schedule from safeReport, not the raw input, so the
        // readiness section can't carry unvetted schedule-config fields.
        reportSchedule: report.schedule,
      }),
      useCases: {
        summary: useCases,
        records: (useCaseRows || []).slice(0, 200).map(safeUseCaseRecord).filter(Boolean),
      },
      incidents: buildIncidentSection(incidents, incidentRows, lineageQueries),
    } : {}),
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
  safeEdmSummary,
  safeReport,
  safePosture,
  safeDetectorFeedbackReport,
  buildLineage,
  hashText,
};
