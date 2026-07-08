'use strict';
/**
 * NCUA Readiness report (examiner profile: federal_credit_union).
 *
 * Pure, privacy-preserving composition over existing evidence inputs: control
 * mappings, coverage, exception review, audit integrity, EDM status, and
 * prompt-free catalog rollups (PLANS/ncua-readiness-center.md, slice 1).
 * Like control-readiness, it never emits prompt bodies, token vaults,
 * secrets, raw finding values, or catalog free text (notes/owner) — counts,
 * enums, and bounded labels only.
 */
const controlMap = require('./control-map');
const { BLOCKED_STATUSES, REDACTED_STATUSES } = require('./control-readiness');

const PROFILES = new Set(['federal_credit_union']);
const { MEMBER_IDENTIFIERS } = controlMap;
const CONTROL_TARGET_TABS = {
  member_information_safeguards: 'ncua',
  ai_use_inventory: 'ncua',
  vendor_service_provider_oversight: 'ncua',
  incident_readiness: 'ncua',
  board_reporting: 'ncua',
  ai_usage_governance: 'catalog',
  fleet_sensor_coverage: 'coverage',
  backup_recoverability: 'deploy',
  tamper_evident_audit: 'audit',
};

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function bound(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n(value))));
}

function safeText(value, fallback = '', limit = 240) {
  const text = String(value || '').trim();
  return (text || fallback).slice(0, limit);
}

function isProfile(value) {
  return PROFILES.has(String(value || ''));
}

function normalizeProfile(value) {
  return isProfile(value) ? String(value) : 'federal_credit_union';
}

function findingTypes(query) {
  const findings = Array.isArray(query && query.findings) ? query.findings : [];
  return findings.map((f) => (f && f.type) || '').filter(Boolean);
}

function memberDataPanel(queries = []) {
  const rows = (Array.isArray(queries) ? queries : [])
    .filter((q) => findingTypes(q).some((type) => type === 'EXACT_MATCH' || MEMBER_IDENTIFIERS.includes(type)));
  const byStatus = (set) => rows.filter((q) => set.has(String(q.status || ''))).length;
  return {
    identifiers: MEMBER_IDENTIFIERS,
    events: rows.length,
    prevented: byStatus(BLOCKED_STATUSES),
    redacted: byStatus(REDACTED_STATUSES),
    released: rows.filter((q) => String(q.status || '') === 'approved').length,
  };
}

function shadowAiPanel(catalog = []) {
  const rows = Array.isArray(catalog) ? catalog : [];
  const count = (status) => rows.filter((app) => app && app.sanctionedStatus === status).length;
  const unsanctioned = rows.filter((app) => app && ['unsanctioned', 'under_review'].includes(app.sanctionedStatus));
  return {
    totalApps: rows.length,
    sanctioned: count('sanctioned'),
    underReview: count('under_review'),
    tolerated: count('tolerated'),
    unsanctioned: count('unsanctioned'),
    blocked: count('blocked'),
    unreviewedEvents: unsanctioned.reduce((sum, app) => sum + n(app.eventCount), 0),
  };
}

const USE_CASE_ACTIVE = new Set(['approved', 'under_review', 'restricted']);

// Prompt-free rollup of inventory rows for readiness scoring, control states,
// and evidence. Counts and dates only — the rows' free-text fields
// (owner/approvedUse/department) never enter the summary.
function useCasesSummary(rows, nowIso) {
  if (!Array.isArray(rows)) return null;
  const nowMs = Date.parse(nowIso || '') || Date.now();
  const status = (row) => String((row && row.reviewStatus) || '');
  const vendor = (row) => String((row && row.vendorStatus) || 'not_reviewed');
  const active = rows.filter((row) => USE_CASE_ACTIVE.has(status(row)));
  return {
    total: rows.length,
    approved: rows.filter((row) => status(row) === 'approved').length,
    underReview: rows.filter((row) => status(row) === 'under_review').length,
    restricted: rows.filter((row) => status(row) === 'restricted').length,
    retired: rows.filter((row) => status(row) === 'retired').length,
    overdue: active.filter((row) => row.nextReviewAt && Date.parse(row.nextReviewAt) < nowMs).length,
    activeTotal: active.length,
    vendorReviewed: active.filter((row) => vendor(row) === 'reviewed').length,
    vendorPending: active.filter((row) => vendor(row) === 'pending').length,
    vendorNotReviewed: active.filter((row) => vendor(row) === 'not_reviewed').length,
  };
}

const INCIDENT_OPEN = new Set(['open', 'under_review']);

// Prompt-free rollup of incident rows for readiness scoring, control states,
// and evidence: statuses, counts, and deadline math only.
function incidentsSummary(rows, nowIso) {
  if (!Array.isArray(rows)) return null;
  const nowMs = Date.parse(nowIso || '') || Date.now();
  const status = (row) => String((row && row.status) || '');
  const overdue = (row) => INCIDENT_OPEN.has(status(row)) && row.deadlineAt && Date.parse(row.deadlineAt) < nowMs;
  const reportedLate = (row) => row.reportedAt && row.deadlineAt && Date.parse(row.reportedAt) > Date.parse(row.deadlineAt);
  return {
    total: rows.length,
    open: rows.filter((row) => status(row) === 'open').length,
    underReview: rows.filter((row) => status(row) === 'under_review').length,
    reported: rows.filter((row) => status(row) === 'reported').length,
    closed: rows.filter((row) => status(row) === 'closed').length,
    overdue: rows.filter(overdue).length,
    reportedLate: rows.filter(reportedLate).length,
  };
}

// Derived, prompt-free incident timeline: consumes only sanitized
// (safeQuery-shaped) rows — who, destination, decision, data types, blocked
// vs exposed. Never raw prompt text and never audit.detail.
function incidentTimeline(incident, safeQueries = []) {
  return safeQueries
    .filter(Boolean)
    .map((q) => ({
      queryId: safeText(q.id, '', 80),
      at: safeText(q.createdAt, '', 80),
      user: safeText(q.user, 'unknown', 160),
      destination: safeText(q.destination, 'unknown', 253),
      decision: safeText(q.status, 'unknown', 40),
      prevented: BLOCKED_STATUSES.has(String(q.status || '')),
      dataClasses: findingTypes(q).slice(0, 24),
    }))
    .sort((a, b) => a.at.localeCompare(b.at));
}

// Board-packet seat block: scalar aggregates plus the license true-up — the
// per-user `users[]` roster is deliberately dropped (this document leaves the
// security team).
function seatAggregates(seatReport, licenseStatus) {
  const s = seatReport || {};
  const licensedSeats = licenseStatus && Number.isFinite(Number(licenseStatus.seats)) ? Number(licenseStatus.seats) : null;
  const configuredLimit = n(s.seatLimit) || null;
  const seatsUsed = n(s.seatsUsed);
  return {
    tenantId: safeText(s.tenantId, '', 80) || null,
    saasMode: s.saasMode === true,
    seatLimit: configuredLimit,
    seatsUsed,
    seatsRemaining: s.seatsRemaining == null ? null : n(s.seatsRemaining),
    overLimit: s.overLimit === true,
    trueUp: {
      licensedSeats,
      configuredLimit,
      seatsUsed,
      // Nothing wires the license seat count to the configured env limit; the
      // packet is where a mismatch becomes visible.
      mismatch: !!((licensedSeats && configuredLimit && licensedSeats !== configuredLimit)
        || (licensedSeats && seatsUsed > licensedSeats)),
    },
  };
}

// Monthly/quarterly executive summary: the readiness report's prompt-free
// panels plus seat aggregates and license state. JSON v1 (per the plan).
function boardPacket(input = {}) {
  const report = input.report || summarize(input);
  const lic = input.licenseStatus || null;
  return {
    generatedAt: report.generatedAt,
    profile: report.profile,
    readiness: { score: report.score, state: report.state },
    memberData: report.panels.memberData,
    shadowAi: report.panels.shadowAi,
    useCases: report.panels.useCases,
    incidents: report.panels.incidents,
    exceptions: report.panels.exceptions,
    exportHealth: report.panels.exportHealth,
    audit: report.panels.audit,
    seats: seatAggregates(input.seatReport, lic),
    license: lic ? {
      state: safeText(lic.state, 'unlicensed', 40),
      plan: safeText(lic.plan, '', 40) || null,
      expires: safeText(lic.expires, '', 80) || null,
    } : null,
  };
}

function edmPanel(edm) {
  if (!edm || typeof edm !== 'object') return { configured: false, enabled: false, active: false, fingerprints: 0 };
  const configured = n(edm.fingerprints) > 0;
  const enabled = edm.enabled === true;
  return {
    configured,
    enabled,
    // A loaded-but-disabled watchlist is NOT protecting members; surfaces must
    // never report it as running (matches edmActive in control-map.js).
    active: configured && enabled,
    fingerprints: n(edm.fingerprints),
    minLength: n(edm.minLength),
    severity: n(edm.severity),
  };
}

function exceptionsPanel(review) {
  if (!review || typeof review !== 'object') return null;
  return {
    total: n(review.total),
    active: n(review.active),
    expiringSoon: n(review.expiringSoon),
    reviewDue: n(review.reviewDue),
    expired: n(review.expired),
    disabled: n(review.disabled),
    reviewWindowDays: n(review.reviewWindowDays),
  };
}

function exportHealthPanel(schedule) {
  if (!schedule || typeof schedule !== 'object') return { scheduled: false };
  return {
    scheduled: schedule.enabled !== false,
    cadence: safeText(schedule.cadence, '', 40) || null,
    nextRunAt: safeText(schedule.nextRunAt, '', 80) || null,
    retentionDays: n(schedule.retentionDays) || null,
  };
}

function auditPanel(integrity) {
  if (!integrity || typeof integrity !== 'object') return { verified: false, count: 0 };
  return { verified: integrity.ok === true, count: n(integrity.count) };
}

function scoreControls(controls) {
  const scored = controls.filter((control) => control.state !== 'not_provided');
  const covered = scored.filter((control) => control.state === 'covered').length;
  return scored.length ? bound((covered / scored.length) * 100) : 0;
}

function stateFor(score, auditVerified) {
  if (!auditVerified) return 'blocked';
  return score >= 90 ? 'ready' : 'attention';
}

function nextActions(controls) {
  return controls
    .filter((control) => control.state === 'attention')
    .slice(0, 5)
    .map((control, index) => ({
      id: control.id,
      label: safeText(control.title, 'Control gap', 120),
      detail: safeText(control.summary, 'Review this control.', 240),
      targetTab: CONTROL_TARGET_TABS[control.id] || 'policy',
      priority: index + 1,
    }));
}

function summarize(input = {}) {
  const generatedAt = input.generatedAt || new Date().toISOString();
  const controls = Array.isArray(input.controls) && input.controls.length
    ? input.controls
    : controlMap.buildControlMappings({ ...input, generatedAt });
  const audit = auditPanel(input.auditIntegrity);
  const score = scoreControls(controls);
  return {
    profile: normalizeProfile(input.examinerProfile),
    generatedAt,
    score,
    state: stateFor(score, audit.verified),
    controls,
    panels: {
      memberData: memberDataPanel(input.queries),
      shadowAi: shadowAiPanel(input.catalog),
      edm: edmPanel(input.edm),
      useCases: (input.useCases && typeof input.useCases === 'object') ? input.useCases : null,
      incidents: (input.incidents && typeof input.incidents === 'object') ? input.incidents : null,
      exceptions: exceptionsPanel(input.policyExceptionReview),
      exportHealth: exportHealthPanel(input.reportSchedule),
      audit,
    },
    nextActions: nextActions(controls),
  };
}

module.exports = {
  summarize,
  isProfile,
  useCasesSummary,
  incidentsSummary,
  incidentTimeline,
  boardPacket,
  _internal: { memberDataPanel, shadowAiPanel, edmPanel, scoreControls, stateFor },
};
