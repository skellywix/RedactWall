'use strict';
/**
 * Sanitized outbound alerting for SIEM/SOC tools.
 *
 * Alerts are best-effort and privacy-preserving: no raw prompt, no redacted
 * prompt body, no token vault, and no raw finding values leave this process.
 */
require('./env').loadEnv();
const crypto = require('node:crypto');
const { safeSensor, safeSensorVersionGap } = require('./sensor-metadata');
const routing = require('./routing');
const { outboundHttpsUrl } = require('./url-policy');

function num(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

// Bound every outbound webhook so a slow/hung SIEM endpoint cannot stall the
// caller (posture snapshots, alert emission) indefinitely.
const OUTBOUND_TIMEOUT_MS = num(process.env.SIEM_WEBHOOK_TIMEOUT_MS, 8000);
function outboundSignal() {
  return typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(OUTBOUND_TIMEOUT_MS) : undefined;
}

function alertThresholds(opts = {}) {
  return {
    minRisk: num(opts.minRisk ?? process.env.SIEM_ALERT_MIN_RISK, 25),
    minSeverity: num(opts.minSeverity ?? process.env.SIEM_ALERT_MIN_SEVERITY, 3),
  };
}

function shouldAlert(query, opts = {}) {
  if (!query) return false;
  if (opts.force) return true;
  const { minRisk, minSeverity } = alertThresholds(opts);
  const status = String(query.status || '');
  if (['pending', 'pending_justification', 'response_flagged', 'response_redacted', 'response_blocked', 'destination_blocked', 'file_upload_blocked', 'action_blocked', 'injection_blocked', 'file_blocked_unscanned', 'ocr_required'].includes(status)) return true;
  return (query.riskScore || 0) >= minRisk || (query.maxSeverity || 0) >= minSeverity;
}

function sanitizedAlert(query, opts = {}) {
  const workflow = routing.publicWorkflow(query);
  return {
    schemaVersion: 1,
    eventType: 'promptwall.security_event',
    action: opts.action || null,
    adminEvent: !!opts.adminEvent,
    adminActor: opts.adminActor || null,
    stepUpScope: opts.stepUpScope || null,
    sensorVersionGap: safeSensorVersionGap(opts.sensorVersionGap),
    queryId: query.id,
    createdAt: query.createdAt,
    status: query.status,
    mode: query.mode || null,
    user: query.user || 'unknown',
    orgId: query.orgId || null,
    source: query.source || 'unknown',
    channel: query.channel || 'unknown',
    sensor: safeSensor(query.sensor),
    destination: query.destination || 'unknown',
    riskScore: query.riskScore || 0,
    maxSeverity: query.maxSeverity || 0,
    maxSeverityLabel: query.maxSeverityLabel || 'none',
    findings: (query.findings || []).map((f) => ({
      type: f.type,
      severity: f.severity,
      score: f.score,
      masked: f.masked,
    })),
    // Bound categories/reasons so the outbound SIEM payload stays prompt-free
    // even if a detector ever embedded a value in a reason string.
    categories: (query.categories || []).slice(0, 40).map((c) => safeText(typeof c === 'string' ? c : (c && c.category) || '', '', 80)),
    reasons: (query.reasons || []).slice(0, 20).map((r) => safeText(r, '', 200)),
    workflow,
  };
}

function safeText(value, fallback = null, limit = 160) {
  const text = String(value || '').trim();
  return text ? text.slice(0, limit) : fallback;
}

function safeNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function boundedInt(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function parseBool(value, fallback = false) {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  return /^(1|true|yes|on)$/i.test(value.trim());
}

function postureFeedConfig(env = process.env, opts = {}) {
  const enabled = Object.prototype.hasOwnProperty.call(opts, 'enabled')
    ? opts.enabled === true
    : parseBool(env.SIEM_POSTURE_FEED_ENABLED, false);
  return {
    enabled,
    minIntervalMs: boundedInt(
      Object.prototype.hasOwnProperty.call(opts, 'minIntervalMs') ? opts.minIntervalMs : env.SIEM_POSTURE_MIN_INTERVAL_MS,
      300000,
      10000,
      86400000,
    ),
  };
}

function postureFeedEnabled(env = process.env, opts = {}) {
  const cfg = postureFeedConfig(env, opts);
  const rawUrl = Object.prototype.hasOwnProperty.call(opts, 'url') ? opts.url : env.SIEM_WEBHOOK_URL;
  return cfg.enabled && !!outboundHttpsUrl(rawUrl);
}

function sanitizedPostureArea(area = {}) {
  const playbook = Array.isArray(area.playbook) ? area.playbook : [];
  const nextStep = playbook.find((step) => step && step.status === 'next');
  const proofLedger = area.proofLedger && typeof area.proofLedger === 'object' ? area.proofLedger : {};
  return {
    id: safeText(area.id, 'unknown', 80),
    label: safeText(area.label, 'Unknown area', 120),
    score: safeNumber(area.score),
    state: safeText(area.state, 'unknown', 40),
    status: safeText(area.status, 'unknown', 40),
    owner: safeText(area.owner, 'security', 80),
    source: safeText(area.source, 'unknown', 80),
    evidenceCount: Array.isArray(area.evidence) ? area.evidence.length : 0,
    gapCount: Array.isArray(area.gaps) ? area.gaps.length : 0,
    playbookDone: playbook.filter((step) => step && step.status === 'done').length,
    playbookTodo: playbook.filter((step) => step && step.status !== 'done').length,
    proofVerified: safeNumber(proofLedger.verified),
    proofAttention: safeNumber(proofLedger.attention),
    proofMissing: safeNumber(proofLedger.missing),
    proofTotal: safeNumber(proofLedger.total),
    nextStep: safeText(nextStep && nextStep.label, null, 120),
  };
}

function actionQueueSummary(actions = []) {
  const rows = Array.isArray(actions) ? actions : [];
  const bySeverity = {};
  const byCategory = {};
  const byWorkflow = {};
  let proofPending = 0;
  for (const action of rows) {
    const severity = safeText(action && action.severity, 'unknown', 40);
    const category = safeText(action && action.category, 'unknown', 80);
    const workflow = safeText(action && action.workflowStatus, 'open', 40);
    bySeverity[severity] = safeNumber(bySeverity[severity]) + 1;
    byCategory[category] = safeNumber(byCategory[category]) + 1;
    byWorkflow[workflow] = safeNumber(byWorkflow[workflow]) + 1;
    if (action && action.workflowProofState === 'proof_pending') proofPending += 1;
  }
  return {
    total: rows.length,
    bySeverity,
    byCategory,
    byWorkflow,
    proofPending,
  };
}

function sanitizedPostureAlert(report = {}, opts = {}) {
  const hardening = report.hardening && typeof report.hardening === 'object' ? report.hardening : {};
  const mission = hardening.mission && typeof hardening.mission === 'object' ? hardening.mission : {};
  const current = mission.current && typeof mission.current === 'object' ? mission.current : {};
  const inventorySummary = report.aiInventory && report.aiInventory.summary && typeof report.aiInventory.summary === 'object'
    ? report.aiInventory.summary
    : {};
  const threatSummary = report.threatGuardrails && report.threatGuardrails.summary && typeof report.threatGuardrails.summary === 'object'
    ? report.threatGuardrails.summary
    : {};
  const segmentSummary = report.segments && report.segments.summary && typeof report.segments.summary === 'object'
    ? report.segments.summary
    : {};
  const proofLedger = mission.proofLedger && typeof mission.proofLedger === 'object'
    ? mission.proofLedger
    : hardening.proofLedger && typeof hardening.proofLedger === 'object' ? hardening.proofLedger : {};
  return {
    schemaVersion: 1,
    eventType: 'promptwall.posture_snapshot',
    action: opts.action || 'POSTURE_SNAPSHOT',
    automatic: opts.automatic === true,
    trigger: safeText(opts.trigger, null, 80),
    generatedAt: safeText(report.generatedAt, new Date().toISOString(), 80),
    windowDays: safeNumber(report.windowDays),
    summary: {
      events: safeNumber(report.summary && report.summary.events),
      sensitiveEvents: safeNumber(report.summary && report.summary.sensitiveEvents),
      blocked: safeNumber(report.summary && report.summary.blocked),
      redacted: safeNumber(report.summary && report.summary.redacted),
      pending: safeNumber(report.summary && report.summary.pending),
      controlRate: safeNumber(report.summary && report.summary.controlRate),
      shadowEvents: safeNumber(report.summary && report.summary.shadowEvents),
      unresolvedShadowDestinations: safeNumber(report.summary && report.summary.unresolvedShadowDestinations),
      activeRequiredSensors: safeNumber(report.summary && report.summary.activeRequiredSensors),
      requiredSensors: safeNumber(report.summary && report.summary.requiredSensors),
      postureSegments: safeNumber(segmentSummary.total),
      postureSegmentAttention: safeNumber(segmentSummary.attention),
      postureSegmentCritical: safeNumber(segmentSummary.critical),
    },
    hardening: {
      score: safeNumber(hardening.score),
      state: safeText(hardening.state, 'unknown', 40),
      ready: safeNumber(hardening.summary && hardening.summary.ready),
      attention: safeNumber(hardening.summary && hardening.summary.attention),
      blocked: safeNumber(hardening.summary && hardening.summary.blocked),
      total: safeNumber(hardening.summary && hardening.summary.total),
      mission: {
        state: safeText(mission.state, 'unknown', 40),
        progressPercent: safeNumber(mission.progress && mission.progress.percent),
        openSteps: safeNumber(mission.progress && mission.progress.open),
        proofLedger: {
          verified: safeNumber(proofLedger.verified),
          attention: safeNumber(proofLedger.attention),
          missing: safeNumber(proofLedger.missing),
          total: safeNumber(proofLedger.total),
          percent: safeNumber(proofLedger.percent),
        },
        currentArea: safeText(current.areaLabel, null, 120),
        currentStep: safeText(current.label, null, 120),
      },
      areas: (Array.isArray(hardening.areas) ? hardening.areas : []).slice(0, 8).map(sanitizedPostureArea),
    },
    aiInventory: {
      sanctioned: safeNumber(inventorySummary.sanctioned),
      unsanctioned: safeNumber(inventorySummary.unsanctioned),
      shadow: safeNumber(inventorySummary.shadow),
      localTools: safeNumber(inventorySummary.localTools),
      unapprovedLocalTools: safeNumber(inventorySummary.unapprovedLocalTools),
      activeDestinations: safeNumber(inventorySummary.activeDestinations),
      totalEvents: safeNumber(inventorySummary.totalEvents),
      highRiskAssets: safeNumber(inventorySummary.highRiskAssets),
    },
    threatGuardrails: {
      events: safeNumber(threatSummary.events),
      detections: safeNumber(threatSummary.detections),
      activeRules: safeNumber(threatSummary.activeRules),
      promptInjection: safeNumber(threatSummary.promptInjection),
      sensitiveDisclosure: safeNumber(threatSummary.sensitiveDisclosure),
      unsafeOutput: safeNumber(threatSummary.unsafeOutput),
      agentActions: safeNumber(threatSummary.agentActions),
      shadowAi: safeNumber(threatSummary.shadowAi),
      unscannedContent: safeNumber(threatSummary.unscannedContent),
    },
    actionQueue: actionQueueSummary(report.actionQueue),
  };
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((out, key) => {
      if (['action', 'automatic', 'generatedAt', 'trigger'].includes(key)) return out;
      out[key] = canonicalize(value[key]);
      return out;
    }, {});
  }
  return value;
}

function postureFingerprint(report = {}, opts = {}) {
  const payload = sanitizedPostureAlert(report, opts);
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(payload))).digest('hex');
}

function postureFeedDecision(report = {}, state = {}, opts = {}) {
  const cfg = postureFeedConfig(opts.env || process.env, opts);
  if (!cfg.enabled && opts.force !== true) return { ok: false, reason: 'disabled' };
  const fingerprint = postureFingerprint(report, { action: opts.action || 'POSTURE_FEED', automatic: true, trigger: opts.trigger });
  const nowMs = boundedInt(opts.nowMs, Date.now(), 0, 8640000000000000);
  if (state.fingerprint === fingerprint && opts.force !== true) return { ok: false, reason: 'unchanged', fingerprint };
  const elapsed = nowMs - safeNumber(state.lastAttemptAt);
  if (state.lastAttemptAt && elapsed < cfg.minIntervalMs && opts.force !== true) {
    return { ok: false, reason: 'rate_limited', retryMs: cfg.minIntervalMs - elapsed, fingerprint };
  }
  return { ok: true, fingerprint, nowMs };
}

async function emitSecurityAlert(query, opts = {}) {
  const rawUrl = Object.prototype.hasOwnProperty.call(opts, 'url') ? opts.url : process.env.SIEM_WEBHOOK_URL;
  if (!rawUrl) return { sent: false, reason: 'disabled' };
  const url = outboundHttpsUrl(rawUrl);
  if (!url) return { sent: false, reason: 'invalid_url' };
  if (!shouldAlert(query, opts)) return { sent: false, reason: 'below_threshold' };

  const headers = { 'Content-Type': 'application/json' };
  const token = Object.prototype.hasOwnProperty.call(opts, 'token') ? opts.token : process.env.SIEM_WEBHOOK_TOKEN;
  if (token) headers.Authorization = 'Bearer ' + token;

  try {
    const fetchImpl = opts.fetch || fetch;
    const res = await fetchImpl(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(sanitizedAlert(query, opts)),
      signal: outboundSignal(),
    });
    return res && res.ok ? { sent: true, status: res.status } : { sent: false, reason: 'http_' + (res && res.status) };
  } catch (e) {
    return { sent: false, reason: 'error' };
  }
}

async function emitPostureAlert(report, opts = {}) {
  const rawUrl = Object.prototype.hasOwnProperty.call(opts, 'url') ? opts.url : process.env.SIEM_WEBHOOK_URL;
  if (!rawUrl) return { sent: false, reason: 'disabled' };
  const url = outboundHttpsUrl(rawUrl);
  if (!url) return { sent: false, reason: 'invalid_url' };

  const headers = { 'Content-Type': 'application/json' };
  const token = Object.prototype.hasOwnProperty.call(opts, 'token') ? opts.token : process.env.SIEM_WEBHOOK_TOKEN;
  if (token) headers.Authorization = 'Bearer ' + token;

  try {
    const fetchImpl = opts.fetch || fetch;
    const res = await fetchImpl(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(sanitizedPostureAlert(report, opts)),
      signal: outboundSignal(),
    });
    return res && res.ok ? { sent: true, status: res.status } : { sent: false, reason: 'http_' + (res && res.status) };
  } catch (e) {
    return { sent: false, reason: 'error' };
  }
}

async function emitPostureFeed(report, opts = {}) {
  const state = opts.state && typeof opts.state === 'object' ? opts.state : {};
  const decision = postureFeedDecision(report, state, opts);
  if (!decision.ok) return { sent: false, attempted: false, reason: decision.reason, retryMs: decision.retryMs };
  state.lastAttemptAt = decision.nowMs;
  const result = await emitPostureAlert(report, {
    ...opts,
    action: opts.action || 'POSTURE_FEED',
    automatic: true,
  });
  if (result.sent) {
    state.fingerprint = decision.fingerprint;
    state.lastSentAt = decision.nowMs;
  }
  return { ...result, attempted: true, fingerprint: decision.fingerprint };
}

module.exports = {
  alertThresholds,
  shouldAlert,
  sanitizedAlert,
  emitSecurityAlert,
  postureFeedConfig,
  postureFeedEnabled,
  sanitizedPostureAlert,
  postureFingerprint,
  postureFeedDecision,
  emitPostureAlert,
  emitPostureFeed,
};
