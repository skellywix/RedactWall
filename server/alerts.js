'use strict';
/**
 * Sanitized outbound alerting for SIEM/SOC tools.
 *
 * Alerts are best-effort and privacy-preserving: no raw prompt, no redacted
 * prompt body, no token vault, and no raw finding values leave this process.
 */
require('./env').loadEnv();
const { safeSensor, safeSensorVersionGap } = require('./sensor-metadata');
const routing = require('./routing');

function num(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
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
  if (['pending', 'pending_justification', 'response_flagged', 'destination_blocked', 'file_upload_blocked', 'injection_blocked', 'file_blocked_unscanned', 'ocr_required'].includes(status)) return true;
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
    categories: query.categories || [],
    reasons: query.reasons || [],
    workflow,
  };
}

async function emitSecurityAlert(query, opts = {}) {
  const url = Object.prototype.hasOwnProperty.call(opts, 'url') ? opts.url : process.env.SIEM_WEBHOOK_URL;
  if (!url) return { sent: false, reason: 'disabled' };
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
    });
    return res && res.ok ? { sent: true, status: res.status } : { sent: false, reason: 'http_' + (res && res.status) };
  } catch (e) {
    return { sent: false, reason: 'error' };
  }
}

module.exports = { alertThresholds, shouldAlert, sanitizedAlert, emitSecurityAlert };
