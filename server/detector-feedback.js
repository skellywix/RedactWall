'use strict';

const coverage = require('./coverage');
const detector = require('./detector');
const customDetectors = require('./custom-detectors');

const VERDICTS = Object.freeze(['valid', 'false_positive', 'too_sensitive', 'missed']);
const VERDICT_LABELS = Object.freeze({
  valid: 'Valid detection',
  false_positive: 'Noisy / false positive',
  too_sensitive: 'Too sensitive',
  missed: 'Missed signal',
});

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function safeText(value, fallback = 'unknown', limit = 160) {
  const text = String(value || '').trim();
  return (text || fallback).slice(0, limit);
}

function knownDetectorIds() {
  try {
    return new Set(detector.listDetectors({
      customDetectors: customDetectors.loadCustomDetectors(),
    }).map((item) => item.id));
  } catch {
    return new Set();
  }
}

function detectorIdsForQuery(q = {}, known = knownDetectorIds()) {
  const ids = [];
  for (const finding of q.findings || []) {
    if (finding && finding.type) ids.push(String(finding.type));
  }
  for (const category of q.categories || []) {
    if (typeof category === 'string') ids.push(category);
    else if (category && category.category) ids.push(String(category.category));
  }
  for (const key of Object.keys(q.entityCounts || {})) ids.push(key);
  return [...new Set(ids.map((id) => safeText(id, '', 80)).filter((id) => id && (!known.size || known.has(id))))].sort();
}

function publicFeedback(record = {}) {
  return {
    id: safeText(record.id, '', 80),
    createdAt: safeText(record.createdAt, '', 80),
    queryId: safeText(record.queryId, '', 80),
    detectorId: safeText(record.detectorId, '', 80),
    verdict: VERDICTS.includes(record.verdict) ? record.verdict : 'valid',
    verdictLabel: VERDICT_LABELS[record.verdict] || VERDICT_LABELS.valid,
    actor: safeText(record.actor, '', 120),
    role: safeText(record.role, '', 80),
    source: safeText(record.source, '', 80),
    channel: safeText(record.channel, '', 80),
    destination: safeText(record.destination, '', 253),
    queryStatus: safeText(record.queryStatus, '', 80),
    riskScore: Math.max(0, Math.min(100, Math.round(n(record.riskScore)))),
    maxSeverity: Math.max(0, Math.min(4, Math.round(n(record.maxSeverity)))),
  };
}

function feedbackState(row) {
  if (row.falsePositive + row.tooSensitive > 0) return 'attention';
  if (row.missed > 0) return 'attention';
  return row.total ? 'ready' : 'review';
}

function emptyDetectorRow(detectorId) {
  return {
    detectorId,
    label: detectorId.replace(/_/g, ' '),
    total: 0,
    valid: 0,
    falsePositive: 0,
    tooSensitive: 0,
    missed: 0,
    affectedQueries: 0,
    maxRiskScore: 0,
    lastSeen: null,
  };
}

function candidateForQuery(q = {}, feedbackByQuery = new Map(), known = knownDetectorIds(), canFeedback) {
  const detectorIds = detectorIdsForQuery(q, known);
  if (!detectorIds.length) return null;
  const feedback = feedbackByQuery.get(q.id) || [];
  const reviewed = new Set(feedback.map((item) => item.detectorId));
  const detectorId = detectorIds.find((id) => !reviewed.has(id)) || detectorIds[0];
  const candidate = {
    queryId: safeText(q.id, '', 80),
    createdAt: safeText(q.createdAt, '', 80),
    detectorId,
    detectorIds: detectorIds.slice(0, 8),
    destination: coverage.normalizeDestination(q.destination || 'unknown'),
    source: safeText(q.source, 'api', 80),
    channel: safeText(q.channel, 'submit', 80),
    status: safeText(q.status, 'unknown', 80),
    riskScore: Math.max(0, Math.min(100, Math.round(n(q.riskScore)))),
    maxSeverity: Math.max(0, Math.min(4, Math.round(n(q.maxSeverity)))),
    feedbackCount: feedback.length,
    reviewed: feedback.length > 0,
  };
  if (typeof canFeedback === 'function') candidate.canFeedback = Boolean(canFeedback(q));
  return candidate;
}

function report({ rows = [], feedback = [], generatedAt = new Date().toISOString(), canFeedback } = {}) {
  const publicRows = (Array.isArray(feedback) ? feedback : []).map(publicFeedback);
  const byQuery = new Map();
  const byDetector = new Map();
  for (const item of publicRows) {
    if (!byQuery.has(item.queryId)) byQuery.set(item.queryId, []);
    byQuery.get(item.queryId).push(item);
    const row = byDetector.get(item.detectorId) || emptyDetectorRow(item.detectorId);
    row.total += 1;
    if (item.verdict === 'valid') row.valid += 1;
    else if (item.verdict === 'false_positive') row.falsePositive += 1;
    else if (item.verdict === 'too_sensitive') row.tooSensitive += 1;
    else if (item.verdict === 'missed') row.missed += 1;
    row.maxRiskScore = Math.max(row.maxRiskScore, item.riskScore);
    if (!row.lastSeen || item.createdAt > row.lastSeen) row.lastSeen = item.createdAt;
    byDetector.set(item.detectorId, row);
  }
  for (const [detectorId, row] of byDetector.entries()) {
    row.affectedQueries = new Set(publicRows.filter((item) => item.detectorId === detectorId).map((item) => item.queryId)).size;
    row.state = feedbackState(row);
    row.detail = row.total ? `${row.falsePositive + row.tooSensitive} noisy / ${row.valid} valid` : 'awaiting feedback';
  }
  const detectors = [...byDetector.values()]
    .sort((a, b) => (b.falsePositive + b.tooSensitive + b.missed) - (a.falsePositive + a.tooSensitive + a.missed)
      || b.total - a.total
      || a.detectorId.localeCompare(b.detectorId))
    .slice(0, 12);
  const known = knownDetectorIds();
  const reviewQueue = (Array.isArray(rows) ? rows : [])
    .slice()
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
    .map((q) => candidateForQuery(q, byQuery, known, canFeedback))
    .filter(Boolean)
    .sort((a, b) => Number(b.canFeedback === true) - Number(a.canFeedback === true)
      || Number(a.reviewed) - Number(b.reviewed)
      || b.riskScore - a.riskScore
      || String(b.createdAt).localeCompare(String(a.createdAt)))
    .slice(0, 10);
  const total = publicRows.length;
  const falsePositive = publicRows.filter((item) => item.verdict === 'false_positive').length;
  const tooSensitive = publicRows.filter((item) => item.verdict === 'too_sensitive').length;
  const missed = publicRows.filter((item) => item.verdict === 'missed').length;
  return {
    generatedAt,
    summary: {
      total,
      valid: publicRows.filter((item) => item.verdict === 'valid').length,
      falsePositive,
      tooSensitive,
      missed,
      noisy: falsePositive + tooSensitive,
      impactedDetectors: detectors.length,
      reviewCandidates: reviewQueue.length,
      privacy: 'metadata only; prompt bodies excluded',
    },
    detectors,
    reviewQueue,
    recent: publicRows.slice(0, 20),
  };
}

module.exports = {
  VERDICTS,
  VERDICT_LABELS,
  detectorIdsForQuery,
  publicFeedback,
  report,
};
