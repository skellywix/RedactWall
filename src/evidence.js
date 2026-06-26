'use strict';
/**
 * Examiner export pack builder.
 *
 * Exports operational evidence without prompt bodies, token vaults, raw retained
 * prompts, or free-form audit details that may contain sensitive context.
 */
const crypto = require('crypto');

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
  };
}

function safeAuditEntry(a) {
  return {
    id: a.id,
    ts: a.ts,
    action: a.action,
    queryId: a.queryId || null,
    actor: a.actor || null,
    prevHash: a.prevHash,
    hash: a.hash,
    detailHash: hashText(a.detail || ''),
  };
}

function buildEvidencePack(input) {
  const now = input.generatedAt || new Date().toISOString();
  return {
    schemaVersion: 1,
    generatedAt: now,
    service: {
      name: 'PromptSentinel',
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
    detectors: input.detectors || [],
    queries: (input.queries || []).map(safeQuery),
    audit: (input.audit || []).map(safeAuditEntry),
  };
}

module.exports = { buildEvidencePack, safeQuery, safeAuditEntry, hashText };
