'use strict';
/**
 * Examiner export pack builder.
 *
 * Exports operational evidence without prompt bodies, token vaults, raw retained
 * prompts, or free-form audit details that may contain sensitive context.
 */
const crypto = require('crypto');

const POLICY_AUDIT_ACTIONS = new Set(['POLICY_UPDATED', 'POLICY_TEMPLATE_APPLIED']);
const POLICY_AUDIT_FIELDS = new Set([
  'enforcementMode',
  'blockMinSeverity',
  'blockRiskScore',
  'alwaysBlock',
  'storeRawForApproval',
  'ignore',
  'disabledDetectors',
  'governedDestinations',
  'scanner',
]);

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

module.exports = { buildEvidencePack, safeQuery, safeAuditEntry, safePolicyChange, hashText };
