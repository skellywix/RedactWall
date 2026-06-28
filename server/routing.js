'use strict';
/**
 * Approval ownership and SLA routing for held PromptWall decisions.
 *
 * The routing contract is deliberately metadata-only. Rules can look at detector
 * ids, categories, source, channel, destination, severity, and risk, but never
 * need raw prompt text or file bytes.
 */

const ROUTABLE_STATUSES = new Set([
  'pending',
  'pending_justification',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'file_blocked_unscanned',
  'injection_blocked',
  'response_flagged',
]);

const SECURITY_LABELS = new Set([
  'CANARY_TOKEN',
  'CREDENTIALS',
  'PASSWORD',
  'PRIVATE_KEY',
  'SECRET_KEY',
  'SOURCE_CODE',
]);

const HEALTH_LABELS = new Set([
  'DOB',
  'HEALTH_INSURANCE_ID',
  'HEALTH_RECORD',
  'MEDICAL_RECORD_NUMBER',
  'US_NPI',
]);

const FINANCIAL_MEMBER_LABELS = new Set([
  'BANK_ACCOUNT',
  'CREDIT_CARD',
  'IBAN',
  'LOAN_NUMBER',
  'MEMBER_ID',
  'ROUTING_NUMBER',
  'SWIFT_BIC',
  'US_ITIN',
  'US_SSN',
  'US_TIN_EIN',
]);

const LEGAL_LABELS = new Set([
  'CONFIDENTIAL_BUSINESS',
  'LEGAL_CONTRACT',
]);

function labelsFor(query = {}) {
  const labels = [];
  for (const finding of query.findings || []) {
    if (finding && finding.type) labels.push(String(finding.type));
  }
  for (const category of query.categories || []) {
    if (typeof category === 'string') labels.push(category);
    else if (category && category.category) labels.push(String(category.category));
  }
  for (const key of Object.keys(query.entityCounts || {})) labels.push(String(key));
  return [...new Set(labels.filter(Boolean))];
}

function firstMatching(labels, wanted) {
  return labels.find((label) => wanted.has(label)) || '';
}

function isoAfterMinutes(now, minutes) {
  const base = now instanceof Date ? now : new Date(now || Date.now());
  return new Date(base.getTime() + minutes * 60 * 1000).toISOString();
}

function routeableStatus(status) {
  return ROUTABLE_STATUSES.has(String(status || ''));
}

function routeDecision(query = {}, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date(opts.now || Date.now());
  const labels = labelsFor(query);
  const source = String(query.source || '').toLowerCase();
  const channel = String(query.channel || '').toLowerCase();
  const riskScore = Number(query.riskScore) || 0;
  const maxSeverity = Number(query.maxSeverity) || 0;

  let route = {
    assignedRole: 'approver',
    assignedGroup: 'compliance',
    workflowReason: 'default_compliance_review',
    slaMinutes: 480,
    notificationStatus: 'not_configured',
    escalatedAt: null,
  };

  const security = firstMatching(labels, SECURITY_LABELS);
  const health = firstMatching(labels, HEALTH_LABELS);
  const financial = firstMatching(labels, FINANCIAL_MEMBER_LABELS);
  const legal = firstMatching(labels, LEGAL_LABELS);

  if (security) {
    route = {
      ...route,
      assignedRole: 'security_admin',
      assignedGroup: 'security',
      workflowReason: `detector:${security}`,
      slaMinutes: security === 'CANARY_TOKEN' || security === 'CREDENTIALS' || security === 'PRIVATE_KEY' || security === 'SECRET_KEY' ? 30 : 60,
    };
  } else if (health) {
    route = {
      ...route,
      assignedGroup: 'privacy',
      workflowReason: `detector:${health}`,
      slaMinutes: 240,
    };
  } else if (financial) {
    route = {
      ...route,
      assignedGroup: 'compliance',
      workflowReason: `detector:${financial}`,
      slaMinutes: 240,
    };
  } else if (legal) {
    route = {
      ...route,
      assignedGroup: 'legal',
      workflowReason: `category:${legal}`,
      slaMinutes: legal === 'CONFIDENTIAL_BUSINESS' ? 240 : 480,
    };
  } else if (source === 'endpoint_agent' || channel === 'file_upload') {
    route = {
      ...route,
      assignedGroup: 'security',
      workflowReason: 'source:endpoint_file_flow',
      slaMinutes: 120,
    };
  }

  if (maxSeverity >= 4 || riskScore >= 75) {
    route = {
      ...route,
      assignedRole: 'security_admin',
      assignedGroup: route.assignedGroup === 'legal' ? 'legal' : 'security',
      workflowReason: route.workflowReason + '+critical',
      slaMinutes: Math.min(route.slaMinutes, 60),
    };
  }

  return {
    assignedRole: route.assignedRole,
    assignedGroup: route.assignedGroup,
    workflowReason: route.workflowReason,
    slaDueAt: isoAfterMinutes(now, route.slaMinutes),
    escalatedAt: route.escalatedAt,
    notificationStatus: route.notificationStatus,
  };
}

function withWorkflow(query = {}, opts = {}) {
  if (!query || !routeableStatus(query.status)) return query;
  if (query.assignedRole || query.assignedGroup || query.slaDueAt) return query;
  return {
    ...query,
    ...routeDecision(query, opts),
  };
}

function publicWorkflow(query = {}) {
  return {
    assignedRole: query.assignedRole || null,
    assignedGroup: query.assignedGroup || null,
    workflowReason: query.workflowReason || null,
    slaDueAt: query.slaDueAt || null,
    escalatedAt: query.escalatedAt || null,
    escalationReason: query.escalationReason || null,
    notificationStatus: query.notificationStatus || null,
    notificationLastAttemptAt: query.notificationLastAttemptAt || null,
    notificationAttemptCount: Number(query.notificationAttemptCount) || 0,
    notificationChannels: Array.isArray(query.notificationChannels)
      ? query.notificationChannels.filter((item) => typeof item === 'string').slice(0, 8)
      : [],
  };
}

module.exports = {
  labelsFor,
  publicWorkflow,
  routeDecision,
  routeableStatus,
  withWorkflow,
};
