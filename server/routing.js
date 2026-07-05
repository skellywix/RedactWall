'use strict';
/**
 * Approval ownership and SLA routing for held PromptWall decisions.
 *
 * The routing contract is deliberately metadata-only. Rules can look at detector
 * ids, categories, source, channel, destination, severity, and risk, but never
 * need raw prompt text or file bytes.
 */
const policy = require('./policy');

const ROUTABLE_STATUSES = new Set([
  'pending',
  'pending_justification',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'injection_blocked',
  'response_flagged',
  'response_blocked',
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
  'FINANCIAL_STATEMENT',
  'IBAN',
  'LOAN_NUMBER',
  'MEMBER_ID',
  'ROUTING_NUMBER',
  'SWIFT_BIC',
  'TAX_FILING',
  'US_ITIN',
  'US_SSN',
  'US_TIN_EIN',
]);

const HR_LABELS = new Set([
  'HR_RECORD',
]);

const LEGAL_LABELS = new Set([
  'CONFIDENTIAL_BUSINESS',
  'LEGAL_CONTRACT',
]);

function labelsFor(query = {}) {
  return [...new Set([
    ...detectorLabelsFor(query),
    ...categoryLabelsFor(query),
  ].filter(Boolean))];
}

function detectorLabelsFor(query = {}) {
  const labels = [];
  for (const finding of query.findings || []) {
    if (finding && finding.type) labels.push(String(finding.type));
  }
  for (const key of Object.keys(query.entityCounts || {})) labels.push(String(key));
  return [...new Set(labels.filter(Boolean))];
}

function categoryLabelsFor(query = {}) {
  const labels = [];
  for (const category of query.categories || []) {
    if (typeof category === 'string') labels.push(category);
    else if (category && category.category) labels.push(String(category.category));
  }
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

function listMatch(ruleValues, queryValues) {
  if (!Array.isArray(ruleValues) || !ruleValues.length) return true;
  const values = new Set((queryValues || []).map((value) => String(value || '').trim().toLowerCase()).filter(Boolean));
  return ruleValues.some((ruleValue) => values.has(String(ruleValue || '').trim().toLowerCase()));
}

function normalizedList(values) {
  const source = Array.isArray(values) ? values : [values];
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const text = String(item || '').trim();
    const key = text.toLowerCase();
    if (!text || seen.has(key)) continue;
    seen.add(key);
    out.push(text);
  }
  return out;
}

function identityFacts(query = {}, context = {}) {
  const users = normalizedList([query.user, context.user]);
  const orgIds = normalizedList([query.orgId, context.orgId]);
  const groups = normalizedList([
    ...(Array.isArray(query.groups) ? query.groups : []),
    ...(Array.isArray(query.userGroups) ? query.userGroups : []),
    ...(Array.isArray(context.groups) ? context.groups : []),
  ]);
  return {
    users,
    orgIds,
    groups,
  };
}

function destinationRuleMatch(ruleValues, destination) {
  if (!Array.isArray(ruleValues) || !ruleValues.length) return true;
  return policy.destinationMatches(destination, ruleValues);
}

function ruleHasMatcher(rule = {}) {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations'].some((key) => Array.isArray(rule[key]) && rule[key].length)
    || rule.minSeverity !== undefined
    || rule.minRiskScore !== undefined;
}

function ruleMatches(rule = {}, query = {}, facts = {}) {
  if (rule.enabled === false) return false;
  if (!ruleHasMatcher(rule)) return false;
  if (!listMatch(rule.users, facts.users)) return false;
  if (!listMatch(rule.groups, facts.groups)) return false;
  if (!listMatch(rule.orgIds, facts.orgIds)) return false;
  if (!listMatch(rule.detectors, facts.detectorLabels)) return false;
  if (!listMatch(rule.categories, facts.categoryLabels)) return false;
  if (!listMatch(rule.sources, [facts.source])) return false;
  if (!listMatch(rule.channels, [facts.channel])) return false;
  if (!destinationRuleMatch(rule.destinations, query.destination)) return false;
  if (rule.minSeverity !== undefined && facts.maxSeverity < Number(rule.minSeverity)) return false;
  if (rule.minRiskScore !== undefined && facts.riskScore < Number(rule.minRiskScore)) return false;
  return true;
}

function customRoute(query = {}, facts = {}, activePolicy = {}) {
  const rules = Array.isArray(activePolicy.approvalRoutingRules) ? activePolicy.approvalRoutingRules : [];
  for (const rule of rules) {
    if (!ruleMatches(rule, query, facts)) continue;
    return {
      assignedRole: rule.assignedRole || 'approver',
      assignedGroup: rule.assignedGroup || 'compliance',
      workflowReason: `rule:${rule.id}${rule.reason ? ':' + rule.reason : ''}`,
      slaMinutes: Number(rule.slaMinutes) || 480,
      notificationStatus: 'not_configured',
      escalatedAt: null,
    };
  }
  return null;
}

function applyCriticalFloor(route, facts) {
  if (!(facts.maxSeverity >= 4 || facts.riskScore >= 75)) return route;
  return {
    ...route,
    assignedRole: 'security_admin',
    assignedGroup: route.assignedGroup === 'legal' ? 'legal' : 'security',
    workflowReason: String(route.workflowReason || 'default_review') + '+critical',
    slaMinutes: Math.min(Number(route.slaMinutes) || 480, 60),
  };
}

function routeDecision(query = {}, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date(opts.now || Date.now());
  const activePolicy = opts.policy || policy.loadPolicy();
  const context = opts.context || opts.identityContext || {};
  const detectorLabels = detectorLabelsFor(query);
  const categoryLabels = categoryLabelsFor(query);
  const labels = [...new Set([...detectorLabels, ...categoryLabels])];
  const source = String(query.source || '').toLowerCase();
  const channel = String(query.channel || '').toLowerCase();
  const riskScore = Number(query.riskScore) || 0;
  const maxSeverity = Number(query.maxSeverity) || 0;
  const facts = {
    labels,
    detectorLabels,
    categoryLabels,
    source,
    channel,
    riskScore,
    maxSeverity,
    ...identityFacts(query, context),
  };

  let route = customRoute(query, facts, activePolicy);
  if (!route) route = {
    assignedRole: 'approver',
    assignedGroup: 'compliance',
    workflowReason: 'default_compliance_review',
    slaMinutes: 480,
    notificationStatus: 'not_configured',
    escalatedAt: null,
  };

  if (route.workflowReason === 'default_compliance_review') {
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
    } else if (firstMatching(labels, HR_LABELS)) {
      route = {
        ...route,
        assignedGroup: 'privacy',
        workflowReason: 'category:HR_RECORD',
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
  }

  route = applyCriticalFloor(route, facts);

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
  detectorLabelsFor,
  categoryLabelsFor,
  labelsFor,
  publicWorkflow,
  ruleMatches,
  routeDecision,
  routeableStatus,
  withWorkflow,
};
