'use strict';
/** Metadata-only policy simulation for the admin console. */
const policyEngine = require('./policy');

const OUTCOMES = [
  'blocked',
  'approval_required',
  'justification_required',
  'redacted',
  'warned',
  'allowed',
  'observed',
];

const STRICTNESS = {
  blocked: 6,
  approval_required: 5,
  justification_required: 5,
  redacted: 4,
  warned: 3,
  allowed: 2,
  observed: 1,
};
const SENSITIVE_LABEL_RE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\b\d{12,19}\b)/;

function boundedNumber(value, fallback = 0, min = 0, max = 100) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.round(parsed)));
}

function safeLabel(value, fallback = 'unknown', max = 120) {
  const text = String(value || '').trim();
  if (!text) return fallback;
  if (SENSITIVE_LABEL_RE.test(text)) return fallback === 'unknown' ? 'redacted_label' : fallback;
  return text.replace(/[^\w .:@+*/-]/g, '').slice(0, max) || fallback;
}

function labelList(value, maxItems = 20) {
  const source = Array.isArray(value) ? value : [];
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const raw = item && typeof item === 'object' ? (item.category || item.type || item.id || item.label) : item;
    const label = safeLabel(raw, '', 80).toUpperCase();
    if (!label || seen.has(label)) continue;
    seen.add(label);
    out.push(label);
    if (out.length >= maxItems) break;
  }
  return out;
}

function findingsFromRow(row = {}) {
  const source = Array.isArray(row.findings) ? row.findings : [];
  return source
    .map((finding) => ({
      type: safeLabel(finding && finding.type, '', 80).toUpperCase(),
      severity: boundedNumber(finding && finding.severity, 0, 0, 4),
      score: Math.max(0, Math.min(1, Number(finding && finding.score) || 0)),
    }))
    .filter((finding) => finding.type);
}

function categoriesFromRow(row = {}) {
  return labelList(row.categories).map((category) => ({ category, score: 1 }));
}

function severityLabel(value) {
  return ({ 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' })[value] || 'none';
}

function analysisFromRow(row = {}) {
  const findings = findingsFromRow(row);
  const categories = categoriesFromRow(row);
  const maxSeverity = Math.max(
    boundedNumber(row.maxSeverity, 0, 0, 4),
    ...findings.map((finding) => finding.severity),
  );
  return {
    findings,
    categories,
    entityCounts: Object.fromEntries([...findings.map((f) => f.type), ...categories.map((c) => c.category)].map((label) => [label, 1])),
    riskScore: boundedNumber(row.riskScore, 0, 0, 100),
    maxSeverity,
    maxSeverityLabel: row.maxSeverityLabel || severityLabel(maxSeverity),
  };
}

function actionFromChannel(channel) {
  const normalized = String(channel || '').trim().toLowerCase();
  if (['paste', 'drop', 'copy', 'download'].includes(normalized)) return normalized;
  if (normalized.includes('paste')) return 'paste';
  if (normalized.includes('drop')) return 'drop';
  if (normalized.includes('copy')) return 'copy';
  if (normalized.includes('download')) return 'download';
  return null;
}

function isFileUpload(row = {}) {
  const channel = String(row.channel || '').toLowerCase();
  const status = String(row.status || '').toLowerCase();
  return channel.includes('file') || channel.includes('upload') || channel === 'drop' || status.includes('file_');
}

function mcpTool(row = {}) {
  if (row.source !== 'mcp_guard' && row.channel !== 'mcp_tool') return '';
  return safeLabel(row.tool || row.destination, '', 160);
}

function wildcardMatches(value, pattern) {
  const target = String(value || '').toLowerCase();
  const raw = String(pattern || '').toLowerCase();
  if (!target || !raw) return false;
  const escaped = raw.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(target);
}

function matchesAny(value, patterns = []) {
  return (patterns || []).some((pattern) => wildcardMatches(value, pattern));
}

function mcpToolOutcome(row, policy) {
  const tool = mcpTool(row);
  if (!tool) return null;
  if (matchesAny(tool, policy.mcpBlockedTools || [])) return { outcome: 'blocked', reason: 'mcp_tool_blocked' };
  if (matchesAny(tool, policy.mcpApprovalRequiredTools || [])) return { outcome: 'approval_required', reason: 'mcp_tool_approval_required' };
  return null;
}

function canMetadataTokenize(analysis) {
  return analysis.findings.length > 0 && analysis.categories.length === 0;
}

function policyModeOutcome(mode, analysis, hardStop) {
  if (hardStop) return 'blocked';
  if (mode === 'redact') return canMetadataTokenize(analysis) ? 'redacted' : 'approval_required';
  if (mode === 'warn') return 'warned';
  if (mode === 'justify') return 'justification_required';
  return 'blocked';
}

function rowContext(row = {}) {
  return {
    user: String(row.user || '').trim().toLowerCase(),
    orgId: String(row.orgId || '').trim().toLowerCase(),
    source: String(row.source || '').trim().toLowerCase(),
    channel: String(row.channel || '').trim().toLowerCase(),
    destination: row.destination || '',
  };
}

function evaluateRow(row, rawPolicy) {
  const policy = policyEngine.normalizePolicy(rawPolicy);
  const destination = policyEngine.normalizeDestination(row.destination || '');
  if (policyEngine.destinationBlocked(destination, policy)) {
    return { outcome: 'blocked', reason: 'destination_blocked' };
  }
  if (isFileUpload(row) && policyEngine.fileUploadBlocked(destination, policy)) {
    return { outcome: 'blocked', reason: 'file_upload_blocked' };
  }
  const action = actionFromChannel(row.channel);
  if (action && policyEngine.browserActionBlocked(action, destination, policy)) {
    return { outcome: 'blocked', reason: 'browser_action_blocked' };
  }
  const mcpOutcome = mcpToolOutcome(row, policy);
  if (mcpOutcome) return mcpOutcome;

  const analysis = analysisFromRow(row);
  const verdict = policyEngine.evaluate(analysis, policy, rowContext({ ...row, destination }));
  if (verdict.decision === 'allow') {
    return { outcome: (analysis.findings.length || analysis.categories.length) ? 'allowed' : 'observed', reason: 'below_threshold' };
  }
  const effective = verdict.policy || policy;
  const hardStop = analysis.findings.some((finding) => (effective.alwaysBlock || []).includes(finding.type));
  return {
    outcome: policyModeOutcome(effective.enforcementMode || 'block', analysis, hardStop),
    reason: hardStop ? 'hard_stop_entity' : 'threshold_or_scope',
  };
}

function emptyOutcomeCounts() {
  return Object.fromEntries(OUTCOMES.map((outcome) => [outcome, 0]));
}

function bump(map, key, patch) {
  const label = safeLabel(key);
  if (!map.has(label)) map.set(label, { label, changed: 0, newlyBlocked: 0, newlyAllowed: 0, proposedBlocked: 0, currentBlocked: 0 });
  const item = map.get(label);
  Object.assign(item, patch(item));
}

function topEntries(map, limit = 6) {
  return Array.from(map.values())
    .sort((a, b) => (b.changed - a.changed) || (b.newlyBlocked - a.newlyBlocked) || a.label.localeCompare(b.label))
    .slice(0, limit);
}

function addAggregate({ row, current, proposed, destinations, categories, sources }) {
  const changed = current.outcome !== proposed.outcome;
  const newlyBlocked = current.outcome !== 'blocked' && proposed.outcome === 'blocked';
  const newlyAllowed = current.outcome !== 'allowed' && proposed.outcome === 'allowed';
  const patch = (item) => ({
    changed: item.changed + (changed ? 1 : 0),
    newlyBlocked: item.newlyBlocked + (newlyBlocked ? 1 : 0),
    newlyAllowed: item.newlyAllowed + (newlyAllowed ? 1 : 0),
    proposedBlocked: item.proposedBlocked + (proposed.outcome === 'blocked' ? 1 : 0),
    currentBlocked: item.currentBlocked + (current.outcome === 'blocked' ? 1 : 0),
  });
  bump(destinations, policyEngine.normalizeDestination(row.destination || '') || 'unknown', patch);
  bump(sources, row.source || 'unknown', patch);
  const labels = [...labelList(row.findings), ...labelList(row.categories)];
  for (const label of (labels.length ? labels : ['NO_DETECTOR_LABEL'])) bump(categories, label, patch);
}

function buildPolicyImpact({ rows = [], currentPolicy = {}, proposedPolicy = {}, limit = 1000, now = new Date() } = {}) {
  const sample = (Array.isArray(rows) ? rows : []).slice(0, Math.max(1, Math.min(Number(limit) || 1000, 5000)));
  const currentCounts = emptyOutcomeCounts();
  const proposedCounts = emptyOutcomeCounts();
  const summary = {
    sampleSize: sample.length,
    changed: 0,
    newlyBlocked: 0,
    newlyAllowed: 0,
    moreRestrictive: 0,
    lessRestrictive: 0,
  };
  const reasonCounts = new Map();
  const destinations = new Map();
  const categories = new Map();
  const sources = new Map();

  for (const row of sample) {
    const current = evaluateRow(row, currentPolicy);
    const proposed = evaluateRow(row, proposedPolicy);
    currentCounts[current.outcome] += 1;
    proposedCounts[proposed.outcome] += 1;
    const changed = current.outcome !== proposed.outcome;
    if (changed) {
      summary.changed += 1;
      reasonCounts.set(proposed.reason, (reasonCounts.get(proposed.reason) || 0) + 1);
    }
    if (current.outcome !== 'blocked' && proposed.outcome === 'blocked') summary.newlyBlocked += 1;
    if (current.outcome !== 'allowed' && proposed.outcome === 'allowed') summary.newlyAllowed += 1;
    if ((STRICTNESS[proposed.outcome] || 0) > (STRICTNESS[current.outcome] || 0)) summary.moreRestrictive += 1;
    if ((STRICTNESS[proposed.outcome] || 0) < (STRICTNESS[current.outcome] || 0)) summary.lessRestrictive += 1;
    addAggregate({ row, current, proposed, destinations, categories, sources });
  }

  return {
    generatedAt: now instanceof Date ? now.toISOString() : new Date(now).toISOString(),
    privacy: {
      mode: 'metadata_only',
      promptBodiesIncluded: false,
      excludedFields: ['redactedPrompt', '_rawPrompt', 'tokenizedPrompt', 'findings.masked'],
    },
    summary: {
      ...summary,
      current: currentCounts,
      proposed: proposedCounts,
    },
    topDeltas: {
      destinations: topEntries(destinations),
      categories: topEntries(categories),
      sources: topEntries(sources, 5),
      reasons: Array.from(reasonCounts.entries())
        .map(([reason, count]) => ({ reason, count }))
        .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason))
        .slice(0, 6),
    },
  };
}

module.exports = {
  buildPolicyImpact,
  evaluateRow,
  analysisFromRow,
};
