'use strict';
/**
 * Policy engine. Decides allow / block-and-hold for each analyzed prompt, and
 * holds the scanner config (ignore-lists, disabled detectors) synced to sensors.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const pkg = require('../package.json');
const adapters = require('../detection-engine/adapters');
const customDetectors = require('./custom-detectors');

const CONFIG_PATH = process.env.SENTINEL_POLICY_PATH || path.join(__dirname, '..', 'config', 'policy.json');
const SENSOR_ID_RE = /^[a-z][a-z0-9_:-]{0,79}$/;
const SENSOR_VERSION_RE = /^[A-Za-z0-9._+:-]{1,80}$/;
const ROUTING_RULE_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ROUTING_GROUP_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const ROUTING_ROLE_RE = /^(security_admin|approver)$/;
const ROUTING_REASON_RE = /^[a-z0-9][a-z0-9_:-]{0,79}$/;
const ROUTING_DETECTOR_RE = /^[A-Z0-9_]{1,80}$/;
const POLICY_MATCH_TEXT_RE = /^[A-Za-z0-9 ._@:+/-]{1,128}$/;
const MCP_TOOL_RE = /^[A-Za-z0-9.*:_/-]{1,160}$/;
const POLICY_MODE_RANK = { warn: 1, redact: 2, justify: 2, block: 3 };
const RESPONSE_SCAN_MODES = new Set(['flag', 'redact', 'block']);
const BROWSER_ACTIONS = new Set(['paste', 'drop', 'copy', 'download']);
const SENSITIVE_ROUTING_CODE_RE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;
const DEFAULT_REQUIRED_SENSORS = ['browser_extension', 'endpoint_agent', 'mcp_guard'];
const DEFAULT_DESIRED_SENSOR_VERSIONS = Object.fromEntries(
  DEFAULT_REQUIRED_SENSORS.map((source) => [source, pkg.version]),
);
const EXCEPTION_REVIEW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

const DEFAULT_POLICY = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 25,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
  // When true, the raw prompt of an item held for approval is retained
  // (encrypted at rest) so an admin can review it. Set false for institutions
  // that forbid any server-side raw retention — reveal then shows redacted only.
  storeRawForApproval: true,
  rawRetentionDays: 30,
  ignore: [],
  disabledDetectors: [],
  governedDestinations: [
    'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
    'gemini.google.com', 'copilot.microsoft.com', 'perplexity.ai', 'poe.com',
    'chat.deepseek.com', 'deepseek.com', 'chat.qwen.ai', 'qwen.ai', 'tongyi.aliyun.com',
    'kimi.com', 'kimi.moonshot.cn', 'doubao.com', 'yuanbao.tencent.com',
    'yiyan.baidu.com', 'ernie.baidu.com', 'chatglm.cn', 'z.ai',
  ],
  allowedDestinations: [],
  blockedDestinations: [],
  blockedFileUploadDestinations: [],
  blockedBrowserActions: [],
  mcpAllowedTools: [],
  mcpBlockedTools: [],
  mcpApprovalRequiredTools: [],
  blockUnapprovedAiDestinations: true,
  responseScanMode: 'flag',
  desktopCollectorDestination: 'Desktop AI',
  approvalRoutingRules: [],
  policyScopes: [],
  policyExceptions: [],
  requiredSensors: DEFAULT_REQUIRED_SENSORS,
  desiredSensorVersions: DEFAULT_DESIRED_SENSOR_VERSIONS,
  scanner: {
    ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
    ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
    ignoreExtensions: ['.tmp', '.log', '.lock'],
    maxFileBytes: Math.round(6.3 * 1024 * 1024),
  },
};

function normalizeSensorId(value) {
  const id = String(value || '').trim().toLowerCase();
  return SENSOR_ID_RE.test(id) ? id : null;
}

function normalizeRequiredSensors(value, fallback = DEFAULT_POLICY.requiredSensors) {
  const source = Array.isArray(value) ? value : fallback;
  const out = [];
  const seen = new Set();
  for (const item of source || []) {
    const id = normalizeSensorId(item);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out.length ? out : DEFAULT_REQUIRED_SENSORS.slice();
}

function normalizeDesiredSensorVersions(value, fallback = DEFAULT_POLICY.desiredSensorVersions) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : fallback;
  const out = {};
  for (const [rawKey, rawValue] of Object.entries(source || {})) {
    const key = normalizeSensorId(rawKey);
    const version = String(rawValue || '').trim();
    if (!key || !SENSOR_VERSION_RE.test(version)) continue;
    out[key] = version;
  }
  return out;
}

function normalizeResponseScanMode(value) {
  const mode = String(value || '').trim().toLowerCase();
  return RESPONSE_SCAN_MODES.has(mode) ? mode : DEFAULT_POLICY.responseScanMode;
}

function normalizeBrowserAction(value) {
  const action = String(value || '').trim().toLowerCase();
  return BROWSER_ACTIONS.has(action) ? action : null;
}

function normalizeRoutingTextList(value, pattern, maxItems = 40) {
  const source = Array.isArray(value) ? value : [];
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const normalized = String(item || '').trim();
    const key = normalized.toLowerCase();
    if (!normalized || seen.has(key) || !pattern.test(normalized)) continue;
    seen.add(key);
    out.push(normalized);
    if (out.length >= maxItems) break;
  }
  return out;
}

function safeRoutingCode(value) {
  const code = String(value || '').trim();
  return code && !SENSITIVE_ROUTING_CODE_RE.test(code);
}

function normalizeSafeRoutingTextList(value, pattern, maxItems = 40) {
  return normalizeRoutingTextList(value, pattern, maxItems).filter((item) => safeRoutingCode(item));
}

function normalizeApprovalRoutingRules(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const id = String(item.id || '').trim().toLowerCase();
    const assignedGroup = String(item.assignedGroup || '').trim().toLowerCase();
    const assignedRole = String(item.assignedRole || '').trim();
    const slaMinutes = Number(item.slaMinutes);
    if (!ROUTING_RULE_ID_RE.test(id) || seen.has(id)) continue;
    if (!ROUTING_GROUP_RE.test(assignedGroup) || !ROUTING_ROLE_RE.test(assignedRole)) continue;
    if (!safeRoutingCode(id) || !safeRoutingCode(assignedGroup)) continue;
    if (!Number.isFinite(slaMinutes)) continue;
    const rule = {
      id,
      enabled: item.enabled !== false,
      assignedGroup,
      assignedRole,
      slaMinutes: Math.max(15, Math.min(7 * 24 * 60, Math.round(slaMinutes))),
    };
    const reason = String(item.reason || '').trim().toLowerCase();
    if (ROUTING_REASON_RE.test(reason) && safeRoutingCode(reason)) rule.reason = reason;
    const users = normalizeSafeRoutingTextList(item.users, POLICY_MATCH_TEXT_RE).map((v) => v.toLowerCase());
    const groups = normalizeSafeRoutingTextList(item.groups || item.userGroups, POLICY_MATCH_TEXT_RE).map((v) => v.toLowerCase());
    const orgIds = normalizeSafeRoutingTextList(item.orgIds, POLICY_MATCH_TEXT_RE).map((v) => v.toLowerCase());
    const detectors = normalizeRoutingTextList(item.detectors, ROUTING_DETECTOR_RE).map((v) => v.toUpperCase());
    const categories = normalizeRoutingTextList(item.categories, ROUTING_DETECTOR_RE).map((v) => v.toUpperCase());
    const sources = normalizeRoutingTextList(item.sources, SENSOR_ID_RE).map((v) => v.toLowerCase());
    const channels = normalizeRoutingTextList(item.channels, SENSOR_ID_RE).map((v) => v.toLowerCase());
    const destinations = normalizeRoutingTextList(item.destinations, /^[A-Za-z0-9.*:_/-]{1,253}$/);
    if (users.length) rule.users = users;
    if (groups.length) rule.groups = groups;
    if (orgIds.length) rule.orgIds = orgIds;
    if (detectors.length) rule.detectors = detectors;
    if (categories.length) rule.categories = categories;
    if (sources.length) rule.sources = sources;
    if (channels.length) rule.channels = channels;
    if (destinations.length) rule.destinations = destinations;
    if (item.minSeverity !== undefined) {
      const minSeverity = Number(item.minSeverity);
      if (Number.isFinite(minSeverity)) rule.minSeverity = Math.max(0, Math.min(4, Math.round(minSeverity)));
    }
    if (item.minRiskScore !== undefined) {
      const minRiskScore = Number(item.minRiskScore);
      if (Number.isFinite(minRiskScore)) rule.minRiskScore = Math.max(0, Math.min(100, Math.round(minRiskScore)));
    }
    const hasMatcher = ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations'].some((key) => Array.isArray(rule[key]) && rule[key].length)
      || rule.minSeverity !== undefined
      || rule.minRiskScore !== undefined;
    if (!hasMatcher) continue;
    seen.add(id);
    out.push(rule);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizePolicyMatchers(item = {}) {
  const users = normalizeSafeRoutingTextList(item.users, POLICY_MATCH_TEXT_RE).map((v) => v.toLowerCase());
  const groups = normalizeSafeRoutingTextList(item.groups || item.userGroups, POLICY_MATCH_TEXT_RE).map((v) => v.toLowerCase());
  const orgIds = normalizeSafeRoutingTextList(item.orgIds, POLICY_MATCH_TEXT_RE).map((v) => v.toLowerCase());
  const detectors = normalizeRoutingTextList(item.detectors, ROUTING_DETECTOR_RE).map((v) => v.toUpperCase());
  const categories = normalizeRoutingTextList(item.categories, ROUTING_DETECTOR_RE).map((v) => v.toUpperCase());
  const sources = normalizeRoutingTextList(item.sources, SENSOR_ID_RE).map((v) => v.toLowerCase());
  const channels = normalizeRoutingTextList(item.channels, SENSOR_ID_RE).map((v) => v.toLowerCase());
  const destinations = normalizeSafeRoutingTextList(item.destinations, /^[A-Za-z0-9.*:_/-]{1,253}$/);
  const matchers = {};
  if (users.length) matchers.users = users;
  if (groups.length) matchers.groups = groups;
  if (orgIds.length) matchers.orgIds = orgIds;
  if (detectors.length) matchers.detectors = detectors;
  if (categories.length) matchers.categories = categories;
  if (sources.length) matchers.sources = sources;
  if (channels.length) matchers.channels = channels;
  if (destinations.length) matchers.destinations = destinations;
  return matchers;
}

function hasPolicyMatcher(rule) {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations']
    .some((key) => Array.isArray(rule[key]) && rule[key].length);
}

function normalizePolicyScopes(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const id = String(item.id || '').trim().toLowerCase();
    if (!ROUTING_RULE_ID_RE.test(id) || seen.has(id) || !safeRoutingCode(id)) continue;
    const scope = {
      id,
      enabled: item.enabled !== false,
      ...normalizePolicyMatchers(item),
    };
    if (!hasPolicyMatcher(scope)) continue;
    const mode = String(item.enforcementMode || '').trim();
    if (Object.prototype.hasOwnProperty.call(POLICY_MODE_RANK, mode)) scope.enforcementMode = mode;
    if (item.blockMinSeverity !== undefined) {
      const minSeverity = Number(item.blockMinSeverity);
      if (Number.isFinite(minSeverity)) scope.blockMinSeverity = Math.max(1, Math.min(4, Math.round(minSeverity)));
    }
    if (item.blockRiskScore !== undefined) {
      const minRiskScore = Number(item.blockRiskScore);
      if (Number.isFinite(minRiskScore)) scope.blockRiskScore = Math.max(0, Math.min(100, Math.round(minRiskScore)));
    }
    const alwaysBlockAdd = normalizeRoutingTextList(item.alwaysBlockAdd, ROUTING_DETECTOR_RE).map((v) => v.toUpperCase());
    if (alwaysBlockAdd.length) scope.alwaysBlockAdd = alwaysBlockAdd;
    const reason = String(item.reason || '').trim().toLowerCase();
    if (ROUTING_REASON_RE.test(reason) && safeRoutingCode(reason)) scope.reason = reason;
    const hasOverride = scope.enforcementMode
      || scope.blockMinSeverity !== undefined
      || scope.blockRiskScore !== undefined
      || (scope.alwaysBlockAdd || []).length;
    if (!hasOverride) continue;
    seen.add(id);
    out.push(scope);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizePolicyExceptions(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const id = String(item.id || '').trim().toLowerCase();
    if (!ROUTING_RULE_ID_RE.test(id) || seen.has(id) || !safeRoutingCode(id)) continue;
    const expiresAt = String(item.expiresAt || '').trim();
    const expires = Date.parse(expiresAt);
    if (!expiresAt || !Number.isFinite(expires)) continue;
    const exception = {
      id,
      enabled: item.enabled !== false,
      action: 'allow',
      expiresAt: new Date(expires).toISOString(),
      ...normalizePolicyMatchers(item),
    };
    if (!hasPolicyMatcher(exception)) continue;
    const ownerGroup = String(item.ownerGroup || '').trim().toLowerCase();
    if (ROUTING_GROUP_RE.test(ownerGroup) && safeRoutingCode(ownerGroup)) exception.ownerGroup = ownerGroup;
    const reviewerRole = String(item.reviewerRole || '').trim().toLowerCase();
    if (ROUTING_ROLE_RE.test(reviewerRole)) exception.reviewerRole = reviewerRole;
    const reviewAfter = String(item.reviewAfter || '').trim();
    const reviewTime = Date.parse(reviewAfter);
    if (reviewAfter && Number.isFinite(reviewTime) && reviewTime <= expires) {
      exception.reviewAfter = new Date(reviewTime).toISOString();
    }
    const reason = String(item.reason || '').trim().toLowerCase();
    if (ROUTING_REASON_RE.test(reason) && safeRoutingCode(reason)) exception.reason = reason;
    seen.add(id);
    out.push(exception);
    if (out.length >= 40) break;
  }
  return out;
}

function exceptionReviewStatus(exception, nowMs, windowMs) {
  if (!exception || exception.enabled === false) return 'disabled';
  const expires = Date.parse(exception.expiresAt);
  if (!Number.isFinite(expires)) return 'invalid';
  if (expires <= nowMs) return 'expired';
  const reviewAfter = Date.parse(exception.reviewAfter || '');
  if (Number.isFinite(reviewAfter) && reviewAfter <= nowMs) return 'review_due';
  if (expires <= nowMs + windowMs) return 'expiring_soon';
  return 'active';
}

function policyExceptionReview(policy = loadPolicy(), options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const nowMs = now.getTime();
  const windowMs = Number.isFinite(Number(options.windowMs))
    ? Math.max(0, Number(options.windowMs))
    : EXCEPTION_REVIEW_WINDOW_MS;
  const items = (policy.policyExceptions || []).map((exception) => {
    const status = exceptionReviewStatus(exception, nowMs, windowMs);
    return {
      id: exception.id,
      enabled: exception.enabled !== false,
      action: exception.action || 'allow',
      expiresAt: exception.expiresAt || null,
      ownerGroup: exception.ownerGroup || null,
      reviewerRole: exception.reviewerRole || null,
      reviewAfter: exception.reviewAfter || null,
      status,
    };
  });
  const count = (status) => items.filter((item) => item.status === status).length;
  return {
    generatedAt: now.toISOString(),
    reviewWindowDays: Math.round(windowMs / (24 * 60 * 60 * 1000)),
    total: items.length,
    active: items.filter((item) => ['active', 'expiring_soon', 'review_due'].includes(item.status)).length,
    disabled: count('disabled'),
    expired: count('expired'),
    reviewDue: count('review_due'),
    expiringSoon: count('expiring_soon'),
    items,
  };
}

function normalizeBlockedBrowserActions(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const id = String(item.id || '').trim().toLowerCase();
    const action = normalizeBrowserAction(item.action);
    if (!ROUTING_RULE_ID_RE.test(id) || seen.has(id) || !safeRoutingCode(id) || !action) continue;
    const destinations = normalizeSafeRoutingTextList(item.destinations, /^[A-Za-z0-9.*:_/-]{1,253}$/);
    if (!destinations.length) continue;
    const rule = { id, enabled: item.enabled !== false, action, destinations };
    const reason = String(item.reason || '').trim().toLowerCase();
    if (ROUTING_REASON_RE.test(reason) && safeRoutingCode(reason)) rule.reason = reason;
    seen.add(id);
    out.push(rule);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizeMcpToolList(value) {
  return normalizeSafeRoutingTextList(value, MCP_TOOL_RE, 200);
}

function normalizePolicy(p = {}) {
  const scanner = {
    ...DEFAULT_POLICY.scanner,
    ...((p && p.scanner) || {}),
  };
  const rawMaxFileBytes = scanner.maxFileBytes;
  const hasConfiguredMaxFileBytes = rawMaxFileBytes !== undefined
    && rawMaxFileBytes !== null
    && rawMaxFileBytes !== ''
    && typeof rawMaxFileBytes !== 'boolean';
  const maxFileBytes = Number(rawMaxFileBytes);
  scanner.maxFileBytes = hasConfiguredMaxFileBytes && Number.isFinite(maxFileBytes)
    ? Math.max(1024, Math.min(50 * 1024 * 1024, Math.round(maxFileBytes)))
    : DEFAULT_POLICY.scanner.maxFileBytes;
  return {
    ...DEFAULT_POLICY,
    ...(p || {}),
    approvalRoutingRules: normalizeApprovalRoutingRules((p || {}).approvalRoutingRules),
    policyScopes: normalizePolicyScopes((p || {}).policyScopes),
    policyExceptions: normalizePolicyExceptions((p || {}).policyExceptions),
    blockedBrowserActions: normalizeBlockedBrowserActions((p || {}).blockedBrowserActions),
    mcpAllowedTools: normalizeMcpToolList((p || {}).mcpAllowedTools),
    mcpBlockedTools: normalizeMcpToolList((p || {}).mcpBlockedTools),
    mcpApprovalRequiredTools: normalizeMcpToolList((p || {}).mcpApprovalRequiredTools),
    requiredSensors: normalizeRequiredSensors((p || {}).requiredSensors),
    desiredSensorVersions: normalizeDesiredSensorVersions((p || {}).desiredSensorVersions),
    responseScanMode: normalizeResponseScanMode((p || {}).responseScanMode),
    scanner,
  };
}

const AUDIT_FIELDS = [
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
  'desktopCollectorDestination',
  'approvalRoutingRules',
  'policyScopes',
  'policyExceptions',
  'requiredSensors',
  'desiredSensorVersions',
  'scanner',
];

function normalizeForAudit(value) {
  if (Array.isArray(value)) {
    return value
      .map(normalizeForAudit)
      .sort((a, b) => String(JSON.stringify(a)).localeCompare(String(JSON.stringify(b))));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalizeForAudit(value[key])]));
  }
  return value;
}

function policyChangeSummary(before, after, meta = {}) {
  const changed = [];
  for (const field of AUDIT_FIELDS) {
    const oldValue = normalizeForAudit(before && before[field]);
    const newValue = normalizeForAudit(after && after[field]);
    if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) {
      changed.push({ field, before: oldValue, after: newValue });
    }
  }
  return {
    type: 'policy_change',
    ...(meta.templateId ? { templateId: String(meta.templateId) } : {}),
    ...(meta.reason ? { reason: String(meta.reason).trim().slice(0, 240) } : {}),
    changed,
  };
}

function policyChangeDetail(before, after, meta = {}) {
  return JSON.stringify(policyChangeSummary(before, after, meta));
}

function loadPolicy() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return normalizePolicy(JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')));
    }
  } catch (e) { /* default */ }
  return normalizePolicy();
}

function savePolicy(p) {
  const dir = path.dirname(CONFIG_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(normalizePolicy(p), null, 2));
}

function analyzeOpts(policy = loadPolicy()) {
  return {
    ignore: policy.ignore || [],
    disabledDetectors: policy.disabledDetectors || [],
    customDetectors: customDetectors.loadCustomDetectors(),
  };
}

function customDetectorsForSensors() {
  return customDetectors.loadCustomDetectors();
}

function rawRetentionDays(policy = loadPolicy()) {
  const n = Number(policy && policy.rawRetentionDays);
  if (!Number.isFinite(n)) return DEFAULT_POLICY.rawRetentionDays;
  return Math.max(0, Math.min(3650, Math.floor(n)));
}

function normalizeDestination(value) {
  const raw = String(value || '').trim().toLowerCase().replace(/\s+/g, '-');
  if (!raw) return 'unknown';
  try {
    const url = raw.includes('://') ? new URL(raw) : new URL(`https://${raw}`);
    return url.hostname.replace(/^www\./, '');
  } catch {
    return raw.replace(/^www\./, '').split(/[/?#]/)[0] || 'unknown';
  }
}

function destinationMatches(destination, patterns) {
  const host = normalizeDestination(destination);
  return (patterns || []).some((pattern) => {
    const target = normalizeDestination(pattern);
    if (!target || target === 'unknown') return false;
    if (target === '*') return true;
    if (target.startsWith('*.')) {
      const base = target.slice(2);
      return host.endsWith('.' + base);
    }
    if (target.startsWith('*')) {
      const base = target.slice(1).replace(/^\./, '');
      return host === base || host.endsWith('.' + base);
    }
    return host === target || host.endsWith('.' + target);
  });
}

function destinationReviewed(destination, policy = loadPolicy()) {
  return destinationMatches(destination, [
    ...((policy || {}).governedDestinations || []),
    ...((policy || {}).allowedDestinations || []),
    ...((policy || {}).blockedDestinations || []),
    ...((policy || {}).blockedFileUploadDestinations || []),
  ]);
}

function unapprovedAiDestination(destination, policy = loadPolicy()) {
  if ((policy || {}).blockUnapprovedAiDestinations === false) return false;
  const normalized = normalizeDestination(destination);
  if (!normalized || normalized === 'unknown') return false;
  if (destinationAllowed(normalized, policy)) return false;
  if (!adapters.isAiHost(normalized)) return false;
  return !destinationReviewed(normalized, policy);
}

function destinationBlockReason(destination, policy = loadPolicy()) {
  if (destinationMatches(destination, (policy || {}).blockedDestinations || [])) return 'Destination blocked by policy';
  if (unapprovedAiDestination(destination, policy)) return 'Unapproved AI destination blocked by policy';
  return 'Destination blocked by policy';
}

function destinationListWithout(list, destination) {
  const target = normalizeDestination(destination);
  const out = [];
  const seen = new Set();
  for (const item of list || []) {
    const normalized = normalizeDestination(item);
    if (!normalized || normalized === 'unknown' || normalized === target || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function destinationListWith(list, destination) {
  const target = normalizeDestination(destination);
  const out = destinationListWithout(list, target);
  if (target && target !== 'unknown') out.push(target);
  return out;
}

function reviewDestination(currentPolicy, destination, decision) {
  const normalized = normalizeDestination(destination);
  if (!normalized || normalized === 'unknown') {
    throw new Error('destination required');
  }
  const action = String(decision || '').toLowerCase();
  if (!['govern', 'allow', 'block'].includes(action)) {
    throw new Error('unknown destination decision');
  }
  const next = {
    ...DEFAULT_POLICY,
    ...(currentPolicy || {}),
    governedDestinations: destinationListWithout((currentPolicy || {}).governedDestinations, normalized),
    allowedDestinations: destinationListWithout((currentPolicy || {}).allowedDestinations, normalized),
    blockedDestinations: destinationListWithout((currentPolicy || {}).blockedDestinations, normalized),
    blockedFileUploadDestinations: destinationListWithout((currentPolicy || {}).blockedFileUploadDestinations, normalized),
  };
  if (action === 'govern') next.governedDestinations = destinationListWith(next.governedDestinations, normalized);
  if (action === 'allow') next.allowedDestinations = destinationListWith(next.allowedDestinations, normalized);
  if (action === 'block') next.blockedDestinations = destinationListWith(next.blockedDestinations, normalized);
  return { destination: normalized, decision: action, policy: next };
}

function destinationBlocked(destination, policy = loadPolicy()) {
  if (destinationAllowed(destination, policy)) return false;
  return destinationMatches(destination, policy.blockedDestinations || [])
    || unapprovedAiDestination(destination, policy);
}

function fileUploadBlocked(destination, policy = loadPolicy()) {
  if (destinationAllowed(destination, policy)) return false;
  return destinationMatches(destination, policy.blockedFileUploadDestinations || []);
}

function destinationAllowed(destination, policy = loadPolicy()) {
  return destinationMatches(destination, policy.allowedDestinations || []);
}

function browserActionBlockRule(action, destination, policy = loadPolicy()) {
  const normalizedAction = normalizeBrowserAction(action);
  if (!normalizedAction) return null;
  for (const rule of (policy.blockedBrowserActions || [])) {
    if (!rule || rule.enabled === false || rule.action !== normalizedAction) continue;
    if (destinationMatches(destination, rule.destinations || [])) return rule;
  }
  return null;
}

function browserActionBlocked(action, destination, policy = loadPolicy()) {
  return !!browserActionBlockRule(action, destination, policy);
}

function browserActionBlockReason(action, destination, policy = loadPolicy()) {
  const rule = browserActionBlockRule(action, destination, policy);
  if (rule && rule.reason) return rule.reason;
  return 'Browser action ' + String(action || 'unknown').trim().toLowerCase() + ' blocked by policy';
}

function analysisDetectorLabels(analysis = {}) {
  return [...new Set((analysis.findings || []).map((item) => String(item.type || '').toUpperCase()).filter(Boolean))];
}

function analysisCategoryLabels(analysis = {}) {
  return [...new Set((analysis.categories || []).map((item) => String(item && (item.category || item) || '').toUpperCase()).filter(Boolean))];
}

function contextGroups(context = {}) {
  return [...new Set((Array.isArray(context.groups) ? context.groups : [])
    .map((item) => String(item || '').trim().toLowerCase())
    .filter(Boolean))];
}

function policyRuleMatches(rule, analysis = {}, context = {}) {
  if (!rule || rule.enabled === false || !hasPolicyMatcher(rule)) return false;
  const detectorLabels = analysisDetectorLabels(analysis);
  const categoryLabels = analysisCategoryLabels(analysis);
  const user = String(context.user || '').trim().toLowerCase();
  const orgId = String(context.orgId || '').trim().toLowerCase();
  const source = String(context.source || '').trim().toLowerCase();
  const channel = String(context.channel || '').trim().toLowerCase();
  const groups = contextGroups(context);
  if (rule.users && !rule.users.includes(user)) return false;
  if (rule.groups && !rule.groups.some((group) => groups.includes(group))) return false;
  if (rule.orgIds && !rule.orgIds.includes(orgId)) return false;
  if (rule.detectors && !rule.detectors.some((detector) => detectorLabels.includes(detector))) return false;
  if (rule.categories && !rule.categories.some((category) => categoryLabels.includes(category))) return false;
  if (rule.sources && !rule.sources.includes(source)) return false;
  if (rule.channels && !rule.channels.includes(channel)) return false;
  if (rule.destinations && !destinationMatches(context.destination || '', rule.destinations)) return false;
  return true;
}

function stricterMode(current, candidate) {
  if (!candidate) return current;
  return (POLICY_MODE_RANK[candidate] || 0) > (POLICY_MODE_RANK[current] || 0) ? candidate : current;
}

function unionList(left = [], right = []) {
  return [...new Set([...(left || []), ...(right || [])].map((item) => String(item || '').trim()).filter(Boolean))];
}

function effectivePolicyForContext(policy = loadPolicy(), analysis = {}, context = {}, options = {}) {
  const base = normalizePolicy(policy);
  const effective = { ...base, alwaysBlock: [...(base.alwaysBlock || [])] };
  const appliedScopes = [];
  for (const scope of base.policyScopes || []) {
    if (!policyRuleMatches(scope, analysis, context)) continue;
    appliedScopes.push(scope.id);
    effective.enforcementMode = stricterMode(effective.enforcementMode || 'block', scope.enforcementMode);
    if (scope.blockMinSeverity !== undefined) {
      effective.blockMinSeverity = Math.min(Number(effective.blockMinSeverity) || DEFAULT_POLICY.blockMinSeverity, scope.blockMinSeverity);
    }
    if (scope.blockRiskScore !== undefined) {
      effective.blockRiskScore = Math.min(Number(effective.blockRiskScore) || DEFAULT_POLICY.blockRiskScore, scope.blockRiskScore);
    }
    if (scope.alwaysBlockAdd) effective.alwaysBlock = unionList(effective.alwaysBlock, scope.alwaysBlockAdd);
  }
  if (appliedScopes.length) effective.appliedPolicyScopes = appliedScopes;
  return effective;
}

function activePolicyException(policy = loadPolicy(), analysis = {}, context = {}, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  for (const exception of (policy.policyExceptions || [])) {
    if (exception.enabled === false) continue;
    if (Date.parse(exception.expiresAt) <= now.getTime()) continue;
    if (policyRuleMatches(exception, analysis, context)) return exception;
  }
  return null;
}

function evaluate(analysis, policy = loadPolicy(), context = {}, options = {}) {
  const effective = effectivePolicyForContext(policy, analysis, context, options);
  const reasons = [];
  const findings = (analysis.findings || []).filter((f) => !(effective.ignore || []).includes(f.type));
  const categories = (analysis.categories || []).filter((c) => !(effective.ignore || []).includes(c && (c.category || c)));

  if (findings.length === 0 && categories.length === 0) {
    return { decision: 'allow', reasons: ['Nothing sensitive detected'], policy: effective, policyScopeIds: effective.appliedPolicyScopes || [] };
  }
  if (categories.length) reasons.push('Sensitive content: ' + categories.map((c) => c && (c.category || c)).join(', '));
  const hardStop = findings.find((f) => (effective.alwaysBlock || []).includes(f.type));
  if (hardStop) reasons.push('Hard-stop entity present: ' + hardStop.type);
  if (analysis.maxSeverity >= effective.blockMinSeverity) reasons.push('Severity ' + analysis.maxSeverityLabel + ' >= policy minimum');
  if (analysis.riskScore >= effective.blockRiskScore) reasons.push('Risk score ' + analysis.riskScore + ' >= ' + effective.blockRiskScore);
  if ((effective.appliedPolicyScopes || []).length) reasons.push('Policy scope matched: ' + effective.appliedPolicyScopes.join(', '));

  const exception = reasons.length && !hardStop ? activePolicyException(effective, analysis, context, options) : null;
  if (exception && exception.action === 'allow') {
    return {
      decision: 'allow',
      reasons: ['Time-bound exception matched: ' + exception.id],
      policy: effective,
      policyScopeIds: effective.appliedPolicyScopes || [],
      policyExceptionId: exception.id,
    };
  }

  const decision = reasons.length ? 'block' : 'allow';
  if (decision === 'allow') reasons.push('Below blocking thresholds');
  return { decision, reasons, policy: effective, policyScopeIds: effective.appliedPolicyScopes || [] };
}

module.exports = {
  loadPolicy,
  savePolicy,
  evaluate,
  analyzeOpts,
  customDetectorsForSensors,
  rawRetentionDays,
  normalizePolicy,
  normalizeDestination,
  normalizeApprovalRoutingRules,
  normalizePolicyScopes,
  normalizePolicyExceptions,
  policyExceptionReview,
  effectivePolicyForContext,
  policyRuleMatches,
  destinationMatches,
  reviewDestination,
  destinationAllowed,
  destinationBlocked,
  destinationBlockReason,
  destinationReviewed,
  fileUploadBlocked,
  browserActionBlockRule,
  browserActionBlocked,
  browserActionBlockReason,
  unapprovedAiDestination,
  normalizeResponseScanMode,
  normalizeBrowserAction,
  normalizeBlockedBrowserActions,
  normalizeMcpToolList,
  policyChangeSummary,
  policyChangeDetail,
  DEFAULT_POLICY,
};
