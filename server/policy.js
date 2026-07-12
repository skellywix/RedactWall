'use strict';
/**
 * Policy engine. Decides allow / block-and-hold for each analyzed prompt, and
 * holds the scanner config (ignore-lists, disabled detectors) synced to sensors.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const pkg = require('../package.json');
const adapters = require('../detection-engine/adapters');
const detector = require('../detection-engine/detect');
const customDetectors = require('./custom-detectors');
const exactMatch = require('./exact-match');
const fileMutationLock = require('./file-mutation-lock');
const privatePaths = require('./private-path');

const CONFIG_ENV_PATH = process.env.REDACTWALL_POLICY_PATH;
const CONFIG_PATH = CONFIG_ENV_PATH || path.join(__dirname, '..', 'config', 'policy.json');
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
const UNMANAGED_INSTALL_MODES = new Set(['allow', 'flag', 'block']);
const BROWSER_ACTIONS = new Set(['paste', 'drop', 'copy', 'download']);
const SENSITIVE_ROUTING_CODE_RE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;
const DEFAULT_REQUIRED_SENSORS = ['browser_extension', 'endpoint_agent', 'mcp_guard'];
const DEFAULT_DESIRED_SENSOR_VERSIONS = Object.fromEntries(
  DEFAULT_REQUIRED_SENSORS.map((source) => [source, pkg.version]),
);
const EXCEPTION_REVIEW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_POLICY_FILE_BYTES = 4 * 1024 * 1024;
const MAX_POLICY_FILE_BYTES_BIGINT = BigInt(MAX_POLICY_FILE_BYTES);

const DEFAULT_POLICY = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 25,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'UK_NINO', 'UK_NHS_NUMBER', 'CANADA_SIN', 'AUSTRALIA_TFN', 'INDIA_AADHAAR', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN', 'EXACT_MATCH'],
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
  // Personal vs corporate AI account detection (ROADMAP N4). orgEmailDomains
  // are the institution's own domains; a login on any of them classifies as
  // corporate. personalAccountAction: allow (telemetry only) | coach | block.
  corporateAiAccounts: { orgEmailDomains: [], personalAccountAction: 'allow' },
  responseScanMode: 'flag',
  unmanagedInstalls: 'allow',
  desktopCollectorDestination: 'Desktop AI',
  approvalRoutingRules: [],
  policyScopes: [],
  policyExceptions: [],
  requiredSensors: DEFAULT_REQUIRED_SENSORS,
  desiredSensorVersions: DEFAULT_DESIRED_SENSOR_VERSIONS,
  scanner: {
    ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
    ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
    ignoreExtensions: ['.lock'],
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

function normalizeUnmanagedInstalls(value) {
  const mode = String(value || '').trim().toLowerCase();
  return UNMANAGED_INSTALL_MODES.has(mode) ? mode : DEFAULT_POLICY.unmanagedInstalls;
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
  const accountTypes = normalizeRoutingTextList(item.accountTypes, /^(?:personal|corporate|unknown)$/i).map((v) => v.toLowerCase());
  const matchers = {};
  if (users.length) matchers.users = users;
  if (groups.length) matchers.groups = groups;
  if (orgIds.length) matchers.orgIds = orgIds;
  if (detectors.length) matchers.detectors = detectors;
  if (categories.length) matchers.categories = categories;
  if (sources.length) matchers.sources = sources;
  if (channels.length) matchers.channels = channels;
  if (destinations.length) matchers.destinations = destinations;
  if (accountTypes.length) matchers.accountTypes = accountTypes;
  return matchers;
}

function hasPolicyMatcher(rule) {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations', 'accountTypes']
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

// Marks a policy object as already normalized so hot callers (evaluate,
// effectivePolicyForContext) and batch callers (policy-impact) can skip a
// redundant re-normalization. Non-enumerable so it never leaks into JSON,
// audit diffs, or deep-equality comparisons.
const NORMALIZED = Symbol('normalizedPolicy');

function isNormalizedPolicy(policy) {
  return !!(policy && policy[NORMALIZED]);
}

function mandatoryAlwaysBlock(value) {
  const configured = Array.isArray(value) ? value : [];
  return [...new Set([...DEFAULT_POLICY.alwaysBlock, ...configured]
    .filter((type) => typeof type === 'string' && type.trim())
    .map((type) => type.trim().toUpperCase()))];
}

function validatePolicyData(value) {
  // Lazy so standalone endpoint packages can import DEFAULT_POLICY without
  // pulling the server-only request-validation dependency graph.
  return require('./validation').policyUpdateSchema.safeParse(value);
}

function normalizePolicy(p = {}) {
  if (isNormalizedPolicy(p)) return p;
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
  const normalized = {
    ...DEFAULT_POLICY,
    ...(p || {}),
    alwaysBlock: mandatoryAlwaysBlock((p || {}).alwaysBlock),
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
    unmanagedInstalls: normalizeUnmanagedInstalls((p || {}).unmanagedInstalls),
    corporateAiAccounts: normalizeCorporateAiAccounts((p || {}).corporateAiAccounts),
    scanner,
  };
  Object.defineProperty(normalized, NORMALIZED, { value: true });
  return normalized;
}

const PERSONAL_ACCOUNT_ACTIONS = ['allow', 'coach', 'block'];
function normalizeCorporateAiAccounts(value) {
  const cfg = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const domains = [];
  const seen = new Set();
  for (const d of Array.isArray(cfg.orgEmailDomains) ? cfg.orgEmailDomains : []) {
    const host = normalizeDestination(d).toLowerCase();
    if (host && host !== 'unknown' && /^[a-z0-9.-]{3,253}$/.test(host) && !seen.has(host) && domains.length < 40) {
      seen.add(host); domains.push(host);
    }
  }
  const action = PERSONAL_ACCOUNT_ACTIONS.includes(String(cfg.personalAccountAction || '').toLowerCase())
    ? String(cfg.personalAccountAction).toLowerCase() : 'allow';
  return { orgEmailDomains: domains, personalAccountAction: action };
}

// Server-side enforcement mirror of the extension's personal-account block.
function personalAccountBlocked(accountType, pol = loadPolicy()) {
  const cfg = (pol && pol.corporateAiAccounts) || {};
  return cfg.personalAccountAction === 'block' && String(accountType || '').toLowerCase() === 'personal';
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
  'corporateAiAccounts',
  'responseScanMode',
  'unmanagedInstalls',
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

function createPolicyLoader(configPath, configuredByEnv = false, fsImpl = fs) {
  const fallback = normalizePolicy();
  let cached = null;
  let lastGood = null;

  function failed(error, signature, cacheResult = true) {
    const policy = lastGood || fallback;
    const result = {
      signature,
      policy,
      ok: false,
      configured: true,
      error,
      usingLastKnownGood: !!lastGood,
    };
    if (cacheResult) cached = result;
    return result;
  }

  function missing() {
    const signature = 'missing';
    if (cached && cached.signature === signature) return cached;
    if (lastGood) return failed('policy file disappeared after a successful load', signature);
    if (configuredByEnv) return failed('configured policy file is missing', signature);
    cached = {
      signature,
      policy: fallback,
      ok: true,
      configured: false,
      error: null,
      usingLastKnownGood: false,
    };
    return cached;
  }

  function state() {
    let stat;
    try {
      stat = fsImpl.statSync(configPath);
    } catch (error) {
      if (error && error.code === 'ENOENT') return missing();
      return failed('policy file could not be inspected', 'stat-error');
    }

    const signature = `${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}`;
    if (cached && cached.signature === signature) return cached;

    let contents;
    try {
      contents = fsImpl.readFileSync(configPath, 'utf8');
    } catch (error) {
      return failed('policy file could not be read', signature, false);
    }

    let parsed;
    try {
      parsed = JSON.parse(contents);
    } catch (error) {
      return failed('policy file is not valid JSON', signature);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return failed('policy file must be a JSON object', signature);
    }
    const parsedPolicy = validatePolicyData(parsed);
    if (!parsedPolicy.success) {
      return failed('policy file failed semantic validation', signature);
    }

    const loaded = normalizePolicy(parsedPolicy.data);
    cached = {
      signature,
      policy: loaded,
      ok: true,
      configured: true,
      error: null,
      usingLastKnownGood: false,
    };
    lastGood = loaded;
    return cached;
  }

  return {
    loadPolicy: () => state().policy,
    status: () => {
      const current = state();
      return {
        ok: current.ok,
        configured: current.configured,
        error: current.error,
        usingLastKnownGood: current.usingLastKnownGood,
      };
    },
    invalidate: () => { cached = null; },
  };
}

const defaultPolicyLoader = createPolicyLoader(CONFIG_PATH, !!CONFIG_ENV_PATH);

function loadPolicy() {
  return defaultPolicyLoader.loadPolicy();
}

function policyStatus() {
  return defaultPolicyLoader.status();
}

function cleanupPolicyTemp(fsImpl, fileDescriptor, tempPath, tempCreated) {
  if (fileDescriptor !== null) {
    try { fsImpl.closeSync(fileDescriptor); } catch (error) { /* preserve original error */ }
  }
  if (tempCreated) {
    try { fsImpl.unlinkSync(tempPath); } catch (error) { /* best-effort cleanup */ }
  }
}

function writePolicyBytesAtomically(configPath, data, options = {}) {
  const fsImpl = options.fs || fs;
  const dir = path.dirname(configPath);
  const mode = options.mode == null ? 0o600 : options.mode;
  const contents = Buffer.isBuffer(data) ? Buffer.from(data) : Buffer.from(String(data), 'utf8');
  const baseNonce = options.nonce || crypto.randomBytes(12).toString('hex');
  const safeNonce = String(baseNonce).replace(/[^A-Za-z0-9_-]/g, '')
    || crypto.randomBytes(12).toString('hex');
  const tempPath = path.join(dir, `.${path.basename(configPath)}.${process.pid}.${safeNonce}.tmp`);
  let fileDescriptor = null;
  let tempCreated = false;
  let publishedCandidate = null;

  try {
    fsImpl.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fileDescriptor = fsImpl.openSync(tempPath, 'wx', mode);
    tempCreated = true;
    fsImpl.writeFileSync(fileDescriptor, contents);
    fsImpl.fsyncSync(fileDescriptor);
    fsImpl.closeSync(fileDescriptor);
    fileDescriptor = null;
    // Publication owns the staged pathname from this point, including every
    // rollback/recovery artifact on failure.
    tempCreated = false;
    const callerVerify = options.verifyPublished;
    const publish = options.exclusive
      ? privatePaths.publishFileExclusiveDurably
      : privatePaths.publishFileDurably;
    publish(tempPath, configPath, {
      ...options,
      fs: fsImpl,
      cleanupComponent: 'policy-file-publication',
      ...(options.exclusive ? { consumeSource: true } : {}),
      verifyPublished(published) {
        const candidate = policyFileSnapshot(published, { ...options, fs: fsImpl });
        if (!candidate.exists || !candidate.contents.equals(contents)) {
          throw policyReadFailure('published policy bytes could not be verified');
        }
        publishedCandidate = candidate;
        if (typeof callerVerify === 'function') return callerVerify(published);
        return undefined;
      },
    });
  } catch (error) {
    cleanupPolicyTemp(fsImpl, fileDescriptor, tempPath, tempCreated);
    throw error;
  }
  if (!publishedCandidate) throw policyReadFailure('published policy identity was not captured');
  return publishedCandidate;
}

function normalizedPolicyForWrite(p) {
  const inputPolicy = validatePolicyData(p == null ? {} : p);
  if (!inputPolicy.success) throw new TypeError('policy failed semantic validation');
  const normalized = normalizePolicy(inputPolicy.data);
  const parsedPolicy = validatePolicyData(normalized);
  if (!parsedPolicy.success) throw new TypeError('policy failed semantic validation');
  return parsedPolicy.data;
}

function writePolicyWithCandidate(configPath, p, options = {}) {
  const normalized = normalizedPolicyForWrite(p);
  const candidate = writePolicyBytesAtomically(
    configPath,
    `${JSON.stringify(normalized, null, 2)}\n`,
    options,
  );
  return { normalized, candidate };
}

function writePolicyAtomically(configPath, p, options = {}) {
  return writePolicyWithCandidate(configPath, p, options).normalized;
}

function exactPolicyLstat(fsImpl, target) {
  return fsImpl.lstatSync(target, { bigint: true });
}

function exactPolicyFstat(fsImpl, descriptor) {
  return fsImpl.fstatSync(descriptor, { bigint: true });
}

function stablePolicyFile(stat, expectedLinks = 1n) {
  return !!stat && typeof stat.dev === 'bigint' && typeof stat.ino === 'bigint'
    && typeof stat.size === 'bigint' && typeof stat.mode === 'bigint'
    && stat.dev > 0n && stat.ino > 0n && stat.size >= 0n
    && stat.isFile() && !stat.isSymbolicLink() && stat.nlink === expectedLinks;
}

function samePolicyStatTime(left, right, name) {
  const ns = `${name}Ns`;
  if (left[ns] !== undefined || right[ns] !== undefined) {
    return left[ns] !== undefined && right[ns] !== undefined && left[ns] === right[ns];
  }
  const ms = `${name}Ms`;
  return left[ms] !== undefined && right[ms] !== undefined && left[ms] === right[ms];
}

function samePolicySnapshot(left, right) {
  return stablePolicyFile(left) && stablePolicyFile(right)
    && left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && samePolicyStatTime(left, right, 'mtime') && samePolicyStatTime(left, right, 'ctime');
}

function policyReadFailure(message, cause) {
  const error = new Error(message);
  error.code = 'POLICY_FILE_INVALID';
  if (cause) error.cause = cause;
  return error;
}

function inspectPolicyFile(configPath, fsImpl) {
  let before;
  try { before = exactPolicyLstat(fsImpl, configPath); }
  catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw policyReadFailure('policy file could not be inspected', error);
  }
  if (!stablePolicyFile(before) || before.size > MAX_POLICY_FILE_BYTES_BIGINT) {
    throw policyReadFailure('policy path is not a bounded private regular file');
  }
  return before;
}

function readPolicySnapshot(configPath, before, fsImpl) {
  const output = Buffer.alloc(Math.min(MAX_POLICY_FILE_BYTES + 1, Number(before.size) + 1));
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let descriptor;
  try {
    descriptor = fsImpl.openSync(configPath, fs.constants.O_RDONLY | noFollow);
    const opened = exactPolicyFstat(fsImpl, descriptor);
    if (!samePolicySnapshot(before, opened)) throw policyReadFailure('policy file changed while opening');
    let offset = 0;
    while (offset < output.length) {
      const count = fsImpl.readSync(descriptor, output, offset, output.length - offset, null);
      if (!count) break;
      offset += count;
    }
    const after = exactPolicyFstat(fsImpl, descriptor);
    const pathAfter = exactPolicyLstat(fsImpl, configPath);
    if (offset > MAX_POLICY_FILE_BYTES || BigInt(offset) !== opened.size
        || !samePolicySnapshot(opened, after) || !samePolicySnapshot(after, pathAfter)) {
      throw policyReadFailure('policy file changed while reading');
    }
    return output.subarray(0, offset);
  } catch (error) {
    if (error && error.code === 'POLICY_FILE_INVALID') throw error;
    throw policyReadFailure('policy file could not be read', error);
  } finally {
    if (descriptor !== undefined) try { fsImpl.closeSync(descriptor); } catch {}
  }
}

function policyFileSnapshot(configPath = CONFIG_PATH, options = {}) {
  const fsImpl = options.fs || fs;
  const before = inspectPolicyFile(configPath, fsImpl);
  if (!before) return { exists: false };
  const contents = readPolicySnapshot(configPath, before, fsImpl);
  const after = inspectPolicyFile(configPath, fsImpl);
  if (!after || !samePolicySnapshot(before, after)) {
    throw policyReadFailure('policy file changed after reading');
  }
  return {
    exists: true,
    contents,
    mode: Number(before.mode & 0o777n),
    identity: after,
  };
}

function policyFromSnapshot(snapshot) {
  if (!snapshot.exists) return normalizePolicy();
  let parsed;
  try {
    parsed = JSON.parse(snapshot.contents.toString('utf8'));
  } catch (error) {
    const invalid = new Error('policy file is not valid JSON');
    invalid.code = 'POLICY_FILE_INVALID';
    throw invalid;
  }
  const result = validatePolicyData(parsed);
  if (!result.success) {
    const invalid = new Error('policy file failed semantic validation');
    invalid.code = 'POLICY_FILE_INVALID';
    throw invalid;
  }
  return normalizePolicy(result.data);
}

function policiesEqual(left, right) {
  return JSON.stringify(normalizedPolicyForWrite(left)) === JSON.stringify(normalizedPolicyForWrite(right));
}

function stalePolicyError() {
  const error = new Error('policy changed before mutation lock acquisition');
  error.code = 'POLICY_WRITE_CONFLICT';
  error.statusCode = 409;
  error.publicMessage = 'policy changed; refresh and retry';
  return error;
}

function policyRollbackFailure(message, cause, details = {}) {
  const error = new Error(message);
  error.code = 'POLICY_ROLLBACK_FAILED';
  error.cause = cause;
  Object.assign(error, details);
  return error;
}

function samePolicyCandidate(left, right) {
  return !!left?.exists && !!right?.exists
    && stablePolicyFile(left.identity) && stablePolicyFile(right.identity)
    && left.identity.dev === right.identity.dev && left.identity.ino === right.identity.ino
    && Buffer.isBuffer(left.contents) && Buffer.isBuffer(right.contents)
    && left.contents.equals(right.contents);
}

function linkedPolicyStat(target, expectedLinks, fsImpl) {
  const stat = exactPolicyLstat(fsImpl, target);
  if (!stablePolicyFile(stat, BigInt(expectedLinks))) {
    throw new Error('retained policy artifact has no stable identity');
  }
  return stat;
}

function sameLinkedPolicy(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && samePolicyStatTime(left, right, 'mtime');
}

function removeExactPolicyArtifact(target, expected, options = {}) {
  const fsImpl = options.fs || fs;
  try {
    privatePaths.removeExactPublicationFile(target, expected, { ...options, fs: fsImpl });
  } catch (error) {
    if (!error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
      try { exactPolicyLstat(fsImpl, target); error.retainedPath = target; }
      catch (inspectError) {
        if (inspectError && inspectError.code === 'ENOENT') error.removedPath = target;
      }
    }
    throw error;
  }
}

function restorePolicySnapshot(configPath, snapshot, options = {}) {
  const fsImpl = options.fs || fs;
  if (snapshot.exists) {
    return writePolicyBytesAtomically(configPath, snapshot.contents, {
      ...options,
      nonce: undefined,
      mode: snapshot.mode,
      exclusive: true,
    });
  }
  const current = inspectPolicyFile(configPath, fsImpl);
  if (current) {
    const error = policyReadFailure('a replacement policy appeared during rollback');
    error.replacementPath = configPath;
    throw error;
  }
  return null;
}

function restoreChangedPolicy(quarantine, configPath, options, originalError) {
  const fsImpl = options.fs || fs;
  const guard = `${quarantine}.restore.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    const source = policyFileSnapshot(quarantine, { ...options, fs: fsImpl });
    if (!source.exists) throw new Error('changed policy replacement is unavailable');
    fsImpl.linkSync(quarantine, configPath);
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    let restored = linkedPolicyStat(configPath, 3, fsImpl);
    let retained = linkedPolicyStat(guard, 3, fsImpl);
    const sourceLink = linkedPolicyStat(quarantine, 3, fsImpl);
    if (!sameLinkedPolicy(source.identity, restored) || !sameLinkedPolicy(source.identity, retained)
        || !sameLinkedPolicy(source.identity, sourceLink)) {
      throw new Error('changed policy replacement could not be identity-bound');
    }
    removeExactPolicyArtifact(quarantine, sourceLink, options);
    quarantinePresent = false;
    restored = linkedPolicyStat(configPath, 2, fsImpl);
    retained = linkedPolicyStat(guard, 2, fsImpl);
    if (!sameLinkedPolicy(source.identity, restored) || !sameLinkedPolicy(source.identity, retained)) {
      throw new Error('changed policy replacement changed during restoration');
    }
    removeExactPolicyArtifact(guard, retained, options);
    guardPresent = false;
    restored = linkedPolicyStat(configPath, 1, fsImpl);
    if (!sameLinkedPolicy(source.identity, restored)) {
      throw new Error('changed policy replacement changed after restoration');
    }
  } catch (error) {
    throw policyRollbackFailure('changed policy replacement was retained for recovery', originalError || error, {
      ...(error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : {})),
      ...(error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: guard } : {})),
      ...(error.removedPath ? { removedPath: error.removedPath } : {}),
      replacementPath: configPath,
    });
  }
  throw policyRollbackFailure('policy changed during rollback; replacement was preserved', originalError, {
    replacementPath: configPath,
  });
}

function cleanupPolicyCandidate(quarantine, candidate, options, originalError) {
  const fsImpl = options.fs || fs;
  const guard = `${quarantine}.cleanup.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let quarantinePresent = true;
  let guardPresent = false;
  try {
    fsImpl.linkSync(quarantine, guard);
    guardPresent = true;
    const source = linkedPolicyStat(quarantine, 2, fsImpl);
    const retained = linkedPolicyStat(guard, 2, fsImpl);
    if (!sameLinkedPolicy(candidate.identity, source) || !sameLinkedPolicy(candidate.identity, retained)) {
      throw new Error('policy cleanup guard changed');
    }
    removeExactPolicyArtifact(quarantine, source, options);
    quarantinePresent = false;
    const exact = policyFileSnapshot(guard, { ...options, fs: fsImpl });
    if (!samePolicyCandidate(candidate, exact)) throw new Error('policy cleanup guard changed after removal');
    removeExactPolicyArtifact(guard, exact.identity, options);
    guardPresent = false;
  } catch (error) {
    throw policyRollbackFailure('policy candidate quarantine could not be removed', originalError || error, {
      ...(error.retainedPath
        ? { retainedPath: error.retainedPath }
        : (quarantinePresent ? { retainedPath: quarantine } : {})),
      ...(error.additionalRetainedPath
        ? { additionalRetainedPath: error.additionalRetainedPath }
        : (guardPresent ? { additionalRetainedPath: guard } : {})),
      ...(error.removedPath ? { removedPath: error.removedPath } : {}),
    });
  }
}

function rollbackPolicyCandidate(configPath, before, candidate, options, originalError) {
  const fsImpl = options.fs || fs;
  const quarantine = `${configPath}.failed-mutation.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  try { fsImpl.renameSync(configPath, quarantine); }
  catch (error) {
    throw policyRollbackFailure('policy rollback could not quarantine the published candidate', originalError || error);
  }
  let quarantined;
  try { quarantined = policyFileSnapshot(quarantine, { ...options, fs: fsImpl }); }
  catch (error) {
    throw policyRollbackFailure('policy rollback retained an unverifiable replacement', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!samePolicyCandidate(candidate, quarantined)) {
    restoreChangedPolicy(quarantine, configPath, options, originalError);
  }
  try { restorePolicySnapshot(configPath, before, options); }
  catch (error) {
    throw policyRollbackFailure('prior policy could not be restored', originalError || error, {
      retainedPath: quarantine,
      ...(error.replacementPath ? { replacementPath: error.replacementPath } : {}),
    });
  }
  let exact;
  try { exact = policyFileSnapshot(quarantine, { ...options, fs: fsImpl }); }
  catch (error) {
    throw policyRollbackFailure('policy candidate quarantine could not be reverified', originalError || error, {
      retainedPath: quarantine,
    });
  }
  if (!samePolicyCandidate(candidate, exact)) {
    throw policyRollbackFailure('policy candidate quarantine changed before cleanup', originalError, {
      retainedPath: quarantine,
    });
  }
  cleanupPolicyCandidate(quarantine, candidate, options, originalError);
}

function invalidatePolicyCache(configPath) {
  if (configPath === path.resolve(CONFIG_PATH)) defaultPolicyLoader.invalidate();
}

function createPolicyMutationWriter(configPath, state, options) {
  return (nextPolicy) => {
    const { normalized: saved, candidate: publishedCandidate } = writePolicyWithCandidate(
      configPath,
      nextPolicy,
      options,
    );
    state.written = true;
    state.candidate = publishedCandidate;
    const verified = policyFileSnapshot(configPath, options);
    if (!samePolicyCandidate(publishedCandidate, verified)) {
      throw policyReadFailure('published policy changed before mutation commit');
    }
    state.candidate = verified;
    invalidatePolicyCache(configPath);
    return normalizePolicy(saved);
  };
}

function rollbackPolicyMutation(configPath, before, candidate, originalError, options) {
  try {
    rollbackPolicyCandidate(configPath, before, candidate, options, originalError);
  } catch (rollbackError) {
    if (rollbackError && rollbackError.code === 'POLICY_ROLLBACK_FAILED') {
      rollbackError.originalCause = originalError;
      throw rollbackError;
    }
    const failure = new Error('policy rollback failed after control-plane commit error');
    failure.code = 'POLICY_ROLLBACK_FAILED';
    failure.cause = originalError;
    failure.rollbackCause = rollbackError;
    throw failure;
  } finally {
    invalidatePolicyCache(configPath);
  }
}

function runPolicyFileMutation(configPath, expectedPolicy, callback, options) {
  const before = policyFileSnapshot(configPath, options);
  const current = policyFromSnapshot(before);
  if (!policiesEqual(current, expectedPolicy)) throw stalePolicyError();
  const state = { written: false, candidate: null };
  const write = createPolicyMutationWriter(configPath, state, options);
  try {
    const result = callback({ current, write });
    if (result && typeof result.then === 'function') {
      throw new TypeError('policy mutation callback must be synchronous');
    }
    return result;
  } catch (error) {
    if (state.written && state.candidate) {
      rollbackPolicyMutation(configPath, before, state.candidate, error, options);
    }
    throw error;
  }
}

function withPolicyFileMutation(expectedPolicy, callback, options = {}) {
  const configPath = path.resolve(options.configPath || CONFIG_PATH);
  return fileMutationLock.withFileMutationLockSync(
    configPath,
    () => runPolicyFileMutation(configPath, expectedPolicy, callback, options),
    { ...options, cleanupComponent: 'policy-file-lock' },
  );
}

async function withPolicyFileMutationAsync(expectedPolicy, callback, options = {}) {
  const configPath = path.resolve(options.configPath || CONFIG_PATH);
  return fileMutationLock.withFileMutationLock(
    configPath,
    () => runPolicyFileMutation(configPath, expectedPolicy, callback, options),
    { ...options, cleanupComponent: 'policy-file-lock' },
  );
}

function savePolicy(p, options = {}) {
  const configPath = path.resolve(options.configPath || CONFIG_PATH);
  return fileMutationLock.withFileMutationLockSync(configPath, () => {
    const saved = writePolicyAtomically(configPath, p, options);
    invalidatePolicyCache(configPath);
    return normalizePolicy(saved);
  }, { ...options, cleanupComponent: 'policy-file-lock' });
}

// Every hard-stop (alwaysBlock) type, including per-scope additions. These must
// never be disabled at detection time by the ignore list — a disabled detector
// produces no finding, so the evaluate()-level hard-stop guard could never fire
// and raw regulated PII would be cleared to send.
function alwaysBlockTypes(policy = loadPolicy()) {
  const types = new Set(mandatoryAlwaysBlock(policy && policy.alwaysBlock));
  for (const scope of policy.policyScopes || []) {
    for (const type of scope.alwaysBlockAdd || []) types.add(type);
  }
  return types;
}

function analyzeOpts(policy = loadPolicy()) {
  const alwaysBlock = alwaysBlockTypes(policy);
  const opts = {
    // Strip hard-stop types from the detection-time ignore list: ignoring a
    // hard-stop entity only removes it from scoring (handled in evaluate), it
    // must never suppress the detector itself.
    ignore: (policy.ignore || []).filter((type) => !alwaysBlock.has(type)),
    // A disabled detector may tune optional coverage, but it can never remove
    // evidence for a global or scoped hard stop. Keep those detectors active so
    // evaluate() can enforce the alwaysBlock invariant.
    disabledDetectors: (policy.disabledDetectors || []).filter((type) => !alwaysBlock.has(type)),
    customDetectors: customDetectors.loadCustomDetectors(),
    // These options are used only at prompt, file-text, and response-text
    // boundaries. A strict reversible encoding that decodes to non-text cannot
    // be cleared as ordinary prose because the text detector could not inspect it.
    opaqueEncodedContent: true,
  };
  const edm = exactMatch.exactMatchConfig();
  if (edm) opts.exactMatch = edm;
  return opts;
}

function customDetectorsForSensors() {
  return customDetectors.loadCustomDetectors();
}

function customDetectorsStatus() {
  return customDetectors.status();
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

function unmanagedInstallBlocked(user, policy = loadPolicy()) {
  if (((policy || {}).unmanagedInstalls || DEFAULT_POLICY.unmanagedInstalls) !== 'block') return false;
  return String(user || '').trim().toLowerCase() === 'unattributed@unmanaged';
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
  if (rule.accountTypes && !rule.accountTypes.includes(String(context.accountType || 'unknown').toLowerCase())) return false;
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

// Append the regulations behind a finding type to a verdict reason, so block
// banners and audit entries say WHICH obligation the data fell under.
function citedReason(label, type) {
  const regs = type ? detector.regulationsFor(type) : [];
  return regs.length ? label + ' [' + regs.join('; ') + ']' : label;
}

function evaluate(analysis, policy = loadPolicy(), context = {}, options = {}) {
  const effective = effectivePolicyForContext(policy, analysis, context, options);
  const reasons = [];
  const ignore = effective.ignore || [];
  const alwaysBlock = effective.alwaysBlock || [];
  // Hard-stop (alwaysBlock) types can never be suppressed by the ignore list:
  // an ignored finding is dropped for scoring, but an ignored hard-stop entity
  // must still force a block, or raw regulated PII could be cleared to send.
  const findings = (analysis.findings || []).filter((f) => alwaysBlock.includes(f.type) || !ignore.includes(f.type));
  const categories = (analysis.categories || []).filter((c) => !ignore.includes(c && (c.category || c)));
  const opaqueEncoded = analysis && analysis.opaqueEncoded === true;

  if (findings.length === 0 && categories.length === 0 && !opaqueEncoded) {
    return { decision: 'allow', reasons: ['Nothing sensitive detected'], policy: effective, policyScopeIds: effective.appliedPolicyScopes || [] };
  }
  if (opaqueEncoded) reasons.push('Opaque reversible encoding could not be inspected');
  if (categories.length) reasons.push('Sensitive content: ' + categories.map((c) => c && (c.category || c)).join(', '));
  const hardStop = findings.find((f) => (effective.alwaysBlock || []).includes(f.type));
  if (hardStop) {
    // Vendor label (never the value) sharpens the reason: "SECRET_KEY (Stripe
    // secret key (live))" tells the approver what leaked without revealing it.
    const hardStopLabel = 'Hard-stop entity present: ' + hardStop.type + (hardStop.vendorLabel ? ' (' + hardStop.vendorLabel + ')' : '');
    reasons.push(citedReason(hardStopLabel, hardStop.type));
  }
  if (analysis.maxSeverity >= effective.blockMinSeverity) {
    const driver = findings.find((f) => f.severity === analysis.maxSeverity && f.type !== (hardStop && hardStop.type));
    reasons.push(citedReason('Severity ' + analysis.maxSeverityLabel + ' >= policy minimum', driver && driver.type));
  }
  if (analysis.riskScore >= effective.blockRiskScore) reasons.push('Risk score ' + analysis.riskScore + ' >= ' + effective.blockRiskScore);
  // A matched scope only annotates an already-blocking decision — it must not by
  // itself convert a sub-threshold detection into a block. Scope telemetry for
  // allowed decisions is still carried via policyScopeIds below.
  if (reasons.length && (effective.appliedPolicyScopes || []).length) {
    reasons.push('Policy scope matched: ' + effective.appliedPolicyScopes.join(', '));
  }

  const exception = reasons.length && !hardStop && !opaqueEncoded ? activePolicyException(effective, analysis, context, options) : null;
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
  createPolicyLoader,
  loadPolicy,
  policyStatus,
  savePolicy,
  writePolicyAtomically,
  withPolicyFileMutation,
  withPolicyFileMutationAsync,
  evaluate,
  analyzeOpts,
  customDetectorsForSensors,
  customDetectorsStatus,
  rawRetentionDays,
  normalizePolicy,
  mandatoryAlwaysBlock,
  normalizeDestination,
  normalizeApprovalRoutingRules,
  normalizePolicyScopes,
  normalizePolicyExceptions,
  policyExceptionReview,
  effectivePolicyForContext,
  policyRuleMatches,
  personalAccountBlocked,
  normalizeCorporateAiAccounts,
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
  unmanagedInstallBlocked,
  normalizeResponseScanMode,
  normalizeUnmanagedInstalls,
  normalizeBrowserAction,
  normalizeBlockedBrowserActions,
  normalizeMcpToolList,
  policyChangeSummary,
  policyChangeDetail,
  DEFAULT_POLICY,
};
