type JsonRecord = Record<string, unknown>;

const DEFAULT_REQUIRED_SENSORS = ['browser_extension', 'endpoint_agent', 'mcp_guard'];
const SENSOR_ID = /^[a-z][a-z0-9_:-]{0,79}$/;
const SENSOR_VERSION = /^[A-Za-z0-9._+:-]{1,80}$/;
const RULE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const GROUP = /^[a-z][a-z0-9_-]{0,63}$/;
const ROLE = /^(security_admin|approver)$/;
const REASON = /^[a-z0-9][a-z0-9_:-]{0,79}$/;
const DETECTOR = /^[A-Z0-9_]{1,80}$/;
const MATCH_TEXT = /^[A-Za-z0-9 ._@:+/-]{1,128}$/;
const DESTINATION = /^[A-Za-z0-9.*:_/-]{1,253}$/;
const MCP_TOOL = /^[A-Za-z0-9.*:_/-]{1,160}$/;
const SENSITIVE_CODE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;
const BROWSER_ACTIONS = new Set(['paste', 'drop', 'copy', 'download']);
const POLICY_MODES = new Set(['warn', 'redact', 'justify', 'block']);

function record(value: unknown): JsonRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null ? value as JsonRecord : null;
}

function safeCode(value: string): boolean {
  return Boolean(value) && !SENSITIVE_CODE.test(value);
}

function normalizedList(
  value: unknown,
  pattern: RegExp,
  transform: (item: string) => string = (item) => item,
  maxItems = 40,
  requireSafeCode = false,
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(value) ? value : []) {
    const item = String(raw || '').trim();
    const key = item.toLowerCase();
    if (!item || seen.has(key) || !pattern.test(item) || (requireSafeCode && !safeCode(item))) continue;
    seen.add(key);
    out.push(transform(item));
    if (out.length >= maxItems) break;
  }
  return out;
}

function setList(target: JsonRecord, key: string, value: string[]): void {
  if (value.length) target[key] = value;
}

function normalizedMatchers(value: unknown): JsonRecord {
  const item = record(value) || {};
  const out: JsonRecord = {};
  setList(out, 'users', normalizedList(item.users, MATCH_TEXT, (entry) => entry.toLowerCase(), 40, true));
  setList(out, 'groups', normalizedList(item.groups || item.userGroups, MATCH_TEXT, (entry) => entry.toLowerCase(), 40, true));
  setList(out, 'orgIds', normalizedList(item.orgIds, MATCH_TEXT, (entry) => entry.toLowerCase(), 40, true));
  setList(out, 'detectors', normalizedList(item.detectors, DETECTOR, (entry) => entry.toUpperCase()));
  setList(out, 'categories', normalizedList(item.categories, DETECTOR, (entry) => entry.toUpperCase()));
  setList(out, 'sources', normalizedList(item.sources, SENSOR_ID, (entry) => entry.toLowerCase()));
  setList(out, 'channels', normalizedList(item.channels, SENSOR_ID, (entry) => entry.toLowerCase()));
  setList(out, 'destinations', normalizedList(item.destinations, DESTINATION, (entry) => entry, 40, true));
  setList(out, 'accountTypes', normalizedList(item.accountTypes, /^(?:personal|corporate|unknown)$/i, (entry) => entry.toLowerCase()));
  return out;
}

function hasMatcher(rule: JsonRecord): boolean {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations', 'accountTypes']
    .some((key) => Array.isArray(rule[key]) && rule[key].length > 0);
}

function normalizedApprovalRules(value: unknown): JsonRecord[] {
  const out: JsonRecord[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(value) ? value : []) {
    const item = record(raw);
    if (!item) continue;
    const id = String(item.id || '').trim().toLowerCase();
    const assignedGroup = String(item.assignedGroup || '').trim().toLowerCase();
    const assignedRole = String(item.assignedRole || '').trim();
    const slaMinutes = Number(item.slaMinutes);
    if (!RULE_ID.test(id) || seen.has(id) || !safeCode(id) || !GROUP.test(assignedGroup)
      || !safeCode(assignedGroup) || !ROLE.test(assignedRole) || !Number.isFinite(slaMinutes)) continue;
    const rule: JsonRecord = {
      id,
      enabled: item.enabled !== false,
      assignedGroup,
      assignedRole,
      slaMinutes: Math.max(15, Math.min(10_080, Math.round(slaMinutes))),
    };
    const reason = String(item.reason || '').trim().toLowerCase();
    if (REASON.test(reason) && safeCode(reason)) rule.reason = reason;
    Object.assign(rule, normalizedMatchers(item));
    delete rule.accountTypes;
    setList(rule, 'destinations', normalizedList(item.destinations, DESTINATION));
    if (item.minSeverity !== undefined && Number.isFinite(Number(item.minSeverity))) {
      rule.minSeverity = Math.max(0, Math.min(4, Math.round(Number(item.minSeverity))));
    }
    if (item.minRiskScore !== undefined && Number.isFinite(Number(item.minRiskScore))) {
      rule.minRiskScore = Math.max(0, Math.min(100, Math.round(Number(item.minRiskScore))));
    }
    if (!hasMatcher(rule) && rule.minSeverity === undefined && rule.minRiskScore === undefined) continue;
    seen.add(id);
    out.push(rule);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizedPolicyScopes(value: unknown): JsonRecord[] {
  const out: JsonRecord[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(value) ? value : []) {
    const item = record(raw);
    if (!item) continue;
    const id = String(item.id || '').trim().toLowerCase();
    if (!RULE_ID.test(id) || seen.has(id) || !safeCode(id)) continue;
    const scope: JsonRecord = { id, enabled: item.enabled !== false, ...normalizedMatchers(item) };
    if (!hasMatcher(scope)) continue;
    const mode = String(item.enforcementMode || '').trim();
    if (POLICY_MODES.has(mode)) scope.enforcementMode = mode;
    if (item.blockMinSeverity !== undefined && Number.isFinite(Number(item.blockMinSeverity))) {
      scope.blockMinSeverity = Math.max(1, Math.min(4, Math.round(Number(item.blockMinSeverity))));
    }
    if (item.blockRiskScore !== undefined && Number.isFinite(Number(item.blockRiskScore))) {
      scope.blockRiskScore = Math.max(0, Math.min(100, Math.round(Number(item.blockRiskScore))));
    }
    setList(scope, 'alwaysBlockAdd', normalizedList(item.alwaysBlockAdd, DETECTOR, (entry) => entry.toUpperCase()));
    const reason = String(item.reason || '').trim().toLowerCase();
    if (REASON.test(reason) && safeCode(reason)) scope.reason = reason;
    if (!scope.enforcementMode && scope.blockMinSeverity === undefined && scope.blockRiskScore === undefined
      && !Array.isArray(scope.alwaysBlockAdd)) continue;
    seen.add(id);
    out.push(scope);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizedPolicyExceptions(value: unknown): JsonRecord[] {
  const out: JsonRecord[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(value) ? value : []) {
    const item = record(raw);
    if (!item) continue;
    const id = String(item.id || '').trim().toLowerCase();
    const expires = Date.parse(String(item.expiresAt || '').trim());
    if (!RULE_ID.test(id) || seen.has(id) || !safeCode(id) || !Number.isFinite(expires)) continue;
    const exception: JsonRecord = {
      id,
      enabled: item.enabled !== false,
      action: 'allow',
      expiresAt: new Date(expires).toISOString(),
      ...normalizedMatchers(item),
    };
    if (!hasMatcher(exception)) continue;
    const ownerGroup = String(item.ownerGroup || '').trim().toLowerCase();
    if (GROUP.test(ownerGroup) && safeCode(ownerGroup)) exception.ownerGroup = ownerGroup;
    const reviewerRole = String(item.reviewerRole || '').trim().toLowerCase();
    if (ROLE.test(reviewerRole)) exception.reviewerRole = reviewerRole;
    const reviewTime = Date.parse(String(item.reviewAfter || '').trim());
    if (Number.isFinite(reviewTime) && reviewTime <= expires) exception.reviewAfter = new Date(reviewTime).toISOString();
    const reason = String(item.reason || '').trim().toLowerCase();
    if (REASON.test(reason) && safeCode(reason)) exception.reason = reason;
    seen.add(id);
    out.push(exception);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizedBrowserActions(value: unknown): JsonRecord[] {
  const out: JsonRecord[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(value) ? value : []) {
    const item = record(raw);
    if (!item) continue;
    const id = String(item.id || '').trim().toLowerCase();
    const action = String(item.action || '').trim().toLowerCase();
    const destinations = normalizedList(item.destinations, DESTINATION, (entry) => entry, 40, true);
    if (!RULE_ID.test(id) || seen.has(id) || !safeCode(id) || !BROWSER_ACTIONS.has(action) || !destinations.length) continue;
    const rule: JsonRecord = { id, enabled: item.enabled !== false, action, destinations };
    const reason = String(item.reason || '').trim().toLowerCase();
    if (REASON.test(reason) && safeCode(reason)) rule.reason = reason;
    seen.add(id);
    out.push(rule);
    if (out.length >= 40) break;
  }
  return out;
}

function normalizedRequiredSensors(value: unknown): string[] {
  const normalized = normalizedList(value, SENSOR_ID, (entry) => entry.toLowerCase(), Number.MAX_SAFE_INTEGER);
  return normalized.length ? normalized : [...DEFAULT_REQUIRED_SENSORS];
}

function normalizedDesiredVersions(value: unknown): JsonRecord {
  const source = record(value) || {};
  const out: JsonRecord = {};
  for (const [rawKey, rawValue] of Object.entries(source)) {
    const key = rawKey.trim().toLowerCase();
    const version = String(rawValue || '').trim();
    if (SENSOR_ID.test(key) && SENSOR_VERSION.test(version)) out[key] = version;
  }
  return out;
}

function comparable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(comparable);
  const object = record(value);
  if (!object) return value;
  return Object.fromEntries(Object.keys(object).sort().map((key) => [key, comparable(object[key])]));
}

function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(comparable(left)) === JSON.stringify(comparable(right));
}

function expectedField(key: string, value: unknown): unknown {
  if (key === 'requiredSensors') return normalizedRequiredSensors(value);
  if (key === 'desiredSensorVersions') return normalizedDesiredVersions(value);
  if (['mcpAllowedTools', 'mcpBlockedTools', 'mcpApprovalRequiredTools'].includes(key)) {
    return normalizedList(value, MCP_TOOL, (entry) => entry, 200, true);
  }
  if (key === 'approvalRoutingRules') return normalizedApprovalRules(value);
  if (key === 'blockedBrowserActions') return normalizedBrowserActions(value);
  if (key === 'policyScopes') return normalizedPolicyScopes(value);
  if (key === 'policyExceptions') return normalizedPolicyExceptions(value);
  return value;
}

const VERIFIED_FIELDS = [
  'enforcementMode', 'blockMinSeverity', 'blockRiskScore', 'storeRawForApproval', 'rawRetentionDays',
  'governedDestinations', 'allowedDestinations', 'blockedDestinations', 'blockedFileUploadDestinations',
  'blockUnapprovedAiDestinations', 'responseScanMode', 'desktopCollectorDestination', 'ignore', 'disabledDetectors',
  'unmanagedInstalls', 'requiredSensors', 'desiredSensorVersions', 'mcpAllowedTools', 'mcpBlockedTools',
  'mcpApprovalRequiredTools', 'approvalRoutingRules', 'blockedBrowserActions', 'policyScopes', 'policyExceptions',
];

export function policyMatchesCoreUpdate(policy: JsonRecord, update: object): boolean {
  const fields = update as JsonRecord;
  for (const key of VERIFIED_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(fields, key) && !equalJson(policy[key], expectedField(key, fields[key]))) return false;
  }
  if (Array.isArray(fields.alwaysBlock)) {
    const required = normalizedList(fields.alwaysBlock, DETECTOR, (entry) => entry.toUpperCase(), 200);
    if (!required.every((detector) => Array.isArray(policy.alwaysBlock) && policy.alwaysBlock.includes(detector))) return false;
  }
  return true;
}
