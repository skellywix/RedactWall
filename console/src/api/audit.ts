import { api, apiErrorSummary, apiJsonBounded, responseJsonBounded } from '../lib/api';
import { cancelResponseBody } from '../lib/bounded-response';

/**
 * Audit-trail API. Route contract from server/app.js:
 *   GET /api/audit?limit=&queryId=  -> { entries, integrity, window, retention }
 *     entries: newest-first hash-chained records from db.listAudit(); each
 *     carries prevHash/hash (and contentHash when tied to a query).
 *     integrity: db.verifyAuditChain() -> { ok, count } on success, or
 *     { ok:false, count, brokenAt, reason:'chain'|'evidence', queryId? }.
 *   GET /api/export/evidence?queryLimit=&auditLimit=  (Security Admin or
 *     Auditor) -> JSON evidence pack in the response body; downloaded
 *     client-side as a blob, same as the legacy dashboard exportEvidence().
 */

export interface AuditEntry {
  id: string;
  ts: string;
  action: string;
  queryId: string;
  actor: string;
  detail: string;
  prevHash: string;
  hash: string;
  contentHash?: string;
}

export interface AuditIntegrity {
  ok: boolean;
  count: number;
  brokenAt?: string;
  reason?: 'chain' | 'evidence' | string;
  queryId?: string;
}

export interface AuditLog {
  entries: AuditEntry[];
  integrity: AuditIntegrity;
  window: AuditWindow;
  retention: string;
}

export interface AuditWindow {
  scope: 'all' | 'query';
  scannedEntries: number;
  totalEntries: number;
  matchedEntries: number;
  returnedEntries: number;
  complete: boolean;
}

export type QueryAuditResult =
  | { kind: 'verified'; entries: AuditEntry[]; window: AuditWindow }
  | { kind: 'unavailable'; reason: 'invalid_request' | 'unavailable_or_malformed' | 'integrity_failure' };

const AUDIT_ENTRIES_MAX = 500;
const AUDIT_TEXT_MAX = 4_096;
const AUDIT_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const EVIDENCE_EXPORT_RESPONSE_MAX_BYTES = 16 * 1024 * 1024;
const HASH64 = /^[0-9a-f]{64}$/;
const EVIDENCE_ARRAY_MAX = 5_000;
const EVIDENCE_OBJECT_KEYS_MAX = 256;
const EVIDENCE_STRING_MAX = 4_096;
const EVIDENCE_TREE_DEPTH_MAX = 12;
const EVIDENCE_TREE_NODES_MAX = 100_000;
const FCU_EXAMINER_PROFILE = 'federal_credit_union';
const INTEGRITY_FAILURE_REASONS = new Set([
  'chain',
  'evidence',
  'checkpoint-authentication',
  'checkpoint-missing',
  'checkpoint-unavailable',
  'checkpoint-truncated',
  'entry-authentication',
  'entry-authentication-missing',
  'checkpoint-diverged',
  'evidence-unanchored',
  'evidence-missing',
  'pending-missing',
  'checkpoint-pending',
]);

type SafeJson = null | boolean | number | string | SafeJson[] | SafeJsonObject;
type SafeJsonObject = { [key: string]: SafeJson };
type EvidenceProfile = typeof FCU_EXAMINER_PROFILE;

const INVALID_JSON = Symbol('invalid-json');
const EVIDENCE_TOP_LEVEL_KEYS = new Set([
  'schemaVersion', 'generatedAt', 'report', 'service', 'scope', 'policy', 'stats', 'auditIntegrity',
  'coverage', 'posture', 'detectorFeedback', 'policyExceptionReview', 'backup', 'restoreDrill', 'edm',
  'controlMappings', 'lineage', 'detectors', 'queries', 'audit', 'complianceDisclaimer', 'controlTests',
  'aupCrosswalk', 'aupAttestation', 'ncuaReadiness', 'useCases', 'incidents',
]);
const EVIDENCE_QUERY_KEYS = new Set([
  'id', 'createdAt', 'status', 'mode', 'user', 'orgId', 'source', 'channel', 'sensor', 'destination',
  'accountType', 'originApp', 'riskScore', 'maxSeverity', 'maxSeverityLabel', 'findings', 'categories',
  'entityCounts', 'reasons', 'promptHash', 'decidedBy', 'decidedAt', 'retentionPurgedAt',
  'retentionPurgedFields', 'installChecks', 'policyScopeIds', 'policyExceptionId', 'workflow',
]);
const EVIDENCE_AUDIT_KEYS = new Set([
  'id', 'ts', 'action', 'queryId', 'actor', 'prevHash', 'hash', 'detailHash', 'policyChange',
]);
const FORBIDDEN_EVIDENCE_KEYS = new Set([
  'rawPrompt', '_rawPrompt', 'redactedPrompt', 'tokenizedPrompt', 'tokenVault', '_tokenVault', 'auditDetails',
]);

function boundedString(value: unknown, max: number, allowEmpty = false): string | null {
  return typeof value === 'string' && value.length <= max && (allowEmpty || value.length > 0) ? value : null;
}

function decodeAuditEntry(value: unknown): AuditEntry | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const id = boundedString(row.id, 80);
  const ts = boundedString(row.ts, 40);
  const action = boundedString(row.action, 160);
  const queryId = boundedString(row.queryId, 80, true);
  const actor = boundedString(row.actor, 320, true);
  const detail = boundedString(row.detail, AUDIT_TEXT_MAX, true);
  const prevHash = boundedString(row.prevHash, 64);
  const hash = boundedString(row.hash, 64);
  if (!id || !ts || !Number.isFinite(Date.parse(ts)) || !action || queryId === null || actor === null || detail === null) return null;
  if (!prevHash || !HASH64.test(prevHash) || !hash || !HASH64.test(hash)) return null;
  if (row.contentHash !== undefined && (typeof row.contentHash !== 'string' || !HASH64.test(row.contentHash))) return null;
  return {
    id,
    ts,
    action,
    queryId,
    actor,
    detail,
    prevHash,
    hash,
    ...(typeof row.contentHash === 'string' ? { contentHash: row.contentHash } : {}),
  };
}

function decodeAuditIntegrity(value: unknown): AuditIntegrity | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (typeof row.ok !== 'boolean' || !Number.isSafeInteger(row.count) || Number(row.count) < 0) return null;
  if (row.ok) {
    return row.reason === undefined && row.brokenAt === undefined && row.queryId === undefined
      ? { ok: true, count: Number(row.count) }
      : null;
  }
  if (typeof row.reason !== 'string' || !INTEGRITY_FAILURE_REASONS.has(row.reason)) return null;
  const brokenAt = row.brokenAt === undefined ? undefined : boundedString(row.brokenAt, 80);
  const queryId = row.queryId === undefined ? undefined : boundedString(row.queryId, 80);
  if (brokenAt === null || queryId === null) return null;
  return {
    ok: false,
    count: Number(row.count),
    reason: row.reason,
    ...(brokenAt ? { brokenAt } : {}),
    ...(queryId ? { queryId } : {}),
  };
}

function nonnegativeInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
}

function decodeAuditWindow(
  value: unknown,
  integrity: AuditIntegrity,
  returnedEntries: number,
  expectedScope: AuditWindow['scope'],
): AuditWindow | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const scanned = nonnegativeInteger(row.scannedEntries);
  const total = nonnegativeInteger(row.totalEntries);
  const matched = nonnegativeInteger(row.matchedEntries);
  const returned = nonnegativeInteger(row.returnedEntries);
  if (row.scope !== expectedScope || typeof row.complete !== 'boolean') return null;
  if (scanned === null || total === null || matched === null || returned === null) return null;
  if (total !== integrity.count || (integrity.ok && scanned > total) || matched > scanned) return null;
  if (returned > matched || returned !== returnedEntries) return null;
  const complete = integrity.ok && scanned === total;
  if (row.complete !== complete) return null;
  return {
    scope: expectedScope,
    scannedEntries: scanned,
    totalEntries: total,
    matchedEntries: matched,
    returnedEntries: returned,
    complete,
  };
}

function decodeAuditLog(value: unknown, maxEntries: number, expectedScope: AuditWindow['scope']): AuditLog | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (!Array.isArray(body.entries) || body.entries.length > maxEntries) return null;
  const entries = body.entries.map(decodeAuditEntry);
  if (!entries.every((entry): entry is AuditEntry => entry !== null)) return null;
  const integrity = decodeAuditIntegrity(body.integrity);
  const retention = boundedString(body.retention, 1_200);
  if (!integrity || !retention) return null;
  const window = decodeAuditWindow(body.window, integrity, entries.length, expectedScope);
  return window ? { entries, integrity, window, retention } : null;
}

function boundedAuditLimit(value: number, fallback: number): number {
  return Number.isSafeInteger(value) ? Math.max(1, Math.min(value, AUDIT_ENTRIES_MAX)) : fallback;
}

export async function fetchAuditLog(limit = 500): Promise<AuditLog | null> {
  const bounded = boundedAuditLimit(limit, AUDIT_ENTRIES_MAX);
  return decodeAuditLog(
    await apiJsonBounded<unknown>(`/api/audit?limit=${bounded}`, AUDIT_RESPONSE_MAX_BYTES),
    bounded,
    'all',
  );
}

/**
 * Item-level audit trail for one held/decided prompt (BLOCKED -> APPROVAL_ROUTED
 * -> REVEAL_RAW -> APPROVED ...). Uses the server's queryId filter and returns
 * entries only when the complete response is well-formed and chain integrity is
 * verified. The response also proves whether the bounded global search covered
 * the complete retained audit set, so an empty recent window is never presented
 * as a complete empty history.
 */
export async function fetchAuditForQuery(queryId: string, limit = 50): Promise<QueryAuditResult> {
  if (!queryId || queryId.length > 80) return { kind: 'unavailable', reason: 'invalid_request' };
  const bounded = boundedAuditLimit(limit, 50);
  const body = decodeAuditLog(
    await apiJsonBounded<unknown>(
      `/api/audit?queryId=${encodeURIComponent(queryId)}&limit=${bounded}`,
      AUDIT_RESPONSE_MAX_BYTES,
    ),
    bounded,
    'query',
  );
  if (!body) return { kind: 'unavailable', reason: 'unavailable_or_malformed' };
  if (!body.integrity.ok) return { kind: 'unavailable', reason: 'integrity_failure' };
  if (body.entries.some((entry) => entry.queryId !== queryId)) {
    return { kind: 'unavailable', reason: 'unavailable_or_malformed' };
  }
  return { kind: 'verified', entries: body.entries, window: body.window };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 80 && Number.isFinite(Date.parse(value));
}

function safeInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= maximum;
}

function boundedTextValue(value: unknown, maximum: number, nullable = false): boolean {
  if (nullable && value === null) return true;
  return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}

function cloneSafeJson(
  value: unknown,
  state: { nodes: number },
  depth = 0,
): SafeJson | typeof INVALID_JSON {
  state.nodes += 1;
  if (state.nodes > EVIDENCE_TREE_NODES_MAX || depth > EVIDENCE_TREE_DEPTH_MAX) return INVALID_JSON;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.length <= EVIDENCE_STRING_MAX ? value : INVALID_JSON;
  if (typeof value === 'number') {
    return Number.isFinite(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER ? value : INVALID_JSON;
  }
  if (Array.isArray(value)) return cloneSafeArray(value, state, depth);
  if (!isRecord(value)) return INVALID_JSON;
  return cloneSafeObject(value, state, depth);
}

function cloneSafeArray(value: unknown[], state: { nodes: number }, depth: number): SafeJson | typeof INVALID_JSON {
  if (value.length > EVIDENCE_ARRAY_MAX) return INVALID_JSON;
  const output: SafeJson[] = [];
  for (const item of value) {
    const cloned = cloneSafeJson(item, state, depth + 1);
    if (cloned === INVALID_JSON) return INVALID_JSON;
    output.push(cloned);
  }
  return output;
}

function cloneSafeObject(
  value: Record<string, unknown>,
  state: { nodes: number },
  depth: number,
): SafeJson | typeof INVALID_JSON {
  const entries = Object.entries(value);
  if (entries.length > EVIDENCE_OBJECT_KEYS_MAX) return INVALID_JSON;
  const output: SafeJsonObject = {};
  for (const [key, item] of entries) {
    if (!key || key.length > 100 || /[\u0000-\u001f]/.test(key) || FORBIDDEN_EVIDENCE_KEYS.has(key)) return INVALID_JSON;
    const cloned = cloneSafeJson(item, state, depth + 1);
    if (cloned === INVALID_JSON) return INVALID_JSON;
    output[key] = cloned;
  }
  return output;
}

function cloneEvidenceObject(value: unknown): SafeJsonObject | null {
  if (!isRecord(value)) return null;
  const cloned = cloneSafeJson(value, { nodes: 0 });
  return cloned !== INVALID_JSON && isRecord(cloned) ? cloned as SafeJsonObject : null;
}

function cloneNullableEvidenceObject(value: unknown): SafeJsonObject | null | undefined {
  if (value === null) return null;
  return cloneEvidenceObject(value) || undefined;
}

function decodeEvidenceIntegrity(value: unknown): SafeJsonObject | null {
  if (!isRecord(value) || typeof value.ok !== 'boolean' || !safeInteger(value.count)) return null;
  if (value.ok === true) {
    if (Object.keys(value).some((key) => !['ok', 'count'].includes(key))) return null;
    return { ok: true, count: value.count as number };
  }
  if (typeof value.reason !== 'string' || !INTEGRITY_FAILURE_REASONS.has(value.reason)) return null;
  const brokenAt = value.brokenAt === undefined ? undefined : boundedString(value.brokenAt, 80);
  const queryId = value.queryId === undefined ? undefined : boundedString(value.queryId, 80);
  if (brokenAt === null || queryId === null) return null;
  return {
    ok: false,
    count: value.count as number,
    reason: value.reason,
    ...(brokenAt ? { brokenAt } : {}),
    ...(queryId ? { queryId } : {}),
  };
}

function decodeEvidenceScope(value: unknown, schemaVersion: 2 | 3): SafeJsonObject | null {
  if (!isRecord(value)) return null;
  const allowed = new Set([
    'queryLimit', 'auditLimit', 'summaryRowsIncluded', 'summariesUseFullHistory', 'rawPromptBodiesIncluded',
    'auditDetailsIncluded', 'backupEvidenceIncluded', 'restoreDrillEvidenceIncluded', 'examinerProfile',
  ]);
  if (!hasOnlyKeys(value, allowed)) return null;
  if (!safeInteger(value.queryLimit, EVIDENCE_ARRAY_MAX) || Number(value.queryLimit) < 1) return null;
  if (!safeInteger(value.auditLimit, EVIDENCE_ARRAY_MAX) || Number(value.auditLimit) < 1) return null;
  if (!safeInteger(value.summaryRowsIncluded) || typeof value.summariesUseFullHistory !== 'boolean') return null;
  if (value.rawPromptBodiesIncluded !== false || value.auditDetailsIncluded !== false) return null;
  if (typeof value.backupEvidenceIncluded !== 'boolean' || typeof value.restoreDrillEvidenceIncluded !== 'boolean') return null;
  if (schemaVersion === 3 && value.examinerProfile !== FCU_EXAMINER_PROFILE) return null;
  if (schemaVersion === 2 && value.examinerProfile !== undefined) return null;
  return {
    queryLimit: value.queryLimit as number,
    auditLimit: value.auditLimit as number,
    summaryRowsIncluded: value.summaryRowsIncluded as number,
    summariesUseFullHistory: value.summariesUseFullHistory,
    rawPromptBodiesIncluded: false,
    auditDetailsIncluded: false,
    backupEvidenceIncluded: value.backupEvidenceIncluded,
    restoreDrillEvidenceIncluded: value.restoreDrillEvidenceIncluded,
    ...(schemaVersion === 3 ? { examinerProfile: FCU_EXAMINER_PROFILE } : {}),
  };
}

function decodeEvidenceService(value: unknown): SafeJsonObject | null {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['name', 'version']))) return null;
  if (value.name !== 'RedactWall' || !boundedTextValue(value.version, 80)) return null;
  return { name: 'RedactWall', version: value.version as string };
}

function decodeEvidenceReport(value: unknown, generatedAt: string): SafeJsonObject | null {
  if (!isRecord(value)) return null;
  const allowed = new Set(['id', 'generatedAt', 'generatedBy', 'periodStart', 'periodEnd', 'scheduled', 'schedule']);
  if (!hasOnlyKeys(value, allowed) || !boundedTextValue(value.id, 120) || value.generatedAt !== generatedAt) return null;
  if (!boundedTextValue(value.generatedBy, 80) || typeof value.scheduled !== 'boolean') return null;
  for (const field of ['periodStart', 'periodEnd'] as const) {
    if (value[field] !== null && !validTimestamp(value[field])) return null;
  }
  const schedule = cloneNullableEvidenceObject(value.schedule);
  if (schedule === undefined) return null;
  return {
    id: value.id as string,
    generatedAt,
    generatedBy: value.generatedBy as string,
    periodStart: value.periodStart as string | null,
    periodEnd: value.periodEnd as string | null,
    scheduled: value.scheduled,
    schedule,
  };
}

function decodeEvidenceStats(value: unknown): SafeJsonObject | null {
  if (!isRecord(value)) return null;
  const countKeys = ['total', 'pending', 'held', 'approved', 'denied', 'allowed', 'todayBlocked'] as const;
  const allowed = new Set<string>([...countKeys, 'topEntities']);
  if (!hasOnlyKeys(value, allowed) || countKeys.some((key) => !safeInteger(value[key]))) return null;
  if (!Array.isArray(value.topEntities) || value.topEntities.length > 8) return null;
  const topEntities: SafeJson[] = [];
  for (const item of value.topEntities) {
    if (!Array.isArray(item) || item.length !== 2 || !boundedTextValue(item[0], 80) || !safeInteger(item[1])) return null;
    topEntities.push([item[0] as string, item[1] as number]);
  }
  return Object.fromEntries([...countKeys.map((key) => [key, value[key] as number]), ['topEntities', topEntities]]);
}

function validStringArray(value: unknown, maximumItems: number, maximumText: number, allowEmpty = true): value is string[] {
  return Array.isArray(value)
    && (allowEmpty || value.length > 0)
    && value.length <= maximumItems
    && value.every((item) => boundedTextValue(item, maximumText));
}

function validOptionalTimestamp(value: unknown): boolean {
  return value === null || validTimestamp(value);
}

function validEvidenceSensor(value: unknown): boolean {
  if (value === null) return true;
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['name', 'version', 'packageVersion', 'platform']))) return false;
  return Object.values(value).every((item) => boundedTextValue(item, 80));
}

function validEvidenceFindings(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > 100) return false;
  return value.every((item) => isRecord(item)
    && hasOnlyKeys(item, new Set(['type', 'severity', 'score', 'masked']))
    && boundedTextValue(item.type, 80)
    && typeof item.severity === 'number' && Number.isFinite(item.severity)
    && typeof item.score === 'number' && Number.isFinite(item.score)
    && boundedTextValue(item.masked, 240));
}

function validEvidenceCounts(value: unknown): boolean {
  if (!isRecord(value) || Object.keys(value).length > 100) return false;
  return Object.entries(value).every(([key, count]) => key.length > 0 && key.length <= 80 && safeInteger(count));
}

function validEvidenceWorkflow(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const strings = ['assignedRole', 'assignedGroup', 'workflowReason', 'escalationReason', 'notificationStatus'] as const;
  const timestamps = ['slaDueAt', 'escalatedAt', 'notificationLastAttemptAt'] as const;
  if (!strings.every((key) => boundedTextValue(value[key], 240, true))) return false;
  if (!timestamps.every((key) => validOptionalTimestamp(value[key]))) return false;
  return safeInteger(value.notificationAttemptCount) && validStringArray(value.notificationChannels, 8, 120);
}

function validEvidenceInstallChecks(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > 80) return false;
  return value.every((item) => isRecord(item)
    && hasOnlyKeys(item, new Set(['id', 'ok', 'detail']))
    && boundedTextValue(item.id, 80)
    && typeof item.ok === 'boolean'
    && (item.detail === undefined || boundedTextValue(item.detail, 160)));
}

function decodeEvidenceQuery(value: unknown): SafeJsonObject | null {
  if (!isRecord(value) || !hasOnlyKeys(value, EVIDENCE_QUERY_KEYS)) return null;
  const requiredText = ['id', 'status', 'user', 'source', 'channel', 'destination', 'accountType', 'maxSeverityLabel'] as const;
  const nullableText = ['mode', 'orgId', 'originApp', 'decidedBy', 'policyExceptionId'] as const;
  if (!validTimestamp(value.createdAt) || !requiredText.every((key) => boundedTextValue(value[key], 320))) return null;
  if (!nullableText.every((key) => boundedTextValue(value[key], 320, true))) return null;
  if (!validEvidenceSensor(value.sensor) || !validEvidenceFindings(value.findings) || !validEvidenceCounts(value.entityCounts)) return null;
  if (!validStringArray(value.categories, 40, 80) || !validStringArray(value.reasons, 20, 200)) return null;
  if (!boundedTextValue(value.promptHash, 64) || !HASH64.test(value.promptHash as string)) return null;
  if (typeof value.riskScore !== 'number' || !Number.isFinite(value.riskScore)) return null;
  if (typeof value.maxSeverity !== 'number' || !Number.isFinite(value.maxSeverity)) return null;
  if (!validOptionalTimestamp(value.decidedAt) || !validOptionalTimestamp(value.retentionPurgedAt)) return null;
  if (!validStringArray(value.retentionPurgedFields, 2, 32) || !validEvidenceInstallChecks(value.installChecks)) return null;
  if (!validStringArray(value.policyScopeIds, 20, 80) || !validEvidenceWorkflow(value.workflow)) return null;
  return cloneEvidenceObject(value);
}

function decodeEvidenceQueries(value: unknown, maximum: number): SafeJson[] | null {
  if (!Array.isArray(value) || value.length > maximum) return null;
  const rows = value.map(decodeEvidenceQuery);
  return rows.every((row): row is SafeJsonObject => row !== null) ? rows : null;
}

function validPolicyChange(value: unknown): boolean {
  if (!isRecord(value) || !hasOnlyKeys(value, new Set(['templateId', 'reason', 'changed']))) return false;
  if (value.templateId !== undefined && !boundedTextValue(value.templateId, 120)) return false;
  if (value.reason !== undefined && !boundedTextValue(value.reason, 240)) return false;
  if (!Array.isArray(value.changed) || value.changed.length > 80) return false;
  return value.changed.every((item) => isRecord(item)
    && hasOnlyKeys(item, new Set(['field', 'before', 'after']))
    && boundedTextValue(item.field, 120)
    && cloneSafeJson(item.before, { nodes: 0 }) !== INVALID_JSON
    && cloneSafeJson(item.after, { nodes: 0 }) !== INVALID_JSON);
}

function decodeEvidenceAuditEntry(value: unknown): SafeJsonObject | null {
  if (!isRecord(value) || !hasOnlyKeys(value, EVIDENCE_AUDIT_KEYS)) return null;
  if (!boundedTextValue(value.id, 80) || !validTimestamp(value.ts) || !boundedTextValue(value.action, 160)) return null;
  if (!boundedTextValue(value.queryId, 80, true) || !boundedTextValue(value.actor, 320, true)) return null;
  for (const key of ['prevHash', 'hash', 'detailHash'] as const) {
    if (!boundedTextValue(value[key], 64) || !HASH64.test(value[key] as string)) return null;
  }
  if (value.policyChange !== undefined && !validPolicyChange(value.policyChange)) return null;
  return cloneEvidenceObject(value);
}

function decodeEvidenceAudit(value: unknown, maximum: number): SafeJson[] | null {
  if (!Array.isArray(value) || value.length > maximum) return null;
  const rows = value.map(decodeEvidenceAuditEntry);
  return rows.every((row): row is SafeJsonObject => row !== null) ? rows : null;
}

function decodeControlMappings(value: unknown): SafeJson[] | null {
  if (!Array.isArray(value) || !value.length || value.length > 100) return null;
  const keys = new Set(['id', 'title', 'state', 'controlFamilies', 'evidence', 'summary', 'lastVerifiedAt']);
  const rows = value.map((item) => {
    if (!isRecord(item) || !hasOnlyKeys(item, keys)) return null;
    if (!boundedTextValue(item.id, 80) || !boundedTextValue(item.title, 180) || !boundedTextValue(item.summary, 1_200)) return null;
    if (!['covered', 'attention', 'not_provided'].includes(String(item.state))) return null;
    if (!validStringArray(item.controlFamilies, 24, 240, false) || !validStringArray(item.evidence, 24, 240, false)) return null;
    if (!validOptionalTimestamp(item.lastVerifiedAt)) return null;
    return cloneEvidenceObject(item);
  });
  return rows.every((row): row is SafeJsonObject => row !== null) ? rows : null;
}

function decodeLineage(value: unknown): SafeJsonObject | null {
  if (!isRecord(value)) return null;
  const expected = ['byUser', 'byDestination', 'bySensor', 'byChannel', 'byCategory', 'byDecision', 'byAccountType', 'byOriginApp'];
  if (!hasOnlyKeys(value, new Set(expected))) return null;
  for (const key of expected) {
    if (!Array.isArray(value[key]) || (value[key] as unknown[]).length > 25) return null;
  }
  return cloneEvidenceObject(value);
}

function decodeGenericArray(value: unknown, maximum: number): SafeJson[] | null {
  if (!Array.isArray(value) || value.length > maximum) return null;
  const cloned = cloneSafeJson(value, { nodes: 0 });
  return cloned !== INVALID_JSON && Array.isArray(cloned) ? cloned : null;
}

function decodeExaminerSections(body: Record<string, unknown>, generatedAt: string): SafeJsonObject | null {
  if (!boundedTextValue(body.complianceDisclaimer, 1_200)) return null;
  const controlTests = cloneEvidenceObject(body.controlTests);
  const aupCrosswalk = decodeGenericArray(body.aupCrosswalk, 100);
  const aupAttestation = cloneNullableEvidenceObject(body.aupAttestation);
  const ncua = cloneEvidenceObject(body.ncuaReadiness);
  const useCases = cloneEvidenceObject(body.useCases);
  const incidents = cloneEvidenceObject(body.incidents);
  if (!controlTests || !aupCrosswalk || aupAttestation === undefined || !ncua || !useCases || !incidents) return null;
  if (ncua.profile !== FCU_EXAMINER_PROFILE || ncua.generatedAt !== generatedAt) return null;
  if (controlTests.generatedAt !== generatedAt) return null;
  return {
    complianceDisclaimer: body.complianceDisclaimer as string,
    controlTests,
    aupCrosswalk,
    aupAttestation,
    ncuaReadiness: ncua,
    useCases,
    incidents,
  };
}

function decodeEvidencePack(value: unknown): SafeJsonObject | null {
  if (!isRecord(value) || !hasOnlyKeys(value, EVIDENCE_TOP_LEVEL_KEYS)) return null;
  if (value.schemaVersion !== 2 && value.schemaVersion !== 3) return null;
  const schemaVersion = value.schemaVersion;
  if (!validTimestamp(value.generatedAt)) return null;
  const generatedAt = value.generatedAt;
  const service = decodeEvidenceService(value.service);
  const scope = decodeEvidenceScope(value.scope, schemaVersion);
  const report = decodeEvidenceReport(value.report, generatedAt);
  const stats = decodeEvidenceStats(value.stats);
  const auditIntegrity = decodeEvidenceIntegrity(value.auditIntegrity);
  if (!service || !scope || !report || !stats || !auditIntegrity) return null;
  const queries = decodeEvidenceQueries(value.queries, Number(scope.queryLimit));
  const audit = decodeEvidenceAudit(value.audit, Number(scope.auditLimit));
  const controlMappings = decodeControlMappings(value.controlMappings);
  const lineage = decodeLineage(value.lineage);
  if (!queries || !audit || !controlMappings || !lineage) return null;
  if (Number(stats.total) < queries.length || Number(auditIntegrity.count) < audit.length) return null;
  if (Number(scope.summaryRowsIncluded) < queries.length) return null;
  if (scope.summariesUseFullHistory === true && scope.summaryRowsIncluded !== stats.total) return null;
  return assembleEvidencePack(value, { schemaVersion, generatedAt, service, scope, report, stats, auditIntegrity, queries, audit, controlMappings, lineage });
}

function assembleEvidencePack(
  body: Record<string, unknown>,
  core: SafeJsonObject & { schemaVersion: 2 | 3; generatedAt: string },
): SafeJsonObject | null {
  const requiredObjects = ['policy', 'coverage', 'posture', 'detectorFeedback', 'policyExceptionReview'] as const;
  const decodedObjects = Object.fromEntries(requiredObjects.map((key) => [key, cloneEvidenceObject(body[key])])) as Record<string, SafeJsonObject | null>;
  if (requiredObjects.some((key) => !decodedObjects[key])) return null;
  const backup = cloneNullableEvidenceObject(body.backup);
  const restoreDrill = cloneNullableEvidenceObject(body.restoreDrill);
  const edm = cloneNullableEvidenceObject(body.edm);
  const detectors = decodeGenericArray(body.detectors, 1_000);
  if (backup === undefined || restoreDrill === undefined || edm === undefined || !detectors) return null;
  const examiner = core.schemaVersion === 3 ? decodeExaminerSections(body, core.generatedAt) : null;
  if (core.schemaVersion === 3 && !examiner) return null;
  const v3Keys = ['complianceDisclaimer', 'controlTests', 'aupCrosswalk', 'aupAttestation', 'ncuaReadiness', 'useCases', 'incidents'];
  if (core.schemaVersion === 2 && v3Keys.some((key) => body[key] !== undefined)) return null;
  return {
    ...core,
    ...decodedObjects,
    backup,
    restoreDrill,
    edm,
    detectors,
    ...(examiner || {}),
  };
}

function downloadJson(payload: unknown, name: string): void {
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/** Downloads the evidence pack as a JSON file. Resolves to a toast-safe error message, or null on success. */
export async function exportEvidencePack(examinerProfile?: EvidenceProfile): Promise<string | null> {
  const profileQuery = examinerProfile ? `&examinerProfile=${encodeURIComponent(examinerProfile)}` : '';
  const res = await api(`/api/export/evidence?queryLimit=1000&auditLimit=1000${profileQuery}`);
  if (!res || !res.ok) return apiErrorSummary(res, 'Evidence export failed');
  const declaredBytes = Number(res.headers.get('content-length'));
  if (Number.isFinite(declaredBytes) && declaredBytes > EVIDENCE_EXPORT_RESPONSE_MAX_BYTES) {
    cancelResponseBody(res);
    return 'Evidence export failed: response exceeded the safe download limit';
  }
  let pack: unknown;
  try {
    pack = await responseJsonBounded<unknown>(res, EVIDENCE_EXPORT_RESPONSE_MAX_BYTES);
    if (pack === null) return 'Evidence export failed: response was malformed, incomplete, or oversized';
  } catch {
    return 'Evidence export failed: response was malformed, incomplete, or oversized';
  }
  const decodedPack = decodeEvidencePack(pack);
  if (!decodedPack) return 'Evidence export failed: response was malformed or incomplete';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  downloadJson(decodedPack, `redactwall-evidence-${stamp}.json`);
  return null;
}
