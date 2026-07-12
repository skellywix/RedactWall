import { api, apiErrorSummary, responseJsonBounded } from '../lib/api';

/**
 * Approval-queue API. Route contract from server/app.js:
 *   GET  /api/queries?status=&limit=          -> publicQuery[] (raw prompt stripped, rawRetained flag added)
 *   POST /api/queries/:id/approve             -> body {note, password}; password step-up (401 invalid, 429 locked)
 *   POST /api/queries/:id/deny                -> body {note}
 *   POST /api/queries/bulk-decision           -> body {ids<=50, action, note, password? for approve}
 *   POST /api/queries/:id/reveal              -> body {password}; Security Admin step-up
 * Decisions return 409 {error:"already <status>"} when the item is no longer held.
 */

export interface QueryFinding {
  type: string;
  masked?: string;
  severity?: number;
  score?: number;
  confidence?: string;
  /** Vendor attribution for SECRET_KEY findings, e.g. "stripe" / "Stripe secret key (live)". */
  vendor?: string;
  vendorLabel?: string;
}

export interface ScoreBreakdownEntry {
  kind?: string;
  type: string;
  severity?: number;
  severityLabel?: string;
  confidence?: string;
  points?: number;
  regulations?: string[];
}

export interface QueueQuery {
  id: string;
  createdAt: string;
  status: string;
  user?: string;
  actor?: string;
  action?: string;
  destination?: string;
  source?: string;
  channel?: string;
  redactedPrompt?: string;
  findings?: QueryFinding[];
  categories?: string[];
  entityCounts?: Record<string, number>;
  reasons?: string[];
  riskScore?: number;
  maxSeverity?: number;
  maxSeverityLabel?: string;
  rawRetained?: boolean;
  assignedRole?: string;
  assignedUser?: string;
  assignedGroup?: string;
  decidedBy?: string;
  decidedAt?: string;
  decisionNote?: string;
  workflowReason?: string;
  escalationReason?: string;
  notificationStatus?: string;
  notificationChannels?: string[];
  scoreBreakdown?: ScoreBreakdownEntry[];
}

export const HELD_QUERY_FILTER = 'held';
export const HELD_QUERY_STATUSES = ['pending', 'pending_justification'] as const;

const HELD_QUERY_STATUS_SET = new Set<string>(HELD_QUERY_STATUSES);

/** Mirrors server/app.js HELD_RELEASE_STATUSES without widening server authority. */
export function isHeldQueryStatus(status?: string): boolean {
  return HELD_QUERY_STATUS_SET.has(String(status || ''));
}

export type QueueFetchFailure = 'forbidden' | 'unavailable';

export type QueueFetchResult =
  | { ok: true; rows: QueueQuery[] }
  | { ok: false; reason: QueueFetchFailure };

export interface RevealResult {
  id: string;
  rawPrompt: string;
  rawRetained: boolean;
  rawDiffersFromRedacted: boolean;
}

export interface BulkOutcome {
  id: string;
  outcome: string;
  reason?: string;
}

export interface BulkDecisionResult {
  results: BulkOutcome[];
  decided: number;
  skipped: number;
}

/** Mutation outcome: exactly one of data/error is set. Error text is safe to toast. */
export interface DecisionResult<T> {
  data: T | null;
  error: string | null;
}

export const BULK_DECISION_LIMIT = 50;
const QUEUE_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const PUBLIC_QUERY_MAX_ROWS = 200;
const RAW_PROMPT_MAX_CHARS = 200_000;
const INVALID_FIELD = Symbol('invalid-public-query-field');
const DETECTOR_ID = /^[A-Z0-9_]+$/;
const BULK_SKIP_REASON = /^(?:not found|not yours to decide|query changed; reload and retry|already [a-z_]{1,80})$/;

type InvalidField = typeof INVALID_FIELD;
type PublicQueryRecord = Record<string, unknown>;

const OPTIONAL_STRING_FIELDS = [
  ['user', 512], ['actor', 512], ['action', 80], ['destination', 512], ['source', 80], ['channel', 80],
  ['redactedPrompt', 200_000], ['maxSeverityLabel', 32], ['assignedRole', 32], ['assignedUser', 128],
  ['assignedGroup', 64], ['decidedBy', 512], ['decisionNote', 2_000], ['workflowReason', 240],
  ['escalationReason', 240], ['notificationStatus', 80],
] as const;

function recordValue(value: unknown): PublicQueryRecord | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as PublicQueryRecord : null;
}

function requiredString(row: PublicQueryRecord, key: string, max: number): string | null {
  const value = row[key];
  return typeof value === 'string' && value.trim().length > 0 && value.length <= max ? value : null;
}

function optionalString(row: PublicQueryRecord, key: string, max: number): string | undefined | InvalidField {
  const value = row[key];
  if (value === undefined || value === null) return undefined;
  return typeof value === 'string' && value.length <= max ? value : INVALID_FIELD;
}

function validTimestamp(value: string): boolean {
  return value.length <= 64 && Number.isFinite(Date.parse(value));
}

function optionalNumber(row: PublicQueryRecord, key: string, min: number, max: number): number | undefined | InvalidField {
  const value = row[key];
  if (value === undefined || value === null) return undefined;
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max ? value : INVALID_FIELD;
}

function optionalBoolean(row: PublicQueryRecord, key: string): boolean | undefined | InvalidField {
  const value = row[key];
  if (value === undefined || value === null) return undefined;
  return typeof value === 'boolean' ? value : INVALID_FIELD;
}

function stringArray(value: unknown, maxItems: number, maxChars: number): string[] | undefined | InvalidField {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.length > maxItems) return INVALID_FIELD;
  return value.every((item) => typeof item === 'string' && item.length <= maxChars) ? [...value] : INVALID_FIELD;
}

function decodeFinding(value: unknown): QueryFinding | null {
  const row = recordValue(value);
  if (!row) return null;
  const type = requiredString(row, 'type', 80);
  if (!type || !DETECTOR_ID.test(type)) return null;
  const result: QueryFinding = { type };
  for (const [key, max] of [['masked', 256], ['confidence', 80], ['vendor', 80], ['vendorLabel', 80]] as const) {
    const field = optionalString(row, key, max);
    if (field === INVALID_FIELD) return null;
    if (field !== undefined) result[key] = field;
  }
  const severity = optionalNumber(row, 'severity', 0, 4);
  const score = optionalNumber(row, 'score', 0, 1);
  if (severity === INVALID_FIELD || score === INVALID_FIELD) return null;
  if (severity !== undefined) result.severity = severity;
  if (score !== undefined) result.score = score;
  return result;
}

function decodeFindings(value: unknown): QueryFinding[] | undefined | InvalidField {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.length > 250) return INVALID_FIELD;
  const findings = value.map(decodeFinding);
  return findings.every((finding): finding is QueryFinding => finding !== null) ? findings : INVALID_FIELD;
}

function decodeBreakdownEntry(value: unknown): ScoreBreakdownEntry | null {
  const row = recordValue(value);
  if (!row) return null;
  const type = requiredString(row, 'type', 80);
  if (!type || !DETECTOR_ID.test(type)) return null;
  const result: ScoreBreakdownEntry = { type };
  for (const [key, max] of [['kind', 32], ['severityLabel', 32], ['confidence', 80]] as const) {
    const field = optionalString(row, key, max);
    if (field === INVALID_FIELD || (key === 'kind' && field !== undefined && !['finding', 'category'].includes(field))) return null;
    if (field !== undefined) result[key] = field;
  }
  const severity = optionalNumber(row, 'severity', 0, 4);
  const points = optionalNumber(row, 'points', 0, 100);
  const regulations = stringArray(row.regulations, 32, 80);
  if (severity === INVALID_FIELD || points === INVALID_FIELD || regulations === INVALID_FIELD) return null;
  if (severity !== undefined) result.severity = severity;
  if (points !== undefined) result.points = points;
  if (regulations !== undefined) result.regulations = regulations;
  return result;
}

function decodeBreakdown(value: unknown): ScoreBreakdownEntry[] | undefined | InvalidField {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.length > 500) return INVALID_FIELD;
  const entries = value.map(decodeBreakdownEntry);
  return entries.every((entry): entry is ScoreBreakdownEntry => entry !== null) ? entries : INVALID_FIELD;
}

function decodeEntityCounts(value: unknown): Record<string, number> | undefined | InvalidField {
  if (value === undefined || value === null) return undefined;
  const row = recordValue(value);
  if (!row || Object.keys(row).length > 500) return INVALID_FIELD;
  const counts: Record<string, number> = {};
  for (const [key, count] of Object.entries(row)) {
    if (!DETECTOR_ID.test(key) || key.length > 80 || !Number.isInteger(count) || (count as number) < 0 || (count as number) > 100_000) {
      return INVALID_FIELD;
    }
    counts[key] = count as number;
  }
  return counts;
}

function copyOptionalStrings(source: PublicQueryRecord, target: PublicQueryRecord): boolean {
  for (const [key, max] of OPTIONAL_STRING_FIELDS) {
    const field = optionalString(source, key, max);
    if (field === INVALID_FIELD) return false;
    if (field !== undefined) target[key] = field;
  }
  return true;
}

function copyOptionalCollections(source: PublicQueryRecord, target: PublicQueryRecord): boolean {
  const fields = {
    findings: decodeFindings(source.findings),
    categories: stringArray(source.categories, 250, 80),
    reasons: stringArray(source.reasons, 40, 240),
    notificationChannels: stringArray(source.notificationChannels, 8, 80),
    scoreBreakdown: decodeBreakdown(source.scoreBreakdown),
    entityCounts: decodeEntityCounts(source.entityCounts),
  };
  if (Object.values(fields).some((value) => value === INVALID_FIELD)) return false;
  for (const [key, value] of Object.entries(fields)) if (value !== undefined) target[key] = value;
  return true;
}

/** Strictly decodes the sanitized subset of a server publicQuery row rendered by the console. */
export function decodePublicQuery(value: unknown): QueueQuery | null {
  const source = recordValue(value);
  if (!source) return null;
  const id = requiredString(source, 'id', 128);
  const status = requiredString(source, 'status', 80);
  const createdAt = requiredString(source, 'createdAt', 64);
  if (!id || !status || !createdAt || !validTimestamp(createdAt)) return null;
  const target: PublicQueryRecord = { id, status, createdAt };
  if (!copyOptionalStrings(source, target) || !copyOptionalCollections(source, target)) return null;
  for (const [key, min, max] of [['riskScore', 0, 100], ['maxSeverity', 0, 4]] as const) {
    const field = optionalNumber(source, key, min, max);
    if (field === INVALID_FIELD) return null;
    if (field !== undefined) target[key] = field;
  }
  const rawRetained = optionalBoolean(source, 'rawRetained');
  if (rawRetained === INVALID_FIELD) return null;
  if (rawRetained !== undefined) target.rawRetained = rawRetained;
  const decidedAt = optionalString(source, 'decidedAt', 64);
  if (decidedAt === INVALID_FIELD || (decidedAt !== undefined && !validTimestamp(decidedAt))) return null;
  if (decidedAt !== undefined) target.decidedAt = decidedAt;
  return target as unknown as QueueQuery;
}

/** A snapshot is trustworthy only when every row is valid and every identity is unique. */
export function decodePublicQuerySnapshot(value: unknown): QueueQuery[] | null {
  if (!Array.isArray(value) || value.length > PUBLIC_QUERY_MAX_ROWS) return null;
  const rows = value.map(decodePublicQuery);
  if (!rows.every((row): row is QueueQuery => row !== null)) return null;
  return new Set(rows.map((row) => row.id)).size === rows.length ? rows : null;
}

async function fetchExactQueueResult(status: string): Promise<QueueFetchResult> {
  const filter = status && status !== 'all' ? `status=${encodeURIComponent(status)}&` : '';
  const res = await api(`/api/queries?${filter}limit=200`);
  if (!res) return { ok: false, reason: 'unavailable' };
  if (res.status === 403) return { ok: false, reason: 'forbidden' };
  if (!res.ok) return { ok: false, reason: 'unavailable' };
  try {
    const rows = decodePublicQuerySnapshot(await responseJsonBounded<unknown>(res, QUEUE_RESPONSE_MAX_BYTES));
    return rows ? { ok: true, rows } : { ok: false, reason: 'unavailable' };
  } catch {
    return { ok: false, reason: 'unavailable' };
  }
}

function combineQueueRows(groups: QueueQuery[][]): QueueQuery[] | null {
  const rows = new Map<string, QueueQuery>();
  for (const group of groups) {
    for (const row of group) {
      if (rows.has(row.id)) return null;
      rows.set(row.id, row);
    }
  }
  return [...rows.values()];
}

export async function fetchQueueResult(status: string): Promise<QueueFetchResult> {
  if (status !== HELD_QUERY_FILTER) return fetchExactQueueResult(status);
  const results = await Promise.all(HELD_QUERY_STATUSES.map((heldStatus) => fetchExactQueueResult(heldStatus)));
  const failures = results.filter((result): result is Extract<QueueFetchResult, { ok: false }> => !result.ok);
  if (failures.length) {
    return { ok: false, reason: failures.some((failure) => failure.reason === 'forbidden') ? 'forbidden' : 'unavailable' };
  }
  const rows = combineQueueRows(results.map((result) => (result.ok ? result.rows : [])));
  if (!rows) return { ok: false, reason: 'unavailable' };
  return {
    ok: true,
    rows,
  };
}

/** Legacy nullable helper retained for views that do not yet render failure detail. */
export async function fetchQueue(status: string): Promise<QueueQuery[] | null> {
  const result = await fetchQueueResult(status);
  return result.ok ? result.rows : null;
}

/** A step-up 401 means a wrong password, not an expired session - unless the server says so. */
async function stepUpFailureMessage(res: Response): Promise<string> {
  const body = await responseJsonBounded<{ error?: string }>(res) || {};
  if (body.error === 'unauthenticated') {
    location.href = '/login.html';
    return 'Session expired.';
  }
  return 'Password confirmation failed.';
}

type MutationDecoder<T> = (value: unknown) => T | null;

function decodedMutationQuery(value: unknown, id: string): QueueQuery | null {
  const query = decodePublicQuery(value);
  return query && query.id === id && typeof query.rawRetained === 'boolean' ? query : null;
}

/** A single decision is complete only when the server returns this query in the requested final state. */
export function decodeDecisionQuery(value: unknown, id: string, status: 'approved' | 'denied'): QueueQuery | null {
  const query = decodedMutationQuery(value, id);
  return query && query.status === status && query.decidedBy && query.decidedAt ? query : null;
}

function normalizedAssignment(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.trim() || undefined;
}

/** Reassignment must echo the requested ownership fields on the same still-held query. */
export function decodeAssignmentQuery(value: unknown, id: string, patch: AssignmentPatch): QueueQuery | null {
  const query = decodedMutationQuery(value, id);
  if (!query || !isHeldQueryStatus(query.status)) return null;
  for (const key of ['assignedUser', 'assignedGroup', 'assignedRole'] as const) {
    if (patch[key] !== undefined && query[key] !== normalizedAssignment(patch[key])) return null;
  }
  return query;
}

/** Raw prompt text is exposed only after every reveal field and invariant validates. */
export function decodeRevealResult(value: unknown, id: string): RevealResult | null {
  const result = recordValue(value);
  if (!result || requiredString(result, 'id', 128) !== id) return null;
  const rawPrompt = result.rawPrompt;
  const rawRetained = result.rawRetained;
  const rawDiffersFromRedacted = result.rawDiffersFromRedacted;
  if (typeof rawPrompt !== 'string' || !rawPrompt.length || rawPrompt.length > RAW_PROMPT_MAX_CHARS) return null;
  if (typeof rawRetained !== 'boolean' || typeof rawDiffersFromRedacted !== 'boolean') return null;
  if (!rawRetained && rawDiffersFromRedacted) return null;
  return { id, rawPrompt, rawRetained, rawDiffersFromRedacted };
}

function decodeBulkOutcome(value: unknown, id: string, status: 'approved' | 'denied'): BulkOutcome | null {
  const outcome = recordValue(value);
  if (!outcome || outcome.id !== id || (outcome.outcome !== status && outcome.outcome !== 'skipped')) return null;
  if (outcome.outcome === 'skipped') {
    if (typeof outcome.reason !== 'string' || !BULK_SKIP_REASON.test(outcome.reason)) return null;
    return { id, outcome: 'skipped', reason: outcome.reason };
  }
  if (outcome.reason !== undefined && outcome.reason !== null) return null;
  return { id, outcome: status };
}

/** Bulk response order, identities, outcomes, and counts must match the submitted decision exactly. */
export function decodeBulkDecisionResult(
  value: unknown,
  ids: string[],
  status: 'approved' | 'denied',
): BulkDecisionResult | null {
  const body = recordValue(value);
  if (!body || !ids.length || ids.length > BULK_DECISION_LIMIT || new Set(ids).size !== ids.length) return null;
  if (!Array.isArray(body.results) || body.results.length !== ids.length) return null;
  const results = body.results.map((outcome, index) => decodeBulkOutcome(outcome, ids[index], status));
  if (!results.every((outcome): outcome is BulkOutcome => outcome !== null)) return null;
  const decided = results.filter((outcome) => outcome.outcome === status).length;
  const skipped = results.length - decided;
  if (body.decided !== decided || body.skipped !== skipped) return null;
  return { results, decided, skipped };
}

async function decisionPost<T>(
  path: string,
  body: unknown,
  fallback: string,
  stepUp: boolean,
  decode: MutationDecoder<T>,
): Promise<DecisionResult<T>> {
  const res = await api(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    allowAuthError: stepUp,
  });
  if (!res) return { data: null, error: fallback };
  if (stepUp && res.status === 401) return { data: null, error: await stepUpFailureMessage(res) };
  if (stepUp && res.status === 429) return { data: null, error: 'Too many confirmation attempts. Try again later.' };
  if (!res.ok) return { data: null, error: await apiErrorSummary(res, fallback) };
  try {
    const data = decode(await responseJsonBounded<unknown>(res, QUEUE_RESPONSE_MAX_BYTES));
    return data === null ? { data: null, error: fallback } : { data, error: null };
  } catch {
    return { data: null, error: fallback };
  }
}

export function approveQuery(id: string, note: string, password: string): Promise<DecisionResult<QueueQuery>> {
  return decisionPost(
    `/api/queries/${encodeURIComponent(id)}/approve`,
    { note, password },
    'Approve failed',
    true,
    (value) => decodeDecisionQuery(value, id, 'approved'),
  );
}

export function denyQuery(id: string, note: string): Promise<DecisionResult<QueueQuery>> {
  return decisionPost(
    `/api/queries/${encodeURIComponent(id)}/deny`,
    { note },
    'Deny failed',
    false,
    (value) => decodeDecisionQuery(value, id, 'denied'),
  );
}

export function bulkDecision(
  ids: string[],
  action: 'approve' | 'deny',
  note: string,
  password?: string,
): Promise<DecisionResult<BulkDecisionResult>> {
  const body = { ids, action, note, ...(password ? { password } : {}) };
  const status = action === 'approve' ? 'approved' : 'denied';
  return decisionPost(
    '/api/queries/bulk-decision',
    body,
    'Bulk decision failed',
    action === 'approve',
    (value) => decodeBulkDecisionResult(value, ids, status),
  );
}

export function revealQuery(id: string, password: string): Promise<DecisionResult<RevealResult>> {
  return decisionPost(
    `/api/queries/${encodeURIComponent(id)}/reveal`,
    { password },
    'Reveal failed',
    true,
    (value) => decodeRevealResult(value, id),
  );
}

/** Inline reassignment fields. Empty string clears a field; omit a field to leave it unchanged. */
export interface AssignmentPatch {
  assignedUser?: string;
  assignedGroup?: string;
  assignedRole?: string;
}

/** POST /api/queries/:id/assign (Security Admin) -> updated publicQuery. Metadata only; never prompt content. */
export function assignQuery(id: string, patch: AssignmentPatch): Promise<DecisionResult<QueueQuery>> {
  return decisionPost(
    `/api/queries/${encodeURIComponent(id)}/assign`,
    patch,
    'Reassign failed',
    false,
    (value) => decodeAssignmentQuery(value, id, patch),
  );
}

/**
 * Step-up probe for OIDC sessions. POST /api/auth/step-up returns:
 *   200 -> elevation already satisfied (auth_time within the window); proceed.
 *   409 {oidc:true} -> re-authenticate with the identity provider to refresh auth_time.
 * Local accounts never call this; they collect a password in the step-up modal.
 */
export type StepUpProbe = 'ok' | 'oidc' | 'error';

export async function probeStepUp(): Promise<StepUpProbe> {
  const res = await api('/api/auth/step-up', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
    allowAuthError: true,
  });
  if (!res) return 'error';
  if (res.ok) return 'ok';
  if (res.status === 409) {
    const body = await responseJsonBounded<{ oidc?: boolean }>(res) || {};
    if (body.oidc) return 'oidc';
  }
  return 'error';
}
