import { api, apiErrorSummary, apiJson } from '../lib/api';

/**
 * Approval-queue API. Route contract from server/app.js:
 *   GET  /api/queries?status=&limit=          -> publicQuery[] (raw prompt stripped, rawRetained flag added)
 *   POST /api/queries/:id/approve             -> body {note, password}; password step-up (401 invalid, 429 locked)
 *   POST /api/queries/:id/deny                -> body {note}
 *   POST /api/queries/bulk-decision           -> body {ids<=50, action, note, password? for approve}
 *   POST /api/queries/:id/reveal              -> body {password}; Security Admin step-up
 * Decisions return 409 {error:"already <status>"} when the item is no longer pending.
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

export interface QueueQuery {
  id: string;
  createdAt?: string;
  status: string;
  user?: string;
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
}

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

export function fetchQueue(status: string): Promise<QueueQuery[] | null> {
  const filter = status && status !== 'all' ? `status=${encodeURIComponent(status)}&` : '';
  return apiJson<QueueQuery[]>(`/api/queries?${filter}limit=200`);
}

/** A step-up 401 means a wrong password, not an expired session - unless the server says so. */
async function stepUpFailureMessage(res: Response): Promise<string> {
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (body.error === 'unauthenticated') {
    location.href = '/login.html';
    return 'Session expired.';
  }
  return 'Password confirmation failed.';
}

async function decisionPost<T>(path: string, body: unknown, fallback: string, stepUp: boolean): Promise<DecisionResult<T>> {
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
    return { data: (await res.json()) as T, error: null };
  } catch {
    return { data: null, error: fallback };
  }
}

export function approveQuery(id: string, note: string, password: string): Promise<DecisionResult<QueueQuery>> {
  return decisionPost(`/api/queries/${encodeURIComponent(id)}/approve`, { note, password }, 'Approve failed', true);
}

export function denyQuery(id: string, note: string): Promise<DecisionResult<QueueQuery>> {
  return decisionPost(`/api/queries/${encodeURIComponent(id)}/deny`, { note }, 'Deny failed', false);
}

export function bulkDecision(
  ids: string[],
  action: 'approve' | 'deny',
  note: string,
  password?: string,
): Promise<DecisionResult<BulkDecisionResult>> {
  const body = { ids, action, note, ...(password ? { password } : {}) };
  return decisionPost('/api/queries/bulk-decision', body, 'Bulk decision failed', action === 'approve');
}

export function revealQuery(id: string, password: string): Promise<DecisionResult<RevealResult>> {
  return decisionPost(`/api/queries/${encodeURIComponent(id)}/reveal`, { password }, 'Reveal failed', true);
}
