import { api, apiErrorSummary, apiJson } from '../lib/api';

/**
 * Audit-trail API. Route contract from server/app.js:
 *   GET /api/audit?limit=&queryId=  -> { entries, integrity, retention }
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
  retention: string;
}

export async function fetchAuditLog(limit = 500): Promise<AuditLog | null> {
  const body = await apiJson<AuditLog>(`/api/audit?limit=${limit}`);
  if (!body || !body.integrity || !Array.isArray(body.entries)) return null;
  return body;
}

/**
 * Item-level audit trail for one held/decided prompt (BLOCKED -> APPROVAL_ROUTED
 * -> REVEAL_RAW -> APPROVED ...). Uses the server's queryId filter; returns the
 * entries alone (integrity is a whole-chain property surfaced in the Audit view).
 * Returns null when the trail is unavailable or malformed - callers must not
 * present that as a verified-empty history.
 */
export async function fetchAuditForQuery(queryId: string, limit = 50): Promise<AuditEntry[] | null> {
  const body = await apiJson<AuditLog>(`/api/audit?queryId=${encodeURIComponent(queryId)}&limit=${limit}`);
  return body && Array.isArray(body.entries) ? body.entries : null;
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
export async function exportEvidencePack(): Promise<string | null> {
  const res = await api('/api/export/evidence?queryLimit=1000&auditLimit=1000');
  if (!res || !res.ok) return apiErrorSummary(res, 'Evidence export failed');
  let pack: unknown;
  try {
    pack = await res.json();
  } catch {
    return 'Evidence export failed';
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  downloadJson(pack, `redactwall-evidence-${stamp}.json`);
  return null;
}
