import { api, responseJsonBounded } from '../lib/api';

/**
 * GET /api/stats -> server/db.js stats(). `topEntities` is up to eight
 * [entityType, count] pairs sorted by count descending; entity types are
 * detector labels only, never prompt text. `todayBlocked` counts today's
 * queries whose status is in the server's blocked-status list (pending,
 * denied, destination/file/action/injection blocks, etc.). The SSE 'stats'
 * event broadcasts this exact object, so both paths normalize through
 * asStats().
 */
export interface Stats {
  total: number;
  /** Legacy exact approval-pending count. */
  pending: number;
  /** Combined approval and justification holds. Null on an older backend. */
  held: number | null;
  approved: number;
  denied: number;
  allowed: number;
  todayBlocked: number;
  topEntities: [string, number][];
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function asEntityPairs(value: unknown): [string, number][] | null {
  if (!Array.isArray(value)) return null;
  if (value.some((pair) => (
    !Array.isArray(pair)
    || pair.length < 2
    || typeof pair[0] !== 'string'
    || !isCount(pair[1])
  ))) return null;
  return value.map(([name, n]) => [name, n]);
}

/** Normalize an untrusted payload (fetch body or SSE event) into Stats. */
export function asStats(data: unknown): Stats | null {
  if (!data || typeof data !== 'object') return null;
  const raw = data as Record<string, unknown>;
  const required = ['total', 'pending', 'approved', 'denied', 'allowed', 'todayBlocked'];
  if (!required.every((key) => isCount(raw[key]))) return null;
  if (raw.held !== undefined && !isCount(raw.held)) return null;
  const topEntities = asEntityPairs(raw.topEntities);
  if (!topEntities) return null;
  return {
    total: count(raw.total),
    pending: count(raw.pending),
    held: raw.held === undefined ? null : count(raw.held),
    approved: count(raw.approved),
    denied: count(raw.denied),
    allowed: count(raw.allowed),
    todayBlocked: count(raw.todayBlocked),
    topEntities,
  };
}

export type StatsFetchResult =
  | { ok: true; stats: Stats }
  | { ok: false; reason: 'forbidden' | 'unavailable' };

export async function fetchStatsResult(): Promise<StatsFetchResult> {
  const res = await api('/api/stats');
  if (!res) return { ok: false, reason: 'unavailable' };
  if (res.status === 403) return { ok: false, reason: 'forbidden' };
  if (!res.ok) return { ok: false, reason: 'unavailable' };
  try {
    const stats = asStats(await responseJsonBounded<unknown>(res));
    return stats ? { ok: true, stats } : { ok: false, reason: 'unavailable' };
  } catch {
    return { ok: false, reason: 'unavailable' };
  }
}

export async function fetchStats(): Promise<Stats | null> {
  const result = await fetchStatsResult();
  return result.ok ? result.stats : null;
}
