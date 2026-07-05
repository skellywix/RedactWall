import { apiJson } from '../lib/api';

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
  pending: number;
  approved: number;
  denied: number;
  allowed: number;
  todayBlocked: number;
  topEntities: [string, number][];
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function asEntityPairs(value: unknown): [string, number][] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((pair): pair is [unknown, unknown] => Array.isArray(pair) && pair.length >= 2)
    .map(([name, n]) => [String(name), count(n)]);
}

/** Normalize an untrusted payload (fetch body or SSE event) into Stats. */
export function asStats(data: unknown): Stats | null {
  if (!data || typeof data !== 'object' || !('total' in data)) return null;
  const raw = data as Record<string, unknown>;
  return {
    total: count(raw.total),
    pending: count(raw.pending),
    approved: count(raw.approved),
    denied: count(raw.denied),
    allowed: count(raw.allowed),
    todayBlocked: count(raw.todayBlocked),
    topEntities: asEntityPairs(raw.topEntities),
  };
}

export async function fetchStats(): Promise<Stats | null> {
  return asStats(await apiJson<unknown>('/api/stats'));
}
