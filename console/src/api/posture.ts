import { api, apiJsonBounded, responseJsonBounded } from '../lib/api';
import { decodeLeakMapReport } from '../components/overview/leakMapTraffic';

const POSTURE_RESPONSE_MAX_BYTES = 8 * 1024 * 1024;

export interface DecisionQualityCard {
  label: string;
  score: number;
  detail: string;
  value: string;
  state: 'ready' | 'blocked' | 'watch' | string;
}

export interface DecisionQualityHotspot {
  label: string;
  kind: string;
  events: number;
  sensitive: number;
  detail?: string;
}

export interface DecisionQualitySummary {
  controlRate?: number;
  pendingReviews?: number;
  overrideWatch?: number;
}

export interface DecisionQualityReport {
  summary?: DecisionQualitySummary;
  cards?: DecisionQualityCard[];
  hotspots?: DecisionQualityHotspot[];
}

export interface LeakMapCategory {
  label: string;
  events: number;
}

/** Sanitized graph node: identity segment, control channel, or destination. */
export interface LeakMapNode {
  id: string;
  label: string;
  typeLabel?: string;
  state?: string;
  status: string;
  events: number;
  sensitive: number;
  controlled: number;
  blocked: number;
  redacted: number;
  coached: number;
  pending: number;
  shadow: number;
  uncontrolled: number;
  /** Policy-authorized continuation, not delivery confirmation. */
  continued?: number;
  /** Exact intersection: uncontrolled sensitive events authorized to continue. */
  uncontrolledContinued?: number;
  users?: number;
  controlRate: number;
  lastSeen?: string | null;
}

export interface LeakMapEdge extends LeakMapNode {
  from: string;
  to: string;
  via: string;
  viaLabel?: string;
  categories?: LeakMapCategory[];
}

export interface LeakMapSummary {
  segments: number;
  destinations: number;
  edges: number;
  shownEdges: number;
  events: number;
  sensitive: number;
  controlled: number;
  uncontrolled: number;
  continued?: number;
  uncontrolledContinued?: number;
  pending: number;
  shadow: number;
  controlRate: number;
  status?: string;
  privacy?: string;
}

export interface LeakMapReport {
  segments: LeakMapNode[];
  channels: LeakMapNode[];
  destinations: LeakMapNode[];
  edges: LeakMapEdge[];
  categories: LeakMapCategory[];
  summary: LeakMapSummary;
}

export interface PostureSurface {
  id: string;
  name?: string;
  status?: string;
  description?: string;
}

export interface PostureReport {
  decisionQuality?: DecisionQualityReport;
  leakMap?: LeakMapReport;
  surfaces?: PostureSurface[];
}

export type PostureFetchResult =
  | { ok: true; report: PostureReport }
  | { ok: false; reason: 'forbidden' | 'unavailable' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value: unknown, max: number): string | undefined | null {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !value || value.length > max || value !== value.trim()) return null;
  if (/[\u0000-\u001f\u007f]/.test(value)) return null;
  return value;
}

function decodeSurfaces(value: unknown): PostureSurface[] | undefined | null {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 64) return null;
  const statuses = new Set(['online', 'warning', 'error', 'idle', 'offline', 'loading']);
  const decoded: PostureSurface[] = [];
  const ids = new Set<string>();
  for (const item of value) {
    if (!isRecord(item)) return null;
    const id = boundedText(item.id, 120);
    const name = boundedText(item.name, 140);
    const status = boundedText(item.status, 16);
    const description = boundedText(item.description, 240);
    if (id === null || id === undefined || status === null || status === undefined || !statuses.has(status) || name === null || description === null || ids.has(id)) return null;
    ids.add(id);
    const surface: PostureSurface = { id, status };
    if (name !== undefined) surface.name = name;
    if (description !== undefined) surface.description = description;
    decoded.push(surface);
  }
  return decoded;
}

function decodeOverviewPosture(value: unknown): PostureReport | null {
  if (!isRecord(value)) return null;
  const leakMap = decodeLeakMapReport(value.leakMap);
  const surfaces = decodeSurfaces(value.surfaces);
  if (!leakMap || surfaces === null) return null;
  const report: PostureReport = { leakMap };
  if (surfaces !== undefined) report.surfaces = surfaces;
  return report;
}

/** Strict current-posture contract: malformed and non-ok responses are not empty evidence. */
export async function fetchPostureResult(limit = 5000): Promise<PostureFetchResult> {
  const res = await api(`/api/posture?limit=${limit}`);
  if (!res) return { ok: false, reason: 'unavailable' };
  if (res.status === 403) return { ok: false, reason: 'forbidden' };
  if (!res.ok) return { ok: false, reason: 'unavailable' };
  try {
    const report = await responseJsonBounded<unknown>(res, POSTURE_RESPONSE_MAX_BYTES);
    const decoded = decodeOverviewPosture(report);
    return decoded
      ? { ok: true, report: decoded }
      : { ok: false, reason: 'unavailable' };
  } catch {
    return { ok: false, reason: 'unavailable' };
  }
}

export function fetchPosture(limit = 5000): Promise<PostureReport | null> {
  return apiJsonBounded<PostureReport>(`/api/posture?limit=${limit}`, POSTURE_RESPONSE_MAX_BYTES);
}
