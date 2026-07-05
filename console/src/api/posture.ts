import { apiJson } from '../lib/api';

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
  events: number;
  sensitive: number;
  controlled: number;
  uncontrolled: number;
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

export function fetchPosture(limit = 5000): Promise<PostureReport | null> {
  return apiJson<PostureReport>(`/api/posture?limit=${limit}`);
}
