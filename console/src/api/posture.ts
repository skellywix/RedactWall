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

export interface PostureReport {
  decisionQuality?: DecisionQualityReport;
}

export function fetchPosture(limit = 5000): Promise<PostureReport | null> {
  return apiJson<PostureReport>(`/api/posture?limit=${limit}`);
}
