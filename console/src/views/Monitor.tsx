import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { api, apiErrorSummary, apiJson } from '../lib/api';
import { fetchQueue, type QueueQuery } from '../api/queries';
import { EmptyState } from '../components/Panel';
import { navigate } from '../lib/router';
import { useSession } from '../lib/session';
import { useEventStream } from '../lib/sse';
import { toast } from '../lib/toast';

/**
 * AI Command Center (legacy tab-monitor). One GET /api/posture payload drives
 * the posture sections; the SOC pack and detector feedback keep their own
 * endpoints. All markup reuses the legacy signal-console class families from
 * console-base.css, so no view stylesheet is needed.
 *
 * Route contract:
 *   GET  /api/posture?limit=5000[&segment=]                    -> Posture
 *   POST /api/posture/actions                                  -> workflow patch (Security Admin UI gate)
 *   POST /api/posture/notify                                   -> SOC snapshot (200 sent / 202 not sent)
 *   GET  /api/integrations/siem/package?profile=[&format=zip]  -> SOC pack (Security Admin)
 *   GET  /api/detector-feedback/report?queryLimit=&feedbackLimit=
 *   POST /api/queries/:id/detector-feedback                    -> {detectorId, verdict, reason}
 *   GET  /api/queries (via api/queries fetchQueue)             -> decision pivot counts
 *   GET  /api/stream                                           -> query/decision/stats reload posture
 */

// ---------------------------------------------------------------------------
// Posture payload types (server/posture.js summarize / control-readiness.js)
// ---------------------------------------------------------------------------

interface PostureMetric {
  id: string;
  label: string;
  value: string | number;
  unit?: string;
  trend?: string;
  status?: string;
  lastUpdated?: string;
}

interface PostureObjective {
  id: string;
  label: string;
  score?: number;
  state?: string;
  detail?: string;
  action?: string;
  targetTab?: string;
}

interface ProofItem {
  id?: string;
  label?: string;
  status?: string;
  detail?: string;
  evidenceAt?: string | null;
  areaLabel?: string;
}

interface ProofLedger {
  verified?: number;
  attention?: number;
  missing?: number;
  total?: number;
  current?: ProofItem | null;
}

interface PlaybookStep {
  id?: string;
  label?: string;
  status?: string;
  detail?: string;
  command?: string;
  validation?: string;
}

interface HardeningArea {
  id: string;
  label?: string;
  description?: string;
  score?: number;
  state?: string;
  owner?: string;
  source?: string;
  evidence?: string[];
  gaps?: string[];
  action?: string;
  targetTab?: string;
  proofs?: ProofItem[];
  proofLedger?: ProofLedger;
  playbook?: PlaybookStep[];
}

interface MissionCurrent {
  label?: string;
  areaLabel?: string;
  detail?: string;
  command?: string;
  validation?: string;
}

interface MissionLaneInfo {
  id: string;
  label?: string;
  state?: string;
  targetTab?: string;
  done?: number;
  total?: number;
  nextStep?: string;
}

interface HardeningMission {
  title?: string;
  state?: string;
  status?: string;
  progress?: { percent?: number };
  current?: MissionCurrent | null;
  proofLedger?: ProofLedger;
  lanes?: MissionLaneInfo[];
}

interface HardeningReport {
  score?: number;
  state?: string;
  areas?: HardeningArea[];
  proofLedger?: ProofLedger;
  mission?: HardeningMission;
}

interface SegmentFilterInfo {
  id: string;
  typeLabel?: string;
  label?: string;
}

interface SegmentCardInfo extends SegmentFilterInfo {
  state?: string;
  score?: number;
  detail?: string;
}

interface SegmentsReport {
  active?: SegmentCardInfo | null;
  filters?: SegmentFilterInfo[];
  matrix?: SegmentCardInfo[];
  summary?: { selectedId?: string; visibleEvents?: number; attention?: number; privacy?: string };
}

interface BaselineDimension {
  id: string;
  label?: string;
  title?: string;
  state?: string;
  score?: number;
  detail?: string;
  targetTab?: string;
}

interface BehaviorBaselinesReport {
  summary?: { anomalies?: number; critical?: number; warning?: number };
  dimensions?: BaselineDimension[];
}

interface McpPolicyBucket {
  count?: number;
  examples?: string[];
}

interface McpPolicyInfo {
  registryMode?: string;
  allowed?: McpPolicyBucket;
  blocked?: McpPolicyBucket;
  approvalRequired?: McpPolicyBucket;
}

interface McpRow {
  id: string;
  name?: string;
  state?: string;
  status?: string;
  detail?: string;
  events?: number;
  riskScore?: number;
}

interface ConnectorProfile {
  id: string;
  label?: string;
  category?: string;
  stage?: string;
  runtimePresent?: boolean;
  configured?: boolean;
  installProof?: boolean;
  operations?: string[];
  scopeCount?: number;
  status?: string;
}

interface ConnectorRegistrySummary {
  shipped?: number;
  profiles?: number;
  profileTemplates?: number;
  shippedRuntimePresent?: number;
  installProof?: boolean;
  nextConnector?: string;
}

interface McpSummaryInfo {
  events?: number;
  activeAgents?: number;
  activeTools?: number;
  controlled?: number;
  blocked?: number;
  registryMode?: string;
  privacy?: string;
}

interface McpRequestRow {
  id: string;
  label?: string;
  events?: number;
  state?: string;
}

interface AgenticMcpReport {
  summary?: McpSummaryInfo;
  agents?: McpRow[];
  tools?: McpRow[];
  connectorRegistry?: { summary?: ConnectorRegistrySummary; profiles?: ConnectorProfile[] };
  requests?: McpRequestRow[];
  policy?: McpPolicyInfo;
}

interface ThreatSummaryInfo {
  events?: number;
  detections?: number;
  activeRules?: number;
  blocked?: number;
  critical?: number;
  promptInjection?: number;
  unsafeOutput?: number;
  privacy?: string;
}

interface ThreatRule {
  id: string;
  label?: string;
  framework?: string;
  detail?: string;
  events?: number;
  state?: string;
  status?: string;
  targetTab?: string;
}

interface ThreatControl {
  label?: string;
  state?: string;
  status?: string;
  detail?: string;
  targetTab?: string;
}

interface ThreatRecent {
  id: string;
  severity?: string;
  status?: string;
  state?: string;
  decision?: string;
  title?: string;
  threats?: string[];
  destination?: string;
  detail?: string;
}

interface ThreatGuardrailsReport {
  summary?: ThreatSummaryInfo;
  rules?: ThreatRule[];
  controls?: ThreatControl[];
  recent?: ThreatRecent[];
}

interface InventoryItem {
  id: string;
  name?: string;
  kind?: string;
  state?: string;
  status?: string;
  source?: string;
  events?: number;
  detail?: string;
  action?: string;
  targetTab?: string;
  riskScore?: number;
  riskLevel?: string;
  riskReason?: string;
}

interface InventorySummaryInfo {
  sanctioned?: number;
  shadow?: number;
  highRiskAssets?: number;
  unapprovedLocalTools?: number;
  activeDestinations?: number;
}

interface AiInventoryReport {
  summary?: InventorySummaryInfo;
  apps?: InventoryItem[];
  tools?: InventoryItem[];
}

interface PostureAction {
  id: string;
  severity?: string;
  category?: string;
  label?: string;
  detail?: string;
  action?: string;
  targetTab?: string;
  command?: string;
  workflowStatus?: string;
  workflowOwner?: string;
  workflowSnoozeUntil?: string;
  workflowUpdatedAt?: string;
  workflowProofState?: string;
}

interface DecisionCard {
  id: string;
  label: string;
  score?: number;
  state?: string;
  value?: string | number;
  detail?: string;
}

interface DecisionHotspot {
  id: string;
  kind?: string;
  label: string;
  events?: number;
  sensitive?: number;
  detail?: string;
}

interface DecisionQualityInfo {
  summary?: { controlRate?: number; pendingReviews?: number; overrideWatch?: number };
  cards?: DecisionCard[];
  hotspots?: DecisionHotspot[];
}

interface GraphLaneInfo {
  id: string;
  label?: string;
  detail?: string;
  count?: number;
}

interface GraphNode {
  id: string;
  lane?: string;
  kind?: string;
  label?: string;
  detail?: string;
  status?: string;
  targetTab?: string;
}

interface GraphEdge {
  id: string;
  from?: string;
  to?: string;
  label?: string;
  detail?: string;
  status?: string;
  events?: number;
}

interface GraphSummaryInfo {
  nodes?: number;
  edges?: number;
  highRiskAssets?: number;
  shadowAssets?: number;
  mcpLinks?: number;
  controlledLinks?: number;
  privacy?: string;
}

interface ControlGraphReport {
  summary?: GraphSummaryInfo;
  lanes?: GraphLaneInfo[];
  nodes?: GraphNode[];
  edges?: GraphEdge[];
}

/** Shared shape of surfaces and events for search/status filtering. */
interface SignalRecordInfo {
  id: string;
  status?: string;
  severity?: string;
  source?: string;
  relatedMetric?: string;
  description?: string;
  name?: string;
  type?: string;
  location?: string;
  title?: string;
}

interface PostureSurfaceInfo extends SignalRecordInfo {
  health?: number;
  confidence?: number;
  /** Humanized string ("live", "5 min ago"), not an ISO date. */
  lastUpdated?: string;
}

interface MonitorEventInfo extends SignalRecordInfo {
  timestamp?: string;
  confidence?: number;
}

interface TrendDay {
  date?: string;
  events?: number;
  blocked?: number;
  redacted?: number;
  allowed?: number;
  coached?: number;
}

interface ControlOutcome {
  label: string;
  events?: number;
  blocked?: number;
  redacted?: number;
  coached?: number;
}

interface Posture {
  generatedAt?: string;
  metrics?: PostureMetric[];
  objectives?: PostureObjective[];
  hardening?: HardeningReport;
  segments?: SegmentsReport;
  behaviorBaselines?: BehaviorBaselinesReport;
  agenticMcp?: AgenticMcpReport;
  threatGuardrails?: ThreatGuardrailsReport;
  aiInventory?: AiInventoryReport;
  actionQueue?: PostureAction[];
  decisionQuality?: DecisionQualityInfo;
  controlGraph?: ControlGraphReport;
  surfaces?: PostureSurfaceInfo[];
  events?: MonitorEventInfo[];
  trend?: TrendDay[];
  controls?: ControlOutcome[];
}

// ---------------------------------------------------------------------------
// Detector feedback + SIEM package types
// ---------------------------------------------------------------------------

interface FeedbackSummary {
  valid?: number;
  noisy?: number;
  reviewCandidates?: number;
  privacy?: string;
}

interface FeedbackDetector {
  detectorId: string;
  total?: number;
  falsePositive?: number;
  tooSensitive?: number;
  state?: string;
  detail?: string;
}

interface FeedbackCandidate {
  queryId: string;
  detectorId: string;
  detectorIds?: string[];
  destination?: string;
  status?: string;
  riskScore?: number;
}

interface FeedbackQualitySummary {
  score?: number;
  floorsMet?: boolean;
  failures?: number;
  semanticRecall?: number;
  semanticPrecision?: number;
  structuredRecall?: number;
  structuredF1?: number;
  benignFalsePositives?: number;
  baitFalsePositives?: number;
}

interface FeedbackReport {
  summary?: FeedbackSummary;
  detectors?: FeedbackDetector[];
  reviewQueue?: FeedbackCandidate[];
  quality?: { summary?: FeedbackQualitySummary };
}

interface SiemSearch {
  name?: string;
  udmSearch?: string;
  spl?: string;
  kql?: string;
}

interface SiemTransport {
  method?: string;
  endpointPath?: string;
  ingestion?: string;
}

interface SiemPrivacyFlags {
  rawPromptBodies?: boolean;
  tokenVaultValues?: boolean;
  rawFindingValues?: boolean;
  rawUrlsOrFilePaths?: boolean;
}

interface SiemProfile {
  id: string;
  label?: string;
  target?: string;
  transport?: SiemTransport;
  fieldMappings?: unknown[];
  samplePayloads?: unknown[];
  savedSearches?: SiemSearch[];
  detections?: SiemSearch[];
  dashboardPanels?: unknown[];
  workbookPanels?: unknown[];
  incidentTemplates?: unknown[];
  setupChecklist?: string[];
}

interface SiemPackage {
  summary?: { searches?: number; samplePayloads?: number; packageFiles?: number };
  privacy?: SiemPrivacyFlags;
  profiles?: SiemProfile[];
}

// ---------------------------------------------------------------------------
// Formatting + tone helpers (ports of the legacy dashboard helpers)
// ---------------------------------------------------------------------------

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');
const fmtTime = (iso?: string | null) =>
  iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-';

function num(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

const clampPct = (value: number) => Math.max(5, Math.min(100, Math.round(value)));
const humanize = (value: string) => (value || '-').replace(/_/g, ' ');

const STATUS_LABELS: Record<string, string> = {
  online: 'Online',
  idle: 'Idle',
  warning: 'Warning',
  error: 'Critical',
  loading: 'Syncing',
  offline: 'Offline',
};

const monitorStatusLabel = (status: string) => STATUS_LABELS[status] || 'Unknown';
const severityLabel = (severity: string) => (severity === 'critical' ? 'Critical' : severity === 'warning' ? 'Warning' : 'Info');

const SOURCE_LABELS: Record<string, string> = {
  browser_extension: 'Browser',
  endpoint_agent: 'Endpoint',
  mcp_guard: 'MCP',
  audit_log: 'Audit',
  approval_queue: 'Approval',
  policy: 'Policy',
  signal_console: 'Console',
  api: 'API',
  proxy: 'Proxy',
};

const sourceLabel = (source?: string) => SOURCE_LABELS[source || ''] || source || 'API';

function readinessTone(state?: string): string {
  const value = String(state || '').toLowerCase();
  if (value === 'ready') return 'ready';
  if (value === 'blocked') return 'blocked';
  return 'attention';
}

function segmentTone(state?: string): string {
  if (state === 'critical') return 'critical';
  if (state === 'attention') return 'warning';
  return 'ready';
}

const baselineTone = (state?: string) => (state === 'critical' ? 'critical' : state === 'warning' ? 'attention' : 'ready');
const baselineStateLabel = (state?: string) => (state === 'critical' ? 'Critical' : state === 'warning' ? 'Watch' : 'Normal');

const INVENTORY_STATE_LABELS: Record<string, string> = {
  sanctioned: 'Sanctioned',
  unsanctioned: 'Unsanctioned',
  shadow: 'Shadow',
  local_approved: 'Approved',
  local_unapproved: 'Unapproved',
};

const inventoryStateLabel = (state: string) => INVENTORY_STATE_LABELS[state] || state.replace(/_/g, ' ');
const inventoryRiskLabel = (level: string) =>
  level === 'critical' ? 'Critical' : level === 'high' ? 'High' : level === 'medium' ? 'Medium' : 'Low';

const MCP_STATE_LABELS: Record<string, string> = {
  allowed_registry: 'Allowed registry',
  approval_required: 'Approval required',
  outside_registry: 'Outside registry',
  blocked: 'Blocked',
  redacted: 'Redacted',
  observed: 'Observed',
  idle: 'Idle',
};

const mcpStateLabel = (state: string) => MCP_STATE_LABELS[state] || inventoryStateLabel(state);

const KNOWN_STATUSES = ['online', 'warning', 'error', 'idle'];

function mcpRowStatus(item: { status?: string; state?: string }): string {
  const status = String(item.status || '').toLowerCase();
  if (KNOWN_STATUSES.includes(status)) return status;
  const state = String(item.state || '');
  if (state === 'blocked' || state === 'outside_registry') return 'error';
  if (state === 'approval_required' || state === 'redacted') return 'warning';
  if (state === 'allowed_registry' || state === 'observed') return 'online';
  return 'idle';
}

function threatStatus(item: { status?: string; state?: string }): string {
  const status = String(item.status || '').toLowerCase();
  if (KNOWN_STATUSES.includes(status)) return status;
  const state = String(item.state || '').toLowerCase();
  if (state === 'critical' || state === 'missing') return 'error';
  if (state === 'attention') return 'warning';
  return 'online';
}

const THREAT_STATE_LABELS: Record<string, string> = {
  ready: 'Ready',
  attention: 'Attention',
  critical: 'Critical',
  missing: 'Missing',
  online: 'Online',
  warning: 'Warning',
  error: 'Critical',
  idle: 'Idle',
};

const threatStateLabel = (state?: string) => THREAT_STATE_LABELS[state || ''] || state || 'Unknown';

function graphStatus(value?: string): string {
  const status = String(value || 'idle');
  return KNOWN_STATUSES.includes(status) ? status : 'idle';
}

function proofStatusLabel(status?: string): string {
  if (status === 'verified') return 'Verified';
  if (status === 'attention') return 'Attention';
  return 'Missing';
}

function actionWorkflowLabel(status?: string): string {
  if (status === 'assigned') return 'Assigned';
  if (status === 'snoozed') return 'Snoozed';
  if (status === 'resolved') return 'Resolved';
  return 'Open';
}

function actionWorkflowTone(status?: string): string {
  return status === 'assigned' || status === 'snoozed' || status === 'resolved' ? status : 'open';
}

function actionWorkflowMeta(item: PostureAction): string {
  const parts: string[] = [];
  if (item.workflowOwner) parts.push(item.workflowOwner);
  if (item.workflowSnoozeUntil && item.workflowStatus === 'snoozed') parts.push(`until ${fmtTime(item.workflowSnoozeUntil)}`);
  if (item.workflowProofState === 'proof_pending') parts.push('proof pending');
  if (item.workflowUpdatedAt) parts.push(fmtTime(item.workflowUpdatedAt));
  return parts.join(' / ');
}

function metricJumpTarget(metricId: string): string {
  const id = metricId.toLowerCase();
  if (id.includes('sensor') || id.includes('coverage')) return 'coverage';
  if (id.includes('deliver') || id.includes('subscription')) return 'integrations';
  if (id.includes('pending') || id.includes('approval') || id.includes('queue')) return 'queue';
  return 'activity';
}

const TREND_LABELS: Record<string, string> = { increased: 'Increased', decreased: 'Decreased', neutral: 'Stable' };

/** Legacy targetTab values -> new console hash routes (all registered in App.tsx). */
const TAB_ROUTES: Record<string, string> = {
  overview: '/',
  queue: '/queue',
  monitor: '/monitor',
  activity: '/activity',
  insights: '/insights',
  coverage: '/coverage',
  lineage: '/lineage',
  'decision-quality': '/decision-quality',
  catalog: '/catalog',
  compliance: '/compliance',
  identity: '/identity',
  policy: '/policy',
  deploy: '/deploy',
  integrations: '/integrations',
  audit: '/audit',
  updates: '/updates',
};

function jumpToTab(tab: string): void {
  const route = TAB_ROUTES[tab];
  if (route) navigate(route);
}

function scrollToAnchor(anchorId: string): void {
  const target = document.getElementById(anchorId);
  if (!target) return;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  target.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
}

// ---------------------------------------------------------------------------
// Search + status filtering (legacy monitorSearchState / monitorMatchesStatus)
// ---------------------------------------------------------------------------

const STATUS_OPTIONS: Array<{ id: string; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'online', label: 'Online' },
  { id: 'idle', label: 'Idle' },
  { id: 'warning', label: 'Warn' },
  { id: 'error', label: 'Critical' },
  { id: 'loading', label: 'Syncing' },
  { id: 'offline', label: 'Offline' },
];

interface SearchUi {
  state: 'disabled' | 'default' | 'focus' | 'warning' | 'error' | 'valid';
  message: string;
}

function searchUiState(rawTerm: string, focused: boolean, refreshing: boolean): SearchUi {
  // Trim only here so the raw input keeps spaces the user is typing (a controlled
  // value trimmed on every keystroke can never contain a multi-word phrase).
  const term = rawTerm.trim();
  if (refreshing) return { state: 'disabled', message: 'Refreshing.' };
  if (!term && focused) return { state: 'focus', message: 'Ready.' };
  if (!term) return { state: 'default', message: 'Type to filter.' };
  if (term.length > 64) return { state: 'error', message: 'Query too long.' };
  if (/[<>`{}]/.test(term)) return { state: 'error', message: 'Unsupported characters.' };
  if (term.length < 2) return { state: 'warning', message: 'Too broad.' };
  return { state: 'valid', message: `Filtered: "${term}".` };
}

function searchHaystack(record: SignalRecordInfo): string {
  return [
    record.id,
    record.name,
    record.type,
    record.status,
    record.severity,
    record.source,
    record.location,
    record.title,
    record.description,
    record.relatedMetric,
  ]
    .join(' ')
    .toLowerCase();
}

function matchesSearch(record: SignalRecordInfo, searchState: string, rawTerm: string): boolean {
  if (searchState === 'error') return false;
  const term = rawTerm.trim();
  if (!term) return true;
  return searchHaystack(record).includes(term.toLowerCase());
}

function matchesStatus(record: SignalRecordInfo, filter: string): boolean {
  if (filter === 'all') return true;
  if (record.status === filter) return true;
  if (filter === 'error' && record.severity === 'critical') return true;
  if (filter === 'warning' && record.severity === 'warning') return true;
  if (filter === 'online' && record.severity === 'info') return true;
  return false;
}

function statusCounts(records: SignalRecordInfo[]): Record<string, number> {
  const counts: Record<string, number> = { all: records.length };
  for (const item of records) {
    const status = item.status || '';
    if (status) counts[status] = (counts[status] ?? 0) + 1;
    if (item.severity === 'critical' && status !== 'error') counts.error = (counts.error ?? 0) + 1;
    if (item.severity === 'warning' && status !== 'warning') counts.warning = (counts.warning ?? 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

function fetchMonitorPosture(segment: string): Promise<Posture | null> {
  const param = segment && segment !== 'all' ? `&segment=${encodeURIComponent(segment)}` : '';
  return apiJson<Posture>(`/api/posture?limit=5000${param}`);
}

function fetchFeedbackReport(): Promise<FeedbackReport | null> {
  return apiJson<FeedbackReport>('/api/detector-feedback/report?queryLimit=1000&feedbackLimit=1000');
}

interface PostureActionPayload {
  id: string;
  status: string;
  owner?: string;
  note?: string;
  snoozeUntil?: string;
}

type WorkflowStatus = 'assigned' | 'snoozed' | 'resolved';

function workflowPatch(status: WorkflowStatus, user: string): Omit<PostureActionPayload, 'id'> {
  if (status === 'assigned') return { status, owner: user || 'security_admin', note: 'assigned_from_command_center' };
  if (status === 'snoozed') {
    const until = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    return { status, snoozeUntil: until, note: 'snoozed_24h_from_command_center' };
  }
  return { status, note: 'remediation_logged_waiting_for_proof' };
}

/** Returns a toast-safe error summary, or null on success. */
async function postPostureAction(payload: PostureActionPayload): Promise<string | null> {
  const response = await api('/api/posture/actions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (response?.ok) return null;
  return apiErrorSummary(response, 'Action update failed');
}

async function postDetectorFeedback(queryId: string, detectorId: string, verdict: 'valid' | 'false_positive'): Promise<boolean> {
  const reason = verdict === 'valid' ? 'operator_validated' : 'operator_marked_noisy';
  const response = await api(`/api/queries/${encodeURIComponent(queryId)}/detector-feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ detectorId, verdict, reason }),
  });
  return Boolean(response?.ok);
}

async function fetchSiemPackage(profile: string): Promise<{ pkg: SiemPackage | null; error: string }> {
  const response = await api(`/api/integrations/siem/package?profile=${encodeURIComponent(profile)}`);
  if (!response || !response.ok) {
    return { pkg: null, error: response && response.status === 400 ? 'unsupported_profile' : 'load_failed' };
  }
  try {
    return { pkg: (await response.json()) as SiemPackage, error: '' };
  } catch {
    return { pkg: null, error: 'load_failed' };
  }
}

/** Returns a toast-safe error summary, or null when the ZIP download started. */
async function downloadSiemZip(profile: string): Promise<string | null> {
  const response = await api(`/api/integrations/siem/package?profile=${encodeURIComponent(profile)}&format=zip`);
  if (!response || !response.ok) return apiErrorSummary(response, 'SIEM package download failed');
  const url = URL.createObjectURL(await response.blob());
  const link = Object.assign(document.createElement('a'), {
    href: url,
    download: `redactwall-siem-${profile || 'all'}-package.zip`,
  });
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  return null;
}

// ---------------------------------------------------------------------------
// Data hooks
// ---------------------------------------------------------------------------

function usePosture(segment: string) {
  const [report, setReport] = useState<Posture | null>(null);
  const [lastUpdated, setLastUpdated] = useState(() => new Date().toISOString());
  // Monotonic request id: a slow posture build for a superseded segment must not
  // overwrite the report the user is now looking at.
  const reqId = useRef(0);
  const load = useCallback(async () => {
    const seq = ++reqId.current;
    const body = await fetchMonitorPosture(segment);
    if (seq !== reqId.current) return body;
    if (body) {
      setReport(body);
      setLastUpdated(body.generatedAt || new Date().toISOString());
    }
    return body;
  }, [segment]);
  useEffect(() => {
    void load();
  }, [load]);
  return { report, lastUpdated, load };
}

function useFeedbackReport() {
  const [report, setReport] = useState<FeedbackReport | null>(null);
  const load = useCallback(async () => {
    const body = await fetchFeedbackReport();
    if (body) setReport(body);
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { report, load };
}

/** Loaded activity window backing the decision pivot counts. */
function useActivityRows() {
  const [rows, setRows] = useState<QueueQuery[]>([]);
  const load = useCallback(async () => {
    const next = await fetchQueue('all');
    if (next) setRows(next);
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { rows, load };
}

interface SiemState {
  pkg: SiemPackage | null;
  error: string;
  loading: boolean;
  downloading: boolean;
  profile: string;
  setProfile: (profile: string) => void;
  load: () => Promise<void>;
  download: () => Promise<void>;
}

function useSiemPackage(role: string | null): SiemState {
  const [pkg, setPkg] = useState<SiemPackage | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [profile, setProfile] = useState('all');
  const load = useCallback(async () => {
    if (role === null) return;
    // GET /api/integrations/siem/package is auditRead (Security Admin OR
    // Auditor); gate the download the same way the server does so the evidence
    // role is not falsely denied its own export.
    if (role !== 'security_admin' && role !== 'auditor') {
      setPkg(null);
      setError('siem_role_required');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    const result = await fetchSiemPackage(profile);
    setPkg(result.pkg);
    setError(result.error);
    setLoading(false);
  }, [role, profile]);
  useEffect(() => {
    void load();
  }, [load]);
  const download = useCallback(async () => {
    setDownloading(true);
    const failure = await downloadSiemZip(profile);
    setDownloading(false);
    if (failure) toast(failure, 'error');
  }, [profile]);
  return { pkg, error, loading, downloading, profile, setProfile, load, download };
}

function useMonitorRefresh(
  loadPosture: () => Promise<Posture | null>,
  loadSiem: () => Promise<void>,
  loadFeedback: () => Promise<void>,
  loadActivity: () => Promise<void>,
) {
  const [refreshing, setRefreshing] = useState(false);
  const [recentEventId, setRecentEventId] = useState('');
  const busyRef = useRef(false);
  const refresh = useCallback(async () => {
    if (busyRef.current) return;
    busyRef.current = true;
    setRefreshing(true);
    try {
      const [body] = await Promise.all([loadPosture(), loadSiem(), loadFeedback(), loadActivity()]);
      setRecentEventId(body?.events?.[0]?.id ?? '');
    } finally {
      busyRef.current = false;
      setRefreshing(false);
    }
  }, [loadPosture, loadSiem, loadFeedback, loadActivity]);
  return { refreshing, recentEventId, refresh };
}

function useActionWorkflow(isAdmin: boolean, user: string, reload: () => Promise<Posture | null>) {
  const [busyKey, setBusyKey] = useState('');
  const run = useCallback(
    async (id: string, status: WorkflowStatus) => {
      if (!isAdmin) {
        toast('Request not allowed for this session.');
        return;
      }
      setBusyKey(`${id}:${status}`);
      const error = await postPostureAction({ id, ...workflowPatch(status, user) });
      if (!error) await reload();
      setBusyKey('');
      if (error) toast(error);
    },
    [isAdmin, user, reload],
  );
  return { busyKey, run };
}

interface SnapshotControl {
  status: string;
  sending: boolean;
  send: () => Promise<void>;
}

function useSocSnapshot(isAdmin: boolean): SnapshotControl {
  const [status, setStatus] = useState('SOC SNAPSHOT READY');
  const [sending, setSending] = useState(false);
  const send = useCallback(async () => {
    if (!isAdmin) return;
    setSending(true);
    setStatus('SENDING');
    try {
      const response = await api('/api/posture/notify', { method: 'POST' });
      const body = response ? ((await response.json().catch(() => ({}))) as { sent?: boolean; reason?: string }) : {};
      if (response?.ok && body.sent) setStatus('SENT TO SOC');
      else setStatus(`NOT SENT - ${humanize(body.reason || 'not configured')}`.slice(0, 80));
    } catch {
      setStatus('SEND FAILED');
    } finally {
      setSending(false);
    }
  }, [isAdmin]);
  return { status, sending, send };
}

type VerdictState = 'busy' | 'failed';

interface VerdictControl {
  states: ReadonlyMap<string, VerdictState>;
  submit: (queryId: string, detectorId: string, verdict: 'valid' | 'false_positive') => Promise<void>;
}

function useDetectorVerdicts(reload: () => Promise<void>): VerdictControl {
  const [states, setStates] = useState<ReadonlyMap<string, VerdictState>>(new Map());
  const submit = useCallback(
    async (queryId: string, detectorId: string, verdict: 'valid' | 'false_positive') => {
      const key = `${queryId}:${detectorId}:${verdict}`;
      setStates((prev) => new Map(prev).set(key, 'busy'));
      const ok = await postDetectorFeedback(queryId, detectorId, verdict);
      if (ok) await reload();
      setStates((prev) => {
        const next = new Map(prev);
        if (ok) next.delete(key);
        else next.set(key, 'failed');
        return next;
      });
    },
    [reload],
  );
  return { states, submit };
}

interface MonitorSelection {
  kind: 'item' | 'event';
  id: string;
}

interface MonitorUi {
  statusFilter: string;
  setStatusFilter: (id: string) => void;
  term: string;
  setTerm: (value: string) => void;
  focused: boolean;
  setFocused: (value: boolean) => void;
  selection: MonitorSelection | null;
  inspectorLoading: boolean;
  expandedPanelId: string;
  expandedEventId: string;
  select: (kind: 'item' | 'event', id: string) => void;
  clear: () => void;
  togglePanel: (id: string) => void;
  toggleEvent: (id: string) => void;
}

function useMonitorUi(): MonitorUi {
  const [statusFilter, setStatusFilter] = useState('all');
  const [term, setTerm] = useState('');
  const [focused, setFocused] = useState(false);
  const [selection, setSelection] = useState<MonitorSelection | null>(null);
  const [inspectorLoading, setInspectorLoading] = useState(false);
  const [expandedPanelId, setExpandedPanelId] = useState('');
  const [expandedEventId, setExpandedEventId] = useState('');
  // 220ms skeleton per selection, matching the legacy inspector timer.
  useEffect(() => {
    if (!selection) return;
    setInspectorLoading(true);
    const timer = setTimeout(() => setInspectorLoading(false), 220);
    return () => clearTimeout(timer);
  }, [selection]);
  const select = useCallback((kind: 'item' | 'event', id: string) => setSelection({ kind, id }), []);
  const clear = useCallback(() => {
    setSelection(null);
    setInspectorLoading(false);
  }, []);
  const togglePanel = useCallback((id: string) => setExpandedPanelId((prev) => (prev === id ? '' : id)), []);
  const toggleEvent = useCallback((id: string) => setExpandedEventId((prev) => (prev === id ? '' : id)), []);
  return {
    statusFilter,
    setStatusFilter,
    term,
    setTerm,
    focused,
    setFocused,
    selection,
    inspectorLoading,
    expandedPanelId,
    expandedEventId,
    select,
    clear,
    togglePanel,
    toggleEvent,
  };
}

// ---------------------------------------------------------------------------
// Shared presentational pieces
// ---------------------------------------------------------------------------

const PULSE_STATUSES = new Set(['loading', 'warning', 'error']);

function SignalDot({ status, label, pulse }: { status: string; label: string; pulse?: boolean }) {
  const pulsing = pulse || PULSE_STATUSES.has(status);
  return <span className={`signal-dot status-${status}${pulsing ? ' is-pulsing' : ''}`} role="img" aria-label={label} />;
}

function TabJump({ tab, label }: { tab: string; label: string }) {
  return (
    <button className="ghost mini" type="button" onClick={() => jumpToTab(tab)}>
      {label}
    </button>
  );
}

function CopyCommandButton({ command, label = 'Copy' }: { command: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1600);
    return () => clearTimeout(timer);
  }, [copied]);
  const copy = () => {
    navigator.clipboard
      .writeText(command)
      .then(() => setCopied(true))
      .catch(() => {});
  };
  return (
    <button className="ghost mini" type="button" onClick={copy}>
      {copied ? 'Copied' : label}
    </button>
  );
}

interface SectionProps {
  title: string;
  summary: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

function Section({ title, summary, actions, children }: SectionProps) {
  return (
    <div className="signal-section">
      <div className="signal-section-head">
        <div>
          <h3>{title}</h3>
          <span>{summary}</span>
        </div>
        {actions ?? null}
      </div>
      {children}
    </div>
  );
}

interface MeterRowProps {
  label: string;
  side: string;
  width: number;
  tone?: string;
  ariaLabel: string;
  detail?: string;
}

function MeterRow({ label, side, width, tone, ariaLabel, detail }: MeterRowProps) {
  return (
    <div className="control-row">
      <div>
        <strong>{label}</strong>
        <span>{side}</span>
      </div>
      <div className="control-bar" role="img" aria-label={ariaLabel}>
        <i className={tone || undefined} style={{ '--w': `${width}%` } as CSSProperties} />
      </div>
      {detail === undefined ? null : <span>{detail}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header + toolbar + segment lens + metrics + decision pivots
// ---------------------------------------------------------------------------

interface ConsoleHeaderProps {
  critical: boolean;
  lastUpdated: string;
  refreshing: boolean;
  onRefresh: () => void;
}

function ConsoleHeader({ critical, lastUpdated, refreshing, onRefresh }: ConsoleHeaderProps) {
  return (
    <div className="signal-console-header">
      <div className="signal-console-title">
        <div>
          <h2>AI Command Center</h2>
          <p>Sanitized member-data posture, control outcomes, and examiner proof without prompt bodies.</p>
        </div>
      </div>
      <div className="signal-header-actions">
        <div className="signal-live-summary">
          <SignalDot
            status={critical ? 'error' : 'online'}
            label={critical ? 'Command center has critical signals' : 'Command center online'}
            pulse
          />
          {critical ? 'ATTENTION' : 'LIVE'}
        </div>
        <span className="signal-updated">UPDATED {fmtTime(lastUpdated)}</span>
        <button className="system-button primary" type="button" disabled={refreshing} aria-busy={refreshing} onClick={onRefresh}>
          {refreshing ? (
            <>
              <span className="button-spinner" aria-hidden="true" />
              Refreshing
            </>
          ) : (
            'Refresh'
          )}
        </button>
      </div>
    </div>
  );
}

interface StatusChipProps {
  option: { id: string; label: string };
  count: number;
  selected: boolean;
  onFilter: (id: string) => void;
}

function StatusChip({ option, count, selected, onFilter }: StatusChipProps) {
  const statusClass = option.id === 'warning' ? ' status-warning' : option.id === 'error' ? ' status-error' : '';
  return (
    <button
      className={`signal-chip${statusClass}${selected ? ' is-selected' : ''}`}
      type="button"
      aria-pressed={selected}
      disabled={!count}
      onClick={() => onFilter(option.id)}
    >
      {option.id === 'all' ? null : <SignalDot status={option.id} label={`${option.label} status filter`} />}
      <span>{option.label}</span>
      <b>{count}</b>
    </button>
  );
}

interface MonitorToolbarProps {
  term: string;
  search: SearchUi;
  counts: Record<string, number>;
  filter: string;
  onTerm: (value: string) => void;
  onFocus: (value: boolean) => void;
  onFilter: (id: string) => void;
}

function MonitorToolbar({ term, search, counts, filter, onTerm, onFocus, onFilter }: MonitorToolbarProps) {
  return (
    <div className="signal-toolbar">
      <div className="signal-input-wrap" data-state={search.state}>
        <label htmlFor="monitorSearch">Search</label>
        <div className="signal-input-box">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="m21 21-4.35-4.35M10.5 18a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15Z"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
            />
          </svg>
          <input
            id="monitorSearch"
            type="search"
            autoComplete="off"
            placeholder="Filter signals"
            value={term}
            disabled={search.state === 'disabled'}
            aria-invalid={search.state === 'error'}
            onChange={(event) => onTerm(event.target.value)}
            onFocus={() => onFocus(true)}
            onBlur={() => onFocus(false)}
          />
        </div>
        <div className="signal-input-help">{search.message}</div>
      </div>
      <div className="signal-filters" aria-label="Status filters">
        {STATUS_OPTIONS.map((option) => (
          <StatusChip key={option.id} option={option} count={counts[option.id] ?? 0} selected={filter === option.id} onFilter={onFilter} />
        ))}
      </div>
    </div>
  );
}

function SegmentCard({ card, selected, onSegment }: { card: SegmentCardInfo; selected: boolean; onSegment: (id: string) => void }) {
  return (
    <button
      className={`segment-card ${segmentTone(card.state)}${selected ? ' is-selected' : ''}`}
      type="button"
      aria-pressed={selected}
      onClick={() => onSegment(card.id)}
    >
      <span>{card.typeLabel || 'Segment'}</span>
      <strong>{card.label || 'Unknown'}</strong>
      <small>{card.detail || ''}</small>
      <b>
        {num(card.score)}
        <em>/100</em>
      </b>
    </button>
  );
}

function SegmentLensEmpty() {
  return (
    <div className="segment-lens is-empty" aria-label="Posture segment lens">
      <div className="segment-lens-summary">Segments will appear after sanitized activity arrives.</div>
      <label className="segment-select">
        <span>Posture segment</span>
        <select value="all" aria-label="Posture segment" disabled>
          <option value="all">All segments</option>
        </select>
      </label>
      <div className="segment-matrix" aria-live="polite" />
    </div>
  );
}

function SegmentLens({ segments, onSegment }: { segments: SegmentsReport | null; onSegment: (id: string) => void }) {
  if (!segments) return <SegmentLensEmpty />;
  const summary = segments.summary ?? {};
  const active = segments.active ?? null;
  const filters = segments.filters?.length ? segments.filters : [{ id: 'all', label: 'All segments', typeLabel: 'All' }];
  const matrix = segments.matrix ?? [];
  const selectedId = summary.selectedId || active?.id || 'all';
  const activeLabel = active ? `${active.typeLabel || 'Segment'}: ${active.label || 'Unknown'}` : 'All segments';
  return (
    <div className="segment-lens" aria-label="Posture segment lens">
      <div className="segment-lens-summary">
        <b>{activeLabel}</b>
        <span>
          {num(summary.visibleEvents)} visible events / {num(summary.attention)} attention /{' '}
          {summary.privacy || 'metadata only; prompt bodies excluded'}
        </span>
      </div>
      <label className="segment-select">
        <span>Posture segment</span>
        <select value={selectedId} aria-label="Posture segment" onChange={(event) => onSegment(event.target.value)}>
          {filters.map((item) => (
            <option key={item.id} value={item.id}>
              {item.typeLabel || 'Segment'} - {item.label || item.id}
            </option>
          ))}
        </select>
      </label>
      <div className="segment-matrix" aria-live="polite">
        {matrix.length ? (
          matrix.slice(0, 8).map((card) => <SegmentCard key={card.id} card={card} selected={card.id === selectedId} onSegment={onSegment} />)
        ) : (
          <EmptyState title="No segments" detail="Awaiting activity." />
        )}
      </div>
    </div>
  );
}

function MetricCard({ metric, updating, lastUpdated }: { metric: PostureMetric; updating: boolean; lastUpdated: string }) {
  const jump = metricJumpTarget(metric.id);
  const status = metric.status || 'normal';
  const dotStatus = status === 'normal' ? 'online' : status === 'critical' ? 'error' : status;
  return (
    <button
      className={`metric-card${status === 'normal' ? '' : ` status-${status}`}${updating ? ' is-updating' : ''}`}
      type="button"
      title={`Open ${jump}`}
      aria-busy={status === 'loading'}
      onClick={() => jumpToTab(jump)}
    >
      <div className="metric-card-head">
        <span>{metric.label}</span>
        <SignalDot status={dotStatus} label={`${metric.label} ${status}`} pulse={updating} />
      </div>
      <div className="metric-value">
        {status === 'loading' ? (
          <>
            <div className="metric-skeleton" aria-hidden="true" />
            <span className="metric-unit">Loading</span>
          </>
        ) : (
          <>
            <span>{metric.value}</span>
            <span className="metric-unit">{metric.unit || ''}</span>
          </>
        )}
      </div>
      <div className="metric-meta">
        <span className={`metric-trend ${metric.trend || 'neutral'}`}>{TREND_LABELS[metric.trend || ''] || 'Stable'}</span>
        <span>{fmtTime(lastUpdated)}</span>
      </div>
    </button>
  );
}

function MetricGrid({ metrics, refreshing, fallbackUpdated }: { metrics: PostureMetric[]; refreshing: boolean; fallbackUpdated: string }) {
  return (
    <div className="metric-grid" aria-live="polite">
      {metrics.length ? (
        metrics.map((metric) => (
          <MetricCard key={metric.id} metric={metric} updating={refreshing} lastUpdated={metric.lastUpdated || fallbackUpdated} />
        ))
      ) : (
        <EmptyState title="Awaiting telemetry" detail="Metrics appear once posture data loads." />
      )}
    </div>
  );
}

/** Tokens match the activity search grammar's substring rule ("blocked" covers destination_blocked etc). */
const DECISION_PIVOTS: Array<{ token: string; label: string }> = [
  { token: 'blocked', label: 'Blocked' },
  { token: 'pending', label: 'Held' },
  { token: 'redacted', label: 'Redacted' },
  { token: 'warned', label: 'Warned' },
  { token: 'allowed', label: 'Allowed' },
  { token: 'denied', label: 'Denied' },
  { token: 'approved', label: 'Approved' },
];

function DecisionPivots({ rows }: { rows: QueueQuery[] }) {
  const count = (token: string) => rows.filter((q) => String(q.status || '').toLowerCase().includes(token)).length;
  return (
    <div className="signal-filters decision-pivots" aria-label="Decision pivots into Exam Activity" aria-live="polite">
      {DECISION_PIVOTS.map((pivot) => (
        <button
          key={pivot.token}
          className="signal-chip"
          type="button"
          title={`Open Exam Activity filtered to status:${pivot.token}`}
          onClick={() => navigate(`/activity?q=${encodeURIComponent('status:' + pivot.token)}`)}
        >
          <span>{pivot.label}</span>
          <b>{count(pivot.token)}</b>
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hardening mission + operator flow
// ---------------------------------------------------------------------------

function MissionPrimary({ mission }: { mission: HardeningMission }) {
  const current = mission.current ?? null;
  const ledger = mission.proofLedger ?? {};
  const proofCurrent = ledger.current ?? null;
  const proofSummary = num(ledger.total)
    ? `${num(ledger.verified)} verified / ${num(ledger.attention)} attention / ${num(ledger.missing)} missing`
    : 'No proof items';
  return (
    <div className="mission-primary">
      <div className="mission-kicker">
        <SignalDot status={mission.status || 'warning'} label={`${mission.title || 'Hardening mission'} ${mission.state || 'attention'}`} />
        <span>{mission.title || 'Hardening mission'}</span>
        <b>{num(mission.progress?.percent)}%</b>
      </div>
      <h3>{current ? current.label : 'Deployment proof complete'}</h3>
      <p>
        {current ? current.areaLabel : 'Gateway, AI assets, and MCP agents'} ·{' '}
        {current ? current.detail : 'All hardening steps are proven from sanitized telemetry and policy state.'}
      </p>
      {current?.command ? (
        <div className="mission-command">
          <code>{current.command}</code>
          <CopyCommandButton command={current.command} />
        </div>
      ) : null}
      <small>{current?.validation || 'Evidence export and SOC posture state are ready.'}</small>
      <div className="mission-proof-ledger">
        <b>Proof ledger</b>
        <span>{proofSummary}</span>
        {proofCurrent ? (
          <small>
            {proofCurrent.areaLabel || 'Readiness area'}: {proofCurrent.label || 'Evidence item'}
          </small>
        ) : (
          <small>All proof rows are verified.</small>
        )}
      </div>
    </div>
  );
}

function MissionLane({ lane }: { lane: MissionLaneInfo }) {
  return (
    <button className={`mission-lane ${readinessTone(lane.state)}`} type="button" role="listitem" onClick={() => jumpToTab(lane.targetTab || 'coverage')}>
      <span>{lane.label || 'Readiness area'}</span>
      <b>
        {num(lane.done)}/{num(lane.total)}
      </b>
      <small>{lane.nextStep || 'Complete'}</small>
    </button>
  );
}

function MissionBanner({ mission }: { mission: HardeningMission | null }) {
  if (!mission) {
    return (
      <div aria-live="polite">
        <EmptyState title="No mission" detail="Refresh posture." />
      </div>
    );
  }
  return (
    <div aria-live="polite">
      <div className={`hardening-mission ${readinessTone(mission.state)}`}>
        <MissionPrimary mission={mission} />
        <div className="mission-progress" role="list" aria-label="Hardening mission lanes">
          {(mission.lanes ?? []).map((lane) => (
            <MissionLane key={lane.id} lane={lane} />
          ))}
        </div>
      </div>
    </div>
  );
}

function HardeningList({ label, items, fallback }: { label: string; items?: string[]; fallback: string }) {
  const rows = items?.length ? items : [fallback];
  return (
    <div className="hardening-list">
      <b>{label}</b>
      <ul>
        {rows.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

interface OperatorStep {
  id: string;
  title: string;
  primary: string;
  meta: string;
  action: string;
  tone: string;
  target: string;
}

/** Pure derivation from posture sub-summaries (port of operator-flow.js operatorSteps). */
function operatorSteps(posture: Posture): OperatorStep[] {
  const threat = posture.threatGuardrails?.summary ?? {};
  const actions = posture.actionQueue ?? [];
  const inventory = posture.aiInventory?.summary ?? {};
  const behavior = posture.behaviorBaselines?.summary ?? {};
  const mcp = posture.agenticMcp?.summary ?? {};
  const graph = posture.controlGraph?.summary ?? {};
  const ledger = posture.hardening?.mission?.proofLedger ?? posture.hardening?.proofLedger ?? {};
  const critical = actions.filter((item) => item.severity === 'critical').length;
  const warning = actions.filter((item) => item.severity === 'warning').length;
  const routed = actions.filter((item) => ['assigned', 'snoozed', 'resolved'].includes(item.workflowStatus || '')).length;
  const highAssets = num(inventory.highRiskAssets) + num(inventory.unapprovedLocalTools);
  const threatOpen = num(threat.critical) + num(threat.blocked);
  const proofOpen = num(ledger.attention) + num(ledger.missing);
  const step = (id: string, title: string, primary: string, meta: string, action: string, tone: string, target: string): OperatorStep => ({
    id, title, primary: primary || '0', meta: meta || 'No open evidence', action, tone: tone || 'idle', target,
  });
  return [
    step('threats', 'Threat triage', `${num(threat.events)} events`, `${num(threat.activeRules)} rules / ${threatOpen} urgent`, 'Review threats', threatOpen ? 'critical' : num(threat.events) ? 'attention' : 'ready', 'threatGuardrailsRows'),
    step('baselines', 'Behavior baselines', `${num(behavior.anomalies)} anomalies`, `${num(behavior.critical)} critical / ${num(behavior.warning)} watch`, 'Review baselines', num(behavior.critical) ? 'critical' : num(behavior.warning) ? 'attention' : 'ready', 'behaviorBaselineRows'),
    step('actions', 'Hardening actions', `${actions.length} actions`, `${critical} critical / ${warning} warning / ${routed} routed`, 'Route actions', critical ? 'critical' : warning ? 'attention' : 'ready', 'hardeningActionQueue'),
    step('assets', 'AI vendor review', `${highAssets} high risk`, `${num(inventory.activeDestinations)} destinations / ${num(mcp.activeAgents)} agents`, 'Review vendors', highAssets > 0 ? 'critical' : 'ready', 'aiInventoryRows'),
    step('graph', 'Control graph', `${num(graph.highRiskAssets)} watched`, `${num(graph.nodes)} nodes / ${num(graph.controlledLinks)} controlled links`, 'Map control', num(graph.highRiskAssets) + num(graph.shadowAssets) > 0 ? 'critical' : 'ready', 'controlGraphMap'),
    step('soc', 'Examiner handoff', `${num(ledger.verified)} proof`, `${proofOpen} open / ${graph.privacy || 'metadata only'}`, 'Prepare evidence', proofOpen ? 'attention' : 'ready', 'siemPackagePreview'),
  ];
}

function OperatorFlow({ posture }: { posture: Posture | null }) {
  const rows = posture ? operatorSteps(posture) : [];
  const urgent = rows.filter((row) => row.tone === 'critical').length;
  const attention = rows.filter((row) => row.tone === 'attention').length;
  const ready = rows.filter((row) => row.tone === 'ready').length;
  return (
    <Section title="Operator Flow" summary={posture ? `${urgent} urgent / ${attention} attention / ${ready} ready` : 'Waiting for data'}>
      <div className="operator-flow-board" aria-live="polite">
        {posture ? (
          rows.map((row) => (
            <button key={row.id} className={`operator-flow-card ${row.tone}`} type="button" onClick={() => scrollToAnchor(row.target)}>
              <span>{row.title}</span>
              <strong>{row.primary}</strong>
              <small>{row.meta}</small>
              <b>{row.action}</b>
            </button>
          ))
        ) : (
          <EmptyState title="Waiting" detail="Posture refresh pending." />
        )}
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Action queue + objectives + AI inventory
// ---------------------------------------------------------------------------

interface WorkflowRunner {
  busyKey: string;
  run: (id: string, status: WorkflowStatus) => Promise<void>;
}

interface ActionRowProps {
  item: PostureAction;
  rank: number;
  isAdmin: boolean;
  workflow: WorkflowRunner;
}

function ActionControls({ item, isAdmin, workflow }: Omit<ActionRowProps, 'rank'>) {
  const workflowButton = (status: WorkflowStatus, label: string) => (
    <button
      className="ghost mini"
      type="button"
      disabled={!isAdmin || workflow.busyKey === `${item.id}:${status}`}
      onClick={() => void workflow.run(item.id, status)}
    >
      {label}
    </button>
  );
  return (
    <div className="action-controls">
      {item.command ? <code>{item.command}</code> : null}
      <TabJump tab={item.targetTab || 'coverage'} label={item.action || 'Open'} />
      {item.command ? <CopyCommandButton command={item.command} label="Copy command" /> : null}
      <div className="action-workflow-controls">
        {workflowButton('assigned', 'Assign to me')}
        {workflowButton('snoozed', 'Snooze')}
        {workflowButton('resolved', 'Log resolved')}
      </div>
    </div>
  );
}

function ActionRow({ item, rank, isAdmin, workflow }: ActionRowProps) {
  const severity = item.severity === 'critical' || item.severity === 'info' ? item.severity : 'warning';
  const meta = actionWorkflowMeta(item);
  return (
    <article className="action-row">
      <div className="action-rank">{rank}</div>
      <div className="action-main">
        <div className="action-kicker">
          <span>{item.category || 'Hardening'}</span>
          <b className={`action-severity ${severity}`}>{severity}</b>
          <b className={`action-workflow-pill ${actionWorkflowTone(item.workflowStatus)}`}>{actionWorkflowLabel(item.workflowStatus)}</b>
        </div>
        <strong>{item.label || 'Review hardening action'}</strong>
        <small>{item.detail || ''}</small>
        {meta ? <small className="action-workflow-meta">{meta}</small> : null}
      </div>
      <ActionControls item={item} isAdmin={isAdmin} workflow={workflow} />
    </article>
  );
}

function ActionQueueSection({ rows, isAdmin, workflow }: { rows: PostureAction[]; isAdmin: boolean; workflow: WorkflowRunner }) {
  const critical = rows.filter((item) => item.severity === 'critical').length;
  const warning = rows.filter((item) => item.severity === 'warning').length;
  const routed = rows.filter((item) => item.workflowStatus === 'assigned' || item.workflowStatus === 'snoozed').length;
  const summary = rows.length ? `${rows.length} actions / ${critical} critical / ${warning} warning / ${routed} routed` : 'All clear';
  return (
    <Section title="Exam Action Queue" summary={summary}>
      <div className="action-queue" id="hardeningActionQueue" aria-live="polite">
        {rows.length ? (
          rows.map((item, index) => <ActionRow key={item.id} item={item} rank={index + 1} isAdmin={isAdmin} workflow={workflow} />)
        ) : (
          <EmptyState title="No action gaps" detail="Hardening gaps are clear." />
        )}
      </div>
    </Section>
  );
}

function ObjectivesSection({ objectives }: { objectives: PostureObjective[] }) {
  const covered = objectives.filter((item) => item.state === 'covered').length;
  return (
    <Section title="Exam Posture Objectives" summary={objectives.length ? `${covered}/${objectives.length} covered` : 'Waiting for data'}>
      <div className="posture-objectives">
        {objectives.length ? (
          objectives.map((item) => (
            <article key={item.id} className={`objective-card ${item.state === 'covered' ? 'good' : 'warn'}`}>
              <div className="objective-score">
                <b>{num(item.score)}</b>
                <span>/100</span>
              </div>
              <div className="objective-body">
                <div className="objective-title">{item.label}</div>
                <div className="objective-detail">{item.detail}</div>
                <TabJump tab={item.targetTab || 'policy'} label={item.action || 'Open'} />
              </div>
            </article>
          ))
        ) : (
          <EmptyState title="No posture data" detail="Refresh posture." />
        )}
      </div>
    </Section>
  );
}

function InventoryRow({ item }: { item: InventoryItem }) {
  const status = item.status === 'online' || item.status === 'warning' ? item.status : 'idle';
  const state = item.state || 'unknown';
  const sideValue = item.kind === 'Endpoint tool' ? (state === 'local_unapproved' ? 'Review' : 'OK') : num(item.events);
  const riskLevel = ['critical', 'high', 'medium', 'low'].includes(item.riskLevel || '') ? String(item.riskLevel) : 'low';
  return (
    <article className={`ai-inventory-row ${status}`}>
      <div className="ai-inventory-main">
        <small>
          {item.kind || 'AI app'} / {item.source || 'coverage'}
        </small>
        <strong>{item.name || 'AI destination'}</strong>
        <span>{item.detail || 'No sanitized detail.'}</span>
        <span className={`ai-inventory-risk ${riskLevel}`}>
          {inventoryRiskLabel(riskLevel)} risk / {num(item.riskScore)}/100
          {item.riskReason ? ` / ${item.riskReason}` : ''}
        </span>
      </div>
      <div className="ai-inventory-side">
        <span className={`ai-inventory-state ${state}`}>{inventoryStateLabel(state)}</span>
        <b>{sideValue}</b>
        <TabJump tab={item.targetTab || 'coverage'} label={item.action || 'Open'} />
      </div>
    </article>
  );
}

function InventorySection({ inventory }: { inventory: AiInventoryReport | null }) {
  const summary = inventory?.summary ?? {};
  const rows = [...(inventory?.apps ?? []), ...(inventory?.tools ?? [])].slice(0, 12);
  const summaryText = inventory
    ? `${num(summary.sanctioned)} sanctioned / ${num(summary.shadow)} shadow / ${num(summary.highRiskAssets)} high risk`
    : 'Waiting for data';
  return (
    <Section title="AI Vendor Inventory" summary={summaryText}>
      <div className="ai-inventory-grid" id="aiInventoryRows" aria-live="polite">
        {rows.length ? (
          rows.map((item) => <InventoryRow key={item.id} item={item} />)
        ) : (
          <EmptyState title="No AI inventory" detail="No governed, shadow, or endpoint AI tools observed." />
        )}
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Agentic MCP control
// ---------------------------------------------------------------------------

const CONNECTOR_CATEGORY_ORDER = ['document_repository', 'collaboration', 'knowledge_base', 'database'];
const CONNECTOR_CATEGORY_LABELS: Record<string, string> = {
  document_repository: 'Documents',
  collaboration: 'Collaboration',
  knowledge_base: 'Knowledge Base',
  database: 'Database',
};

interface ConnectorReadiness {
  state: string;
  label: string;
  proof: string;
}

function connectorReadiness(item: ConnectorProfile): ConnectorReadiness {
  if (item.status === 'warning') return { state: 'warning', label: 'Check', proof: 'attention' };
  if (item.stage === 'shipped' && item.runtimePresent && item.configured) return { state: 'online', label: 'Configured', proof: 'runtime and env' };
  if (item.stage === 'shipped' && item.runtimePresent) {
    return { state: 'online', label: 'Runtime', proof: item.installProof ? 'install proof' : 'package proof' };
  }
  if (item.stage === 'shipped') return { state: 'warning', label: 'Registered', proof: 'runtime missing' };
  return item.configured ? { state: 'warning', label: 'Template', proof: 'env ready' } : { state: 'idle', label: 'Template', proof: 'profile only' };
}

function connectorGroups(profiles: ConnectorProfile[]): Array<[string, ConnectorProfile[]]> {
  const byCategory = new Map<string, ConnectorProfile[]>();
  for (const profile of profiles) {
    const key = profile.category || 'other';
    byCategory.set(key, [...(byCategory.get(key) ?? []), profile]);
  }
  const extras = [...byCategory.keys()].filter((key) => !CONNECTOR_CATEGORY_ORDER.includes(key));
  return [...CONNECTOR_CATEGORY_ORDER, ...extras]
    .filter((key) => byCategory.has(key))
    .map((key) => [key, byCategory.get(key) ?? []]);
}

function McpPanel({ title, count, extraClass, children }: { title: string; count: ReactNode; extraClass?: string; children: ReactNode }) {
  return (
    <section className={`agentic-mcp-panel${extraClass ? ` ${extraClass}` : ''}`}>
      <div className="agentic-mcp-panel-head">
        <strong>{title}</strong>
        <span>{count}</span>
      </div>
      {children}
    </section>
  );
}

function McpKpi({ label, value, meta }: { label: string; value: ReactNode; meta: string }) {
  return (
    <div className="agentic-mcp-kpi">
      <span>{label}</span>
      <b>{value}</b>
      <em>{meta}</em>
    </div>
  );
}

function McpReadinessRail({ registry }: { registry: ConnectorRegistrySummary }) {
  const shipped = num(registry.shipped);
  const runtime = num(registry.shippedRuntimePresent);
  const profiles = num(registry.profiles) || shipped;
  const templates = num(registry.profileTemplates);
  const next = registry.nextConnector || 'none';
  return (
    <div className="agentic-mcp-readiness">
      <div>
        <span>Catalog</span>
        <b>{shipped}/{profiles}</b>
        <small>{templates ? `${templates} templates` : 'all shipped'}</small>
      </div>
      <div>
        <span>Runtime</span>
        <b>{runtime}</b>
        <small>{runtime === shipped && shipped > 0 ? 'all packaged' : 'needs package proof'}</small>
      </div>
      <div>
        <span>Proof</span>
        <b>{registry.installProof ? 'Heartbeat' : 'Package'}</b>
        <small>{registry.installProof ? 'registry heartbeat' : 'local registry'}</small>
      </div>
      <div>
        <span>Next</span>
        <b>{next === 'none' ? 'Complete' : next}</b>
        <small>{next === 'none' ? 'no template gap' : 'connector gap'}</small>
      </div>
    </div>
  );
}

function ConnectorRow({ item }: { item: ConnectorProfile }) {
  const readiness = connectorReadiness(item);
  const operations = item.operations?.length ? item.operations.join(', ') : 'guarded tool path';
  return (
    <button className={`agentic-mcp-row connector ${readiness.state}`} type="button" onClick={() => jumpToTab('monitor')}>
      <span>{readiness.label}</span>
      <strong>{item.label || item.id || 'connector'}</strong>
      <small>
        {operations} / {readiness.proof}
      </small>
      <b>{num(item.scopeCount)}</b>
    </button>
  );
}

function ConnectorCatalog({ profiles, registry }: { profiles: ConnectorProfile[]; registry: ConnectorRegistrySummary }) {
  return (
    <McpPanel title="Connector Catalog" count={`${num(registry.shipped)}/${num(registry.profiles)}`} extraClass="agentic-mcp-connectors">
      {profiles.length ? (
        connectorGroups(profiles).map(([category, items]) => (
          <section key={category} className="agentic-mcp-category">
            <div className="agentic-mcp-category-head">
              <strong>{CONNECTOR_CATEGORY_LABELS[category] || 'Connectors'}</strong>
              <span>
                {items.filter((item) => connectorReadiness(item).state === 'online').length}/{items.length}
              </span>
            </div>
            <div className="agentic-mcp-list">
              {items.map((item) => (
                <ConnectorRow key={item.id} item={item} />
              ))}
            </div>
          </section>
        ))
      ) : (
        <EmptyState title="No connectors" detail="Connector profiles appear after the MCP registry loads." />
      )}
    </McpPanel>
  );
}

function McpDataRow({ item, kind }: { item: McpRow; kind: 'agent' | 'tool' }) {
  const agent = kind === 'agent';
  return (
    <button className={`agentic-mcp-row ${mcpRowStatus(item)}`} type="button" onClick={() => jumpToTab(agent ? 'lineage' : 'policy')}>
      <span>{mcpStateLabel(item.state || 'observed')}</span>
      <strong>{item.name || (agent ? 'mcp-agent' : 'mcp-tool')}</strong>
      <small>{item.detail || 'No sanitized detail.'}</small>
      <b>{agent ? `${num(item.riskScore)}/100` : num(item.events)}</b>
    </button>
  );
}

function McpPolicyRow({ title, bucket }: { title: string; bucket?: McpPolicyBucket }) {
  const examples = bucket?.examples ?? [];
  return (
    <div className="agentic-mcp-policy-row">
      <span>{title}</span>
      <b>{num(bucket?.count)}</b>
      <small>{examples.length ? examples.join(', ') : 'none'}</small>
    </div>
  );
}

function McpPolicyPanel({ policy, requests }: { policy: McpPolicyInfo; requests: McpRequestRow[] }) {
  return (
    <McpPanel title="Policy" count={policy.registryMode || 'observe'}>
      <div className="agentic-mcp-policy">
        <McpPolicyRow title="Allowed" bucket={policy.allowed} />
        <McpPolicyRow title="Blocked" bucket={policy.blocked} />
        <McpPolicyRow title="Approval" bucket={policy.approvalRequired} />
      </div>
      <div className="agentic-mcp-requests">
        {requests.length ? (
          requests.map((request) => (
            <div key={request.id} className="agentic-mcp-request">
              <span>{request.label || 'Request'}</span>
              <b>{num(request.events)}</b>
              <small>{mcpStateLabel(request.state || 'observed')}</small>
            </div>
          ))
        ) : (
          <EmptyState title="No requests" detail="No MCP request classes observed." />
        )}
      </div>
    </McpPanel>
  );
}

function AgenticMcpBody({ mcp }: { mcp: AgenticMcpReport }) {
  const summary = mcp.summary ?? {};
  const registry = mcp.connectorRegistry?.summary ?? {};
  const policy = mcp.policy ?? {};
  const agents = mcp.agents ?? [];
  const tools = mcp.tools ?? [];
  return (
    <>
      <McpReadinessRail registry={registry} />
      <div className="agentic-mcp-kpis">
        <McpKpi label="Events" value={num(summary.events)} meta={summary.registryMode || 'observe'} />
        <McpKpi label="Controlled" value={num(summary.controlled)} meta={`${num(summary.blocked)} blocked`} />
        <McpKpi label="Runtime" value={num(registry.shippedRuntimePresent)} meta={`${num(registry.shipped)} shipped`} />
        <McpKpi label="Policy" value={policy.registryMode || 'observe'} meta={`${num(policy.allowed?.count)} allowed`} />
      </div>
      <div className="agentic-mcp-layout">
        <ConnectorCatalog profiles={mcp.connectorRegistry?.profiles ?? []} registry={registry} />
        <McpPanel title="Agents" count={agents.length}>
          <div className="agentic-mcp-list">
            {agents.length ? (
              agents.slice(0, 6).map((item) => <McpDataRow key={item.id} item={item} kind="agent" />)
            ) : (
              <EmptyState title="No agents" detail="No MCP agents have reported through the guard." />
            )}
          </div>
        </McpPanel>
        <McpPanel title="Tools" count={tools.length}>
          <div className="agentic-mcp-list">
            {tools.length ? (
              tools.slice(0, 8).map((item) => <McpDataRow key={item.id} item={item} kind="tool" />)
            ) : (
              <EmptyState title="No tools" detail="No MCP tools have enough evidence yet." />
            )}
          </div>
        </McpPanel>
        <McpPolicyPanel policy={policy} requests={mcp.requests ?? []} />
      </div>
    </>
  );
}

function agenticMcpSummary(mcp: AgenticMcpReport): string {
  const summary = mcp.summary ?? {};
  const registry = mcp.connectorRegistry?.summary ?? {};
  const templates = num(registry.profileTemplates);
  return [
    `${num(summary.activeAgents)} agents`,
    `${num(summary.activeTools)} tools`,
    `${num(summary.controlled)} controlled`,
    `${num(registry.shipped)} shipped connectors`,
    templates ? `${templates} template gaps` : 'catalog shipped',
    summary.privacy || 'prompt bodies excluded',
  ].join(' / ');
}

function AgenticMcpSection({ mcp }: { mcp: AgenticMcpReport | null }) {
  return (
    <Section title="Agentic MCP Control" summary={mcp ? agenticMcpSummary(mcp) : 'Waiting for data'}>
      <div className="agentic-mcp-board" id="agenticMcpRows" aria-live="polite">
        {mcp ? <AgenticMcpBody mcp={mcp} /> : <EmptyState title="No MCP control data" detail="MCP guard traffic and policy state will appear after posture refresh." />}
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// AI threat guardrails + control graph
// ---------------------------------------------------------------------------

function ThreatRuleRow({ rule }: { rule: ThreatRule }) {
  return (
    <button
      className={`agentic-mcp-row threat-guardrail-row ${threatStatus(rule)}`}
      type="button"
      title={rule.detail || ''}
      onClick={() => jumpToTab(rule.targetTab || 'activity')}
    >
      <span>{rule.framework || 'AI risk'}</span>
      <strong>{rule.label || 'Guardrail'}</strong>
      <small>{rule.detail || 'No sanitized detail.'}</small>
      <b>{num(rule.events)}</b>
    </button>
  );
}

function ThreatControlRow({ control }: { control: ThreatControl }) {
  return (
    <button className="agentic-mcp-policy-row threat-guardrail-control" type="button" onClick={() => jumpToTab(control.targetTab || 'policy')}>
      <span>{control.label || 'Control'}</span>
      <b>{threatStateLabel(control.state)}</b>
      <small>{control.detail || 'No detail.'}</small>
    </button>
  );
}

function ThreatRecentRow({ event }: { event: ThreatRecent }) {
  const threats = event.threats?.length ? event.threats.join(', ') : 'AI threat';
  return (
    <button
      className={`agentic-mcp-row threat-guardrail-row ${threatStatus(event)}`}
      type="button"
      title={event.detail || ''}
      onClick={() => jumpToTab('activity')}
    >
      <span>{event.decision || event.severity || 'event'}</span>
      <strong>{event.title || 'Threat event'}</strong>
      <small>
        {threats} / {event.destination || 'unknown'} / {event.detail || 'raw content excluded'}
      </small>
      <b>{event.severity || 'info'}</b>
    </button>
  );
}

function ThreatColumns({ data }: { data: ThreatGuardrailsReport }) {
  const rules = data.rules ?? [];
  const controls = data.controls ?? [];
  const recent = data.recent ?? [];
  return (
    <div className="agentic-mcp-columns">
      <McpPanel title="Guardrails" count={rules.filter((rule) => num(rule.events) > 0).length}>
        <div className="agentic-mcp-list">
          {rules.length ? (
            rules.slice(0, 6).map((rule) => <ThreatRuleRow key={rule.id} rule={rule} />)
          ) : (
            <EmptyState title="No active rules" detail="No AI threat guardrail evidence yet." />
          )}
        </div>
      </McpPanel>
      <McpPanel title="Controls" count={controls.length}>
        <div className="agentic-mcp-policy">
          {controls.length ? (
            controls.map((control, index) => <ThreatControlRow key={index} control={control} />)
          ) : (
            <EmptyState title="No controls" detail="Policy guardrail controls are not available." />
          )}
        </div>
      </McpPanel>
      <McpPanel title="Recent" count={recent.length}>
        <div className="agentic-mcp-list">
          {recent.length ? (
            recent.map((event) => <ThreatRecentRow key={event.id} event={event} />)
          ) : (
            <EmptyState title="No recent threats" detail="Recent AI threat events will appear here." />
          )}
        </div>
      </McpPanel>
    </div>
  );
}

function ThreatGuardrailsSection({ data }: { data: ThreatGuardrailsReport | null }) {
  const summary = data?.summary ?? {};
  const summaryText = data
    ? `${num(summary.events)} events / ${num(summary.activeRules)} active rules / ${summary.privacy || 'prompt bodies excluded'}`
    : 'Waiting for data';
  return (
    <Section title="AI Threat Guardrails" summary={summaryText}>
      <div className="agentic-mcp-board" id="threatGuardrailsRows" aria-live="polite">
        {data ? (
          <>
            <div className="agentic-mcp-kpis">
              <McpKpi label="Events" value={num(summary.events)} meta={`${num(summary.detections)} detections`} />
              <McpKpi label="Critical" value={num(summary.critical)} meta={`${num(summary.blocked)} blocked`} />
              <McpKpi label="Injection" value={num(summary.promptInjection)} meta="OWASP LLM01" />
              <McpKpi label="Unsafe output" value={num(summary.unsafeOutput)} meta="response scan" />
            </div>
            <ThreatColumns data={data} />
          </>
        ) : (
          <EmptyState title="No AI threat data" detail="Threat guardrails appear after posture refresh." />
        )}
      </div>
    </Section>
  );
}

function GraphLane({ lane, nodes }: { lane: GraphLaneInfo; nodes: GraphNode[] }) {
  return (
    <section className="control-graph-lane">
      <div className="control-graph-lane-head">
        <div>
          <strong>{lane.label || 'Lane'}</strong>
          <small>{lane.detail || ''}</small>
        </div>
        <b>{num(lane.count) || nodes.length}</b>
      </div>
      <div className="control-graph-node-list">
        {nodes.length ? (
          nodes.map((node) => (
            <button
              key={node.id}
              className={`control-graph-node ${graphStatus(node.status)}`}
              type="button"
              title={node.detail || ''}
              onClick={() => jumpToTab(node.targetTab || 'monitor')}
            >
              <span>{node.kind || node.lane || 'node'}</span>
              <strong>{node.label || 'Unknown'}</strong>
              <small>{node.detail || 'Awaiting proof'}</small>
            </button>
          ))
        ) : (
          <EmptyState title="Empty" detail="No sanitized evidence." />
        )}
      </div>
    </section>
  );
}

function GraphEdges({ edges, nodes, summary }: { edges: GraphEdge[]; nodes: GraphNode[]; summary: GraphSummaryInfo }) {
  const labelFor = (id?: string) => nodes.find((node) => node.id === id)?.label ?? id ?? '';
  return (
    <section className="control-graph-edges">
      <div className="control-graph-edges-head">
        <strong>Highest-risk links</strong>
        <span>
          {num(summary.controlledLinks)} controlled / {num(summary.mcpLinks)} MCP
        </span>
      </div>
      {edges.length ? (
        edges.slice(0, 10).map((edge) => (
          <div key={edge.id} className={`control-graph-edge ${graphStatus(edge.status)}`}>
            <span>{edge.status || 'idle'}</span>
            <div>
              <strong>
                {labelFor(edge.from)} -&gt; {labelFor(edge.to)}
              </strong>
              <small>
                {edge.label || 'flow'} / {edge.detail || 'sanitized metadata only'}
              </small>
            </div>
            <b>{num(edge.events)}</b>
          </div>
        ))
      ) : (
        <EmptyState title="No links" detail="Awaiting links." />
      )}
    </section>
  );
}

function ControlGraphSection({ graph }: { graph: ControlGraphReport | null }) {
  const summary = graph?.summary ?? {};
  const lanes = graph?.lanes ?? [];
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const summaryText = graph
    ? `${num(summary.nodes)} nodes / ${num(summary.edges)} links / ${num(summary.highRiskAssets)} high risk / ${summary.privacy || 'prompt bodies excluded'}`
    : 'Waiting for data';
  const empty = !graph || (!nodes.length && !edges.length);
  return (
    <Section title="AI Control Graph" summary={summaryText}>
      <div className="control-graph" id="controlGraphMap" aria-live="polite">
        {empty ? (
          <EmptyState title="No graph" detail="Awaiting events." />
        ) : (
          <>
            <div className="control-graph-lanes">
              {lanes.map((lane) => (
                <GraphLane key={lane.id} lane={lane} nodes={nodes.filter((node) => (node.lane || 'assets') === lane.id)} />
              ))}
            </div>
            <GraphEdges edges={edges} nodes={nodes} summary={summary} />
          </>
        )}
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Hardening workbench + SOC snapshot
// ---------------------------------------------------------------------------

function ProofLedgerBlock({ ledger, proofs }: { ledger: ProofLedger; proofs: ProofItem[] }) {
  return (
    <div className="hardening-proof-ledger">
      <div className="proof-ledger-head">
        <b>Evidence ledger</b>
        <span>
          {num(ledger.verified)} verified / {num(ledger.attention)} attention / {num(ledger.missing)} missing
        </span>
      </div>
      {proofs.length ? (
        proofs.map((proof, index) => (
          <div key={proof.id ?? index} className={`proof-row ${proof.status || 'missing'}`}>
            <span>{proofStatusLabel(proof.status)}</span>
            <div>
              <strong>{proof.label || 'Evidence item'}</strong>
              <small>
                {proof.detail || ''}
                {proof.evidenceAt ? ` / ${fmt(proof.evidenceAt)}` : ''}
              </small>
            </div>
          </div>
        ))
      ) : (
        <p className="hardening-step-empty">No proof rows published.</p>
      )}
    </div>
  );
}

function RunbookBlock({ steps }: { steps: PlaybookStep[] }) {
  return (
    <div className="hardening-runbook">
      <b>Runbook</b>
      {steps.length ? (
        steps.map((step, index) => (
          <div key={step.id ?? index} className={`hardening-step ${step.status || 'todo'}`}>
            <div className="hardening-step-head">
              <span>{step.status || 'todo'}</span>
              <strong>{step.label || 'Remediation step'}</strong>
            </div>
            <p>{step.detail || ''}</p>
            {step.command ? <code>{step.command}</code> : null}
            <small>{step.validation || ''}</small>
          </div>
        ))
      ) : (
        <p className="hardening-step-empty">No remediation steps published.</p>
      )}
    </div>
  );
}

function HardeningAreaCard({ area }: { area: HardeningArea }) {
  const status = area.state === 'ready' ? 'online' : area.state === 'blocked' ? 'error' : 'warning';
  return (
    <article className={`hardening-card ${readinessTone(area.state)}`}>
      <div className="hardening-head">
        <div className="hardening-title">
          <SignalDot status={status} label={`${area.label || ''} ${area.state || ''}`} />
          <strong>{area.label || ''}</strong>
        </div>
        <div className="hardening-score">
          {num(area.score)}
          <span>/100</span>
        </div>
      </div>
      <p className="hardening-desc">{area.description || ''}</p>
      <div className="hardening-meta">
        <span>{area.owner || 'security'}</span>
        <span>{area.source || 'control'}</span>
      </div>
      <div className="hardening-lists">
        <HardeningList label="Proof" items={area.evidence?.slice(0, 3)} fallback="Awaiting proof" />
        <HardeningList label="Gaps" items={area.gaps?.slice(0, 3)} fallback="No open gaps" />
      </div>
      <ProofLedgerBlock ledger={area.proofLedger ?? {}} proofs={(area.proofs ?? []).slice(0, 6)} />
      <RunbookBlock steps={(area.playbook ?? []).slice(0, 5)} />
      <TabJump tab={area.targetTab || 'coverage'} label={area.action || 'Open'} />
    </article>
  );
}

function WorkbenchSection({ hardening, isAdmin, snapshot }: { hardening: HardeningReport | null; isAdmin: boolean; snapshot: SnapshotControl }) {
  const areas = hardening?.areas ?? [];
  const ready = areas.filter((area) => area.state === 'ready').length;
  const summary = areas.length ? `${ready}/${areas.length} ready / ${num(hardening?.score)} overall` : 'Waiting for data';
  const actions = (
    <div className="signal-header-actions">
      <span className="signal-updated">{snapshot.status}</span>
      <button
        className="system-button secondary"
        type="button"
        disabled={snapshot.sending || !isAdmin}
        aria-busy={snapshot.sending}
        title={isAdmin ? 'Send sanitized posture snapshot' : 'Security Admin required'}
        onClick={() => void snapshot.send()}
      >
        {snapshot.sending ? (
          <>
            <span className="button-spinner" aria-hidden="true" />
            Sending
          </>
        ) : (
          'Send SOC snapshot'
        )}
      </button>
    </div>
  );
  return (
    <Section title="Hardening Workbench" summary={summary} actions={actions}>
      <div className="hardening-board" aria-live="polite">
        {areas.length ? (
          areas.map((area) => <HardeningAreaCard key={area.id} area={area} />)
        ) : (
          <EmptyState title="No hardening data" detail="Refresh readiness." />
        )}
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// SOC integration pack
// ---------------------------------------------------------------------------

const SIEM_PROFILES: Array<{ value: string; label: string }> = [
  { value: 'all', label: 'All profiles' },
  { value: 'splunk', label: 'Splunk' },
  { value: 'sentinel', label: 'Microsoft Sentinel' },
  { value: 'chronicle', label: 'Google SecOps' },
  { value: 'servicenow', label: 'ServiceNow' },
];

function siemSummary(siem: SiemState, canUse: boolean): string {
  if (!canUse) return 'Security Admin or Auditor required';
  if (siem.loading) return 'Preparing package';
  if (siem.error) return `Package error - ${humanize(siem.error)}`.slice(0, 80);
  const profiles = siem.pkg?.profiles ?? [];
  if (!profiles.length) return 'Waiting for package';
  const counts = siem.pkg?.summary ?? {};
  return `${profiles.length} profile${profiles.length === 1 ? '' : 's'} / ${num(counts.searches)} searches / ${num(counts.packageFiles)} files`;
}

function SiemSidebar({ counts, privacy, profileCount }: { counts: { searches?: number; samplePayloads?: number; packageFiles?: number }; privacy: SiemPrivacyFlags; profileCount: number }) {
  const flag = (value?: boolean) => (value === false ? 'omitted' : 'check');
  return (
    <aside className="siem-package-sidebar">
      <div className="siem-kpi-grid">
        <div className="siem-kpi">
          <span>Profiles</span>
          <b>{profileCount}</b>
        </div>
        <div className="siem-kpi">
          <span>Searches</span>
          <b>{num(counts.searches)}</b>
        </div>
        <div className="siem-kpi">
          <span>Samples</span>
          <b>{num(counts.samplePayloads)}</b>
        </div>
        <div className="siem-kpi">
          <span>Files</span>
          <b>{num(counts.packageFiles)}</b>
        </div>
      </div>
      <div className="siem-privacy-list">
        <span>
          Raw prompts <b>{flag(privacy.rawPromptBodies)}</b>
        </span>
        <span>
          Token vaults <b>{flag(privacy.tokenVaultValues)}</b>
        </span>
        <span>
          Raw findings <b>{flag(privacy.rawFindingValues)}</b>
        </span>
        <span>
          URL paths/files <b>{flag(privacy.rawUrlsOrFilePaths)}</b>
        </span>
      </div>
    </aside>
  );
}

function SiemProfileRow({ profile }: { profile: SiemProfile }) {
  const searches = [...(profile.savedSearches ?? []), ...(profile.detections ?? [])];
  const panels = [...(profile.dashboardPanels ?? []), ...(profile.workbookPanels ?? []), ...(profile.incidentTemplates ?? [])];
  const first = searches[0] ?? {};
  const ready = first.name || first.udmSearch || first.spl || first.kql || 'Field mappings ready';
  const check = profile.setupChecklist?.[0] || 'Setup checklist ready';
  const transport = profile.transport ?? {};
  return (
    <article className="siem-profile-row">
      <div className="siem-profile-head">
        <div>
          <strong>{profile.label || profile.id}</strong>
          <span>{profile.target || ''}</span>
        </div>
        <span className="status-chip tone-secure" title="Package contains sanitized samples, mappings, searches, and setup files.">
          <span className="status-light tone-secure" aria-hidden="true" />
          ZIP ready
        </span>
      </div>
      <div className="siem-profile-meta">
        <span>{(profile.fieldMappings ?? []).length} mappings</span>
        <span>{(profile.samplePayloads ?? []).length} samples</span>
        <span>{searches.length} searches</span>
        <span>{panels.length} panels</span>
      </div>
      <p>{transport.ingestion || transport.endpointPath || transport.method || 'Offline setup package'}</p>
      <div className="siem-search-list">
        <b>Ready content</b>
        <ul>
          <li>{ready}</li>
          <li>{check}</li>
        </ul>
      </div>
    </article>
  );
}

function SiemBody({ siem, canUse }: { siem: SiemState; canUse: boolean }) {
  if (!canUse) return <EmptyState title="Access required" detail="SIEM and SOAR packages are available to Security Admins and Auditors." />;
  if (siem.loading) return <EmptyState title="Preparing package" detail="Generating sanitized mappings, searches, and setup checks." />;
  if (siem.error) return <EmptyState title={`Package error - ${humanize(siem.error)}`.slice(0, 80)} detail="Refresh or choose a supported profile." />;
  const profiles = siem.pkg?.profiles ?? [];
  if (!profiles.length) return <EmptyState title="Waiting for package" detail="Refresh the command center to build the SOC package." />;
  return (
    <>
      <SiemSidebar counts={siem.pkg?.summary ?? {}} privacy={siem.pkg?.privacy ?? {}} profileCount={profiles.length} />
      <div className="siem-profile-list">
        {profiles.map((profile) => (
          <SiemProfileRow key={profile.id} profile={profile} />
        ))}
      </div>
    </>
  );
}

function SiemSection({ siem, canUse }: { siem: SiemState; canUse: boolean }) {
  const busy = siem.loading || siem.downloading;
  const actions = (
    <div className="signal-header-actions">
      <label className="siem-profile-select">
        Profile
        <select value={siem.profile} disabled={busy || !canUse} aria-label="SIEM package profile" onChange={(event) => siem.setProfile(event.target.value)}>
          {SIEM_PROFILES.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <button
        className="system-button secondary"
        type="button"
        disabled={busy || !canUse || Boolean(siem.error)}
        aria-busy={busy}
        onClick={() => void siem.download()}
      >
        {busy ? (
          <>
            <span className="button-spinner" aria-hidden="true" />
            {siem.loading ? 'Preparing' : 'Downloading'}
          </>
        ) : (
          'Download ZIP'
        )}
      </button>
    </div>
  );
  return (
    <Section title="SOC Integration Pack" summary={siemSummary(siem, canUse)} actions={actions}>
      <div className="siem-package-board" id="siemPackagePreview" aria-live="polite">
        <SiemBody siem={siem} canUse={canUse} />
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Insight grid: trend, control outcomes, baselines, decision quality, feedback
// ---------------------------------------------------------------------------

function TrendDayCol({ row, max }: { row: TrendDay; max: number }) {
  const events = num(row.events);
  const height = Math.max(5, Math.round((events / max) * 100));
  const share = (part: number) => (events ? Math.max(4, Math.round((part / events) * height)) : 0);
  const detail = `${row.date}: ${events} events, ${num(row.blocked)} blocked, ${num(row.redacted)} redacted, ${num(row.coached)} coached, ${num(row.allowed)} allowed`;
  return (
    <div className="trend-day" tabIndex={0} role="img" aria-label={detail} data-tooltip={detail}>
      <div className="trend-stack" style={{ '--h': `${height}%` } as CSSProperties}>
        <i className="trend-blocked" style={{ '--share': `${share(num(row.blocked))}%` } as CSSProperties} />
        <i className="trend-redacted" style={{ '--share': `${share(num(row.redacted))}%` } as CSSProperties} />
        <i className="trend-coached" style={{ '--share': `${share(num(row.coached))}%` } as CSSProperties} />
        <i className="trend-allowed" style={{ '--share': `${share(num(row.allowed))}%` } as CSSProperties} />
      </div>
      <span>{String(row.date || '').slice(5)}</span>
    </div>
  );
}

function TrendSection({ trend }: { trend: TrendDay[] }) {
  const max = Math.max(1, ...trend.map((row) => num(row.events)));
  const total = trend.reduce((sum, row) => sum + num(row.events), 0);
  return (
    <Section title="Risk Trend" summary={trend.length ? `${total} events / ${trend.length} days` : 'Waiting for data'}>
      <div className="trend-chart" aria-live="polite">
        {trend.length ? (
          trend.map((row, index) => <TrendDayCol key={row.date ?? index} row={row} max={max} />)
        ) : (
          <EmptyState title="No trend data" detail="Recent activity appears here." />
        )}
      </div>
    </Section>
  );
}

function ControlOutcomesSection({ controls }: { controls: ControlOutcome[] }) {
  const total = controls.reduce((sum, row) => sum + num(row.events), 0);
  return (
    <Section title="Control Outcomes" summary={controls.length ? `${controls.length} control paths` : 'Waiting for data'}>
      <div className="control-breakdown" aria-live="polite">
        {controls.length ? (
          controls.map((row) => {
            const events = num(row.events);
            const controlled = num(row.blocked) + num(row.redacted) + num(row.coached);
            return (
              <MeterRow
                key={row.label}
                label={row.label}
                side={`${controlled} controlled / ${events} events`}
                width={total ? Math.max(5, Math.round((events / total) * 100)) : 0}
                ariaLabel={`${row.label} ${events} events`}
              />
            );
          })
        ) : (
          <EmptyState title="No outcomes" detail="Awaiting controls." />
        )}
      </div>
    </Section>
  );
}

function BehaviorBaselinesSection({ baselines }: { baselines: BehaviorBaselinesReport | null }) {
  const summary = baselines?.summary ?? {};
  const rows = (baselines?.dimensions ?? []).slice(0, 6);
  const summaryText = baselines
    ? `${num(summary.anomalies)} anomalies / ${num(summary.critical)} critical / ${num(summary.warning)} watch`
    : 'Waiting for data';
  return (
    <Section title="Behavior Baselines" summary={summaryText}>
      <div className="control-breakdown behavior-baselines" id="behaviorBaselineRows" aria-live="polite">
        {rows.length ? (
          rows.map((item) => (
            <button key={item.id} className={`behavior-baseline-row ${baselineTone(item.state)}`} type="button" onClick={() => jumpToTab(item.targetTab || 'activity')}>
              <span>{baselineStateLabel(item.state)}</span>
              <strong>{item.title || 'Behavior baseline'}</strong>
              <small>
                {item.label || 'metadata'} / {item.detail || 'No unusual change'}
              </small>
              <b>{num(item.score)}</b>
            </button>
          ))
        ) : (
          <EmptyState title="No behavior anomalies" detail="Recent metadata matches the learned baseline." />
        )}
      </div>
    </Section>
  );
}

const dqTone = (state?: string) => `tone-${state === 'ready' ? 'secure' : state === 'blocked' ? 'critical' : 'warn'}`;

function DecisionQualitySection({ quality }: { quality: DecisionQualityInfo | null }) {
  const summary = quality?.summary ?? null;
  const cards = quality?.cards ?? [];
  const hotspots = (quality?.hotspots ?? []).slice(0, 4);
  const summaryText = summary
    ? `${num(summary.controlRate)}% controlled / ${num(summary.pendingReviews)} pending / ${num(summary.overrideWatch)} overrides`
    : 'Waiting for data';
  return (
    <Section title="Reviewer Decision Quality" summary={summaryText}>
      <div className="control-breakdown" id="decisionQualityRows" aria-live="polite">
        {!summary ? (
          <EmptyState title="No reviewer decision data" detail="Recent approval, coaching, and override outcomes appear here." />
        ) : (
          <>
            {cards.map((card) => (
              <MeterRow
                key={card.id}
                label={card.label}
                side={`${card.value ?? ''} / ${num(card.score)}/100`}
                width={clampPct(num(card.score))}
                tone={dqTone(card.state)}
                ariaLabel={`${card.label} ${num(card.score)} out of 100`}
                detail={card.detail || ''}
              />
            ))}
            {hotspots.length ? (
              <div className="control-row">
                <div>
                  <strong>Member-Data Decision Hotspots</strong>
                  <span>metadata only</span>
                </div>
              </div>
            ) : null}
            {hotspots.map((item) => (
              <MeterRow
                key={item.id}
                label={item.label}
                side={`${item.kind || ''} / ${num(item.events)} events`}
                width={clampPct(num(item.sensitive))}
                ariaLabel={`${item.label} ${num(item.events)} events`}
                detail={item.detail || 'metadata-only hotspot'}
              />
            ))}
          </>
        )}
      </div>
    </Section>
  );
}

function FeedbackBar({ label, value, total, detail, state }: { label: string; value: number; total: number; detail: string; state: string }) {
  const width = total ? Math.max(5, Math.min(100, Math.round((value / total) * 100))) : 5;
  const tone = state === 'attention' ? 'tone-warn' : state === 'ready' ? 'tone-secure' : '';
  return <MeterRow label={label} side={`${value}/${total}`} width={width} tone={tone} ariaLabel={`${label} ${value} of ${total}`} detail={detail} />;
}

function QualityBars({ quality }: { quality: FeedbackQualitySummary }) {
  const failures = num(quality.failures);
  const falsePositives = num(quality.benignFalsePositives) + num(quality.baitFalsePositives);
  return (
    <>
      <FeedbackBar
        label="Held-out Eval"
        value={num(quality.score)}
        total={100}
        detail={quality.floorsMet ? 'floors met' : `${failures} floor gap${failures === 1 ? '' : 's'}`}
        state={quality.floorsMet ? 'ready' : 'attention'}
      />
      <FeedbackBar
        label="Semantic Recall"
        value={num(quality.semanticRecall)}
        total={100}
        detail={`${num(quality.semanticPrecision)}% precision`}
        state={num(quality.semanticRecall) >= 70 ? 'ready' : 'attention'}
      />
      <FeedbackBar
        label="Structured Recall"
        value={num(quality.structuredRecall)}
        total={100}
        detail={`${num(quality.structuredF1)}% F1`}
        state={num(quality.structuredRecall) >= 95 ? 'ready' : 'attention'}
      />
      <FeedbackBar
        label="False Positives"
        value={falsePositives}
        total={1}
        detail="benign plus structured bait"
        state={falsePositives === 0 ? 'ready' : 'attention'}
      />
    </>
  );
}

function CandidateRow({ item, verdicts }: { item: FeedbackCandidate; verdicts: VerdictControl }) {
  const verdictButton = (verdict: 'valid' | 'false_positive', label: string) => {
    const state = verdicts.states.get(`${item.queryId}:${item.detectorId}:${verdict}`);
    return (
      <button className="ghost mini" type="button" disabled={state === 'busy'} onClick={() => void verdicts.submit(item.queryId, item.detectorId, verdict)}>
        {state === 'failed' ? 'Retry' : label}
      </button>
    );
  };
  return (
    <div className="control-row">
      <div>
        <strong>{item.detectorId}</strong>
        <span>
          {item.destination || ''} / {item.status || ''}
        </span>
      </div>
      <div className="control-bar" role="img" aria-label={`${item.detectorId} risk ${num(item.riskScore)}`}>
        <i style={{ '--w': `${clampPct(num(item.riskScore))}%` } as CSSProperties} />
      </div>
      <span>{item.detectorIds?.join(', ') || 'detector'}</span>
      <div className="action-workflow-controls">
        {verdictButton('valid', 'Valid')}
        {verdictButton('false_positive', 'Noisy')}
      </div>
    </div>
  );
}

function detectorFeedbackSummary(report: FeedbackReport | null): string {
  const summary = report?.summary;
  if (!summary) return 'Waiting for data';
  const counts = `${num(summary.noisy)} noisy / ${num(summary.valid)} valid / ${num(summary.reviewCandidates)} candidates`;
  const quality = report?.quality?.summary;
  return quality ? `${num(quality.score)}/100 eval / ${counts}` : counts;
}

function DetectorFeedbackSection({ report, verdicts }: { report: FeedbackReport | null; verdicts: VerdictControl }) {
  const summary = report?.summary ?? null;
  const quality = report?.quality?.summary ?? null;
  const detectors = (report?.detectors ?? []).slice(0, 4);
  const candidates = (report?.reviewQueue ?? []).slice(0, 4);
  return (
    <Section title="Detection Feedback" summary={detectorFeedbackSummary(report)}>
      <div className="control-breakdown" id="detectorFeedbackRows" aria-live="polite">
        {!summary ? (
          <EmptyState title="No detector feedback" detail="Validated and noisy detections appear here without prompt bodies." />
        ) : (
          <>
            {quality ? <QualityBars quality={quality} /> : null}
            {detectors.length ? (
              detectors.map((row) => (
                <FeedbackBar
                  key={row.detectorId}
                  label={row.detectorId}
                  value={num(row.falsePositive) + num(row.tooSensitive)}
                  total={num(row.total)}
                  detail={row.detail || ''}
                  state={row.state || ''}
                />
              ))
            ) : (
              <EmptyState title="No scored detectors" detail="Submit feedback from candidates below." />
            )}
            {candidates.length ? (
              <div className="control-row">
                <div>
                  <strong>Review Candidates</strong>
                  <span>metadata only</span>
                </div>
              </div>
            ) : null}
            {candidates.map((item) => (
              <CandidateRow key={`${item.queryId}:${item.detectorId}`} item={item} verdicts={verdicts} />
            ))}
          </>
        )}
      </div>
    </Section>
  );
}

function InsightGrid({ report, feedback, verdicts }: { report: Posture | null; feedback: FeedbackReport | null; verdicts: VerdictControl }) {
  return (
    <div className="signal-insight-grid">
      <TrendSection trend={report?.trend ?? []} />
      <ControlOutcomesSection controls={report?.controls ?? []} />
      <BehaviorBaselinesSection baselines={report?.behaviorBaselines ?? null} />
      <DecisionQualitySection quality={report?.decisionQuality ?? null} />
      <DetectorFeedbackSection report={feedback} verdicts={verdicts} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Signal layout: surfaces grid + activity feed + inspector
// ---------------------------------------------------------------------------

function SurfacePanel({ item, ui }: { item: PostureSurfaceInfo; ui: MonitorUi }) {
  const selected = ui.selection?.kind === 'item' && ui.selection.id === item.id;
  const expanded = ui.expandedPanelId === item.id;
  const status = item.status || 'idle';
  const tone = status === 'warning' || status === 'error' || status === 'loading' ? ` status-${status}` : '';
  return (
    <article
      className={`surveillance-panel${tone}${selected ? ' is-selected' : ''}${expanded ? ' is-expanded' : ''}${status === 'loading' ? ' is-loading' : ''}`}
      role="listitem"
      aria-busy={status === 'loading'}
    >
      <button className="surveillance-main" type="button" aria-pressed={selected} onClick={() => ui.select('item', item.id)}>
        <div className="surveillance-title">
          <SignalDot status={status} label={`${item.name || ''} ${monitorStatusLabel(status)}`} />
          <strong>{item.name || ''}</strong>
        </div>
        <div className="surveillance-line">
          <b>{monitorStatusLabel(status)}</b>
          <span>{num(item.health)}%</span>
          <span>{item.lastUpdated || ''}</span>
        </div>
      </button>
      <span className="surveillance-hover-meta">{sourceLabel(item.source)}</span>
      <button className="panel-expand" type="button" aria-expanded={expanded} onClick={() => ui.togglePanel(item.id)}>
        {expanded ? 'Hide' : 'Inspect'}
      </button>
      <div className="surveillance-expanded">
        {sourceLabel(item.source)} / {item.location || ''} / {num(item.confidence)}% confidence
      </div>
    </article>
  );
}

function EventRow({ event, ui, isNew }: { event: MonitorEventInfo; ui: MonitorUi; isNew: boolean }) {
  const selected = ui.selection?.kind === 'event' && ui.selection.id === event.id;
  const expanded = ui.expandedEventId === event.id;
  const severity = event.severity || 'info';
  return (
    <>
      <div
        className={`activity-feed-row severity-${severity}${selected ? ' is-selected' : ''}${isNew ? ' is-new' : ''}`}
        role="option"
        tabIndex={0}
        aria-selected={selected}
        onClick={(mouse) => {
          if ((mouse.target as HTMLElement).closest('button,a,input,select,textarea')) return;
          ui.select('event', event.id);
        }}
        onKeyDown={(key) => {
          if (key.key !== 'Enter' && key.key !== ' ') return;
          key.preventDefault();
          ui.select('event', event.id);
        }}
      >
        <span>{fmtTime(event.timestamp)}</span>
        <span className={`severity-label ${severity}`}>
          <span aria-hidden="true">{severity === 'critical' || severity === 'warning' ? '!' : 'i'}</span>
          {severityLabel(severity)}
        </span>
        <span>{sourceLabel(event.source)}</span>
        <b>{event.title || ''}</b>
        <button className="activity-expand" type="button" aria-expanded={expanded} onClick={() => ui.toggleEvent(event.id)}>
          {expanded ? 'Hide' : 'Details'}
        </button>
      </div>
      <div className={`activity-detail-block${expanded ? ' is-expanded' : ''}`}>
        <div>{event.description || ''}</div>
      </div>
    </>
  );
}

interface InspectorView {
  title: string;
  description: string;
  id: string;
  status: string;
  source: string;
  timestamp: string;
  healthLabel: string;
  health: string;
  relatedMetric: string;
  state: string;
}

function surfaceInspector(item?: PostureSurfaceInfo): InspectorView | null {
  if (!item) return null;
  return {
    title: item.name || '',
    description: item.description || '',
    id: item.id,
    status: monitorStatusLabel(item.status || ''),
    source: sourceLabel(item.source),
    timestamp: item.lastUpdated || '-',
    healthLabel: 'Health',
    health: `${num(item.health)}% health / ${num(item.confidence)}% confidence`,
    relatedMetric: item.relatedMetric || '',
    state: item.status === 'error' ? 'state-error' : item.status === 'warning' ? 'state-warning' : '',
  };
}

function eventInspector(event?: MonitorEventInfo): InspectorView | null {
  if (!event) return null;
  return {
    title: event.title || '',
    description: event.description || '',
    id: event.id,
    status: severityLabel(event.severity || 'info'),
    source: sourceLabel(event.source),
    timestamp: fmt(event.timestamp),
    healthLabel: 'Confidence',
    health: `${num(event.confidence)}% confidence`,
    relatedMetric: event.relatedMetric || '',
    state: event.severity === 'critical' ? 'state-error' : event.severity === 'warning' ? 'state-warning' : '',
  };
}

function InspectorField({ label, value }: { label: string; value: string }) {
  return (
    <div className="inspector-field">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function InspectorAside({ ui, surfaces, events }: { ui: MonitorUi; surfaces: PostureSurfaceInfo[]; events: MonitorEventInfo[] }) {
  if (ui.inspectorLoading) {
    return (
      <aside className="signal-inspector" aria-live="polite" aria-busy="true">
        <div className="signal-inspector-head">
          <div>
            <h3>Inspector</h3>
            <p>Loading selection.</p>
          </div>
          <div className="button-spinner" aria-hidden="true" />
        </div>
      </aside>
    );
  }
  const selection = ui.selection;
  const view = selection
    ? selection.kind === 'item'
      ? surfaceInspector(surfaces.find((item) => item.id === selection.id))
      : eventInspector(events.find((event) => event.id === selection.id))
    : null;
  if (!view) {
    return (
      <aside className="signal-inspector" aria-live="polite">
        <div className="signal-inspector-head">
          <div>
            <h3>Inspector</h3>
            <p>No selection.</p>
          </div>
        </div>
      </aside>
    );
  }
  return (
    <aside className={`signal-inspector${view.state ? ` ${view.state}` : ''}`} aria-live="polite">
      <div className="signal-inspector-head">
        <div>
          <h3>{view.title}</h3>
          <p>{view.description}</p>
        </div>
        <button className="system-button ghost" type="button" onClick={ui.clear}>
          Close
        </button>
      </div>
      <div className="inspector-grid">
        <InspectorField label="ID" value={view.id} />
        <InspectorField label="Status" value={view.status} />
        <InspectorField label="Source" value={view.source} />
        <InspectorField label="Timestamp" value={view.timestamp} />
        <InspectorField label={view.healthLabel} value={view.health} />
      </div>
      <div className="inspector-id">{view.relatedMetric}</div>
    </aside>
  );
}

interface SignalLayoutProps {
  surfaces: PostureSurfaceInfo[];
  events: MonitorEventInfo[];
  ui: MonitorUi;
  search: SearchUi;
  recentEventId: string;
}

function SignalLayout({ surfaces, events, ui, search, recentEventId }: SignalLayoutProps) {
  const visibleSurfaces = useMemo(
    () => surfaces.filter((item) => matchesStatus(item, ui.statusFilter) && matchesSearch(item, search.state, ui.term)),
    [surfaces, ui.statusFilter, search.state, ui.term],
  );
  const visibleEvents = useMemo(
    () => events.filter((event) => matchesStatus(event, ui.statusFilter) && matchesSearch(event, search.state, ui.term)),
    [events, ui.statusFilter, search.state, ui.term],
  );
  return (
    <div className="signal-layout">
      <div className="signal-main-stack">
        <Section title="Surfaces" summary={visibleSurfaces.length ? `${visibleSurfaces.length} visible` : 'No matches'}>
          <div className="surveillance-grid" role="list" aria-label="Monitored systems">
            {visibleSurfaces.length ? (
              visibleSurfaces.map((item) => <SurfacePanel key={item.id} item={item} ui={ui} />)
            ) : (
              <EmptyState title="No matches" detail="Adjust status or search." />
            )}
          </div>
        </Section>
        <Section title="Activity" summary={visibleEvents.length ? `${visibleEvents.length} visible` : 'No matches'}>
          <div className="activity-feed" role="listbox" aria-label="Signal event timeline">
            {visibleEvents.length ? (
              visibleEvents.map((event) => <EventRow key={event.id} event={event} ui={ui} isNew={event.id === recentEventId} />)
            ) : (
              <EmptyState title="No events" detail="Clear search or broaden status." />
            )}
          </div>
        </Section>
      </div>
      <InspectorAside ui={ui} surfaces={surfaces} events={events} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

export default function Monitor() {
  const { me } = useSession();
  const role = me ? me.role : null;
  const isAdmin = role === 'security_admin';
  const canUseSiem = role === 'security_admin' || role === 'auditor';
  const [segment, setSegment] = useState('all');
  const posture = usePosture(segment);
  const siem = useSiemPackage(role);
  const feedback = useFeedbackReport();
  const activity = useActivityRows();
  const { refreshing, recentEventId, refresh } = useMonitorRefresh(posture.load, siem.load, feedback.load, activity.load);
  const ui = useMonitorUi();
  const workflow = useActionWorkflow(isAdmin, me ? me.user : '', posture.load);
  const snapshot = useSocSnapshot(isAdmin);
  const verdicts = useDetectorVerdicts(feedback.load);

  const reloadLive = useCallback(() => {
    void posture.load();
    void activity.load();
  }, [posture.load, activity.load]);
  useEventStream({ query: reloadLive, decision: reloadLive, stats: reloadLive });

  const report = posture.report;
  const search = searchUiState(ui.term, ui.focused, refreshing);
  const surfaces = report?.surfaces ?? [];
  const events = report?.events ?? [];
  const critical = surfaces.some((item) => item.status === 'error') || events.some((event) => event.severity === 'critical');

  return (
    <div className="monitor-view">
      <div className="signal-console" aria-label="AI Command Center">
        <ConsoleHeader critical={critical} lastUpdated={posture.lastUpdated} refreshing={refreshing} onRefresh={() => void refresh()} />
        <MonitorToolbar
          term={ui.term}
          search={search}
          counts={statusCounts([...surfaces, ...events])}
          filter={ui.statusFilter}
          onTerm={ui.setTerm}
          onFocus={ui.setFocused}
          onFilter={ui.setStatusFilter}
        />
        <SegmentLens segments={report?.segments ?? null} onSegment={setSegment} />
        <MetricGrid metrics={report?.metrics ?? []} refreshing={refreshing} fallbackUpdated={report?.generatedAt || posture.lastUpdated} />
        <DecisionPivots rows={activity.rows} />
        <MissionBanner mission={report?.hardening?.mission ?? null} />
        <OperatorFlow posture={report} />
        <ActionQueueSection rows={report?.actionQueue ?? []} isAdmin={isAdmin} workflow={workflow} />
        <ObjectivesSection objectives={report?.objectives ?? []} />
        <InventorySection inventory={report?.aiInventory ?? null} />
        <AgenticMcpSection mcp={report?.agenticMcp ?? null} />
        <ThreatGuardrailsSection data={report?.threatGuardrails ?? null} />
        <ControlGraphSection graph={report?.controlGraph ?? null} />
        <WorkbenchSection hardening={report?.hardening ?? null} isAdmin={isAdmin} snapshot={snapshot} />
        <SiemSection siem={siem} canUse={canUseSiem} />
        <InsightGrid report={report} feedback={feedback.report} verdicts={verdicts} />
        <SignalLayout surfaces={surfaces} events={events} ui={ui} search={search} recentEventId={recentEventId} />
      </div>
    </div>
  );
}
