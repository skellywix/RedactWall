import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { validZipArchive } from '../api/evidence';
import { fetchQueue, type QueueQuery } from '../api/queries';
import { EmptyState } from '../components/Panel';
import {
  CommandCenterBrief,
  type BriefTone,
  type CommandCenterBriefItem,
} from '../components/monitor/CommandCenterBrief';
import {
  MonitorWorkspaceGroup,
  MonitorWorkspaceNav,
  type MonitorWorkspaceItem,
} from '../components/monitor/MonitorWorkspace';
import { api, apiErrorSummary, apiJsonBounded, responseBytesBounded, responseJsonBounded } from '../lib/api';
import { navigate } from '../lib/router';
import { useSession } from '../lib/session';
import { useEventStream } from '../lib/sse';
import { decodeSocNotifyResponse, isCompleteSiemPackageResponse } from '../lib/strict-console-response';
import { toast } from '../lib/toast';
import './Monitor.css';

const POSTURE_RESPONSE_MAX_BYTES = 8 * 1024 * 1024;
const FEEDBACK_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const SIEM_JSON_MAX_BYTES = 4 * 1024 * 1024;
const SIEM_ZIP_MAX_BYTES = 16 * 1024 * 1024;
const NOTIFY_RESPONSE_MAX_BYTES = 64 * 1024;

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
  source?: string;
  action?: string;
  targetTab?: string;
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
  id?: string;
  label?: string;
  areaLabel?: string;
  status?: string;
  detail?: string;
  command?: string;
  validation?: string;
  targetTab?: string;
  owner?: string;
  source?: string;
}

interface MissionLaneInfo {
  id: string;
  label?: string;
  state?: string;
  status?: string;
  score?: number;
  owner?: string;
  source?: string;
  targetTab?: string;
  done?: number;
  total?: number;
  nextStep?: string;
}

interface HardeningMission {
  title?: string;
  state?: string;
  status?: string;
  progress?: { done?: number; total?: number; open?: number; percent?: number };
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
  state?: string;
  events?: number;
  controlRate?: number;
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
  summary?: {
    selectedId?: string;
    visibleEvents?: number;
    total?: number;
    critical?: number;
    attention?: number;
    ready?: number;
    privacy?: string;
  };
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
  summary?: { activeEvents?: number; anomalies?: number; critical?: number; warning?: number };
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

type PostureLoadState = 'loading' | 'switching' | 'ready' | 'partial' | 'stale' | 'unavailable';
type AuxiliaryLoadState = 'loading' | 'ready' | 'stale' | 'unavailable';

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
  /** Server-derived authority for this exact query and signed-in requester. */
  canFeedback?: boolean;
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
  redactedPromptBodies?: boolean;
  tokenVaultValues?: boolean;
  rawFindingValues?: boolean;
  secretsOrCredentials?: boolean;
  rawUrlsOrFilePaths?: boolean;
  sampleData?: string;
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
  summary?: { profileCount?: number; searches?: number; samplePayloads?: number; dashboards?: number; packageFiles?: number };
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

function isReportedNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isReportedText(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function reportedArrayCount<T>(items: T[] | undefined, singular: string, plural = `${singular}s`): string {
  if (!Array.isArray(items)) return `${plural} not reported`;
  return `${items.length} ${items.length === 1 ? singular : plural}`;
}

function reportedNumberCount(value: unknown, singular: string, plural = `${singular}s`): string {
  if (!isReportedNumber(value)) return `${plural} not reported`;
  return `${value} ${value === 1 ? singular : plural}`;
}

function hasReportedNumbers(values: unknown[]): boolean {
  return values.every(isReportedNumber);
}

function hasUniqueReportedIds(rows: Array<{ id?: string }>): boolean {
  const ids = rows.map((row) => row.id);
  return ids.every(isReportedText) && new Set(ids).size === ids.length;
}

function reportedStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => isReportedText(item));
}

function proofItemReported(item: ProofItem | null | undefined): item is ProofItem {
  return Boolean(
    item
    && isReportedText(item.id)
    && isReportedText(item.label)
    && isReportedText(item.status)
    && isReportedText(item.detail)
    && (item.evidenceAt === null || item.evidenceAt === undefined || typeof item.evidenceAt === 'string')
  );
}

function proofLedgerReported(ledger: ProofLedger | null | undefined, requireCurrent = false): ledger is ProofLedger {
  if (!ledger || !hasReportedNumbers([ledger.verified, ledger.attention, ledger.missing, ledger.total])) return false;
  if (num(ledger.verified) + num(ledger.attention) + num(ledger.missing) !== ledger.total) return false;
  if (requireCurrent && !Object.prototype.hasOwnProperty.call(ledger, 'current')) return false;
  return ledger.current === null || ledger.current === undefined || proofItemReported(ledger.current);
}

function playbookStepReported(step: PlaybookStep): boolean {
  return isReportedText(step.id)
    && isReportedText(step.label)
    && isReportedText(step.status)
    && isReportedText(step.detail)
    && (step.command === undefined || typeof step.command === 'string')
    && (step.validation === undefined || typeof step.validation === 'string');
}

function hardeningAreaReported(area: HardeningArea): boolean {
  if (!isReportedText(area.id) || !isReportedText(area.label) || !isReportedText(area.description)) return false;
  if (!isReportedNumber(area.score) || !isReportedText(area.state) || !isReportedText(area.owner) || !isReportedText(area.source)) return false;
  if (!reportedStringArray(area.evidence) || !reportedStringArray(area.gaps)) return false;
  if (!Array.isArray(area.proofs) || !area.proofs.every(proofItemReported)) return false;
  if (!proofLedgerReported(area.proofLedger) || area.proofLedger.total !== area.proofs.length) return false;
  return Array.isArray(area.playbook) && area.playbook.every(playbookStepReported);
}

function missionCurrentReported(current: MissionCurrent | null | undefined): boolean {
  if (current === null) return true;
  return Boolean(
    current
    && isReportedText(current.id)
    && isReportedText(current.label)
    && isReportedText(current.areaLabel)
    && isReportedText(current.status)
    && isReportedText(current.detail)
    && typeof current.command === 'string'
    && typeof current.validation === 'string'
  );
}

function missionLaneReported(lane: MissionLaneInfo): boolean {
  return isReportedText(lane.id)
    && isReportedText(lane.label)
    && isReportedText(lane.state)
    && isReportedText(lane.status)
    && isReportedNumber(lane.score)
    && isReportedText(lane.owner)
    && isReportedText(lane.source)
    && isReportedText(lane.targetTab)
    && hasReportedNumbers([lane.done, lane.total])
    && num(lane.done) <= num(lane.total)
    && isReportedText(lane.nextStep);
}

function hardeningMissionReported(mission: HardeningMission | null | undefined, areaIds: Set<string>): boolean {
  const progress = mission?.progress;
  const lanes = mission?.lanes;
  if (!mission || !isReportedText(mission.title) || !isReportedText(mission.state) || !isReportedText(mission.status)) return false;
  if (!progress || !hasReportedNumbers([progress.done, progress.total, progress.open, progress.percent])) return false;
  if (num(progress.done) + num(progress.open) !== progress.total || num(progress.percent) < 0 || num(progress.percent) > 100) return false;
  if (!missionCurrentReported(mission.current) || !proofLedgerReported(mission.proofLedger, true)) return false;
  return Array.isArray(lanes)
    && lanes.every(missionLaneReported)
    && hasUniqueReportedIds(lanes)
    && lanes.length === areaIds.size
    && lanes.every((lane) => areaIds.has(lane.id));
}

function hardeningReported(hardening: HardeningReport | null | undefined): boolean {
  const areas = hardening?.areas;
  if (!hardening || !isReportedNumber(hardening.score) || !isReportedText(hardening.state) || !Array.isArray(areas)) return false;
  if (!areas.every(hardeningAreaReported) || !hasUniqueReportedIds(areas)) return false;
  const areaIds = new Set(areas.map((area) => area.id));
  const proofTotal = areas.reduce((sum, area) => sum + num(area.proofLedger?.total), 0);
  return proofLedgerReported(hardening.proofLedger, true)
    && hardening.proofLedger.total === proofTotal
    && hardeningMissionReported(hardening.mission, areaIds)
    && hardening.mission?.proofLedger?.total === proofTotal;
}

function actionQueueReported(rows: PostureAction[] | undefined): rows is PostureAction[] {
  if (!Array.isArray(rows) || !hasUniqueReportedIds(rows)) return false;
  return rows.every((item) => (
    isReportedText(item.id)
    && isReportedText(item.severity)
    && isReportedText(item.category)
    && isReportedText(item.label)
    && isReportedText(item.detail)
    && isReportedText(item.action)
    && isReportedText(item.targetTab)
    && isReportedText(item.workflowStatus)
    && typeof item.workflowOwner === 'string'
    && typeof item.workflowSnoozeUntil === 'string'
    && typeof item.workflowUpdatedAt === 'string'
    && isReportedText(item.workflowProofState)
    && (item.command === undefined || typeof item.command === 'string')
  ));
}

function reportedNumberValue(value: unknown): number | string {
  return isReportedNumber(value) ? value : 'Not reported';
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
  return state === 'ready' ? 'ready' : 'warning';
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

function actionIsVerifiedComplete(item: PostureAction): boolean {
  return item.workflowStatus === 'resolved' && ['resolved', 'verified', 'proof_verified'].includes(item.workflowProofState || '');
}

function actionNeedsAttention(item: PostureAction): boolean {
  return !actionIsVerifiedComplete(item);
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

function scrollToAnchor(anchorId: string, moveFocus = false): void {
  const target = document.getElementById(anchorId);
  if (!target) return;
  const workspace = target instanceof HTMLDetailsElement ? target : target.closest('details');
  if (workspace instanceof HTMLDetailsElement) workspace.open = true;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  target.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
  if (!moveFocus) return;
  const focusTarget = workspace instanceof HTMLDetailsElement ? workspace.querySelector('summary') : target;
  if (!(focusTarget instanceof HTMLElement)) return;
  if (!focusTarget.matches('button,a,input,select,textarea,summary,[tabindex]')) focusTarget.tabIndex = -1;
  focusTarget.focus({ preventScroll: true });
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

function surfacesReported(surfaces: PostureSurfaceInfo[] | undefined): surfaces is PostureSurfaceInfo[] {
  return Array.isArray(surfaces) && surfaces.every((surface) => (
    isReportedText(surface.id)
    && isReportedText(surface.name)
    && isReportedText(surface.status)
    && isReportedText(surface.source)
    && hasReportedNumbers([surface.health, surface.confidence])
  ));
}

function eventsReported(events: MonitorEventInfo[] | undefined): events is MonitorEventInfo[] {
  return Array.isArray(events) && events.every((event) => (
    isReportedText(event.id)
    && isReportedText(event.timestamp)
    && isReportedText(event.severity)
    && isReportedText(event.status)
    && isReportedText(event.source)
    && isReportedText(event.title)
    && isReportedText(event.description)
    && isReportedNumber(event.confidence)
  ));
}

// ---------------------------------------------------------------------------
// Fetchers
// ---------------------------------------------------------------------------

function fetchMonitorPosture(segment: string): Promise<Posture | null> {
  const param = segment && segment !== 'all' ? `&segment=${encodeURIComponent(segment)}` : '';
  return apiJsonBounded<Posture>(`/api/posture?limit=5000${param}`, POSTURE_RESPONSE_MAX_BYTES);
}

/**
 * A posture response may advance the visible scope only when the server binds
 * it to that exact scope. Conflicting response metadata is treated as
 * unverified rather than guessing which field is authoritative.
 */
function boundPostureSegment(report: Posture): string | null {
  const summaryId = report.segments?.summary?.selectedId;
  const activeId = report.segments?.active?.id;
  if (!isReportedText(summaryId) || summaryId.length > 180) return null;
  if (activeId !== undefined && activeId !== null && (!isReportedText(activeId) || activeId.length > 180)) return null;
  if (summaryId && activeId && summaryId !== activeId) return null;
  return summaryId;
}

function postureFullyReported(report: Posture): boolean {
  return Boolean(
    isReportedText(report.generatedAt)
    && segmentsReported(report.segments ?? null)
    && metricsReported(report.metrics)
    && objectivesReported(report.objectives)
    && actionQueueReported(report.actionQueue)
    && hardeningReported(report.hardening)
    && inventoryReported(report.aiInventory ?? null)
    && agenticMcpReported(report.agenticMcp ?? null)
    && threatGuardrailsReported(report.threatGuardrails ?? null)
    && controlGraphReported(report.controlGraph ?? null)
    && behaviorBaselinesReported(report.behaviorBaselines ?? null)
    && decisionQualityReported(report.decisionQuality ?? null)
    && trendReported(report.trend)
    && controlsReported(report.controls)
    && surfacesReported(report.surfaces)
    && eventsReported(report.events)
  );
}

function fetchFeedbackReport(): Promise<FeedbackReport | null> {
  return apiJsonBounded<FeedbackReport>(
    '/api/detector-feedback/report?queryLimit=1000&feedbackLimit=1000',
    FEEDBACK_RESPONSE_MAX_BYTES,
  );
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
  const pkg = await responseJsonBounded<unknown>(response, SIEM_JSON_MAX_BYTES);
  return isCompleteSiemPackageResponse(pkg)
    ? { pkg: pkg as SiemPackage, error: '' }
    : { pkg: null, error: 'unverified_package' };
}

/** Returns a toast-safe error summary, or null when the ZIP download started. */
async function downloadSiemZip(profile: string): Promise<string | null> {
  const response = await api(`/api/integrations/siem/package?profile=${encodeURIComponent(profile)}&format=zip`);
  if (!response || !response.ok) return apiErrorSummary(response, 'SIEM package download failed');
  const contentType = String(response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
  const bytes = contentType === 'application/zip'
    ? await responseBytesBounded(response, SIEM_ZIP_MAX_BYTES)
    : null;
  if (!bytes || !validZipArchive(bytes)) return 'SIEM package download failed: malformed or oversized archive';
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
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
  const [state, setState] = useState<PostureLoadState>('loading');
  const [verifiedSegment, setVerifiedSegment] = useState('all');
  const hasReport = useRef(false);
  const verifiedSegmentRef = useRef('all');
  // Monotonic request id: a slow posture build for a superseded segment must not
  // overwrite the report the user is now looking at.
  const reqId = useRef(0);
  const load = useCallback(async () => {
    const seq = ++reqId.current;
    if (!hasReport.current) setState('loading');
    else if (segment !== verifiedSegmentRef.current) setState('switching');
    const body = await fetchMonitorPosture(segment);
    if (seq !== reqId.current) return body;
    const nextVerifiedSegment = body ? boundPostureSegment(body) : null;
    if (body && nextVerifiedSegment === segment) {
      hasReport.current = true;
      verifiedSegmentRef.current = nextVerifiedSegment;
      setVerifiedSegment(nextVerifiedSegment);
      setReport(body);
      setLastUpdated(body.generatedAt || new Date().toISOString());
      setState(postureFullyReported(body) ? 'ready' : 'partial');
    } else {
      setState(hasReport.current ? 'stale' : 'unavailable');
    }
    return body && nextVerifiedSegment === segment ? body : null;
  }, [segment]);
  useEffect(() => {
    void load();
  }, [load]);
  return { report, lastUpdated, state, verifiedSegment, load };
}

function useFeedbackReport() {
  const [report, setReport] = useState<FeedbackReport | null>(null);
  const [state, setState] = useState<AuxiliaryLoadState>('loading');
  const hasReport = useRef(false);
  const load = useCallback(async () => {
    const body = await fetchFeedbackReport();
    if (body) {
      hasReport.current = true;
      setReport(body);
      setState('ready');
    } else {
      setState(hasReport.current ? 'stale' : 'unavailable');
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { report, state, load };
}

/** Loaded activity window backing the decision pivot counts. */
function useActivityRows() {
  const [rows, setRows] = useState<QueueQuery[] | null>(null);
  const [state, setState] = useState<AuxiliaryLoadState>('loading');
  const hasRows = useRef(false);
  const load = useCallback(async () => {
    const next = await fetchQueue('all');
    if (next) {
      hasRows.current = true;
      setRows(next);
      setState('ready');
    } else {
      setState(hasRows.current ? 'stale' : 'unavailable');
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { rows, state, load };
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
    try {
      const failure = await downloadSiemZip(profile);
      if (failure) toast(failure, 'error');
    } catch {
      toast('SIEM package download failed', 'error');
    } finally {
      setDownloading(false);
    }
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

function useActionWorkflow(canWrite: boolean, user: string, reload: () => Promise<Posture | null>) {
  const [busyKey, setBusyKey] = useState('');
  const run = useCallback(
    async (id: string, status: WorkflowStatus) => {
      if (!canWrite) {
        toast('Request not allowed for this session.');
        return;
      }
      setBusyKey(`${id}:${status}`);
      const error = await postPostureAction({ id, ...workflowPatch(status, user) });
      if (!error) await reload();
      setBusyKey('');
      if (error) toast(error);
    },
    [canWrite, user, reload],
  );
  return { busyKey, run };
}

interface SnapshotControl {
  status: string;
  sending: boolean;
  send: () => Promise<void>;
}

function useSocSnapshot(canSend: boolean): SnapshotControl {
  const [status, setStatus] = useState('SOC SNAPSHOT READY');
  const [sending, setSending] = useState(false);
  const send = useCallback(async () => {
    if (!canSend) return;
    setSending(true);
    setStatus('SENDING');
    try {
      const response = await api('/api/posture/notify', { method: 'POST' });
      if (!response?.ok) {
        const error = await apiErrorSummary(response, 'request failed');
        setStatus(`NOT SENT - ${humanize(error)}`.slice(0, 80));
        return;
      }
      const body = decodeSocNotifyResponse(await responseJsonBounded<unknown>(response, NOTIFY_RESPONSE_MAX_BYTES));
      if (body?.sent === true && response.status === 200) setStatus('SENT TO SOC');
      else if (body?.sent === false && response.status === 202) {
        setStatus(`NOT SENT - ${humanize(body.reason || 'not configured')}`.slice(0, 80));
      } else setStatus('NOT SENT - UNVERIFIED RESPONSE');
    } catch {
      setStatus('SEND FAILED');
    } finally {
      setSending(false);
    }
  }, [canSend]);
  return { status, sending, send };
}

type VerdictState = 'busy' | 'failed';

interface VerdictControl {
  canSubmit: boolean;
  states: ReadonlyMap<string, VerdictState>;
  submit: (queryId: string, detectorId: string, verdict: 'valid' | 'false_positive') => Promise<void>;
}

function useDetectorVerdicts(reload: () => Promise<void>, canSubmit: boolean): VerdictControl {
  const [states, setStates] = useState<ReadonlyMap<string, VerdictState>>(new Map());
  const submit = useCallback(
    async (queryId: string, detectorId: string, verdict: 'valid' | 'false_positive') => {
      if (!canSubmit) {
        toast('Request not allowed for this session.');
        return;
      }
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
    [canSubmit, reload],
  );
  return { canSubmit, states, submit };
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

function PermissionNote({ id, children }: { id: string; children: ReactNode }) {
  return (
    <p className="monitor-permission-note" id={id} tabIndex={0}>
      <span aria-hidden="true">Permission</span>
      {children}
    </p>
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
  state: PostureLoadState;
  lastUpdated: string;
  refreshing: boolean;
  onRefresh: () => void;
}

function consolePresence(state: PostureLoadState, critical: boolean, lastUpdated: string): { dot: string; label: string; updated: string } {
  if (state === 'loading') return { dot: 'loading', label: 'SYNCING', updated: 'AWAITING POSTURE' };
  if (state === 'switching') return { dot: 'loading', label: 'SWITCHING SCOPE', updated: `SHOWING ${fmtTime(lastUpdated)} SNAPSHOT` };
  if (state === 'unavailable') return { dot: 'error', label: 'UNAVAILABLE', updated: 'NO VERIFIED POSTURE' };
  if (state === 'stale') return { dot: 'warning', label: 'STALE', updated: `LAST VERIFIED ${fmtTime(lastUpdated)}` };
  if (state === 'partial') return { dot: 'warning', label: 'PARTIAL', updated: `INCOMPLETE SNAPSHOT ${fmtTime(lastUpdated)}` };
  return {
    dot: critical ? 'error' : 'online',
    label: critical ? 'ATTENTION' : 'LIVE',
    updated: `UPDATED ${fmtTime(lastUpdated)}`,
  };
}

function ConsoleHeader({ critical, state, lastUpdated, refreshing, onRefresh }: ConsoleHeaderProps) {
  const presence = consolePresence(state, critical, lastUpdated);
  return (
    <div className="signal-console-header">
      <div className="signal-console-title">
        <div>
          <h2>Texas FCU Command Center</h2>
          <p>Sanitized member-data posture, control outcomes, and examiner proof without prompt bodies.</p>
        </div>
      </div>
      <div className="signal-header-actions">
        <div className="signal-live-summary">
          <SignalDot
            status={presence.dot}
            label={`Command center ${presence.label.toLowerCase()}`}
            pulse
          />
          {presence.label}
        </div>
        <span className="signal-updated">{presence.updated}</span>
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
  count?: number;
  selected: boolean;
  onFilter: (id: string) => void;
}

function StatusChip({ option, count, selected, onFilter }: StatusChipProps) {
  const statusClass = option.id === 'warning' ? ' status-warning' : option.id === 'error' ? ' status-error' : '';
  const reported = isReportedNumber(count);
  return (
    <button
      className={`signal-chip${statusClass}${selected ? ' is-selected' : ''}`}
      type="button"
      aria-pressed={selected}
      disabled={!reported || count === 0}
      title={reported ? undefined : 'Status count not reported'}
      onClick={() => onFilter(option.id)}
    >
      {option.id === 'all' ? null : <SignalDot status={option.id} label={`${option.label} status filter`} />}
      <span>{option.label}</span>
      <b>{reported ? count : '—'}</b>
    </button>
  );
}

interface MonitorToolbarProps {
  term: string;
  search: SearchUi;
  counts: Record<string, number> | null;
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
          <StatusChip key={option.id} option={option} count={counts ? (counts[option.id] ?? 0) : undefined} selected={filter === option.id} onFilter={onFilter} />
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
        {reportedNumberValue(card.score)}
        <em>{isReportedNumber(card.score) ? '/100' : ''}</em>
      </b>
    </button>
  );
}

function SegmentLensEmpty() {
  return (
    <div className="segment-lens is-empty" aria-label="Posture segment lens">
      <div className="segment-lens-summary">Segment scope not reported in the latest posture.</div>
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

interface SegmentSelectControlProps {
  segments: SegmentsReport | null;
  selectedId: string;
  onSegment: (id: string) => void;
  compact?: boolean;
}

function SegmentSelectControl({ segments, selectedId, onSegment, compact = false }: SegmentSelectControlProps) {
  const filters = segments?.filters?.length ? segments.filters : [{ id: 'all', label: 'All segments', typeLabel: 'All' }];
  const value = filters.some((item) => item.id === selectedId) ? selectedId : (segments?.summary?.selectedId || 'all');
  return (
    <label className={compact ? 'command-scope-select' : 'segment-select'}>
      <span>{compact ? 'Change scope' : 'Posture segment'}</span>
      <select value={value} aria-label={compact ? 'Command center scope' : 'Posture segment'} disabled={!segments} onChange={(event) => onSegment(event.target.value)}>
        {filters.map((item) => (
          <option key={item.id} value={item.id}>
            {item.typeLabel || 'Segment'} - {item.label || item.id}
          </option>
        ))}
      </select>
    </label>
  );
}

function metricsReported(metrics: PostureMetric[] | undefined): metrics is PostureMetric[] {
  return Array.isArray(metrics) && metrics.every((metric) => (
    isReportedText(metric.id)
    && isReportedText(metric.label)
    && (isReportedText(metric.value) || isReportedNumber(metric.value))
    && isReportedText(metric.status)
  ));
}

function objectivesReported(objectives: PostureObjective[] | undefined): objectives is PostureObjective[] {
  return Array.isArray(objectives) && objectives.every((objective) => (
    isReportedText(objective.id)
    && isReportedText(objective.label)
    && isReportedText(objective.state)
    && isReportedNumber(objective.score)
  ));
}

function segmentsReported(segments: SegmentsReport | null): boolean {
  const summary = segments?.summary;
  const active = segments?.active;
  const filters = segments?.filters;
  const matrix = segments?.matrix;
  const segmentStates = new Set(['ready', 'attention', 'critical']);
  const isCount = (value: unknown): value is number => isReportedNumber(value) && Number.isSafeInteger(value) && value >= 0;
  const isScore = (value: unknown): value is number => isCount(value) && value <= 100;
  if (!summary || !isReportedText(summary.selectedId) || !isCount(summary.visibleEvents)
    || !isCount(summary.total) || !isCount(summary.critical) || !isCount(summary.attention) || !isCount(summary.ready)) return false;
  if (summary.critical + summary.attention + summary.ready !== summary.total) return false;
  if (!isReportedText(summary.privacy) || !Array.isArray(filters) || !filters.length || !hasUniqueReportedIds(filters)) return false;
  if (!filters.every((item) => (
    isReportedText(item.label)
    && isReportedText(item.typeLabel)
    && (item.state === undefined || segmentStates.has(item.state))
    && (item.events === undefined || isCount(item.events))
    && (item.controlRate === undefined || isScore(item.controlRate))
  ))) return false;
  if (!Array.isArray(matrix) || !matrix.length || !hasUniqueReportedIds(matrix)) return false;
  if (!matrix.every((item) => (
    isReportedText(item.id)
    && isReportedText(item.label)
    && isReportedText(item.typeLabel)
    && segmentStates.has(item.state || '')
    && isScore(item.score)
  ))) return false;
  if (!filters.some((item) => item.id === 'all')) return false;
  if (summary.selectedId === 'all') return active === null && matrix.some((item) => item.id === 'all');
  return Boolean(
    active
    && active.id === summary.selectedId
    && isReportedText(active.label)
    && isReportedText(active.typeLabel)
    && segmentStates.has(active.state || '')
    && isScore(active.score)
    && filters.some((item) => item.id === summary.selectedId)
    && matrix.some((item) => item.id === summary.selectedId)
  );
}

function SegmentLens({ segments, onSegment }: { segments: SegmentsReport | null; onSegment: (id: string) => void }) {
  const reported = segmentsReported(segments);
  if (!segments || !reported) return <SegmentLensEmpty />;
  const summary = segments.summary ?? {};
  const active = segments.active ?? null;
  const matrix = segments.matrix ?? [];
  const selectedId = summary.selectedId || 'all';
  const activeLabel = active ? `${active.typeLabel || 'Segment'}: ${active.label || 'Unknown'}` : 'All segments';
  return (
    <div className="segment-lens" aria-label="Posture segment lens">
      <div className="segment-lens-summary">
        <b>{activeLabel}</b>
        <span>
          {reportedNumberCount(summary.visibleEvents, 'visible event')} / {reportedNumberCount(summary.attention, 'attention item')} /{' '}
          {summary.privacy || 'metadata only; prompt bodies excluded'}
        </span>
      </div>
      <SegmentSelectControl segments={segments} selectedId={selectedId} onSegment={onSegment} />
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

function MetricGrid({ metrics, refreshing, fallbackUpdated }: { metrics?: PostureMetric[]; refreshing: boolean; fallbackUpdated: string }) {
  const reported = metricsReported(metrics);
  const rows = reported ? metrics : [];
  return (
    <div className="metric-grid" aria-live="polite">
      {!reported ? (
        <EmptyState title="Posture metrics not reported" detail="The latest posture did not include metric evidence." />
      ) : rows.length ? (
        rows.map((metric) => (
          <MetricCard key={metric.id} metric={metric} updating={refreshing} lastUpdated={metric.lastUpdated || fallbackUpdated} />
        ))
      ) : (
        <EmptyState title="No posture metrics" detail="The verified posture explicitly contained no metrics." />
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

function auxiliaryStateLabel(state: AuxiliaryLoadState, subject: string): string {
  const label = `${subject.charAt(0).toUpperCase()}${subject.slice(1)}`;
  if (state === 'loading') return `Loading ${subject}`;
  if (state === 'unavailable') return `${label} unavailable`;
  if (state === 'stale') return `Last verified ${subject}`;
  return '';
}

function DecisionPivots({ rows, state }: { rows: QueueQuery[] | null; state: AuxiliaryLoadState }) {
  const count = (token: string) => rows?.filter((q) => String(q.status || '').toLowerCase().includes(token)).length;
  const stateLabel = auxiliaryStateLabel(state, 'activity');
  return (
    <div className="signal-filters decision-pivots" aria-label="Decision pivots into Exam Activity" aria-live="polite">
      {stateLabel ? <span className={`decision-pivot-state state-${state}`}>{stateLabel}</span> : null}
      {DECISION_PIVOTS.map((pivot) => (
        <button
          key={pivot.token}
          className="signal-chip"
          type="button"
          disabled={!rows}
          title={`Open Exam Activity filtered to status:${pivot.token}`}
          onClick={() => navigate(`/activity?q=${encodeURIComponent('status:' + pivot.token)}`)}
        >
          <span>{pivot.label}</span>
          <b>{count(pivot.token) ?? 'Not reported'}</b>
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hardening mission + operator flow
// ---------------------------------------------------------------------------

function proofLedgerSummary(ledger?: ProofLedger): string {
  if (!ledger) return 'Proof ledger not reported';
  const parts = [
    isReportedNumber(ledger.verified) ? `${ledger.verified} verified` : null,
    isReportedNumber(ledger.attention) ? `${ledger.attention} attention` : null,
    isReportedNumber(ledger.missing) ? `${ledger.missing} missing` : null,
  ].filter((part): part is string => Boolean(part));
  return parts.length ? parts.join(' / ') : 'Proof counts not reported';
}

function MissionPrimary({ mission }: { mission: HardeningMission }) {
  const current = mission.current && typeof mission.current === 'object' ? mission.current : null;
  const ledger = mission.proofLedger;
  const proofCurrent = ledger?.current && typeof ledger.current === 'object' ? ledger.current : null;
  const progress = isReportedNumber(mission.progress?.percent) ? `${mission.progress.percent}%` : 'Progress not reported';
  return (
    <div className="mission-primary">
      <div className="mission-kicker">
        <SignalDot status={mission.status || 'warning'} label={`${mission.title || 'Hardening mission'} ${mission.state || 'attention'}`} />
        <span>{mission.title || 'Hardening mission'}</span>
        <b>{progress}</b>
      </div>
      <h3>{current ? current.label || 'Current mission step' : 'Current mission step not reported'}</h3>
      <p>
        {current
          ? `${current.areaLabel || 'Readiness area'} · ${current.detail || 'Step detail not reported.'}`
          : 'The latest posture did not include a current mission step.'}
      </p>
      {current?.command ? (
        <div className="mission-command">
          <code>{current.command}</code>
          <CopyCommandButton command={current.command} />
        </div>
      ) : null}
      <small>{current?.validation || 'Current validation not reported.'}</small>
      <div className="mission-proof-ledger">
        <b>Proof ledger</b>
        <span>{proofLedgerSummary(ledger)}</span>
        {proofCurrent ? (
          <small>
            {proofCurrent.areaLabel || 'Readiness area'}: {proofCurrent.label || 'Evidence item'}
          </small>
        ) : (
          <small>Current proof item not reported.</small>
        )}
      </div>
    </div>
  );
}

function MissionLane({ lane }: { lane: MissionLaneInfo }) {
  const progress = isReportedNumber(lane.done) && isReportedNumber(lane.total) ? `${lane.done}/${lane.total}` : 'Not reported';
  return (
    <button className={`mission-lane ${readinessTone(lane.state)}`} type="button" role="listitem" onClick={() => jumpToTab(lane.targetTab || 'coverage')}>
      <span>{lane.label || 'Readiness area'}</span>
      <b>{progress}</b>
      <small>{lane.nextStep || 'Next step not reported'}</small>
    </button>
  );
}

function MissionBanner({ mission }: { mission: HardeningMission | null }) {
  if (!mission) {
    return (
      <div aria-live="polite">
        <EmptyState title="Hardening mission not reported" detail="The latest posture did not include mission evidence." />
      </div>
    );
  }
  return (
    <div aria-live="polite">
      <div className={`hardening-mission ${readinessTone(mission.state)}`}>
        <MissionPrimary mission={mission} />
        <div className="mission-progress" role="list" aria-label="Hardening mission lanes">
          {Array.isArray(mission.lanes) ? mission.lanes.map((lane) => (
            <MissionLane key={lane.id} lane={lane} />
          )) : <EmptyState title="Mission lanes not reported" detail="Lane progress was omitted from the latest posture." />}
        </div>
      </div>
    </div>
  );
}

function HardeningList({
  label,
  items,
  missingFallback,
  emptyFallback,
}: {
  label: string;
  items?: string[];
  missingFallback: string;
  emptyFallback: string;
}) {
  const rows = !Array.isArray(items) ? [missingFallback] : items.length ? items : [emptyFallback];
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

function operatorFlowReported(posture: Posture): boolean {
  const threat = posture.threatGuardrails?.summary;
  const inventory = posture.aiInventory?.summary;
  const behavior = posture.behaviorBaselines?.summary;
  const mcp = posture.agenticMcp?.summary;
  const graph = posture.controlGraph?.summary;
  const ledger = posture.hardening?.mission?.proofLedger ?? posture.hardening?.proofLedger;
  return actionQueueReported(posture.actionQueue) && proofLedgerReported(ledger, true) && hasReportedNumbers([
    threat?.events, threat?.activeRules, threat?.critical, threat?.blocked,
    inventory?.highRiskAssets, inventory?.unapprovedLocalTools, inventory?.activeDestinations,
    behavior?.activeEvents, behavior?.anomalies, behavior?.critical, behavior?.warning,
    mcp?.activeAgents,
    graph?.highRiskAssets, graph?.shadowAssets, graph?.nodes, graph?.controlledLinks,
    ledger?.verified, ledger?.attention, ledger?.missing,
  ]);
}

function OperatorFlow({ posture }: { posture: Posture | null }) {
  const reported = Boolean(posture && operatorFlowReported(posture));
  const rows = posture && reported ? operatorSteps(posture) : [];
  const urgent = rows.filter((row) => row.tone === 'critical').length;
  const attention = rows.filter((row) => row.tone === 'attention').length;
  const ready = rows.filter((row) => row.tone === 'ready').length;
  return (
    <Section title="FCU Operator Flow" summary={reported ? `${urgent} urgent / ${attention} attention / ${ready} ready` : 'Operator flow not reported'}>
      <div className="operator-flow-board" aria-live="polite">
        {reported ? (
          rows.map((row) => (
            <button key={row.id} className={`operator-flow-card ${row.tone}`} type="button" onClick={() => scrollToAnchor(row.target)}>
              <span>{row.title}</span>
              <strong>{row.primary}</strong>
              <small>{row.meta}</small>
              <b>{row.action}</b>
            </button>
          ))
        ) : (
          <EmptyState title="Operator flow not reported" detail="Required threat, behavior, asset, graph, action, or proof counts were omitted." />
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
  canWrite: boolean;
  workflow: WorkflowRunner;
}

const POSTURE_ACTION_PERMISSION_ID = 'postureActionPermission';

function ActionControls({ item, canWrite, workflow }: Omit<ActionRowProps, 'rank'>) {
  const workflowButton = (status: WorkflowStatus, label: string) => (
    <button
      className="ghost mini"
      type="button"
      disabled={!canWrite || workflow.busyKey === `${item.id}:${status}`}
      aria-describedby={!canWrite ? POSTURE_ACTION_PERMISSION_ID : undefined}
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

function ActionRow({ item, rank, canWrite, workflow }: ActionRowProps) {
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
      <ActionControls item={item} canWrite={canWrite} workflow={workflow} />
    </article>
  );
}

function actionQueueSummary(rows: PostureAction[] | undefined, state: PostureLoadState): string {
  if (state === 'loading') return 'Syncing verified action state';
  if (state === 'unavailable') return 'Action state unavailable';
  if (!rows) return 'Not included in the latest posture';
  const critical = rows.filter((item) => item.severity === 'critical').length;
  const warning = rows.filter((item) => item.severity === 'warning').length;
  const routed = rows.filter((item) => item.workflowStatus === 'assigned' || item.workflowStatus === 'snoozed').length;
  const prefix = state === 'stale' ? 'Last verified / ' : '';
  return rows.length ? `${prefix}${rows.length} actions / ${critical} critical / ${warning} warning / ${routed} routed` : `${prefix}All clear`;
}

function ActionQueueEmpty({ rows, state }: { rows: PostureAction[] | undefined; state: PostureLoadState }) {
  if (state === 'loading') return <EmptyState title="Loading action state" detail="Waiting for the current sanitized posture." />;
  if (state === 'unavailable') return <EmptyState title="Action state unavailable" detail="Refresh before treating the queue as clear." />;
  if (!rows) return <EmptyState title="Action status not reported" detail="The latest posture did not include an action queue." />;
  if (state === 'stale') return <EmptyState title="No gaps in the last verified queue" detail="The latest refresh failed, so this is not a current all-clear." />;
  return <EmptyState title="No action gaps" detail="Current hardening gaps are clear." />;
}

interface ActionQueueSectionProps {
  rows: PostureAction[] | undefined;
  state: PostureLoadState;
  canWrite: boolean;
  workflow: WorkflowRunner;
}

function ActionQueueSection({ rows, state, canWrite, workflow }: ActionQueueSectionProps) {
  return (
    <Section title="Urgent Action Queue" summary={actionQueueSummary(rows, state)}>
      {!canWrite ? (
        <PermissionNote id={POSTURE_ACTION_PERMISSION_ID}>
          Security Admin or Operations Administrator access is required to update posture actions.
        </PermissionNote>
      ) : null}
      <div className="action-queue" id="hardeningActionQueue" aria-live="polite" aria-busy={state === 'loading'}>
        {rows?.length ? (
          rows.map((item, index) => <ActionRow key={item.id} item={item} rank={index + 1} canWrite={canWrite} workflow={workflow} />)
        ) : (
          <ActionQueueEmpty rows={rows} state={state} />
        )}
      </div>
    </Section>
  );
}

function ObjectivesSection({ objectives }: { objectives?: PostureObjective[] }) {
  const reported = objectivesReported(objectives);
  const rows = reported ? objectives : [];
  const covered = rows.filter((item) => item.state === 'covered').length;
  return (
    <Section title="Exam Posture Objectives" summary={!reported ? 'Objectives not reported' : rows.length ? `${covered}/${rows.length} covered` : 'No objectives'}>
      <div className="posture-objectives">
        {!reported ? (
          <EmptyState title="Posture objectives not reported" detail="The latest posture did not include examiner objectives." />
        ) : rows.length ? (
          rows.map((item) => (
            <article key={item.id} className={`objective-card ${item.state === 'covered' ? 'good' : 'warn'}`}>
              <div className="objective-score">
                <b>{reportedNumberValue(item.score)}</b>
                <span>{isReportedNumber(item.score) ? '/100' : ''}</span>
              </div>
              <div className="objective-body">
                <div className="objective-title">{item.label}</div>
                <div className="objective-detail">{item.detail}</div>
                <TabJump tab={item.targetTab || 'policy'} label={item.action || 'Open'} />
              </div>
            </article>
          ))
        ) : (
          <EmptyState title="No posture objectives" detail="The verified posture explicitly contained no objectives." />
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

function inventoryReported(inventory: AiInventoryReport | null): boolean {
  const summary = inventory?.summary;
  const apps = inventory?.apps;
  const tools = inventory?.tools;
  const itemReported = (item: InventoryItem) => (
    isReportedText(item.id)
    && isReportedText(item.name)
    && isReportedText(item.kind)
    && isReportedText(item.state)
    && isReportedText(item.status)
    && isReportedText(item.source)
    && isReportedNumber(item.riskScore)
    && isReportedText(item.riskLevel)
    && (item.kind === 'Endpoint tool' || isReportedNumber(item.events))
  );
  if (!summary || !Array.isArray(apps) || !Array.isArray(tools)) return false;
  if (!apps.every(itemReported) || !tools.every(itemReported)) return false;
  if (!hasReportedNumbers([
    summary.sanctioned,
    summary.shadow,
    summary.highRiskAssets,
    summary.unapprovedLocalTools,
    summary.activeDestinations,
  ])) return false;
  const all = [...apps, ...tools];
  return Boolean(
    summary.sanctioned === apps.filter((item) => item.state === 'sanctioned').length
    && summary.shadow === apps.filter((item) => item.state === 'shadow').length
    && summary.activeDestinations === apps.filter((item) => Number(item.events) > 0).length
    && summary.highRiskAssets === all.filter((item) => item.riskLevel === 'critical' || item.riskLevel === 'high').length
    && (all.length > 0 || summary.unapprovedLocalTools === 0)
  );
}

function InventorySection({ inventory }: { inventory: AiInventoryReport | null }) {
  const reported = inventoryReported(inventory);
  const summary = inventory?.summary ?? {};
  const rows = [...(inventory?.apps ?? []), ...(inventory?.tools ?? [])].slice(0, 12);
  const summaryText = reported
    ? `${num(summary.sanctioned)} sanctioned / ${num(summary.shadow)} shadow / ${num(summary.highRiskAssets)} high risk`
    : 'AI inventory not reported';
  return (
    <Section title="AI Vendor Inventory" summary={summaryText}>
      <div className="ai-inventory-grid" id="aiInventoryRows" aria-live="polite">
        {!reported ? (
          <EmptyState title="AI inventory not reported" detail="Required inventory counts, apps, or tools were omitted from the latest posture." />
        ) : rows.length ? (
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

function agenticMcpReported(mcp: AgenticMcpReport | null): boolean {
  const summary = mcp?.summary;
  const registry = mcp?.connectorRegistry?.summary;
  const policy = mcp?.policy;
  const agents = mcp?.agents;
  const tools = mcp?.tools;
  const requests = mcp?.requests;
  const profiles = mcp?.connectorRegistry?.profiles;
  if (!summary || !registry || !policy || !Array.isArray(agents) || !Array.isArray(tools) || !Array.isArray(requests) || !Array.isArray(profiles)) return false;
  const rowReported = (row: McpRow) => (
    isReportedText(row.id)
    && isReportedText(row.name)
    && isReportedText(row.state)
    && isReportedText(row.status)
    && isReportedNumber(row.events)
    && isReportedNumber(row.riskScore)
  );
  const profileReported = (profile: ConnectorProfile) => (
    isReportedText(profile.id)
    && isReportedText(profile.label)
    && isReportedText(profile.category)
    && isReportedText(profile.stage)
    && isReportedText(profile.status)
    && typeof profile.runtimePresent === 'boolean'
    && typeof profile.configured === 'boolean'
    && typeof profile.installProof === 'boolean'
    && Array.isArray(profile.operations)
    && isReportedNumber(profile.scopeCount)
  );
  const bucketReported = (bucket?: McpPolicyBucket) => (
    isReportedNumber(bucket?.count)
    && Array.isArray(bucket?.examples)
    && bucket.examples.every(isReportedText)
    && bucket.examples.length === Math.min(bucket.count, 6)
  );
  if (!agents.every(rowReported) || !tools.every(rowReported) || !profiles.every(profileReported)) return false;
  if (!requests.every((request) => isReportedText(request.id) && isReportedText(request.label) && isReportedText(request.state) && isReportedNumber(request.events))) return false;
  if (!bucketReported(policy.allowed) || !bucketReported(policy.blocked) || !bucketReported(policy.approvalRequired)) return false;
  if (typeof registry.installProof !== 'boolean' || !isReportedText(registry.nextConnector) || !isReportedText(policy.registryMode)) return false;
  if (!hasReportedNumbers([
    summary.events, summary.activeAgents, summary.activeTools, summary.controlled, summary.blocked,
    registry.shipped, registry.profiles, registry.profileTemplates, registry.shippedRuntimePresent,
  ])) return false;
  return Boolean(
    summary.activeAgents === agents.length
    && summary.activeTools === tools.length
    && summary.events === requests.reduce((sum, request) => sum + Number(request.events), 0)
    && summary.registryMode === policy.registryMode
    && registry.profiles === profiles.length
    && registry.shipped === profiles.filter((profile) => profile.stage === 'shipped').length
    && registry.profileTemplates === profiles.filter((profile) => profile.stage === 'template').length
    && registry.shippedRuntimePresent === profiles.filter((profile) => profile.stage === 'shipped' && profile.runtimePresent).length
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
  const reported = agenticMcpReported(mcp);
  return (
    <Section title="Agentic MCP Control" summary={reported && mcp ? agenticMcpSummary(mcp) : 'MCP control details not reported'}>
      <div className="agentic-mcp-board" id="agenticMcpRows" aria-live="polite">
        {reported && mcp
          ? <AgenticMcpBody mcp={mcp} />
          : <EmptyState title="MCP control details not reported" detail="Required MCP counts, registry, policy, agents, tools, or requests were omitted." />}
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

function threatGuardrailsReported(data: ThreatGuardrailsReport | null): boolean {
  const summary = data?.summary;
  const rules = data?.rules;
  const controls = data?.controls;
  const recent = data?.recent;
  if (!summary || !Array.isArray(rules) || !Array.isArray(controls) || !Array.isArray(recent)) return false;
  if (!hasReportedNumbers([
    summary.events,
    summary.detections,
    summary.activeRules,
    summary.blocked,
    summary.critical,
    summary.promptInjection,
    summary.unsafeOutput,
  ])) return false;
  if (!rules.every((rule) => (
    isReportedText(rule.id)
    && isReportedText(rule.label)
    && isReportedText(rule.framework)
    && isReportedText(rule.state)
    && isReportedText(rule.status)
    && isReportedNumber(rule.events)
  ))) return false;
  if (!controls.every((control) => isReportedText(control.label) && isReportedText(control.state) && isReportedText(control.detail))) return false;
  if (!recent.every((event) => (
    isReportedText(event.id)
    && isReportedText(event.severity)
    && isReportedText(event.status)
    && isReportedText(event.decision)
    && isReportedText(event.title)
    && Array.isArray(event.threats)
  ))) return false;
  return Boolean(
    summary.activeRules === rules.filter((rule) => Number(rule.events) > 0).length
    && summary.detections === rules.reduce((sum, rule) => sum + Number(rule.events), 0)
    && summary.promptInjection === Number(rules.find((rule) => rule.id === 'prompt_injection')?.events ?? 0)
    && summary.unsafeOutput === Number(rules.find((rule) => rule.id === 'unsafe_output')?.events ?? 0)
    && ((summary.events === 0) === (recent.length === 0))
  );
}

function ThreatGuardrailsSection({ data }: { data: ThreatGuardrailsReport | null }) {
  const reported = threatGuardrailsReported(data);
  const summary = data?.summary ?? {};
  const summaryText = reported
    ? `${num(summary.events)} events / ${num(summary.activeRules)} active rules / ${summary.privacy || 'prompt bodies excluded'}`
    : 'AI threat guardrails not reported';
  return (
    <Section title="AI Threat Guardrails" summary={summaryText}>
      <div className="agentic-mcp-board" id="threatGuardrailsRows" aria-live="polite">
        {reported && data ? (
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
          <EmptyState title="AI threat guardrails not reported" detail="Required threat counts, guardrails, controls, or recent events were omitted." />
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

function controlGraphReported(graph: ControlGraphReport | null): boolean {
  const summary = graph?.summary;
  const lanes = graph?.lanes;
  const nodes = graph?.nodes;
  const edges = graph?.edges;
  if (!summary || !Array.isArray(lanes) || !Array.isArray(nodes) || !Array.isArray(edges)) return false;
  if (!hasReportedNumbers([
    summary.nodes,
    summary.edges,
    summary.highRiskAssets,
    summary.shadowAssets,
    summary.mcpLinks,
    summary.controlledLinks,
  ])) return false;
  if (!lanes.every((lane) => isReportedText(lane.id) && isReportedText(lane.label) && isReportedNumber(lane.count))) return false;
  if (!nodes.every((node) => isReportedText(node.id) && isReportedText(node.lane) && isReportedText(node.label) && isReportedText(node.status))) return false;
  if (!edges.every((edge) => isReportedText(edge.id) && isReportedText(edge.from) && isReportedText(edge.to) && isReportedText(edge.status) && isReportedNumber(edge.events))) return false;
  const nodeIds = new Set(nodes.map((node) => node.id));
  const laneIds = new Set(lanes.map((lane) => lane.id));
  return Boolean(
    summary.nodes === nodes.length
    && summary.edges === edges.length
    && nodes.every((node) => laneIds.has(node.lane || ''))
    && edges.every((edge) => nodeIds.has(edge.from || '') && nodeIds.has(edge.to || ''))
    && lanes.every((lane) => lane.count === nodes.filter((node) => node.lane === lane.id).length)
  );
}

function ControlGraphSection({ graph }: { graph: ControlGraphReport | null }) {
  const reported = controlGraphReported(graph);
  const summary = graph?.summary ?? {};
  const lanes = graph?.lanes ?? [];
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const summaryText = reported
    ? `${num(summary.nodes)} nodes / ${num(summary.edges)} links / ${num(summary.highRiskAssets)} high risk / ${summary.privacy || 'prompt bodies excluded'}`
    : 'AI control graph not reported';
  const empty = reported && !nodes.length && !edges.length;
  return (
    <Section title="AI Control Graph" summary={summaryText}>
      <div className="control-graph" id="controlGraphMap" aria-live="polite">
        {!reported ? (
          <EmptyState title="AI control graph not reported" detail="Required graph counts, lanes, nodes, or links were omitted." />
        ) : empty ? (
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

function ProofLedgerBlock({ ledger, proofs }: { ledger?: ProofLedger; proofs?: ProofItem[] }) {
  return (
    <div className="hardening-proof-ledger">
      <div className="proof-ledger-head">
        <b>Evidence ledger</b>
        <span>{proofLedgerSummary(ledger)}</span>
      </div>
      {!Array.isArray(proofs) ? (
        <p className="hardening-step-empty">Proof rows not reported.</p>
      ) : proofs.length ? (
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

function RunbookBlock({ steps }: { steps?: PlaybookStep[] }) {
  return (
    <div className="hardening-runbook">
      <b>Runbook</b>
      {!Array.isArray(steps) ? (
        <p className="hardening-step-empty">Runbook steps not reported.</p>
      ) : steps.length ? (
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
  const scoreReported = isReportedNumber(area.score);
  return (
    <article className={`hardening-card ${readinessTone(area.state)}`}>
      <div className="hardening-head">
        <div className="hardening-title">
          <SignalDot status={status} label={`${area.label || ''} ${area.state || ''}`} />
          <strong>{area.label || ''}</strong>
        </div>
        <div className="hardening-score">
          {scoreReported ? area.score : 'Not reported'}
          {scoreReported ? <span>/100</span> : null}
        </div>
      </div>
      <p className="hardening-desc">{area.description || ''}</p>
      <div className="hardening-meta">
        <span>{area.owner || 'Owner not reported'}</span>
        <span>{area.source || 'Source not reported'}</span>
      </div>
      <div className="hardening-lists">
        <HardeningList
          label="Proof"
          items={area.evidence?.slice(0, 3)}
          missingFallback="Proof state not reported"
          emptyFallback="No proof items reported"
        />
        <HardeningList
          label="Gaps"
          items={area.gaps?.slice(0, 3)}
          missingFallback="Gap state not reported"
          emptyFallback="No open gaps reported"
        />
      </div>
      <ProofLedgerBlock ledger={area.proofLedger} proofs={area.proofs?.slice(0, 6)} />
      <RunbookBlock steps={area.playbook?.slice(0, 5)} />
      <TabJump tab={area.targetTab || 'coverage'} label={area.action || 'Open'} />
    </article>
  );
}

const SOC_SNAPSHOT_PERMISSION_ID = 'socSnapshotPermission';

function WorkbenchSection({ hardening, canSendSnapshot, snapshot }: { hardening: HardeningReport | null; canSendSnapshot: boolean; snapshot: SnapshotControl }) {
  const areasReported = Array.isArray(hardening?.areas);
  const areas = areasReported ? hardening?.areas ?? [] : [];
  const ready = areas.filter((area) => area.state === 'ready').length;
  const readinessReported = areas.every((area) => Boolean(area.state));
  const score = isReportedNumber(hardening?.score) ? `${hardening.score} overall` : 'overall score not reported';
  const summary = !areasReported
    ? 'Hardening areas not reported'
    : areas.length
      ? `${readinessReported ? `${ready}/${areas.length} ready` : 'readiness state not reported'} / ${score}`
      : 'No hardening areas reported';
  const actions = (
    <div className="signal-header-actions">
      <span className="signal-updated">{snapshot.status}</span>
      <button
        className="system-button secondary"
        type="button"
        disabled={snapshot.sending || !canSendSnapshot}
        aria-busy={snapshot.sending}
        aria-describedby={!canSendSnapshot ? SOC_SNAPSHOT_PERMISSION_ID : undefined}
        title={canSendSnapshot ? 'Send sanitized posture snapshot' : 'Security Admin required'}
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
      {!canSendSnapshot ? (
        <PermissionNote id={SOC_SNAPSHOT_PERMISSION_ID}>
          Security Admin access is required to send SOC snapshots.
        </PermissionNote>
      ) : null}
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

const SIEM_PERMISSION_ID = 'siemPackagePermission';

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
        <select
          value={siem.profile}
          disabled={busy || !canUse}
          aria-label="SIEM package profile"
          aria-describedby={!canUse ? SIEM_PERMISSION_ID : undefined}
          onChange={(event) => siem.setProfile(event.target.value)}
        >
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
        aria-describedby={!canUse ? SIEM_PERMISSION_ID : undefined}
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
      {!canUse ? (
        <PermissionNote id={SIEM_PERMISSION_ID}>
          Security Admin or Auditor access is required to prepare or download SIEM packages.
        </PermissionNote>
      ) : null}
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

function trendReported(trend: TrendDay[] | undefined): trend is TrendDay[] {
  return Array.isArray(trend) && trend.every((row) => (
    typeof row.date === 'string'
    && hasReportedNumbers([row.events, row.blocked, row.redacted, row.coached, row.allowed])
  ));
}

function TrendSection({ trend }: { trend?: TrendDay[] }) {
  const reported = trendReported(trend);
  const rows = reported ? trend : [];
  const max = Math.max(1, ...rows.map((row) => num(row.events)));
  const total = rows.reduce((sum, row) => sum + num(row.events), 0);
  return (
    <Section title="Risk Trend" summary={!reported ? 'Risk trend not reported' : rows.length ? `${total} events / ${rows.length} days` : 'No trend activity'}>
      <div className="trend-chart" aria-live="polite">
        {!reported ? (
          <EmptyState title="Risk trend not reported" detail="Required daily trend counts were omitted from the latest posture." />
        ) : rows.length ? (
          rows.map((row, index) => <TrendDayCol key={row.date ?? index} row={row} max={max} />)
        ) : (
          <EmptyState title="No trend data" detail="Recent activity appears here." />
        )}
      </div>
    </Section>
  );
}

function controlsReported(controls: ControlOutcome[] | undefined): controls is ControlOutcome[] {
  return Array.isArray(controls) && controls.every((row) => (
    typeof row.label === 'string'
    && hasReportedNumbers([row.events, row.blocked, row.redacted, row.coached])
  ));
}

function ControlOutcomesSection({ controls }: { controls?: ControlOutcome[] }) {
  const reported = controlsReported(controls);
  const rows = reported ? controls : [];
  const total = rows.reduce((sum, row) => sum + num(row.events), 0);
  return (
    <Section title="Control Outcomes" summary={!reported ? 'Control outcomes not reported' : rows.length ? `${rows.length} control paths` : 'No control outcomes'}>
      <div className="control-breakdown" aria-live="polite">
        {!reported ? (
          <EmptyState title="Control outcomes not reported" detail="Required control-path counts were omitted from the latest posture." />
        ) : rows.length ? (
          rows.map((row) => {
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

function behaviorBaselinesReported(baselines: BehaviorBaselinesReport | null): boolean {
  const summary = baselines?.summary;
  const dimensions = baselines?.dimensions;
  if (!summary || !Array.isArray(dimensions)) return false;
  if (!hasReportedNumbers([summary.activeEvents, summary.anomalies, summary.critical, summary.warning])) return false;
  if (!dimensions.every((dimension) => (
    isReportedText(dimension.id)
    && (isReportedText(dimension.label) || isReportedText(dimension.title))
    && isReportedText(dimension.state)
    && isReportedNumber(dimension.score)
  ))) return false;
  return Boolean(
    summary.anomalies === dimensions.length
    && summary.critical === dimensions.filter((dimension) => dimension.state === 'critical').length
    && summary.warning === dimensions.filter((dimension) => dimension.state === 'warning').length
  );
}

function BehaviorBaselinesSection({ baselines }: { baselines: BehaviorBaselinesReport | null }) {
  const reported = behaviorBaselinesReported(baselines);
  const summary = baselines?.summary ?? {};
  const rows = (baselines?.dimensions ?? []).slice(0, 6);
  const summaryText = reported
    ? `${num(summary.anomalies)} anomalies / ${num(summary.critical)} critical / ${num(summary.warning)} watch`
    : 'Behavior baselines not reported';
  return (
    <Section title="Behavior Baselines" summary={summaryText}>
      <div className="control-breakdown behavior-baselines" id="behaviorBaselineRows" aria-live="polite">
        {!reported ? (
          <EmptyState title="Behavior baselines not reported" detail="Required anomaly counts or baseline dimensions were omitted." />
        ) : rows.length ? (
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
          <EmptyState
            title={num(summary.activeEvents) > 0 ? 'No behavior anomalies' : 'No baseline activity'}
            detail={num(summary.activeEvents) > 0 ? 'Observed metadata matches the learned baseline.' : 'No eligible recent metadata was available for baseline comparison.'}
          />
        )}
      </div>
    </Section>
  );
}

const dqTone = (state?: string) => `tone-${state === 'ready' ? 'secure' : state === 'blocked' ? 'critical' : 'warn'}`;

function decisionQualityReported(quality: DecisionQualityInfo | null): boolean {
  const summary = quality?.summary;
  const cards = quality?.cards;
  const hotspots = quality?.hotspots;
  if (!summary || !Array.isArray(cards) || !Array.isArray(hotspots)) return false;
  if (!hasReportedNumbers([summary.controlRate, summary.pendingReviews, summary.overrideWatch])) return false;
  if (!cards.every((card) => (
    isReportedText(card.id)
    && isReportedText(card.label)
    && isReportedNumber(card.score)
    && isReportedText(card.state)
    && (isReportedText(card.value) || isReportedNumber(card.value))
  ))) return false;
  if (!hotspots.every((hotspot) => (
    isReportedText(hotspot.id)
    && isReportedText(hotspot.kind)
    && isReportedText(hotspot.label)
    && hasReportedNumbers([hotspot.events, hotspot.sensitive])
  ))) return false;
  return cards.length > 0 || hotspots.length > 0
    || (summary.controlRate === 0 && summary.pendingReviews === 0 && summary.overrideWatch === 0);
}

function DecisionQualitySection({ quality }: { quality: DecisionQualityInfo | null }) {
  const reported = decisionQualityReported(quality);
  const summary = quality?.summary ?? null;
  const cards = quality?.cards ?? [];
  const hotspots = (quality?.hotspots ?? []).slice(0, 4);
  const summaryText = reported && summary
    ? `${num(summary.controlRate)}% controlled / ${num(summary.pendingReviews)} pending / ${num(summary.overrideWatch)} overrides`
    : 'Reviewer decision quality not reported';
  return (
    <Section title="Reviewer Decision Quality" summary={summaryText}>
      <div className="control-breakdown" id="decisionQualityRows" aria-live="polite">
        {!reported || !summary ? (
          <EmptyState title="Reviewer decision quality not reported" detail="Required quality counts, score cards, or hotspots were omitted." />
        ) : !cards.length && !hotspots.length ? (
          <EmptyState title="No reviewer decision hotspots" detail="The verified snapshot contained no scored cards or decision hotspots." />
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

const DETECTOR_FEEDBACK_PERMISSION_ID = 'detectorFeedbackPermission';

function candidatePermissionId(item: FeedbackCandidate): string {
  const token = `${item.queryId}-${item.detectorId}`.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 140);
  return `detector-feedback-candidate-${token}`;
}

function CandidateRow({ item, verdicts }: { item: FeedbackCandidate; verdicts: VerdictControl }) {
  const candidateAllowed = item.canFeedback === true;
  const canSubmit = verdicts.canSubmit && candidateAllowed;
  const permissionId = verdicts.canSubmit && !candidateAllowed ? candidatePermissionId(item) : DETECTOR_FEEDBACK_PERMISSION_ID;
  const disabledTitle = !verdicts.canSubmit
    ? 'Security Admin or Member Data Reviewer required'
    : item.canFeedback === false
      ? 'This candidate is assigned to another reviewer or role'
      : 'Candidate authorization not reported';
  const verdictButton = (verdict: 'valid' | 'false_positive', label: string) => {
    const state = verdicts.states.get(`${item.queryId}:${item.detectorId}:${verdict}`);
    return (
      <button
        className="ghost mini"
        type="button"
        disabled={!canSubmit || state === 'busy'}
        aria-describedby={!canSubmit ? permissionId : undefined}
        title={canSubmit ? `Mark detector ${label.toLowerCase()}` : disabledTitle}
        onClick={() => void verdicts.submit(item.queryId, item.detectorId, verdict)}
      >
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
        {verdicts.canSubmit && !candidateAllowed ? (
          <small id={permissionId}>
            {item.canFeedback === false ? 'Assigned to another reviewer or role.' : 'Candidate authorization not reported.'}
          </small>
        ) : null}
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

function feedbackQualityReported(quality: FeedbackQualitySummary | undefined): quality is FeedbackQualitySummary {
  return Boolean(
    quality
    && typeof quality.floorsMet === 'boolean'
    && hasReportedNumbers([
      quality.score, quality.failures, quality.semanticRecall, quality.semanticPrecision,
      quality.structuredRecall, quality.structuredF1, quality.benignFalsePositives, quality.baitFalsePositives,
    ]),
  );
}

function detectorFeedbackReported(report: FeedbackReport | null): boolean {
  const summary = report?.summary;
  return Boolean(
    summary
    && Array.isArray(report?.detectors)
    && Array.isArray(report?.reviewQueue)
    && report.detectors.every((item) => hasReportedNumbers([item.total, item.falsePositive, item.tooSensitive]))
    && report.reviewQueue.every((item) => (
      typeof item.queryId === 'string'
      && typeof item.detectorId === 'string'
      && isReportedNumber(item.riskScore)
      && typeof item.canFeedback === 'boolean'
    ))
    && hasReportedNumbers([summary.noisy, summary.valid, summary.reviewCandidates]),
  );
}

function detectorFeedbackSummary(report: FeedbackReport | null, state: AuxiliaryLoadState): string {
  const summary = report?.summary;
  if (!summary || !detectorFeedbackReported(report)) return auxiliaryStateLabel(state, 'detector feedback') || 'Feedback details not reported';
  const counts = `${num(summary.noisy)} noisy / ${num(summary.valid)} valid / ${num(summary.reviewCandidates)} candidates`;
  const quality = report?.quality?.summary;
  const verified = feedbackQualityReported(quality) ? `${num(quality.score)}/100 eval / ${counts}` : counts;
  return state === 'stale' ? `Last verified / ${verified}` : verified;
}

function DetectorFeedbackSection({ report, state, verdicts }: { report: FeedbackReport | null; state: AuxiliaryLoadState; verdicts: VerdictControl }) {
  const reported = detectorFeedbackReported(report);
  const summary = report?.summary ?? null;
  const quality = report?.quality?.summary ?? null;
  const qualityReported = feedbackQualityReported(quality ?? undefined);
  const detectors = (report?.detectors ?? []).slice(0, 4);
  const candidates = (report?.reviewQueue ?? []).slice(0, 4);
  return (
    <Section title="Detection Feedback" summary={detectorFeedbackSummary(report, state)}>
      {!verdicts.canSubmit ? (
        <PermissionNote id={DETECTOR_FEEDBACK_PERMISSION_ID}>
          Security Admin or Member Data Reviewer access is required to submit detector feedback.
        </PermissionNote>
      ) : null}
      <div className="control-breakdown" id="detectorFeedbackRows" aria-live="polite">
        {!summary || !reported ? (
          <EmptyState
            title={state === 'loading' ? 'Loading detector feedback' : state === 'unavailable' ? 'Detector feedback unavailable' : 'Feedback details not reported'}
            detail={state === 'unavailable' ? 'Refresh before treating review candidates as zero.' : 'Required counts, detector rows, candidates, or candidate authority were not fully reported.'}
          />
        ) : (
          <>
            {report?.quality && !qualityReported ? (
              <EmptyState title="Detection quality not reported" detail="The held-out quality summary was incomplete; candidate authorization remains independently verified." />
            ) : quality && qualityReported ? <QualityBars quality={quality} /> : null}
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

function InsightGrid({ report, feedback, feedbackState, verdicts }: { report: Posture | null; feedback: FeedbackReport | null; feedbackState: AuxiliaryLoadState; verdicts: VerdictControl }) {
  return (
    <div className="signal-insight-grid">
      <TrendSection trend={report?.trend} />
      <ControlOutcomesSection controls={report?.controls} />
      <BehaviorBaselinesSection baselines={report?.behaviorBaselines ?? null} />
      <DecisionQualitySection quality={report?.decisionQuality ?? null} />
      <DetectorFeedbackSection report={feedback} state={feedbackState} verdicts={verdicts} />
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
  surfaces?: PostureSurfaceInfo[];
  events?: MonitorEventInfo[];
  ui: MonitorUi;
  search: SearchUi;
  recentEventId: string;
}

function SignalLayout({ surfaces, events, ui, search, recentEventId }: SignalLayoutProps) {
  const surfaceRows = surfacesReported(surfaces) ? surfaces : null;
  const eventRows = eventsReported(events) ? events : null;
  const visibleSurfaces = useMemo(
    () => (surfaceRows ?? []).filter((item) => matchesStatus(item, ui.statusFilter) && matchesSearch(item, search.state, ui.term)),
    [surfaceRows, ui.statusFilter, search.state, ui.term],
  );
  const visibleEvents = useMemo(
    () => (eventRows ?? []).filter((event) => matchesStatus(event, ui.statusFilter) && matchesSearch(event, search.state, ui.term)),
    [eventRows, ui.statusFilter, search.state, ui.term],
  );
  return (
    <div className="signal-layout">
      <div className="signal-main-stack">
        <Section title="Surfaces" summary={!surfaceRows ? 'Surfaces not reported' : !surfaceRows.length ? 'No monitored surfaces' : visibleSurfaces.length ? `${visibleSurfaces.length} visible` : 'No matches'}>
          <div className="surveillance-grid" role="list" aria-label="Monitored systems">
            {!surfaceRows ? (
              <EmptyState title="Surfaces not reported" detail="The latest posture omitted monitored-surface evidence." />
            ) : !surfaceRows.length ? (
              <EmptyState title="No monitored surfaces" detail="The verified posture explicitly contained no monitored surfaces." />
            ) : visibleSurfaces.length ? (
              visibleSurfaces.map((item) => <SurfacePanel key={item.id} item={item} ui={ui} />)
            ) : (
              <EmptyState title="No matches" detail="Adjust status or search." />
            )}
          </div>
        </Section>
        <Section title="Activity" summary={!eventRows ? 'Activity events not reported' : !eventRows.length ? 'No recent events' : visibleEvents.length ? `${visibleEvents.length} visible` : 'No matches'}>
          <div className="activity-feed" role="listbox" aria-label="Signal event timeline">
            {!eventRows ? (
              <EmptyState title="Activity events not reported" detail="The latest posture omitted recent live-event evidence." />
            ) : !eventRows.length ? (
              <EmptyState title="No recent events" detail="The verified posture explicitly contained no recent events." />
            ) : visibleEvents.length ? (
              visibleEvents.map((event) => <EventRow key={event.id} event={event} ui={ui} isNew={event.id === recentEventId} />)
            ) : (
              <EmptyState title="No events" detail="Clear search or broaden status." />
            )}
          </div>
        </Section>
      </div>
      <InspectorAside ui={ui} surfaces={surfaceRows ?? []} events={eventRows ?? []} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Task-first operational brief + workspace summaries
// ---------------------------------------------------------------------------

function briefTone(status: string | undefined, state: PostureLoadState): BriefTone {
  const normalized = String(status || '').toLowerCase();
  if (state === 'unavailable' || ['critical', 'error', 'blocked'].includes(normalized)) return 'critical';
  if (state === 'loading') return 'neutral';
  if (state === 'switching' || state === 'partial' || state === 'stale' || ['warning', 'attention'].includes(normalized)) return 'attention';
  return normalized ? 'ready' : 'neutral';
}

function missingBrief(id: string, label: string, state: PostureLoadState, detail: string): CommandCenterBriefItem {
  const loading = state === 'loading';
  const unavailable = state === 'unavailable';
  return {
    id,
    label,
    value: loading ? 'Syncing' : unavailable ? 'Unavailable' : 'Not reported',
    detail: loading ? 'Waiting for verified posture.' : unavailable ? 'Refresh before relying on this state.' : detail,
    tone: briefTone(undefined, state),
  };
}

function metricById(report: Posture, id: string): PostureMetric | undefined {
  return report.metrics?.find((metric) => metric.id === id);
}

function enforcementBrief(report: Posture | null, state: PostureLoadState): CommandCenterBriefItem {
  if (!report) return missingBrief('enforcement', 'Enforcement health', state, 'Health was not included.');
  const control = metricById(report, 'controlled-sensitive');
  const score = report.hardening?.score;
  if (score === undefined && !control) return missingBrief('enforcement', 'Enforcement health', state, 'Health was not included.');
  const controlValue = control ? `${control.value}${control.unit || ''} control rate` : 'Control rate not reported';
  return {
    id: 'enforcement',
    label: 'Enforcement health',
    value: score === undefined ? `${control?.value ?? '-'}${control?.unit || ''}` : `${num(score)}/100`,
    detail: `${controlValue} / ${report.hardening?.mission?.status || report.hardening?.state || 'posture available'}`,
    tone: briefTone(report.hardening?.state || control?.status, state),
  };
}

function urgentBrief(report: Posture | null, state: PostureLoadState): CommandCenterBriefItem {
  if (!report) return missingBrief('actions', 'Urgent actions', state, 'Action state was not included.');
  const rows = report.actionQueue;
  if (!rows) return missingBrief('actions', 'Urgent actions', state, 'Action state was not included.');
  if (!rows.length) {
    return {
      id: 'actions',
      label: 'Urgent actions',
      value: 'Clear',
      detail: 'The verified action queue is explicitly empty.',
      tone: briefTone('ready', state),
    };
  }
  const open = rows.filter(actionNeedsAttention);
  const complete = rows.filter(actionIsVerifiedComplete);
  const critical = open.filter((item) => item.severity === 'critical').length;
  const routed = open.filter((item) => item.workflowStatus === 'assigned' || item.workflowStatus === 'snoozed').length;
  const proofPending = open.filter((item) => item.workflowProofState === 'proof_pending').length;
  const proofUnreported = open.filter((item) => item.workflowStatus === 'resolved' && !item.workflowProofState).length;
  return {
    id: 'actions',
    label: 'Urgent actions',
    value: open.length ? `${open.length} open` : 'Clear',
    detail: open.length
      ? `${critical} critical / ${routed} routed / ${proofPending} proof pending / ${proofUnreported} proof status not reported / ${complete.length} verified complete`
      : `${complete.length} explicitly resolved with verified proof / no open gaps`,
    tone: briefTone(critical ? 'critical' : open.length ? 'attention' : 'ready', state),
  };
}

function scopeLabel(segments: SegmentsReport, segmentId: string): string {
  if (segmentId === 'all') return 'All activity';
  const filter = segments.filters?.find((item) => item.id === segmentId);
  const active = segments.active?.id === segmentId ? segments.active : null;
  return filter?.label || active?.label || segmentId;
}

function scopeBrief(
  report: Posture | null,
  state: PostureLoadState,
  verifiedSegment: string,
  requestedSegment: string,
): CommandCenterBriefItem {
  if (!report?.segments) return missingBrief('scope', 'Active scope', state, 'Scope detail was not included.');
  const segments = report.segments;
  const label = scopeLabel(segments, verifiedSegment);
  const requestedLabel = scopeLabel(segments, requestedSegment);
  const summary = segments.summary ?? {};
  const stateDetail = state === 'switching'
    ? `Switching to ${requestedLabel}; showing verified ${label}`
    : state === 'stale' && requestedSegment !== verifiedSegment
      ? `Switch failed; showing last verified ${label}`
      : state === 'stale'
        ? `Refresh failed; showing last verified ${label}`
        : `Showing verified ${label}`;
  const visible = reportedNumberCount(summary.visibleEvents, 'visible event');
  const attention = reportedNumberCount(summary.attention, 'attention item');
  const scopedAttention = segments.active
    ? segments.active.state !== 'ready'
    : isReportedNumber(summary.attention) && summary.attention > 0;
  return {
    id: 'scope',
    label: 'Active scope',
    value: label,
    detail: `${stateDetail} / ${visible} / ${attention} / ${summary.privacy || 'privacy detail not reported'}`,
    tone: briefTone(scopedAttention ? 'attention' : undefined, state),
  };
}

function sensorBrief(report: Posture | null, state: PostureLoadState): CommandCenterBriefItem {
  if (!report) return missingBrief('sensors', 'Sensor coverage', state, 'Coverage was not included.');
  const metric = metricById(report, 'active-sensors');
  if (!metric) return missingBrief('sensors', 'Sensor coverage', state, 'Required sensor coverage was not included.');
  return {
    id: 'sensors',
    label: 'Sensor coverage',
    value: `${metric.value}${metric.unit || ''}`,
    detail: 'Required browser, endpoint, and MCP enforcement surfaces.',
    tone: briefTone(metric.status, state),
  };
}

function evidenceAge(generatedAt: string): { label: string; status: string } {
  const ageMs = Date.now() - new Date(generatedAt).getTime();
  if (!Number.isFinite(ageMs)) return { label: 'Timestamp missing', status: 'warning' };
  const minutes = Math.max(0, Math.floor(ageMs / 60_000));
  if (minutes < 1) return { label: 'Just now', status: 'ready' };
  if (minutes < 60) return { label: `${minutes}m old`, status: minutes > 15 ? 'warning' : 'ready' };
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return { label: `${hours}h old`, status: 'warning' };
  return { label: `${Math.floor(hours / 24)}d old`, status: 'critical' };
}

function evidenceBrief(report: Posture | null, state: PostureLoadState): CommandCenterBriefItem {
  if (!report?.generatedAt) return missingBrief('evidence', 'Evidence freshness', state, 'A generation timestamp was not included.');
  const ledger = report.hardening?.mission?.proofLedger ?? report.hardening?.proofLedger;
  const age = evidenceAge(report.generatedAt);
  const proofDetail = proofLedgerSummary(ledger);
  return {
    id: 'evidence',
    label: 'Evidence freshness',
    value: age.label,
    detail: `${proofDetail} / generated ${fmt(report.generatedAt)} / prompt bodies excluded`,
    tone: briefTone(age.status, state),
  };
}

interface OperationalBriefProps {
  report: Posture | null;
  state: PostureLoadState;
  requestedSegment: string;
  verifiedSegment: string;
  onSegment: (id: string) => void;
}

function OperationalBrief({ report, state, requestedSegment, verifiedSegment, onSegment }: OperationalBriefProps) {
  const items = [
    { ...enforcementBrief(report, state), actionLabel: 'Review enforcement', onActivate: () => scrollToAnchor('workspace-enforcement', true) },
    { ...urgentBrief(report, state), actionLabel: 'Work queue', onActivate: () => scrollToAnchor('hardeningActionQueue', true) },
    {
      ...scopeBrief(report, state, verifiedSegment, requestedSegment),
      control: <SegmentSelectControl segments={report?.segments ?? null} selectedId={requestedSegment} onSegment={onSegment} compact />,
      actionLabel: 'Review scope detail',
      onActivate: () => scrollToAnchor('workspace-enforcement', true),
    },
    { ...sensorBrief(report, state), actionLabel: 'Inspect surfaces', onActivate: () => scrollToAnchor('workspace-live', true) },
    { ...evidenceBrief(report, state), actionLabel: 'Prepare evidence', onActivate: () => scrollToAnchor('workspace-evidence', true) },
  ];
  return <CommandCenterBrief items={items} />;
}

const MONITOR_WORKSPACES: MonitorWorkspaceItem[] = [
  { id: 'workspace-enforcement', label: 'Enforcement & scope', description: 'Policy health, mission, and objectives' },
  { id: 'workspace-estate', label: 'AI estate & guardrails', description: 'Assets, MCP, threats, and graph' },
  { id: 'workspace-evidence', label: 'Evidence operations', description: 'Proof, snapshots, and SIEM package' },
  { id: 'workspace-intelligence', label: 'Decision intelligence', description: 'Trends, feedback, and outcomes' },
  { id: 'workspace-live', label: 'Live signals', description: 'Search, surfaces, activity, and inspector' },
];

function enforcementWorkspaceSummary(report: Posture | null): string {
  if (!report) return 'Waiting for verified posture';
  const mission = report.hardening?.mission?.status || report.hardening?.state || 'mission not reported';
  const metrics = metricsReported(report.metrics) ? reportedArrayCount(report.metrics, 'metric') : 'metrics not reported';
  const objectives = objectivesReported(report.objectives) ? reportedArrayCount(report.objectives, 'objective') : 'objectives not reported';
  return `${metrics} / ${objectives} / ${mission}`;
}

function estateWorkspaceSummary(report: Posture | null): string {
  if (!report) return 'Waiting for verified posture';
  const inventory = report.aiInventory ?? null;
  const mcp = report.agenticMcp ?? null;
  const threat = report.threatGuardrails ?? null;
  const graph = report.controlGraph ?? null;
  const assets = inventoryReported(inventory)
    ? reportedNumberCount((inventory?.apps?.length ?? 0) + (inventory?.tools?.length ?? 0), 'asset')
    : 'assets not reported';
  const agents = agenticMcpReported(mcp) ? reportedNumberCount(mcp?.summary?.activeAgents, 'MCP agent') : 'MCP control not reported';
  const threats = threatGuardrailsReported(threat) ? reportedNumberCount(threat?.summary?.events, 'threat event') : 'threat events not reported';
  const nodes = controlGraphReported(graph) ? reportedNumberCount(graph?.summary?.nodes, 'graph node') : 'graph nodes not reported';
  return `${assets} / ${agents} / ${threats} / ${nodes}`;
}

function evidenceWorkspaceSummary(report: Posture | null, siem: SiemState, canUse: boolean): string {
  if (!report && !siem.pkg) return canUse ? 'Waiting for proof and package data' : 'Role-scoped evidence controls';
  return `${reportedArrayCount(report?.hardening?.areas, 'hardening area')} / ${siemSummary(siem, canUse)}`;
}

function intelligenceWorkspaceSummary(
  report: Posture | null,
  feedback: FeedbackReport | null,
  feedbackState: AuxiliaryLoadState,
  activityRows: QueueQuery[] | null,
  activityState: AuxiliaryLoadState,
): string {
  const candidates = feedback?.summary?.reviewCandidates;
  const candidateSummary = detectorFeedbackReported(feedback)
    ? reportedNumberCount(candidates, 'candidate')
    : auxiliaryStateLabel(feedbackState, 'detector feedback') || 'Detector feedback not reported';
  const activitySummary = activityRows ? `${activityRows.length} decisions` : auxiliaryStateLabel(activityState, 'activity');
  if (!report) return `${activitySummary} / ${candidateSummary}`;
  const trendSummary = trendReported(report.trend) ? reportedArrayCount(report.trend, 'trend day') : 'trend days not reported';
  const controlSummary = controlsReported(report.controls) ? reportedArrayCount(report.controls, 'control path') : 'control paths not reported';
  return `${trendSummary} / ${controlSummary} / ${activitySummary} / ${candidateSummary}`;
}

function liveWorkspaceSummary(report: Posture | null): string {
  if (!report) return 'Waiting for live surfaces and events';
  const surfaces = surfacesReported(report.surfaces) ? reportedArrayCount(report.surfaces, 'surface') : 'surfaces not reported';
  const events = eventsReported(report.events) ? reportedArrayCount(report.events, 'recent event') : 'recent events not reported';
  return `${surfaces} / ${events}`;
}

function MonitorDataNotice({ state, onRefresh }: { state: PostureLoadState; onRefresh: () => void }) {
  if (state !== 'partial' && state !== 'stale' && state !== 'unavailable') return null;
  const message = state === 'stale'
    ? 'The latest posture refresh failed. Values below are the last verified snapshot and are not a current all-clear.'
    : state === 'partial'
      ? 'The current posture is scope-verified but incomplete. Missing evidence is marked not reported and is not a current all-clear.'
      : 'Current posture is unavailable. RedactWall is not substituting zeroes or an all-clear state.';
  return (
    <div className="monitor-data-notice" role="alert">
      <span>{message}</span>
      <button className="system-button secondary" type="button" onClick={onRefresh}>Retry posture</button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

interface MonitorCapabilities {
  canWritePostureActions: boolean;
  canWriteDetectorFeedback: boolean;
  canSendSocSnapshot: boolean;
  canUseSiem: boolean;
}

function monitorCapabilities(role: string | null): MonitorCapabilities {
  return {
    canWritePostureActions: role === 'security_admin' || role === 'operator',
    canWriteDetectorFeedback: role === 'security_admin' || role === 'approver',
    canSendSocSnapshot: role === 'security_admin',
    canUseSiem: role === 'security_admin' || role === 'auditor',
  };
}

export default function Monitor() {
  const { me } = useSession();
  const role = me ? me.role : null;
  const capabilities = monitorCapabilities(role);
  const [segment, setSegment] = useState('all');
  const posture = usePosture(segment);
  const siem = useSiemPackage(role);
  const feedback = useFeedbackReport();
  const activity = useActivityRows();
  const { refreshing, recentEventId, refresh } = useMonitorRefresh(posture.load, siem.load, feedback.load, activity.load);
  const ui = useMonitorUi();
  const workflow = useActionWorkflow(capabilities.canWritePostureActions, me ? me.user : '', posture.load);
  const snapshot = useSocSnapshot(capabilities.canSendSocSnapshot);
  const verdicts = useDetectorVerdicts(feedback.load, capabilities.canWriteDetectorFeedback);

  const reloadLive = useCallback(() => {
    void posture.load();
    void activity.load();
  }, [posture.load, activity.load]);
  useEventStream({ query: reloadLive, decision: reloadLive, stats: reloadLive });

  const report = posture.report;
  const search = searchUiState(ui.term, ui.focused, refreshing);
  const surfaces = report?.surfaces;
  const events = report?.events;
  const reportedSurfaces = surfacesReported(surfaces) ? surfaces : [];
  const reportedEvents = eventsReported(events) ? events : [];
  const critical = reportedSurfaces.some((item) => item.status === 'error') || reportedEvents.some((event) => event.severity === 'critical');

  return (
    <div className="monitor-view">
      <div className="signal-console" aria-label="Texas FCU Command Center">
        <ConsoleHeader
          critical={critical}
          state={posture.state}
          lastUpdated={posture.lastUpdated}
          refreshing={refreshing}
          onRefresh={() => void refresh()}
        />
        <MonitorDataNotice state={posture.state} onRefresh={() => void refresh()} />
        <OperationalBrief
          report={report}
          state={posture.state}
          requestedSegment={segment}
          verifiedSegment={posture.verifiedSegment}
          onSegment={setSegment}
        />
        <div className="monitor-primary-actions">
          <ActionQueueSection rows={report?.actionQueue} state={posture.state} canWrite={capabilities.canWritePostureActions} workflow={workflow} />
        </div>
        <MonitorWorkspaceNav items={MONITOR_WORKSPACES} />

        <MonitorWorkspaceGroup
          id="workspace-enforcement"
          label="Enforcement & scope"
          description="Active policy posture, scope, mission progress, and examiner objectives."
          summary={enforcementWorkspaceSummary(report)}
        >
          <SegmentLens segments={report?.segments ?? null} onSegment={setSegment} />
          <MetricGrid metrics={report?.metrics} refreshing={refreshing} fallbackUpdated={report?.generatedAt || posture.lastUpdated} />
          <MissionBanner mission={report?.hardening?.mission ?? null} />
          <OperatorFlow posture={report} />
          <ObjectivesSection objectives={report?.objectives} />
        </MonitorWorkspaceGroup>

        <MonitorWorkspaceGroup
          id="workspace-estate"
          label="AI estate & guardrails"
          description="Sanctioned and shadow AI assets, agentic MCP control, threat guardrails, and control paths."
          summary={estateWorkspaceSummary(report)}
        >
          <InventorySection inventory={report?.aiInventory ?? null} />
          <AgenticMcpSection mcp={report?.agenticMcp ?? null} />
          <ThreatGuardrailsSection data={report?.threatGuardrails ?? null} />
          <ControlGraphSection graph={report?.controlGraph ?? null} />
        </MonitorWorkspaceGroup>

        <MonitorWorkspaceGroup
          id="workspace-evidence"
          label="Evidence operations"
          description="Hardening proof, sanitized SOC notifications, and role-scoped SIEM delivery packages."
          summary={evidenceWorkspaceSummary(report, siem, capabilities.canUseSiem)}
        >
          <WorkbenchSection hardening={report?.hardening ?? null} canSendSnapshot={capabilities.canSendSocSnapshot} snapshot={snapshot} />
          <SiemSection siem={siem} canUse={capabilities.canUseSiem} />
        </MonitorWorkspaceGroup>

        <MonitorWorkspaceGroup
          id="workspace-intelligence"
          label="Decision intelligence"
          description="Decision pivots, risk trends, control outcomes, behavior baselines, and detector feedback."
          summary={intelligenceWorkspaceSummary(report, feedback.report, feedback.state, activity.rows, activity.state)}
        >
          <DecisionPivots rows={activity.rows} state={activity.state} />
          <InsightGrid report={report} feedback={feedback.report} feedbackState={feedback.state} verdicts={verdicts} />
        </MonitorWorkspaceGroup>

        <MonitorWorkspaceGroup
          id="workspace-live"
          label="Live signals"
          description="Status filtering, surface health, recent activity, drill-through detail, and selection inspector."
          summary={liveWorkspaceSummary(report)}
        >
          <MonitorToolbar
            term={ui.term}
            search={search}
            counts={surfacesReported(surfaces) && eventsReported(events) ? statusCounts([...surfaces, ...events]) : null}
            filter={ui.statusFilter}
            onTerm={ui.setTerm}
            onFocus={ui.setFocused}
            onFilter={ui.setStatusFilter}
          />
          <SignalLayout surfaces={surfaces} events={events} ui={ui} search={search} recentEventId={recentEventId} />
        </MonitorWorkspaceGroup>
      </div>
    </div>
  );
}
