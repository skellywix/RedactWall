import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  applyPolicyTemplate,
  fetchPolicy,
  fetchPolicyTemplates,
  postPolicyImpact,
  putPolicy,
  type EnforcementMode,
  type ImpactDelta,
  type ImpactOutcome,
  type Policy as PolicyDoc,
  type PolicyImpact,
  type PolicyTemplate,
  type PolicyUpdate,
  type ResponseScanMode,
} from '../api/policy';
import { EmptyState, Panel } from '../components/Panel';
import { api, apiErrorSummary, apiJson } from '../lib/api';
import { csvStamp } from '../lib/csv';
import { routeHref } from '../lib/router';
import { roleLabel, useSession } from '../lib/session';
import { toast } from '../lib/toast';
import './Policy.css';

/**
 * Configuration view (full port of the legacy #tab-policy Configuration tab).
 * Form-edits every policy field the legacy console edits: enforcement core,
 * destination governance, fleet posture, MCP tool governance, approval
 * routing, browser action controls, and scoped rules/exceptions JSON, plus
 * the detection tester, setup/health/sensor/environment cards, retention
 * purge, and policy export. No SSE auto-reload: refreshing the form mid-edit
 * would silently discard operator changes (matches legacy).
 *
 * Endpoints (all named in the port spec): GET/PUT /api/policy,
 * GET /api/policy/templates, PUT /api/policy/apply-template,
 * POST /api/policy/impact, POST /api/retention/purge, GET /api/preflight,
 * GET /api/coverage, GET /api/detectors/meta, POST /api/detectors/test.
 */

// ---- Static option lists -----------------------------------------------------

const MODES: [EnforcementMode, string, string][] = [
  ['warn', 'Monitor', 'Warn users and allow them to continue'],
  ['justify', 'Justify', 'Require a business reason before send'],
  ['redact', 'Redact', 'Tokenize PII before release'],
  ['block', 'Enforce', 'Hold risky prompts for approval'],
];

const SEVERITIES: [number, string][] = [
  [1, 'low'],
  [2, 'medium'],
  [3, 'high'],
  [4, 'critical'],
];

const SCAN_MODES: [ResponseScanMode, string][] = [
  ['flag', 'Flag and alert'],
  ['redact', 'Redact before display'],
  ['block', 'Block display'],
];

const OUTCOMES: [ImpactOutcome, string][] = [
  ['blocked', 'Blocked'],
  ['approval_required', 'Approval required'],
  ['justification_required', 'Justification required'],
  ['redacted', 'Redacted'],
  ['warned', 'Warned'],
  ['allowed', 'Allowed'],
  ['observed', 'Observed'],
];

type DestListKey =
  | 'governedDestinations'
  | 'allowedDestinations'
  | 'blockedDestinations'
  | 'blockedFileUploadDestinations';

const DESTINATION_FIELDS: [DestListKey, string, string][] = [
  ['governedDestinations', 'Governed AI destinations', 'chatgpt.com\nclaude.ai'],
  ['allowedDestinations', 'Allowed AI destinations', 'chatgpt.com\nclaude.ai'],
  ['blockedDestinations', 'Blocked AI destinations', 'deepseek.com\n*.example-ai.com'],
  ['blockedFileUploadDestinations', 'Blocked file uploads', 'chatgpt.com\ndesktop-ai-app'],
];

type McpKey = 'mcpAllowedTools' | 'mcpBlockedTools' | 'mcpApprovalRequiredTools';

/** [draft key, label, placeholder, readonly empty-chip text] */
const MCP_FIELDS: [McpKey, string, string, string][] = [
  ['mcpAllowedTools', 'Allowed MCP tools', 'sharepoint.fetch*\ndrive.read*', 'all tools unless blocked'],
  ['mcpBlockedTools', 'Blocked MCP tools', '*.delete*\ndatabase.write*', 'none'],
  ['mcpApprovalRequiredTools', 'Approval-required MCP tools', 'sharepoint.export*\ndrive.share*', 'none'],
];

const ROUTING_PLACEHOLDER =
  '[{"id":"legal_group_contracts","groups":["RedactWall Legal"],"categories":["LEGAL_CONTRACT"],"destinations":["claude.ai"],"assignedGroup":"legal","assignedRole":"approver","slaMinutes":60}]';

const BROWSER_ACTIONS_PLACEHOLDER =
  '[{"id":"block_paste_chatgpt","action":"paste","destinations":["chatgpt.com"],"reason":"clipboard_paste_blocked"},' +
  '{"id":"block_drop_claude","action":"drop","destinations":["claude.ai"],"reason":"file_drop_blocked"},' +
  '{"id":"block_copy_chatgpt","action":"copy","destinations":["chatgpt.com"],"reason":"response_copy_blocked"},' +
  '{"id":"block_download_chatgpt","action":"download","destinations":["chatgpt.com"],"reason":"download_blocked"}]';

const SCOPES_PLACEHOLDER =
  '[{"id":"legal_contract_review","groups":["RedactWall Legal"],"destinations":["claude.ai"],"categories":["LEGAL_CONTRACT"],"enforcementMode":"block","blockMinSeverity":2}]';

const EXCEPTIONS_PLACEHOLDER =
  '[{"id":"legal_vendor_24h","users":["counsel@example.test"],"destinations":["claude.ai"],"categories":["LEGAL_CONTRACT"],"expiresAt":"2030-01-01T00:00:00.000Z","ownerGroup":"legal","reviewerRole":"security_admin","reviewAfter":"2029-12-15T00:00:00.000Z"}]';

/** Form fields (plus alwaysBlock chips) excluded from the advanced JSON block. */
const FORM_EDITED_FIELDS = new Set<string>([
  'enforcementMode',
  'blockMinSeverity',
  'blockRiskScore',
  'storeRawForApproval',
  'rawRetentionDays',
  'governedDestinations',
  'allowedDestinations',
  'blockedDestinations',
  'blockedFileUploadDestinations',
  'blockUnapprovedAiDestinations',
  'responseScanMode',
  'desktopCollectorDestination',
  'alwaysBlock',
  'requiredSensors',
  'desiredSensorVersions',
  'mcpAllowedTools',
  'mcpBlockedTools',
  'mcpApprovalRequiredTools',
  'approvalRoutingRules',
  'blockedBrowserActions',
  'policyScopes',
  'policyExceptions',
]);

// ---- Pure text helpers (must-match ports of the legacy parse/format set) -----

const humanize = (value: string) => (value || '-').replace(/_/g, ' ');
const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '-');

function listText(items: string[]): string {
  return (items || []).join('\n');
}

/** Mirrors legacy parsePolicyList: newline/comma separated, trimmed, deduped. */
function parseList(value: string): string[] {
  return [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];
}

/** Mirrors legacy policyMapText: one `key=version` per line. */
function mapText(items: Record<string, string>): string {
  return Object.entries(items).map(([key, value]) => `${key}=${value}`).join('\n');
}

/** Mirrors legacy parsePolicyMap: split at first `=` (or whitespace), skip invalid chunks. */
function parseMap(value: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const chunk of value.split(/[\n,]+/)) {
    const trimmed = chunk.trim();
    if (!trimmed) continue;
    const separator = trimmed.includes('=') ? trimmed.indexOf('=') : trimmed.search(/\s/);
    if (separator <= 0) continue;
    const key = trimmed.slice(0, separator).trim();
    const version = trimmed.slice(separator + 1).trim();
    if (key && version) out[key] = version;
  }
  return out;
}

function jsonText(value: unknown): string {
  return JSON.stringify(value ?? [], null, 2);
}

/** Empty text is `[]`; invalid JSON toasts the legacy message and aborts (null). */
function parseJsonArray(value: string, label: string): unknown[] | null {
  const raw = value.trim();
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('expected array');
    return parsed;
  } catch {
    toast(`${label} must be valid JSON array syntax.`, 'warn');
    return null;
  }
}

function cleanId(value: string, fallback: string): string {
  const id = value.toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 64);
  return id || fallback;
}

// ---- Narrowing helpers for advanced policy fields (index signature = unknown) --

type RuleJson = Record<string, unknown>;

function strArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function strMap(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) if (typeof entry === 'string') out[key] = entry;
  return out;
}

function ruleList(value: unknown): RuleJson[] {
  return Array.isArray(value) ? value.filter((item): item is RuleJson => Boolean(item) && typeof item === 'object') : [];
}

function ruleStr(rule: RuleJson, key: string): string {
  const value = rule[key];
  return typeof value === 'string' ? value : '';
}

const MATCHER_SUMMARY_KEYS = ['users', 'groups', 'orgIds', 'sources', 'channels', 'destinations', 'detectors', 'categories'];

function shortValue(value: string): string {
  return value.length > 36 ? `${value.slice(0, 33)}...` : value;
}

function matcherSummary(rule: RuleJson): string {
  return MATCHER_SUMMARY_KEYS.map((key) => ({ key, values: strArray(rule[key]) }))
    .filter((entry) => entry.values.length)
    .map(({ key, values }) => `${key}:${values.slice(0, 2).map(shortValue).join('|')}${values.length > 2 ? '+' : ''}`)
    .join(' ');
}

function exceptionLifecycle(rule: RuleJson): string {
  const now = Date.now();
  const expires = Date.parse(ruleStr(rule, 'expiresAt'));
  const reviewAfter = Date.parse(ruleStr(rule, 'reviewAfter'));
  let status = 'active';
  if (rule.enabled === false) status = 'disabled';
  else if (Number.isFinite(expires) && expires <= now) status = 'expired';
  else if (Number.isFinite(reviewAfter) && reviewAfter <= now) status = 'review due';
  else if (Number.isFinite(expires) && expires <= now + 7 * 24 * 60 * 60 * 1000) status = 'expiring soon';
  const parts = [status];
  const ownerGroup = ruleStr(rule, 'ownerGroup');
  if (ownerGroup) parts.push(`owner ${ownerGroup}`);
  const reviewerRole = ruleStr(rule, 'reviewerRole');
  if (reviewerRole) parts.push(`reviewer ${reviewerRole}`);
  const review = ruleStr(rule, 'reviewAfter');
  if (review) parts.push(`review ${review}`);
  return parts.join(' ');
}

// ---- Preflight / coverage (optional decorations, never block the form) --------

const OPTIONAL_TIMEOUT_MS = 1800;

interface PreflightCheck {
  id: string;
  ok: boolean;
  severity?: string;
}

interface Preflight {
  production?: boolean;
  level?: string;
  checks?: PreflightCheck[];
}

interface CoverageSensor {
  source?: string;
  events?: number;
  lastSeen?: string;
  desiredVersion?: string;
  latestVersion?: string;
  installHealth?: { state?: string };
  required?: boolean;
}

interface Coverage {
  sensors?: CoverageSensor[];
  totals?: { fleetAttention?: number };
}

function fetchPreflight(): Promise<Preflight | null> {
  return apiJson<Preflight>('/api/preflight');
}

function fetchCoverage(): Promise<Coverage | null> {
  return apiJson<Coverage>('/api/coverage');
}

function withTimeout<T>(promise: Promise<T | null>, ms: number): Promise<T | null> {
  return Promise.race([
    promise,
    new Promise<null>((resolve) => {
      window.setTimeout(() => resolve(null), ms);
    }),
  ]);
}

type CardState = 'good' | 'warn' | 'bad';

interface ConfigHealth {
  score: number;
  ok: number;
  total: number;
  state: CardState;
  failed: number;
  label: string;
}

function configHealth(preflight: Preflight | null): ConfigHealth {
  const checks = preflight?.checks || [];
  const ok = checks.filter((check) => check.ok).length;
  const score = checks.length ? Math.round((ok / checks.length) * 100) : 0;
  const state: CardState = preflight?.level === 'blocked' ? 'bad' : score < 100 ? 'warn' : 'good';
  return { score, ok, total: checks.length, state, failed: checks.length - ok, label: preflight?.level ? humanize(preflight.level) : 'unknown' };
}

function checkGroupState(preflight: Preflight | null, ids: string[]): CardState {
  const byId = new Map((preflight?.checks || []).map((check): [string, PreflightCheck] => [check.id, check]));
  const selected = ids.map((id) => byId.get(id)).filter((check): check is PreflightCheck => Boolean(check));
  if (!selected.length) return 'warn';
  if (selected.some((check) => !check.ok && check.severity === 'error')) return 'bad';
  if (selected.some((check) => !check.ok)) return 'warn';
  return 'good';
}

function stateLabel(state: CardState): string {
  return { good: 'Ready', warn: 'Needs review', bad: 'Blocked' }[state];
}

// ---- Detection tester API (analyzed in memory server-side, never stored) ------

interface DetectorMeta {
  severityLabels?: Record<string, string>;
  regulations?: Record<string, string[]>;
}

interface TestFinding {
  type: string;
  severity?: number;
  severityLabel?: string;
  confidence?: string;
  score?: number;
  regulations?: string[];
}

interface BreakdownEntry {
  kind?: string;
  type: string;
  severityLabel?: string;
  confidence?: string;
  points?: number;
  regulations?: string[];
}

interface DetectorTestResult {
  decision: string;
  reasons?: string[];
  riskScore?: number;
  scoreBreakdown?: BreakdownEntry[];
  findings?: TestFinding[];
}

let detectorMetaCache: Promise<DetectorMeta | null> | null = null;

/** GET /api/detectors/meta once per session (legacy caches it the same way). */
function detectorMetaOnce(): Promise<DetectorMeta | null> {
  if (!detectorMetaCache) detectorMetaCache = withTimeout(apiJson<DetectorMeta>('/api/detectors/meta'), 2500);
  return detectorMetaCache;
}

function postDetectorTest(text: string): Promise<Response | null> {
  return api('/api/detectors/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
}

// ---- Draft model ---------------------------------------------------------------

/** Text-input mirror of the editable policy fields. Rule arrays stay raw JSON strings. */
interface Draft {
  enforcementMode: EnforcementMode;
  blockMinSeverity: number;
  blockRiskScore: string;
  storeRawForApproval: boolean;
  rawRetentionDays: string;
  blockUnapprovedAiDestinations: boolean;
  responseScanMode: ResponseScanMode;
  desktopCollectorDestination: string;
  governedDestinations: string;
  allowedDestinations: string;
  blockedDestinations: string;
  blockedFileUploadDestinations: string;
  requiredSensors: string;
  desiredSensorVersions: string;
  mcpAllowedTools: string;
  mcpBlockedTools: string;
  mcpApprovalRequiredTools: string;
  approvalRoutingRules: string;
  blockedBrowserActions: string;
  policyScopes: string;
  policyExceptions: string;
}

/** Draft keys whose value is a plain string, safe to patch generically. */
type StringDraftKey = { [K in keyof Draft]: Draft[K] extends string ? (string extends Draft[K] ? K : never) : never }[keyof Draft];

function textPatch(key: StringDraftKey, value: string): Partial<Draft> {
  const change: Partial<Draft> = {};
  change[key] = value;
  return change;
}

/** Blank stays invalid (NaN -> JSON null -> 400 naming the field) instead of silently becoming 0. */
function numberField(value: string): number {
  return value.trim() === '' ? Number.NaN : Number(value);
}

function draftFromPolicy(policy: PolicyDoc): Draft {
  return {
    enforcementMode: policy.enforcementMode,
    blockMinSeverity: policy.blockMinSeverity,
    blockRiskScore: String(policy.blockRiskScore),
    storeRawForApproval: policy.storeRawForApproval !== false,
    rawRetentionDays: String(policy.rawRetentionDays),
    blockUnapprovedAiDestinations: policy.blockUnapprovedAiDestinations !== false,
    responseScanMode: policy.responseScanMode,
    desktopCollectorDestination: policy.desktopCollectorDestination || 'Desktop AI',
    governedDestinations: listText(policy.governedDestinations),
    allowedDestinations: listText(policy.allowedDestinations),
    blockedDestinations: listText(policy.blockedDestinations),
    blockedFileUploadDestinations: listText(policy.blockedFileUploadDestinations),
    requiredSensors: listText(strArray(policy.requiredSensors)),
    desiredSensorVersions: mapText(strMap(policy.desiredSensorVersions)),
    mcpAllowedTools: listText(strArray(policy.mcpAllowedTools)),
    mcpBlockedTools: listText(strArray(policy.mcpBlockedTools)),
    mcpApprovalRequiredTools: listText(strArray(policy.mcpApprovalRequiredTools)),
    approvalRoutingRules: jsonText(policy.approvalRoutingRules),
    blockedBrowserActions: jsonText(policy.blockedBrowserActions),
    policyScopes: jsonText(policy.policyScopes),
    policyExceptions: jsonText(policy.policyExceptions),
  };
}

function updateFromDraft(draft: Draft): PolicyUpdate {
  return {
    enforcementMode: draft.enforcementMode,
    blockMinSeverity: draft.blockMinSeverity,
    blockRiskScore: numberField(draft.blockRiskScore),
    storeRawForApproval: draft.storeRawForApproval,
    rawRetentionDays: numberField(draft.rawRetentionDays),
    blockUnapprovedAiDestinations: draft.blockUnapprovedAiDestinations,
    responseScanMode: draft.responseScanMode,
    desktopCollectorDestination: draft.desktopCollectorDestination.trim(),
    governedDestinations: parseList(draft.governedDestinations),
    allowedDestinations: parseList(draft.allowedDestinations),
    blockedDestinations: parseList(draft.blockedDestinations),
    blockedFileUploadDestinations: parseList(draft.blockedFileUploadDestinations),
  };
}

/** Full PUT /api/policy body — PolicyUpdate plus the fields this view now edits. */
interface FullPolicyUpdate extends PolicyUpdate {
  requiredSensors: string[];
  desiredSensorVersions: Record<string, string>;
  mcpAllowedTools: string[];
  mcpBlockedTools: string[];
  mcpApprovalRequiredTools: string[];
  approvalRoutingRules: unknown[];
  blockedBrowserActions: unknown[];
  policyScopes: unknown[];
  policyExceptions: unknown[];
}

/** Null (after a toast) when a rule JSON textarea does not parse — save/preview abort. */
function buildUpdate(draft: Draft): FullPolicyUpdate | null {
  const approvalRoutingRules = parseJsonArray(draft.approvalRoutingRules, 'Approval routing rules');
  if (!approvalRoutingRules) return null;
  const blockedBrowserActions = parseJsonArray(draft.blockedBrowserActions, 'Browser action controls');
  if (!blockedBrowserActions) return null;
  const policyScopes = parseJsonArray(draft.policyScopes, 'Scoped enforcement rules');
  if (!policyScopes) return null;
  const policyExceptions = parseJsonArray(draft.policyExceptions, 'Time-bound exceptions');
  if (!policyExceptions) return null;
  return {
    ...updateFromDraft(draft),
    requiredSensors: parseList(draft.requiredSensors),
    desiredSensorVersions: parseMap(draft.desiredSensorVersions),
    mcpAllowedTools: parseList(draft.mcpAllowedTools),
    mcpBlockedTools: parseList(draft.mcpBlockedTools),
    mcpApprovalRequiredTools: parseList(draft.mcpApprovalRequiredTools),
    approvalRoutingRules,
    blockedBrowserActions,
    policyScopes,
    policyExceptions,
  };
}

function isDirty(policy: PolicyDoc, draft: Draft): boolean {
  return JSON.stringify(draft) !== JSON.stringify(draftFromPolicy(policy));
}

function metaLine(policy: PolicyDoc): string {
  return `${policy.enforcementMode} mode / severity >= ${policy.blockMinSeverity} / risk >= ${policy.blockRiskScore}`;
}

// ---- Inline status line (port of legacy #polSaved / setPolicyStatus) ----------

interface StatusLine {
  text: string;
  set: (message: string, clearAfterMs?: number) => void;
}

function useStatusLine(): StatusLine {
  const [text, setText] = useState('');
  const timer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    [],
  );
  const set = useCallback((message: string, clearAfterMs = 0) => {
    if (timer.current) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
    setText(message);
    if (clearAfterMs > 0) {
      timer.current = window.setTimeout(() => {
        setText('');
        timer.current = null;
      }, clearAfterMs);
    }
  }, []);
  return { text, set };
}

// ---- Mutations -----------------------------------------------------------------

async function requestJson<T>(request: Promise<Response | null>, fallback: string): Promise<T | null> {
  const res = await request;
  if (!res || !res.ok) {
    toast(await apiErrorSummary(res, fallback), 'error');
    return null;
  }
  try {
    return (await res.json()) as T;
  } catch {
    toast(fallback, 'error');
    return null;
  }
}

async function savePolicyDraft(draft: Draft | null, adopt: (policy: PolicyDoc) => void, status: StatusLine): Promise<void> {
  if (!draft) return;
  const body = buildUpdate(draft);
  if (!body) return;
  status.set('Saving');
  const res = await putPolicy(body);
  if (!res || !res.ok) {
    status.set(await apiErrorSummary(res, 'Could not save'));
    return;
  }
  const saved = (await res.json().catch(() => null)) as PolicyDoc | null;
  if (saved) adopt(saved);
  status.set('Saved', 4000);
}

function readinessSummary(health: ConfigHealth, impact: PolicyImpact | null): string {
  const impactText = impact?.summary ? ` / ${impact.summary.changed || 0} policy impact change(s)` : '';
  if (health.state === 'bad') return `${health.failed} blocking check(s)${impactText}`;
  return `${health.failed} warning(s), ${health.ok}/${health.total || 0} checks ready${impactText}`;
}

interface TestCtx {
  draft: Draft | null;
  readOnly: boolean;
  setImpact: (impact: PolicyImpact | null) => void;
  setPreflight: (preflight: Preflight | null) => void;
  setCoverage: (coverage: Coverage | null) => void;
  status: StatusLine;
}

/** Legacy "Test configuration": preflight + coverage refresh plus impact preview of the draft. */
async function runConfigurationTest(ctx: TestCtx): Promise<void> {
  const body = ctx.readOnly || !ctx.draft ? null : buildUpdate(ctx.draft);
  if (!ctx.readOnly && !body) return;
  ctx.status.set('VERIFYING');
  const [preflight, coverage, impactRes] = await Promise.all([
    withTimeout(fetchPreflight(), OPTIONAL_TIMEOUT_MS),
    withTimeout(fetchCoverage(), OPTIONAL_TIMEOUT_MS),
    body ? postPolicyImpact(body) : Promise.resolve<Response | null>(null),
  ]);
  ctx.setPreflight(preflight);
  if (coverage) ctx.setCoverage(coverage);
  let impact: PolicyImpact | null = null;
  if (body) {
    if (!impactRes || !impactRes.ok) {
      ctx.status.set(await apiErrorSummary(impactRes, 'Could not preview impact'));
      return;
    }
    impact = (await impactRes.json().catch(() => null)) as PolicyImpact | null;
    if (impact) ctx.setImpact(impact);
  }
  ctx.status.set(readinessSummary(configHealth(preflight), impact), 3600);
}

/** POST /api/retention/purge — purges retained raw approval data past rawRetentionDays. */
async function runRetentionPurge(status: StatusLine): Promise<void> {
  const res = await api('/api/retention/purge', { method: 'POST' });
  if (!res || !res.ok) {
    toast(await apiErrorSummary(res, 'Could not run purge'), 'error');
    return;
  }
  const body = (await res.json().catch(() => ({}))) as { purged?: number };
  status.set(`Purged ${body.purged || 0} record(s)`, 4000);
}

/** GET /api/policy -> pretty-printed blob download (CSP-safe anchor click). */
async function exportPolicyJson(): Promise<void> {
  const policy = await fetchPolicy();
  if (!policy) {
    toast('Could not load the policy for export.', 'error');
    return;
  }
  const blob = new Blob([JSON.stringify(policy, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `redactwall-policy-${csvStamp()}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

interface MutationCtx {
  draft: Draft | null;
  readOnly: boolean;
  adopt: (policy: PolicyDoc) => void;
  load: () => Promise<void>;
  setImpact: (impact: PolicyImpact | null) => void;
  setBusy: (busy: boolean) => void;
  setPreflight: (preflight: Preflight | null) => void;
  setCoverage: (coverage: Coverage | null) => void;
  status: StatusLine;
}

function usePolicyMutations(ctx: MutationCtx) {
  const { draft, readOnly, adopt, load, setImpact, setBusy, setPreflight, setCoverage, status } = ctx;
  const wrap = (action: () => Promise<void>) => async () => {
    setBusy(true);
    try {
      await action();
    } finally {
      setBusy(false);
    }
  };
  const save = wrap(() => savePolicyDraft(draft, adopt, status));
  const testConfiguration = wrap(() => runConfigurationTest({ draft, readOnly, setImpact, setPreflight, setCoverage, status }));
  const purge = wrap(() => runRetentionPurge(status));
  const applyTemplate = (id: string) =>
    wrap(async () => {
      const merged = await requestJson<PolicyDoc>(applyPolicyTemplate(id), 'Could not apply template');
      if (!merged) return;
      toast('Template applied.', 'good');
      setImpact(null);
      await load(); // refetch: the saved policy is re-normalized server-side
    })();
  return { save, testConfiguration, purge, applyTemplate };
}

function usePolicyEditor(readOnly: boolean) {
  const [policy, setPolicy] = useState<PolicyDoc | null>(null);
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [impact, setImpact] = useState<PolicyImpact | null>(null);
  const [preflight, setPreflight] = useState<Preflight | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const status = useStatusLine();

  const adopt = useCallback((next: PolicyDoc) => {
    setPolicy(next);
    setDraft(draftFromPolicy(next));
  }, []);
  const load = useCallback(async () => {
    const optional = Promise.all([withTimeout(fetchPreflight(), OPTIONAL_TIMEOUT_MS), withTimeout(fetchCoverage(), OPTIONAL_TIMEOUT_MS)]);
    const [pol, tpls] = await Promise.all([fetchPolicy(), fetchPolicyTemplates()]);
    const [pf, cov] = await optional;
    if (pol) adopt(pol);
    if (tpls) setTemplates(tpls);
    setPreflight(pf);
    if (cov) setCoverage(cov);
    setLoaded(true);
  }, [adopt]);
  useEffect(() => {
    load();
  }, [load]);

  const mutations = usePolicyMutations({ draft, readOnly, adopt, load, setImpact, setBusy, setPreflight, setCoverage, status });
  const patch = (change: Partial<Draft>) => setDraft((current) => (current ? { ...current, ...change } : current));
  const discard = () => {
    if (policy) setDraft(draftFromPolicy(policy));
    setImpact(null);
    status.set('');
  };
  return { policy, templates, draft, impact, preflight, coverage, loaded, busy, status, patch, discard, ...mutations };
}

// ---- Small shared UI atoms -------------------------------------------------------

/** Legacy statusChip/statePill: .pill.status-chip with a tone class from the shared sheets. */
const CHIP_TONE_CLASS: Record<CardState, string> = { good: 'secure', warn: 'warn', bad: 'critical' };

function StatusChip({ tone, label, detail }: { tone: CardState; label: string; detail?: string }) {
  return (
    <span className={`pill ${tone} status-chip tone-${CHIP_TONE_CLASS[tone]}`} title={detail || label}>
      {label}
    </span>
  );
}

function StatePill({ state, label }: { state: CardState; label?: string }) {
  const text = label ?? stateLabel(state);
  return <StatusChip tone={state} label={text} detail={`Verification state: ${text}\nSystem health: ${stateLabel(state)}`} />;
}

function textChips(items: string[]): ReactNode[] {
  return items.map((item) => (
    <span key={item} className="chip">
      {item}
    </span>
  ));
}

function ChipRow({ chips, empty }: { chips: ReactNode[]; empty: string }) {
  return (
    <div className="chips">
      {chips.length ? (
        chips
      ) : (
        <span className="chip">{empty}</span>
      )}
    </div>
  );
}

function ReadonlyChips({ label, chips, empty }: { label: string; chips: ReactNode[]; empty: string }) {
  return (
    <div className="policy-list-field">
      <span>{label}</span>
      <ChipRow chips={chips} empty={empty} />
    </div>
  );
}

interface ListFieldProps {
  label: string;
  value: string;
  placeholder: string;
  disabled: boolean;
  minHeight?: number;
  onChange: (value: string) => void;
}

function ListField({ label, value, placeholder, disabled, minHeight, onChange }: ListFieldProps) {
  return (
    <label className="policy-list-field">
      <span>{label}</span>
      <textarea
        className="policy-textarea"
        spellCheck={false}
        value={value}
        placeholder={placeholder}
        disabled={disabled}
        style={minHeight ? { minHeight } : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

interface JsonTextareaProps {
  ariaLabel: string;
  value: string;
  placeholder: string;
  minHeight: number;
  disabled: boolean;
  onChange: (value: string) => void;
}

function JsonTextarea({ ariaLabel, value, placeholder, minHeight, disabled, onChange }: JsonTextareaProps) {
  return (
    <textarea
      className="policy-textarea"
      spellCheck={false}
      aria-label={ariaLabel}
      value={value}
      placeholder={placeholder}
      disabled={disabled}
      style={{ minHeight }}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

// ---- Core form fields (existing controls, unchanged behavior) ---------------------

interface FieldProps {
  draft: Draft;
  disabled: boolean;
  patch: (change: Partial<Draft>) => void;
}

function CheckboxField(props: { id: string; label: string; checked: boolean; disabled: boolean; onChange: (checked: boolean) => void }) {
  return (
    <>
      <label htmlFor={props.id}>{props.label}</label>
      <input
        id={props.id}
        type="checkbox"
        checked={props.checked}
        disabled={props.disabled}
        onChange={(event) => props.onChange(event.target.checked)}
      />
    </>
  );
}

interface InputFieldProps {
  id: string;
  label: string;
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
}

function NumberField({ id, label, value, disabled, onChange, min, max }: InputFieldProps & { min: number; max: number }) {
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <input id={id} type="number" min={min} max={max} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} />
    </>
  );
}

function TextField({ id, label, value, disabled, onChange, maxLength }: InputFieldProps & { maxLength: number }) {
  return (
    <>
      <label htmlFor={id}>{label}</label>
      <input id={id} type="text" maxLength={maxLength} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} />
    </>
  );
}

function SelectField(props: {
  id: string;
  label: string;
  value: string | number;
  options: readonly (readonly [string | number, string])[];
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <>
      <label htmlFor={props.id}>{props.label}</label>
      <select id={props.id} value={props.value} disabled={props.disabled} onChange={(event) => props.onChange(event.target.value)}>
        {props.options.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </>
  );
}

function ModePicker({ mode, disabled, onChange }: { mode: EnforcementMode; disabled: boolean; onChange: (mode: EnforcementMode) => void }) {
  return (
    <section className="policy-section">
      <h3>Texas FCU policy mode</h3>
      <p className="policy-hint">
        What every RedactWall sensor does when it sees member information. Hard-stop identifiers still block regardless of mode.
      </p>
      <div className="policy-modes" role="radiogroup" aria-label="Enforcement mode">
        {MODES.map(([value, title, detail]) => (
          <label key={value} className={`policy-mode${mode === value ? ' selected' : ''}`}>
            <span>
              <input
                type="radio"
                name="policy-mode"
                value={value}
                checked={mode === value}
                disabled={disabled}
                onChange={() => onChange(value)}
              />
              {title}
            </span>
            <p>{detail}</p>
          </label>
        ))}
      </div>
    </section>
  );
}

function ThresholdFields({ draft, disabled, patch }: FieldProps) {
  return (
    <section className="policy-section">
      <h3>Member-data blocking thresholds</h3>
      <div className="policy-field-grid">
        <SelectField
          id="pol-sev"
          label="Block at minimum severity"
          options={SEVERITIES}
          value={draft.blockMinSeverity}
          disabled={disabled}
          onChange={(value) => patch({ blockMinSeverity: Number(value) })}
        />
        <NumberField
          id="pol-risk"
          label="Block at risk score greater than or equal to"
          min={0}
          max={100}
          value={draft.blockRiskScore}
          disabled={disabled}
          onChange={(value) => patch({ blockRiskScore: value })}
        />
      </div>
    </section>
  );
}

function HandlingFields({ draft, disabled, patch }: FieldProps) {
  return (
    <section className="policy-section">
      <h3>Approval retention and handling</h3>
      <div className="policy-field-grid">
        <CheckboxField
          id="pol-store-raw"
          label="Retain raw prompts for approval review (encrypted at rest)"
          checked={draft.storeRawForApproval}
          disabled={disabled}
          onChange={(checked) => patch({ storeRawForApproval: checked })}
        />
        <NumberField
          id="pol-retention"
          label="Purge retained raw approval data after days"
          min={0}
          max={3650}
          value={draft.rawRetentionDays}
          disabled={disabled}
          onChange={(value) => patch({ rawRetentionDays: value })}
        />
        <CheckboxField
          id="pol-block-unapproved"
          label="Block unapproved AI destinations"
          checked={draft.blockUnapprovedAiDestinations}
          disabled={disabled}
          onChange={(checked) => patch({ blockUnapprovedAiDestinations: checked })}
        />
        <SelectField
          id="pol-response-scan"
          label="When AI responses contain sensitive data"
          options={SCAN_MODES}
          value={draft.responseScanMode}
          disabled={disabled}
          onChange={(value) => patch({ responseScanMode: value as ResponseScanMode })}
        />
        <TextField
          id="pol-desktop"
          label="Default desktop upload destination"
          maxLength={80}
          value={draft.desktopCollectorDestination}
          disabled={disabled}
          onChange={(value) => patch({ desktopCollectorDestination: value })}
        />
      </div>
    </section>
  );
}

function DestinationLists({ draft, disabled, patch }: FieldProps) {
  return (
    <section className="policy-section">
      <h3>AI vendor governance</h3>
      <p className="policy-hint">One destination per line; * wildcards allowed. Allowed entries override blocks for approved Texas FCU use cases.</p>
      <div className="policy-list-grid">
        {DESTINATION_FIELDS.map(([key, label, placeholder]) => (
          <label key={key} className="policy-list-field">
            <span>{label}</span>
            <textarea
              value={draft[key]}
              placeholder={placeholder}
              spellCheck={false}
              disabled={disabled}
              onChange={(event) => patch(textPatch(key, event.target.value))}
            />
          </label>
        ))}
      </div>
    </section>
  );
}

function HardStops({ items }: { items: string[] }) {
  return (
    <section className="policy-section">
      <h3>Member-information hard stops</h3>
      <p className="policy-hint">
        These identifiers block or tokenize even when the global mode is softer. Change them by applying the NCUA / GLBA template or via the API.
      </p>
      <div className="policy-chips">
        {items.length ? (
          items.map((item) => (
            <span key={item} className="policy-chip static">
              {item}
            </span>
          ))
        ) : (
          <span className="policy-chip static">none</span>
        )}
      </div>
    </section>
  );
}

function TemplatePicker({ templates, disabled, onApply }: { templates: PolicyTemplate[]; disabled: boolean; onApply: (id: string) => void }) {
  const [pending, setPending] = useState<PolicyTemplate | null>(null);
  if (!templates.length) return null;
  return (
    <section className="policy-section">
      <h3>Policy templates</h3>
      <p className="policy-hint">Start from the NCUA / GLBA credit-union preset, then tune thresholds and destinations. Applying saves immediately.</p>
      <div className="policy-chips">
        {templates.map((template) => (
          <button
            key={template.id}
            type="button"
            className={`policy-chip${pending?.id === template.id ? ' selected' : ''}`}
            title={template.description}
            disabled={disabled}
            onClick={() => setPending(template)}
          >
            {template.label}
          </button>
        ))}
      </div>
      {pending ? (
        <TemplateConfirm
          template={pending}
          disabled={disabled}
          onCancel={() => setPending(null)}
          onApply={() => {
            setPending(null);
            onApply(pending.id);
          }}
        />
      ) : null}
    </section>
  );
}

function TemplateConfirm(props: { template: PolicyTemplate; disabled: boolean; onApply: () => void; onCancel: () => void }) {
  return (
    <div className="policy-confirm" role="alert">
      <span>
        Apply <strong>{props.template.label}</strong> over the saved policy? {props.template.description}
      </span>
      <button type="button" className="policy-btn primary" disabled={props.disabled} onClick={props.onApply}>
        Apply template
      </button>
      <button type="button" className="policy-btn" onClick={props.onCancel}>
        Cancel
      </button>
    </div>
  );
}

// ---- Readiness cards (Setup Checklist / Health / Environment / Sensor Setup) -----

interface CardProps {
  policy: PolicyDoc;
  preflight: Preflight | null;
  coverage: Coverage | null;
}

interface ChecklistItem {
  label: string;
  state: CardState;
  detail: string;
}

function setupChecklist(policy: PolicyDoc, preflight: Preflight | null, coverage: Coverage | null): ChecklistItem[] {
  const health = configHealth(preflight);
  const sensorCount = (coverage?.sensors || []).filter((sensor) => sensor.events || sensor.required).length;
  const governed = policy.governedDestinations.length;
  const routing = ruleList(policy.approvalRoutingRules).length;
  return [
    {
      label: 'Admin access',
      state: checkGroupState(preflight, [
        'admin_password', 'admin_password_strength', 'admin_mfa', 'admin_mfa_secret',
        'session_secret', 'session_secret_strength',
      ]),
      detail: 'MFA, password, session',
    },
    {
      label: 'Identity provider',
      state: checkGroupState(preflight, [
        'oidc_config', 'oidc_client_secret_strength', 'oidc_endpoints', 'oidc_scim_users', 'scim_bearer_token_strength',
      ]),
      detail: 'OIDC and SCIM',
    },
    { label: 'Deploy sensors', state: sensorCount ? 'good' : 'warn', detail: `${sensorCount} observed` },
    { label: 'Define destinations', state: governed ? 'good' : 'warn', detail: `${governed} governed` },
    { label: 'Choose policy mode', state: policy.enforcementMode ? 'good' : 'warn', detail: humanize(policy.enforcementMode) },
    { label: 'Set approval routing', state: routing ? 'good' : 'warn', detail: `${routing} rules` },
    { label: 'Review DLP rules', state: policy.alwaysBlock.length ? 'good' : 'warn', detail: `${policy.alwaysBlock.length} hard stops` },
    { label: 'Test configuration', state: health.state === 'bad' ? 'bad' : 'good', detail: `${health.ok}/${health.total} checks` },
  ];
}

function SetupChecklistCard({ policy, preflight, coverage }: CardProps) {
  const items = setupChecklist(policy, preflight, coverage);
  const done = items.filter((item) => item.state === 'good').length;
  return (
    <div className="config-card pad">
      <div className="sensor-head">
        <div>
          <h3>Texas FCU Setup Checklist</h3>
          <p>Fast path from install to governed Texas FCU pilot.</p>
        </div>
        <StatusChip tone={done === items.length ? 'good' : 'warn'} label={`${done}/${items.length} ready`} />
      </div>
      <div className="setup-list">
        {items.map((item) => (
          <div key={item.label} className="setup-item">
            <span className={`setup-dot ${item.state}`}>{item.state === 'bad' ? '!' : ''}</span>
            <span>{item.label}</span>
            <small>{item.detail}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function HealthCard({ policy, preflight, coverage }: CardProps) {
  const health = configHealth(preflight);
  const rows: [string, string][] = [
    ['Sensors', `${strArray(policy.requiredSensors).length} required`],
    ['Destinations', `${policy.governedDestinations.length} governed`],
    ['Fleet gaps', String(coverage?.totals?.fleetAttention || 0)],
    ['Preflight checks', `${health.failed} open`],
  ];
  return (
    <div className="config-card pad">
      <div className="sensor-head">
        <div>
          <h3>Policy Health</h3>
          <p>Readiness across auth, sensors, member data, and AI governance.</p>
        </div>
        <StatePill state={health.state} label={health.state === 'good' ? 'Good' : health.label} />
      </div>
      <div className={`health-score ${health.state}`}>
        <b>{health.score}</b>
        <span>/ 100</span>
      </div>
      <div className="health-rows">
        {rows.map(([label, value]) => (
          <div key={label} className="health-row">
            <span>{label}</span>
            <b>{value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

const ENV_GROUPS: [string, string[]][] = [
  ['Admin auth', ['admin_password', 'admin_password_strength', 'admin_mfa', 'admin_mfa_secret']],
  ['Sensor ingest key', ['ingest_key', 'ingest_key_strength']],
  ['Session secret', ['session_secret', 'session_secret_strength']],
  ['Raw approval encryption', ['raw_prompt_encryption', 'data_key_strength']],
  ['Evidence store', ['sqlite_local_disk']],
  ['Tenant controls', ['saas_tenant_id', 'saas_seat_limit', 'saas_tenant_context', 'saas_user_identity']],
];

function EnvironmentCard({ preflight }: { preflight: Preflight | null }) {
  return (
    <div className="config-card pad">
      <h3>Control Plane Settings</h3>
      <p>Security-critical setup status without exposing secret values.</p>
      <div className="settings-list">
        <div className="settings-row">
          <span>Runtime</span>
          <b>
            <StatePill state={preflight?.production ? 'good' : 'warn'} label={preflight?.production ? 'Production' : 'Local / pilot'} />
          </b>
        </div>
        {ENV_GROUPS.map(([label, ids]) => (
          <div key={label} className="settings-row">
            <span>{label}</span>
            <b>
              <StatePill state={checkGroupState(preflight, ids)} />
            </b>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatusCards(props: CardProps) {
  return (
    <div className="policy-cards">
      <SetupChecklistCard {...props} />
      <HealthCard {...props} />
      <EnvironmentCard preflight={props.preflight} />
    </div>
  );
}

const SENSOR_LABELS: Record<string, [string, string]> = {
  browser_extension: ['Browser Extension', 'Web AI prompts and responses'],
  endpoint_agent: ['Endpoint Agent', 'Desktop AI apps and file handoff'],
  mcp_guard: ['MCP Guard', 'Agent tool calls and document context'],
};

function SensorCard({ id, policy, coverage }: { id: string; policy: PolicyDoc; coverage: Coverage | null }) {
  const [label, detail] = id in SENSOR_LABELS ? SENSOR_LABELS[id] : [humanize(id), 'Custom sensor'];
  const sensor: CoverageSensor = (coverage?.sensors || []).find((item) => item.source === id) ?? {};
  const required = strArray(policy.requiredSensors).includes(id);
  const state: CardState = sensor.installHealth?.state === 'attention' ? 'warn' : sensor.events || required ? 'good' : 'warn';
  const version = strMap(policy.desiredSensorVersions)[id] || sensor.desiredVersion || sensor.latestVersion || '-';
  return (
    <div className="sensor-card">
      <div className="sensor-head">
        <div>
          <b>{label}</b>
          <p>{detail}</p>
        </div>
        <StatePill state={state} label={sensor.events ? 'Observed' : required ? 'Required' : 'Optional'} />
      </div>
      <dl>
        <div>
          <dt>Desired version</dt>
          <dd>{version}</dd>
        </div>
        <div>
          <dt>Events</dt>
          <dd>{sensor.events || 0}</dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>{sensor.lastSeen ? fmt(sensor.lastSeen) : 'No events yet'}</dd>
        </div>
      </dl>
      <a className="ghost mini" href={routeHref('/coverage')}>
        Configure sensor
      </a>
    </div>
  );
}

function SensorSetupCard({ policy, coverage }: { policy: PolicyDoc; coverage: Coverage | null }) {
  const ids = [...new Set(['browser_extension', 'endpoint_agent', 'mcp_guard', ...strArray(policy.requiredSensors)])];
  return (
    <div className="config-card pad">
      <div className="sensor-head">
        <div>
          <h3>Texas FCU Sensor Setup</h3>
          <p>Deploy and manage the branch browser, endpoint, and MCP control points that feed one shared policy.</p>
        </div>
        <a className="ghost mini" href={routeHref('/coverage')}>
          View coverage
        </a>
      </div>
      <div className="sensor-cards">
        {ids.map((id) => (
          <SensorCard key={id} id={id} policy={policy} coverage={coverage} />
        ))}
      </div>
    </div>
  );
}

// ---- Guided builders (pure client-side; write into the draft textarea strings) ---

type BuilderFields = Record<string, string>;

const MATCHER_KEYS = ['users', 'groups', 'destinations', 'detectors', 'categories'] as const;
const ROUTE_MATCHER_KEYS = ['groups', 'destinations', 'categories', 'detectors'] as const;

const SCOPE_DEFAULTS: BuilderFields = {
  id: '', groups: '', users: '', destinations: '', categories: '', detectors: '', mode: 'block', severity: '2', risk: '', reason: '',
};
const EXCEPTION_DEFAULTS: BuilderFields = {
  id: '', groups: '', users: '', destinations: '', categories: '', detectors: '',
  hours: '24', ownerGroup: '', reviewerRole: '', reviewHours: '24', reason: '',
};
const ROUTE_DEFAULTS: BuilderFields = {
  id: '', group: '', role: 'approver', sla: '60', groups: '', destinations: '', categories: '', detectors: '',
  severity: '3', risk: '', reason: '',
};

const SCOPE_MODES: [string, string][] = [
  ['block', 'Block'],
  ['justify', 'Require justification'],
  ['redact', 'Redact'],
  ['warn', 'Warn'],
];
const SEVERITY_OVERRIDES: [string, string][] = [
  ['', 'No override'],
  ['1', 'low'],
  ['2', 'medium'],
  ['3', 'high'],
  ['4', 'critical'],
];
const ROUTE_SEVERITIES: [string, string][] = [
  ['', 'Any'],
  ['1', 'low'],
  ['2', 'medium'],
  ['3', 'high'],
  ['4', 'critical'],
];
const REVIEWER_ROLES: [string, string][] = [
  ['', 'Unassigned'],
  ['security_admin', 'Security Admin'],
  ['approver', 'Approver'],
];
const ROUTE_ROLES: [string, string][] = [
  ['approver', 'Approver'],
  ['security_admin', 'Security Admin'],
];

function useBuilderFields(defaults: BuilderFields) {
  const [fields, setFields] = useState(defaults);
  const set = (key: string) => (value: string) => setFields((current) => ({ ...current, [key]: value }));
  return { fields, set };
}

function collectMatchers(fields: BuilderFields, keys: readonly string[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const key of keys) {
    const values = parseList(fields[key] || '');
    if (values.length) out[key] = values;
  }
  return out;
}

function suggestedId(prefix: string, fields: BuilderFields): string {
  const pieces = ['groups', 'users', 'destinations', 'categories', 'detectors']
    .map((key) => parseList(fields[key] || '')[0] || '')
    .filter(Boolean);
  return cleanId(`${prefix}_${pieces.join('_')}`, `${prefix}_rule`);
}

function suggestedRouteId(fields: BuilderFields): string {
  const pieces = [fields.group, fields.groups, fields.destinations, fields.categories, fields.detectors]
    .map((value) => parseList(value || '')[0] || '')
    .filter(Boolean);
  return cleanId(`route_${pieces.join('_')}`, 'approval_route');
}

/** Upsert by rule id into a JSON-array textarea string (null aborts, toast already shown). */
function upsertRule(text: string, rule: RuleJson, label: string): string | null {
  const existing = parseJsonArray(text, label);
  if (!existing) return null;
  const next = existing.filter((item) => !(item && typeof item === 'object' && (item as RuleJson).id === rule.id));
  next.push(rule);
  return JSON.stringify(next, null, 2);
}

/** Empty string -> null; otherwise clamp + round like the legacy numberField. */
function clampField(raw: string, min: number, max: number): number | null {
  if (raw === '') return null;
  const value = Number(raw);
  return Number.isFinite(value) ? Math.max(min, Math.min(max, Math.round(value))) : null;
}

function buildScopeRule(fields: BuilderFields): RuleJson | null {
  const matchers = collectMatchers(fields, MATCHER_KEYS);
  if (!Object.keys(matchers).length) {
    toast('Scoped enforcement needs at least one matcher.', 'warn');
    return null;
  }
  const rule: RuleJson = { id: cleanId(fields.id, suggestedId('scope', fields)), ...matchers, enforcementMode: fields.mode };
  const severity = Number(fields.severity);
  if (fields.severity !== '' && Number.isFinite(severity)) rule.blockMinSeverity = severity;
  const risk = Number(fields.risk);
  if (fields.risk !== '' && Number.isFinite(risk)) rule.blockRiskScore = risk;
  const reason = cleanId(fields.reason, '');
  if (reason) rule.reason = reason;
  return rule;
}

function buildExceptionRule(fields: BuilderFields): RuleJson | null {
  const matchers = collectMatchers(fields, MATCHER_KEYS);
  if (!Object.keys(matchers).length) {
    toast('Time-bound exception needs at least one matcher.', 'warn');
    return null;
  }
  const hours = Math.max(1, Math.min(720, Number(fields.hours) || 24));
  const now = Date.now();
  const rule: RuleJson = {
    id: cleanId(fields.id, suggestedId('exception', fields)),
    ...matchers,
    action: 'allow',
    expiresAt: new Date(now + hours * 60 * 60 * 1000).toISOString(),
  };
  const ownerGroup = cleanId(fields.ownerGroup, '');
  if (ownerGroup) rule.ownerGroup = ownerGroup;
  if (fields.reviewerRole) rule.reviewerRole = fields.reviewerRole;
  if (fields.reviewHours !== '') {
    const reviewHours = Math.max(1, Math.min(hours, Number(fields.reviewHours) || hours));
    rule.reviewAfter = new Date(now + reviewHours * 60 * 60 * 1000).toISOString();
  }
  const reason = cleanId(fields.reason, '');
  if (reason) rule.reason = reason;
  return rule;
}

function buildRouteRule(fields: BuilderFields): { rule?: RuleJson; error?: string } {
  const matchers = collectMatchers(fields, ROUTE_MATCHER_KEYS);
  const severity = clampField(fields.severity, 0, 4);
  const risk = clampField(fields.risk, 0, 100);
  if (!Object.keys(matchers).length && severity == null && risk == null) return { error: 'Approval route needs a matcher' };
  const group = cleanId(fields.group, '');
  if (!group) return { error: 'Approval route needs an assigned group' };
  const rule: RuleJson = {
    id: cleanId(fields.id, suggestedRouteId(fields)),
    ...matchers,
    assignedGroup: group,
    assignedRole: fields.role || 'approver',
    slaMinutes: clampField(fields.sla, 15, 10080) ?? 60,
  };
  if (severity != null) rule.minSeverity = severity;
  if (risk != null) rule.minRiskScore = risk;
  const reason = cleanId(fields.reason, '');
  if (reason) rule.reason = reason;
  return { rule };
}

function BuilderInput(props: {
  label: string;
  value: string;
  placeholder?: string;
  type?: string;
  min?: number;
  max?: number;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      {props.label}
      <input
        type={props.type || 'text'}
        value={props.value}
        placeholder={props.placeholder}
        min={props.min}
        max={props.max}
        onChange={(event) => props.onChange(event.target.value)}
      />
    </label>
  );
}

function BuilderSelect(props: { label: string; value: string; options: readonly (readonly [string, string])[]; onChange: (value: string) => void }) {
  return (
    <label>
      {props.label}
      <select value={props.value} onChange={(event) => props.onChange(event.target.value)}>
        {props.options.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}

function BuilderShell({ title, buttonLabel, onAdd, children }: { title: string; buttonLabel: string; onAdd: () => void; children: ReactNode }) {
  return (
    <div className="policy-builder">
      <h3>{title}</h3>
      <div className="mini-grid">{children}</div>
      <button type="button" className="btn" onClick={onAdd}>
        {buttonLabel}
      </button>
    </div>
  );
}

function MatcherInputs({
  fields,
  set,
  detectorsPlaceholder,
}: {
  fields: BuilderFields;
  set: (key: string) => (value: string) => void;
  detectorsPlaceholder: string;
}) {
  return (
    <>
      <BuilderInput label="SCIM groups" value={fields.groups} placeholder="RedactWall Legal" onChange={set('groups')} />
      <BuilderInput label="Users" value={fields.users} placeholder="counsel@example.test" onChange={set('users')} />
      <BuilderInput label="Destinations" value={fields.destinations} placeholder="claude.ai" onChange={set('destinations')} />
      <BuilderInput label="Categories" value={fields.categories} placeholder="LEGAL_CONTRACT" onChange={set('categories')} />
      <BuilderInput label="Detectors" value={fields.detectors} placeholder={detectorsPlaceholder} onChange={set('detectors')} />
    </>
  );
}

interface RuleBuilderProps {
  value: string;
  onChange: (value: string) => void;
  status: StatusLine;
}

function ScopeBuilder({ value, onChange, status }: RuleBuilderProps) {
  const { fields, set } = useBuilderFields(SCOPE_DEFAULTS);
  const add = () => {
    const rule = buildScopeRule(fields);
    if (!rule) return;
    const next = upsertRule(value, rule, 'Scoped enforcement rules');
    if (next === null) return;
    onChange(next);
    status.set(`Added scoped rule ${String(rule.id)}`);
  };
  return (
    <BuilderShell title="Guided Scoped Enforcement" buttonLabel="Add scoped rule" onAdd={add}>
      <BuilderInput label="Rule id" value={fields.id} placeholder="legal_contract_review" onChange={set('id')} />
      <MatcherInputs fields={fields} set={set} detectorsPlaceholder="SECRET_KEY" />
      <BuilderSelect label="Mode" value={fields.mode} options={SCOPE_MODES} onChange={set('mode')} />
      <BuilderSelect label="Min severity" value={fields.severity} options={SEVERITY_OVERRIDES} onChange={set('severity')} />
      <BuilderInput label="Risk score" type="number" min={0} max={100} value={fields.risk} placeholder="25" onChange={set('risk')} />
      <BuilderInput label="Reason" value={fields.reason} placeholder="legal_contract_review" onChange={set('reason')} />
    </BuilderShell>
  );
}

function ExceptionBuilder({ value, onChange, status }: RuleBuilderProps) {
  const { fields, set } = useBuilderFields(EXCEPTION_DEFAULTS);
  const add = () => {
    const rule = buildExceptionRule(fields);
    if (!rule) return;
    const next = upsertRule(value, rule, 'Time-bound exceptions');
    if (next === null) return;
    onChange(next);
    status.set(`Added exception ${String(rule.id)}`);
  };
  return (
    <BuilderShell title="Guided Time-bound Exception" buttonLabel="Add exception" onAdd={add}>
      <BuilderInput label="Exception id" value={fields.id} placeholder="legal_vendor_24h" onChange={set('id')} />
      <MatcherInputs fields={fields} set={set} detectorsPlaceholder="SOURCE_CODE" />
      <BuilderInput label="Expires after hours" type="number" min={1} max={720} value={fields.hours} onChange={set('hours')} />
      <BuilderInput label="Owner group" value={fields.ownerGroup} placeholder="legal" onChange={set('ownerGroup')} />
      <BuilderSelect label="Reviewer role" value={fields.reviewerRole} options={REVIEWER_ROLES} onChange={set('reviewerRole')} />
      <BuilderInput label="Review after hours" type="number" min={1} max={720} value={fields.reviewHours} onChange={set('reviewHours')} />
      <BuilderInput label="Reason" value={fields.reason} placeholder="approved_vendor_review" onChange={set('reason')} />
    </BuilderShell>
  );
}

function RouteBuilder({ value, onChange, status }: RuleBuilderProps) {
  const { fields, set } = useBuilderFields(ROUTE_DEFAULTS);
  const add = () => {
    const { rule, error } = buildRouteRule(fields);
    if (error || !rule) {
      if (error) status.set(error);
      return;
    }
    const next = upsertRule(value, rule, 'Approval routing rules');
    if (next === null) return;
    onChange(next);
    status.set(`Added route ${String(rule.id)}`);
  };
  return (
    <BuilderShell title="Approval Route Builder" buttonLabel="Add route" onAdd={add}>
      <BuilderInput label="Route id" value={fields.id} placeholder="lending_high_risk" onChange={set('id')} />
      <BuilderInput label="Assigned group" value={fields.group} placeholder="lending" onChange={set('group')} />
      <BuilderSelect label="Role" value={fields.role} options={ROUTE_ROLES} onChange={set('role')} />
      <BuilderInput label="SLA minutes" type="number" min={15} max={10080} value={fields.sla} onChange={set('sla')} />
      <BuilderInput label="SCIM groups" value={fields.groups} placeholder="RedactWall Lending" onChange={set('groups')} />
      <BuilderInput label="Destinations" value={fields.destinations} placeholder="claude.ai" onChange={set('destinations')} />
      <BuilderInput label="Categories" value={fields.categories} placeholder="LEGAL_CONTRACT" onChange={set('categories')} />
      <BuilderInput label="Detectors" value={fields.detectors} placeholder="SECRET_KEY" onChange={set('detectors')} />
      <BuilderSelect label="Min severity" value={fields.severity} options={ROUTE_SEVERITIES} onChange={set('severity')} />
      <BuilderInput label="Min risk" type="number" min={0} max={100} value={fields.risk} placeholder="60" onChange={set('risk')} />
      <BuilderInput label="Reason" value={fields.reason} placeholder="lending_review" onChange={set('reason')} />
    </BuilderShell>
  );
}

const MCP_TOOL_RE = /^[A-Za-z0-9.*:_/-]{1,160}$/;

const MCP_DECISIONS: [string, string][] = [
  ['approval', 'Require approval'],
  ['blocked', 'Block'],
  ['allowed', 'Allow registry'],
];

const MCP_PRESETS: [string, string][] = [
  ['', 'Custom'],
  ['sharepoint.fetch*', 'SharePoint read'],
  ['drive.read*', 'Drive read'],
  ['sharepoint.export*', 'SharePoint export'],
  ['drive.share*', 'Drive share'],
  ['*.delete*', 'Delete tools'],
  ['database.write*', 'Database writes'],
];

/** Move the pattern exclusively into the chosen list (removed from the other two). */
function applyMcpPattern(draft: Draft, pattern: string, decision: string): Partial<Draft> {
  const strip = (text: string) => parseList(text).filter((item) => item !== pattern);
  const allowed = strip(draft.mcpAllowedTools);
  const blocked = strip(draft.mcpBlockedTools);
  const approval = strip(draft.mcpApprovalRequiredTools);
  if (decision === 'allowed') allowed.push(pattern);
  else if (decision === 'blocked') blocked.push(pattern);
  else approval.push(pattern);
  return {
    mcpAllowedTools: [...new Set(allowed)].join('\n'),
    mcpBlockedTools: [...new Set(blocked)].join('\n'),
    mcpApprovalRequiredTools: [...new Set(approval)].join('\n'),
  };
}

function McpToolBuilder({ draft, patch, status }: { draft: Draft; patch: (change: Partial<Draft>) => void; status: StatusLine }) {
  const [pattern, setPattern] = useState('');
  const [decision, setDecision] = useState('approval');
  const [preset, setPreset] = useState('');
  const choosePreset = (value: string) => {
    setPreset(value);
    if (value) setPattern(value);
  };
  const apply = () => {
    const value = pattern.trim();
    if (!MCP_TOOL_RE.test(value)) {
      status.set('Invalid MCP tool pattern');
      return;
    }
    patch(applyMcpPattern(draft, value, decision));
    status.set(`Applied MCP rule ${value}`);
  };
  return (
    <BuilderShell title="MCP Tool Builder" buttonLabel="Apply MCP rule" onAdd={apply}>
      <BuilderInput label="Tool pattern" value={pattern} placeholder="sharepoint.export*" onChange={setPattern} />
      <BuilderSelect label="Decision" value={decision} options={MCP_DECISIONS} onChange={setDecision} />
      <BuilderSelect label="Preset" value={preset} options={MCP_PRESETS} onChange={choosePreset} />
    </BuilderShell>
  );
}

// ---- Rule sections (editable textareas or readonly chip summaries) ----------------

interface SectionProps {
  policy: PolicyDoc;
  draft: Draft;
  readOnly: boolean;
  disabled: boolean;
  patch: (change: Partial<Draft>) => void;
  status: StatusLine;
}

function browserActionChips(policy: PolicyDoc): ReactNode[] {
  return ruleList(policy.blockedBrowserActions).map((rule, index) => (
    <span key={ruleStr(rule, 'id') || index} className="chip">
      <b>{ruleStr(rule, 'action') || 'action'}</b> {strArray(rule.destinations).join(', ')}
    </span>
  ));
}

function BrowserActionsSection({ policy, draft, readOnly, disabled, patch }: SectionProps) {
  return (
    <section className="policy-section">
      <h3>Browser action controls</h3>
      <p className="policy-hint">Block paste, drop, copy, or download actions on specific destinations before data leaves the browser.</p>
      {readOnly ? (
        <ChipRow chips={browserActionChips(policy)} empty="no action blocks" />
      ) : (
        <JsonTextarea
          ariaLabel="Browser action controls"
          value={draft.blockedBrowserActions}
          placeholder={BROWSER_ACTIONS_PLACEHOLDER}
          minHeight={130}
          disabled={disabled}
          onChange={(value) => patch(textPatch('blockedBrowserActions', value))}
        />
      )}
    </section>
  );
}

function versionChips(policy: PolicyDoc): ReactNode[] {
  return Object.entries(strMap(policy.desiredSensorVersions)).map(([key, value]) => (
    <span key={key} className="chip">
      <b>{key}</b> {value}
    </span>
  ));
}

function FleetPostureSection({ policy, draft, readOnly, disabled, patch }: SectionProps) {
  return (
    <section className="policy-section">
      <h3>Fleet posture</h3>
      <p className="policy-hint">Required sensors and desired versions used by install-health checks.</p>
      <div className="policy-list-grid">
        {readOnly ? (
          <>
            <ReadonlyChips label="Required sensors" chips={textChips(strArray(policy.requiredSensors))} empty="none" />
            <ReadonlyChips label="Desired sensor versions" chips={versionChips(policy)} empty="none" />
          </>
        ) : (
          <>
            <ListField
              label="Required sensors"
              value={draft.requiredSensors}
              placeholder={'browser_extension\nendpoint_agent\nmcp_guard'}
              disabled={disabled}
              onChange={(value) => patch(textPatch('requiredSensors', value))}
            />
            <ListField
              label="Desired sensor versions"
              value={draft.desiredSensorVersions}
              placeholder={'browser_extension=0.3.0\nendpoint_agent=0.3.0'}
              disabled={disabled}
              onChange={(value) => patch(textPatch('desiredSensorVersions', value))}
            />
          </>
        )}
      </div>
    </section>
  );
}

function McpSection({ policy, draft, readOnly, disabled, patch, status }: SectionProps) {
  return (
    <section className="policy-section">
      <h3>MCP tool governance</h3>
      <p className="policy-hint">Restrict agent tools before execution and require review for high-impact connectors.</p>
      <div className="policy-list-grid">
        {MCP_FIELDS.map(([key, label, placeholder, empty]) =>
          readOnly ? (
            <ReadonlyChips key={key} label={label} chips={textChips(strArray(policy[key]))} empty={empty} />
          ) : (
            <ListField
              key={key}
              label={label}
              value={draft[key]}
              placeholder={placeholder}
              disabled={disabled}
              onChange={(value) => patch(textPatch(key, value))}
            />
          ),
        )}
      </div>
      {readOnly ? null : <McpToolBuilder draft={draft} patch={patch} status={status} />}
    </section>
  );
}

function routingChips(policy: PolicyDoc): ReactNode[] {
  return ruleList(policy.approvalRoutingRules).map((rule, index) => (
    <span key={ruleStr(rule, 'id') || index} className="chip">
      <b>{ruleStr(rule, 'id')}</b> {ruleStr(rule, 'assignedGroup')} / {roleLabel(ruleStr(rule, 'assignedRole'))} {matcherSummary(rule)}
    </span>
  ));
}

function RoutingSection({ policy, draft, readOnly, disabled, patch, status }: SectionProps) {
  return (
    <section className="policy-section">
      <h3>Approval routing</h3>
      <p className="policy-hint">Route held prompts to the right group and role with SLA context.</p>
      {readOnly ? (
        <ChipRow chips={routingChips(policy)} empty="default routing" />
      ) : (
        <>
          <JsonTextarea
            ariaLabel="Approval routing rules"
            value={draft.approvalRoutingRules}
            placeholder={ROUTING_PLACEHOLDER}
            minHeight={160}
            disabled={disabled}
            onChange={(value) => patch(textPatch('approvalRoutingRules', value))}
          />
          <RouteBuilder value={draft.approvalRoutingRules} onChange={(value) => patch(textPatch('approvalRoutingRules', value))} status={status} />
        </>
      )}
    </section>
  );
}

function scopeChips(policy: PolicyDoc): ReactNode[] {
  return ruleList(policy.policyScopes).map((rule, index) => (
    <span key={ruleStr(rule, 'id') || index} className="chip">
      <b>{ruleStr(rule, 'id')}</b> {ruleStr(rule, 'enforcementMode') || 'scope'} {matcherSummary(rule)}
    </span>
  ));
}

function exceptionChips(policy: PolicyDoc): ReactNode[] {
  return ruleList(policy.policyExceptions).map((rule, index) => (
    <span key={ruleStr(rule, 'id') || index} className="chip">
      <b>{ruleStr(rule, 'id')}</b> {ruleStr(rule, 'expiresAt')} {matcherSummary(rule)} {exceptionLifecycle(rule)}
    </span>
  ));
}

function AdvancedRulesSection({ policy, draft, readOnly, disabled, patch, onPurge }: SectionProps & { onPurge: () => void }) {
  return (
    <section className="policy-section">
      <h3>Advanced policy JSON</h3>
      <p className="policy-hint">Edit scoped enforcement and time-bound exceptions directly when the guided builders are not enough.</p>
      <div className="policy-advanced-grid">
        {readOnly ? (
          <>
            <ReadonlyChips label="Scoped enforcement rules" chips={scopeChips(policy)} empty="no scoped rules" />
            <ReadonlyChips label="Time-bound exceptions" chips={exceptionChips(policy)} empty="no exceptions" />
          </>
        ) : (
          <>
            <ListField
              label="Scoped enforcement rules"
              value={draft.policyScopes}
              placeholder={SCOPES_PLACEHOLDER}
              minHeight={190}
              disabled={disabled}
              onChange={(value) => patch(textPatch('policyScopes', value))}
            />
            <ListField
              label="Time-bound exceptions"
              value={draft.policyExceptions}
              placeholder={EXCEPTIONS_PLACEHOLDER}
              minHeight={190}
              disabled={disabled}
              onChange={(value) => patch(textPatch('policyExceptions', value))}
            />
          </>
        )}
      </div>
      {readOnly ? (
        <div className="readonly-note">Read-only auditor view</div>
      ) : (
        <button type="button" className="btn" disabled={disabled} onClick={onPurge}>
          Run retention purge
        </button>
      )}
    </section>
  );
}

function RuleSections(props: SectionProps & { onPurge: () => void }) {
  return (
    <>
      <BrowserActionsSection {...props} />
      <FleetPostureSection {...props} />
      <McpSection {...props} />
      <RoutingSection {...props} />
      {props.readOnly ? null : (
        <div className="policy-builder-grid">
          <ScopeBuilder
            value={props.draft.policyScopes}
            onChange={(value) => props.patch(textPatch('policyScopes', value))}
            status={props.status}
          />
          <ExceptionBuilder
            value={props.draft.policyExceptions}
            onChange={(value) => props.patch(textPatch('policyExceptions', value))}
            status={props.status}
          />
        </div>
      )}
      <AdvancedRulesSection {...props} />
    </>
  );
}

// ---- Detection tester ---------------------------------------------------------------

interface RationaleEntry {
  kind: string;
  type: string;
  severityLabel: string;
  confidence: string;
  points: number;
  regulations: string[];
}

function confidenceFromScore(score: number): string {
  return score >= 0.9 ? 'very_likely' : score >= 0.7 ? 'likely' : 'possible';
}

function rationaleEntries(result: DetectorTestResult, meta: DetectorMeta | null): RationaleEntry[] {
  const breakdown = result.scoreBreakdown || [];
  if (breakdown.length) {
    return breakdown.map((entry) => ({
      kind: entry.kind || 'finding',
      type: entry.type,
      severityLabel: entry.severityLabel || 'medium',
      confidence: entry.confidence || 'possible',
      points: entry.points || 0,
      regulations: entry.regulations || [],
    }));
  }
  return (result.findings || []).map((finding) => ({
    kind: 'finding',
    type: finding.type,
    severityLabel: finding.severityLabel || meta?.severityLabels?.[String(finding.severity ?? '')] || 'medium',
    confidence: finding.confidence || confidenceFromScore(finding.score || 0),
    points: Math.round((finding.severity || 0) * (finding.score || 0) * 8),
    regulations: finding.regulations || meta?.regulations?.[finding.type] || [],
  }));
}

function RationaleRow({ entry }: { entry: RationaleEntry }) {
  return (
    <div className="rationale-row">
      <span className={`sev ${entry.severityLabel.toLowerCase()}`}>{entry.severityLabel}</span>
      <span className="rationale-what">
        <b>{entry.type}</b>
        {entry.kind === 'category' ? <i> content category</i> : null}
      </span>
      <span className="rationale-conf" title="How sure the engine is: validated match = very likely, contextual = likely, pattern-only = possible">
        {humanize(entry.confidence)}
      </span>
      <span className="rationale-pts" title="Points this detection added to the risk score (severity x confidence weight)">
        +{entry.points}
      </span>
      <span className="rationale-regs">
        {entry.regulations.map((reg) => (
          <span key={reg} className="reg-chip" title="Obligation this data falls under">
            {reg}
          </span>
        ))}
      </span>
    </div>
  );
}

function Rationale({ result, meta }: { result: DetectorTestResult; meta: DetectorMeta | null }) {
  const entries = rationaleEntries(result, meta);
  if (!entries.length) return null;
  return (
    <div className="rationale">
      <div className="rationale-head">
        Why this score: <b>{result.riskScore ?? 0}/100</b>
      </div>
      {entries.map((entry, index) => (
        <RationaleRow key={`${entry.type}-${index}`} entry={entry} />
      ))}
      <div className="rationale-note">
        Each detection adds severity × confidence points. Chips cite the law or obligation that makes the data sensitive - these appear
        in the block reasons and audit trail too.
      </div>
    </div>
  );
}

type TesterView =
  | { kind: 'idle' }
  | { kind: 'note'; text: string }
  | { kind: 'result'; result: DetectorTestResult; meta: DetectorMeta | null };

function TesterResultView({ view }: { view: TesterView }) {
  if (view.kind === 'idle') return null;
  if (view.kind === 'note') return <div className="empty">{view.text}</div>;
  const reasons = view.result.reasons || [];
  return (
    <>
      <div className="reasons">
        <StatusChip
          tone={view.result.decision === 'block' ? 'bad' : 'good'}
          label={view.result.decision.toUpperCase()}
          detail={`Decision under current policy\n${reasons.join('\n')}`}
        />{' '}
        {reasons.join('; ')}
      </div>
      <Rationale result={view.result} meta={view.meta} />
    </>
  );
}

function DetectionTester() {
  const [text, setText] = useState('');
  const [view, setView] = useState<TesterView>({ kind: 'idle' });
  const [testing, setTesting] = useState(false);
  const run = async () => {
    const sample = text.trim();
    if (!sample) {
      setView({ kind: 'note', text: 'Paste some sample text first.' });
      return;
    }
    setTesting(true);
    try {
      const [meta, res] = await Promise.all([detectorMetaOnce(), postDetectorTest(sample)]);
      const result = res && res.ok ? ((await res.json().catch(() => null)) as DetectorTestResult | null) : null;
      setView(result ? { kind: 'result', result, meta } : { kind: 'note', text: 'Test failed - check your session.' });
    } finally {
      setTesting(false);
    }
  };
  const runButton = (
    <button type="button" className="ghost mini" disabled={testing} onClick={run}>
      {testing ? 'Testing…' : 'Test detection'}
    </button>
  );
  return (
    <Panel title="Member Data Test Bench" meta={runButton}>
      <p className="policy-hint">
        Paste sample text to see exactly how the live policy would score and decide it - the sample is analyzed in memory and never
        stored or logged
      </p>
      <textarea
        className="policy-textarea policy-tester-input"
        rows={3}
        value={text}
        spellCheck={false}
        placeholder="e.g. Draft a payoff letter for member SSN 123-45-6789 and loan LN-120045"
        aria-label="Sample text to test"
        onChange={(event) => setText(event.target.value)}
      />
      <div aria-live="polite">
        <TesterResultView view={view} />
      </div>
    </Panel>
  );
}

// ---- Impact preview -------------------------------------------------------------------

function ImpactSummary({ summary }: { summary: PolicyImpact['summary'] }) {
  const tiles: [string, number, string][] = [
    ['Changed outcomes', summary.changed, 'info'],
    ['Newly blocked', summary.newlyBlocked, 'critical'],
    ['Newly allowed', summary.newlyAllowed, 'secure'],
    ['More restrictive', summary.moreRestrictive, 'warn'],
    ['Less restrictive', summary.lessRestrictive, 'warn'],
  ];
  return (
    <div className="policy-impact-tiles">
      {tiles.map(([label, value, tone]) => (
        <div key={label} className={`policy-impact-tile tone-${tone}`}>
          <b>{value}</b>
          <span>{label}</span>
        </div>
      ))}
    </div>
  );
}

function OutcomeTable({ current, proposed }: { current: Record<ImpactOutcome, number>; proposed: Record<ImpactOutcome, number> }) {
  return (
    <div className="policy-outcomes">
      <div className="policy-outcome-row policy-outcome-head">
        <span>Outcome</span>
        <span>Current</span>
        <span>Proposed</span>
        <span>Delta</span>
      </div>
      {OUTCOMES.map(([key, label]) => {
        const from = current[key] || 0;
        const to = proposed[key] || 0;
        const delta = to - from;
        return (
          <div className="policy-outcome-row" key={key}>
            <span>{label}</span>
            <span>{from}</span>
            <span>{to}</span>
            <span className={delta > 0 ? 'delta-up' : delta < 0 ? 'delta-down' : 'delta-flat'}>
              {delta > 0 ? `+${delta}` : delta}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function deltaRows(items: ImpactDelta[]): [string, string][] {
  return (items || [])
    .filter((item) => item.changed > 0)
    .map((item) => [item.label, `${item.changed} changed / +${item.newlyBlocked} blocked / +${item.newlyAllowed} allowed`]);
}

function DeltaGroup({ label, rows }: { label: string; rows: [string, string][] }) {
  return (
    <div className="policy-delta-group">
      <strong>{label}</strong>
      {rows.map(([name, detail]) => (
        <div key={name} className="policy-delta-row">
          <span className="policy-delta-label">{name}</span>
          <span>{detail}</span>
        </div>
      ))}
    </div>
  );
}

function ImpactDeltas({ deltas }: { deltas: PolicyImpact['topDeltas'] }) {
  const groups: [string, [string, string][]][] = [
    ['Destinations', deltaRows(deltas.destinations)],
    ['Detections', deltaRows(deltas.categories)],
    ['Sources', deltaRows(deltas.sources)],
    ['Change reasons', (deltas.reasons || []).map((r) => [r.reason.replace(/_/g, ' '), String(r.count)] as [string, string])],
  ];
  const nonEmpty = groups.filter(([, rows]) => rows.length);
  if (!nonEmpty.length) return null;
  return (
    <div className="policy-impact-deltas">
      {nonEmpty.map(([label, rows]) => (
        <DeltaGroup key={label} label={label} rows={rows} />
      ))}
    </div>
  );
}

function ImpactPreview({ impact }: { impact: PolicyImpact }) {
  return (
    <section className="policy-section policy-impact" aria-live="polite">
      <h3>Impact preview</h3>
      <p className="policy-hint">
        Draft policy replayed against {impact.summary.sampleSize} recent events. Metadata only — prompt bodies are excluded.
      </p>
      <ImpactSummary summary={impact.summary} />
      <OutcomeTable current={impact.summary.current} proposed={impact.summary.proposed} />
      <ImpactDeltas deltas={impact.topDeltas} />
    </section>
  );
}

function ImpactHint() {
  return (
    <section className="policy-section" aria-live="polite">
      <div className="policy-impact-head">
        <h3>Impact preview</h3>
        <StatePill state="warn" label="Not run" />
      </div>
      <div className="policy-impact-empty">Run Test configuration to preview changed outcomes. Prompt bodies are excluded.</div>
    </section>
  );
}

// ---- Advanced read-only JSON (fields with no editor on this tab) ------------------------

function advancedFields(policy: PolicyDoc): Record<string, unknown> {
  return Object.fromEntries(Object.entries(policy).filter(([key]) => !FORM_EDITED_FIELDS.has(key)));
}

function AdvancedJson({ policy }: { policy: PolicyDoc }) {
  return (
    <details className="policy-advanced">
      <summary>Advanced policy fields (read-only)</summary>
      <p className="policy-hint">
        Detector ignore lists, scanner ignore rules, corporate AI account policy, and unmanaged-install handling are edited via the API
        or configuration files. Saving here leaves them unchanged.
      </p>
      <pre>{JSON.stringify(advancedFields(policy), null, 2)}</pre>
    </details>
  );
}

// ---- Header / action rows ------------------------------------------------------------------

function HeaderRow({ preflight }: { preflight: Preflight | null }) {
  const health = configHealth(preflight);
  return (
    <div className="policy-head-row">
      <StatePill state={health.state} label={`${health.score}/100 ready`} />
      <button
        type="button"
        className="ghost"
        title="Download the active policy as JSON for change review"
        onClick={() => void exportPolicyJson()}
      >
        Download policy JSON
      </button>
    </div>
  );
}

interface ActionRowProps {
  readOnly: boolean;
  busy: boolean;
  dirty: boolean;
  statusText: string;
  onSave: () => void;
  onTest: () => void;
  onDiscard: () => void;
}

function ActionRow({ readOnly, busy, dirty, statusText, onSave, onTest, onDiscard }: ActionRowProps) {
  return (
    <div className="policy-actions">
      <button type="button" className="policy-btn" disabled={busy || !dirty} onClick={onDiscard}>
        Discard changes
      </button>
      <button type="button" className="policy-btn" disabled={busy} onClick={onTest}>
        Test configuration
      </button>
      {readOnly ? (
        <span className="policy-readonly-note">Read-only view — Security Admin required to edit</span>
      ) : (
        <button type="button" className="policy-btn primary" disabled={busy} onClick={onSave}>
          Save changes
        </button>
      )}
      <span className="save-status" role="status">
        {statusText}
      </span>
    </div>
  );
}

interface EditorProps {
  policy: PolicyDoc;
  draft: Draft;
  templates: PolicyTemplate[];
  impact: PolicyImpact | null;
  preflight: Preflight | null;
  coverage: Coverage | null;
  readOnly: boolean;
  busy: boolean;
  dirty: boolean;
  status: StatusLine;
  patch: (change: Partial<Draft>) => void;
  onSave: () => void;
  onTest: () => void;
  onDiscard: () => void;
  onApplyTemplate: (id: string) => void;
  onPurge: () => void;
}

function PolicyEditor(props: EditorProps) {
  const { policy, draft, readOnly, busy, patch, status } = props;
  const disabled = readOnly || busy;
  const section: SectionProps = { policy, draft, readOnly, disabled, patch, status };
  return (
    <div className="policy-editor">
      <HeaderRow preflight={props.preflight} />
      <ActionRow
        readOnly={readOnly}
        busy={busy}
        dirty={props.dirty}
        statusText={status.text}
        onSave={props.onSave}
        onTest={props.onTest}
        onDiscard={props.onDiscard}
      />
      {props.impact ? <ImpactPreview impact={props.impact} /> : <ImpactHint />}
      <StatusCards policy={policy} preflight={props.preflight} coverage={props.coverage} />
      <SensorSetupCard policy={policy} coverage={props.coverage} />
      <ModePicker mode={draft.enforcementMode} disabled={disabled} onChange={(mode) => patch({ enforcementMode: mode })} />
      <ThresholdFields draft={draft} disabled={disabled} patch={patch} />
      <HandlingFields draft={draft} disabled={disabled} patch={patch} />
      <DestinationLists draft={draft} disabled={disabled} patch={patch} />
      <HardStops items={policy.alwaysBlock} />
      <TemplatePicker templates={props.templates} disabled={disabled} onApply={props.onApplyTemplate} />
      <RuleSections {...section} onPurge={props.onPurge} />
      <AdvancedJson policy={policy} />
    </div>
  );
}

export default function Policy() {
  const { me } = useSession();
  const readOnly = !me || me.role !== 'security_admin';
  const editor = usePolicyEditor(readOnly);
  const { policy, draft, loaded } = editor;

  return (
    <div className="policy-view">
      <DetectionTester />
      <Panel title="Policy Configuration" meta={!loaded ? 'Loading' : policy ? metaLine(policy) : 'Waiting for data'}>
        {loaded && !policy ? (
          <EmptyState title="Policy unavailable" detail="The enforcement policy could not be loaded. Refresh or check the server." />
        ) : policy && draft ? (
          <PolicyEditor
            policy={policy}
            draft={draft}
            templates={editor.templates}
            impact={editor.impact}
            preflight={editor.preflight}
            coverage={editor.coverage}
            readOnly={readOnly}
            busy={editor.busy}
            dirty={isDirty(policy, draft)}
            status={editor.status}
            patch={editor.patch}
            onSave={editor.save}
            onTest={editor.testConfiguration}
            onDiscard={editor.discard}
            onApplyTemplate={editor.applyTemplate}
            onPurge={editor.purge}
          />
        ) : null}
      </Panel>
    </div>
  );
}
