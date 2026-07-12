import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { syncTicketStatuses } from '../api/evidence';
import {
  decodePublicQuery,
  decodePublicQuerySnapshot,
  type QueueQuery,
  type ScoreBreakdownEntry,
} from '../api/queries';
import { EmptyState, Panel } from '../components/Panel';
import { apiJson, apiJsonBounded } from '../lib/api';
import { downloadCsv, csvStamp } from '../lib/csv';
import { navigate } from '../lib/router';
import { roleLabel, useSession } from '../lib/session';
import { useEventStream } from '../lib/sse';
import { toast } from '../lib/toast';
import './Activity.css';

/**
 * All Activity: read-only, paginated drill-down over every gated prompt event.
 * Route contract from server/app.js:
 *   GET /api/queries?limit=200 -> sanitized publicQuery[] (raw prompt stripped server-side)
 *   GET /api/detectors/meta    -> { severityLabels, regulations }; rationale fallback, lazy + cached
 *   SSE /api/stream            -> `query` {type, query} prepends the row; `decision` {id, status} refetches
 * Inbound pivot seed: /app/#/activity?q=<encoded search> pre-fills the toolbar search
 * (same grammar as the legacy global search: user:/actor:/dest:/destination:/status:/sev:/severity:/source:/action:).
 */

type ActivityQuery = QueueQuery;

interface DetectorsMeta {
  severityLabels?: Record<string, string>;
  regulations?: Record<string, string[]>;
}

interface SavedView {
  name: string;
  search?: string;
  range?: number;
  pageSize?: number;
}

type SavedViewDraft = Omit<SavedView, 'name'>;

interface PageSlice {
  rows: ActivityQuery[];
  page: number;
  total: number;
  totalPages: number;
  start: number;
  end: number;
}

interface PopoverState {
  detail: string;
  left: number;
  top: number;
}

type Tone = 'good' | 'bad' | 'warn' | 'info';
type ChipOpener = (detail: string, anchor: DOMRect) => void;
type ActivityDataState = 'loading' | 'ready' | 'stale' | 'unavailable';

interface SequencedActivityEvent {
  sequence: number;
  row: ActivityQuery;
}

const ACTIVITY_COLS = ['time', 'source', 'user', 'destination', 'owner', 'severity', 'risk', 'detected', 'status'] as const;
type ActivityCol = (typeof ACTIVITY_COLS)[number];

const COL_LABELS: Record<ActivityCol, string> = {
  time: 'Time',
  source: 'Source',
  user: 'User',
  destination: 'Destination',
  owner: 'Owner',
  severity: 'Severity',
  risk: 'Risk',
  detected: 'Detected',
  status: 'Status',
};

const RANGE_OPTIONS = [
  { value: 1, label: 'Last 24 hours' },
  { value: 7, label: 'Last 7 days' },
  { value: 30, label: 'Last 30 days' },
  { value: 0, label: 'All retained' },
];
const SIZE_OPTIONS = [10, 25, 50, 100].map((size) => ({ value: size, label: `${size} rows` }));

const COLS_KEY = 'redactwall.activityCols';
const SAVED_VIEWS_MAX = 12;
const ROW_LIMIT = 200;
const SEARCH_MAX_CHARS = 512;
const ACTIVITY_RESPONSE_MAX_BYTES = 8 * 1024 * 1024;
let sessionSavedViews: SavedView[] = [];
let sessionViewSequence = 1;

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '-');
const humanize = (value?: string) => (value || '-').replace(/_/g, ' ');
const statusCheckCount = (count: number) => `${count} status ${count === 1 ? 'check' : 'checks'}`;
const ticketSyncStopLabel = (reason?: string) => reason === 'deadline_exceeded'
  ? 'wall-clock safety deadline reached'
  : reason === 'check_limit_reached'
    ? 'status-check safety cap reached'
    : 'one or more provider checks failed';
const sevClass = (label?: string) => (label || 'low').toLowerCase();

/** Port of the legacy dashboard statusTone(). */
const GOOD_STATUSES = new Set(['approved', 'allowed', 'justified', 'warned_sent', 'redacted', 'response_redacted', 'sensor_heartbeat']);
const BAD_STATUSES = new Set([
  'denied', 'blocked_by_user', 'destination_blocked', 'file_upload_blocked', 'action_blocked',
  'injection_blocked', 'response_flagged', 'response_blocked', 'seat_limit_blocked', 'ocr_required',
]);
const WARN_STATUSES = new Set(['pending', 'shadow_ai', 'paste_flagged']);

function statusTone(status?: string): Tone {
  const s = (status || '').toLowerCase();
  if (GOOD_STATUSES.has(s)) return 'good';
  if (BAD_STATUSES.has(s)) return 'bad';
  if (WARN_STATUSES.has(s)) return 'warn';
  return 'info';
}

const CHIP_TONE: Record<Tone, string> = { good: 'secure', warn: 'warn', bad: 'critical', info: 'live' };

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

function sourceLabel(source?: string): string {
  return (source && SOURCE_LABELS[source]) || source || 'API';
}

/** Legacy normalizeRole(): anything outside the known roles reads as Auditor. */
const OWNER_ROLES = new Set(['security_admin', 'approver', 'operator', 'auditor']);

function workflowOwner(q: ActivityQuery): string {
  const group = q.assignedGroup || 'unassigned';
  if (!q.assignedRole) return group;
  return `${group} / ${roleLabel(OWNER_ROLES.has(q.assignedRole) ? q.assignedRole : 'auditor')}`;
}

function severityRowClass(q: ActivityQuery): string {
  const tone = statusTone(q.status);
  if (tone === 'bad') return 'critical';
  if (tone === 'warn') return 'warning';
  return '';
}

// ---- Search grammar (legacy parseSearch/queryText; shared contract with Audit pivots) ----

const SEARCH_FIELDS: Record<string, (q: ActivityQuery) => string> = {
  user: (q) => q.user || q.actor || '',
  actor: (q) => q.actor || q.user || '',
  dest: (q) => q.destination || '',
  destination: (q) => q.destination || '',
  status: (q) => q.status || '',
  sev: (q) => q.maxSeverityLabel || '',
  severity: (q) => q.maxSeverityLabel || '',
  source: (q) => q.source || '',
  action: (q) => q.action || '',
};

function queryText(q: ActivityQuery): string {
  return [
    q.id, q.user, q.destination, q.source, q.channel, q.status, q.maxSeverityLabel,
    q.assignedRole, q.assignedGroup, q.workflowReason, q.escalationReason, q.notificationStatus,
    ...(q.notificationChannels ?? []), q.redactedPrompt, ...(q.reasons ?? []), ...(q.categories ?? []),
    ...(q.findings ?? []).map((f) => `${f.type} ${f.masked || ''}`),
    ...Object.keys(q.entityCounts ?? {}),
  ].filter(Boolean).join(' ').toLowerCase();
}

function matchesToken(q: ActivityQuery, token: string, haystack: string): boolean {
  const m = token.match(/^([a-z]+):(.+)$/);
  const field = m ? SEARCH_FIELDS[m[1]] : undefined;
  if (m && field) return field(q).toLowerCase().includes(m[2]);
  return haystack.includes(token);
}

function matchesSearch(q: ActivityQuery, term: string): boolean {
  const tokens = term.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!tokens.length) return true;
  const haystack = queryText(q);
  return tokens.every((token) => matchesToken(q, token, haystack));
}

/** Legacy withinRangeDays: 0 = all retained; unparseable timestamps are kept. */
function withinRangeDays(iso: string | undefined, days: number): boolean {
  if (!days) return true;
  const ts = Date.parse(iso || '');
  return !Number.isFinite(ts) || ts >= Date.now() - days * 86400000;
}

function paginate(rows: ActivityQuery[], page: number, pageSize: number): PageSlice {
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  return { rows: rows.slice(start, end), page: safePage, total, totalPages, start, end };
}

// ---- CSV export (filtered rows, all pages; never includes prompt text) ----

function exportActivityCsv(rows: ActivityQuery[]): void {
  const lines: Array<Array<string | number>> = [
    ['Time', 'Source', 'User', 'Destination', 'Owner', 'Severity', 'Risk', 'Detected', 'Status'],
    ...rows.map((q) => [
      fmt(q.createdAt), sourceLabel(q.source), q.user || '', q.destination || '', workflowOwner(q),
      q.maxSeverityLabel || 'low', q.riskScore ?? 0, Object.keys(q.entityCounts ?? {}).join('; '), humanize(q.status),
    ]),
  ];
  downloadCsv(`redactwall-activity-${csvStamp()}.csv`, lines);
}

// ---- localStorage (corrupt JSON tolerated, as legacy) ----

function readStoredArray(key: string): unknown[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(key) || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function readHiddenCols(): ReadonlySet<string> {
  return new Set(readStoredArray(COLS_KEY).filter((value): value is string => typeof value === 'string'));
}

// ---- SSE payload + hash-seed narrowing ----

function asEventRow(data: unknown): ActivityQuery | null {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  return decodePublicQuery((data as { query?: unknown }).query);
}

function mergeActivityRows(snapshot: ActivityQuery[], events: SequencedActivityEvent[]): ActivityQuery[] {
  let rows = snapshot;
  for (const event of events) {
    rows = [event.row, ...rows.filter((row) => row.id !== event.row.id)];
  }
  return rows.slice(0, ROW_LIMIT);
}

function searchSeedFromHash(): string {
  const query = location.hash.split('?')[1] || '';
  return (new URLSearchParams(query).get('q') || '').slice(0, SEARCH_MAX_CHARS);
}

// ---- Detectors meta: fetched lazily on first expand, cached module-level ----

let detectorsMetaPromise: Promise<DetectorsMeta | null> | null = null;

function loadDetectorsMeta(): Promise<DetectorsMeta | null> {
  detectorsMetaPromise ??= apiJson<DetectorsMeta>('/api/detectors/meta');
  return detectorsMetaPromise;
}

function useDetectorsMeta(active: boolean): DetectorsMeta | null {
  const [meta, setMeta] = useState<DetectorsMeta | null>(null);
  const requested = useRef(false);
  useEffect(() => {
    if (!active || requested.current) return;
    requested.current = true;
    let cancelled = false;
    loadDetectorsMeta().then((value) => {
      if (!cancelled && value) setMeta(value);
    });
    return () => {
      cancelled = true;
    };
  }, [active]);
  return meta;
}

// ---- Data + table state hooks ----

function useActivityRows() {
  const [rows, setRows] = useState<ActivityQuery[] | null>(null);
  const [state, setState] = useState<ActivityDataState>('loading');
  const [recentId, setRecentId] = useState('');
  const newRowTimer = useRef(0);
  const rowsRef = useRef<ActivityQuery[] | null>(null);
  const requestRef = useRef(0);
  const eventSequenceRef = useRef(0);
  const eventsRef = useRef<SequencedActivityEvent[]>([]);
  const load = useCallback(async () => {
    const requestId = ++requestRef.current;
    const startedAtSequence = eventSequenceRef.current;
    const payload = await apiJsonBounded<unknown>(`/api/queries?limit=${ROW_LIMIT}`, ACTIVITY_RESPONSE_MAX_BYTES);
    const next = decodePublicQuerySnapshot(payload);
    if (requestId !== requestRef.current) return;
    if (!next) {
      setState(rowsRef.current ? 'stale' : 'unavailable');
      return;
    }
    const laterEvents = eventsRef.current.filter((event) => event.sequence > startedAtSequence);
    const merged = mergeActivityRows(next, laterEvents);
    eventsRef.current = [];
    rowsRef.current = merged;
    setRows(merged);
    setState('ready');
  }, []);
  const onQuery = useCallback((data: unknown) => {
    const row = asEventRow(data);
    if (!row) return;
    const event = { sequence: ++eventSequenceRef.current, row };
    eventsRef.current = [...eventsRef.current.slice(-(ROW_LIMIT - 1)), event];
    setRows((prev) => {
      const next = mergeActivityRows(prev ?? [], [event]);
      rowsRef.current = next;
      return next;
    });
    setState((current) => current === 'unavailable' ? 'stale' : current);
    setRecentId(row.id);
    window.clearTimeout(newRowTimer.current);
    newRowTimer.current = window.setTimeout(() => setRecentId(''), 1000);
  }, []);
  useEffect(() => {
    void load();
    return () => {
      requestRef.current += 1;
      window.clearTimeout(newRowTimer.current);
    };
  }, [load]);
  useEventStream({ query: onQuery, decision: load });
  return { rows, state, recentId };
}

/** Filter order matches legacy: range -> search -> paginate; page resets on any control change. */
function useActivityTable(rows: ActivityQuery[]) {
  const [search, setSearch] = useState(searchSeedFromHash);
  const [rangeDays, setRangeDays] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [page, setPage] = useState(1);
  const filtered = useMemo(
    () => rows.filter((q) => withinRangeDays(q.createdAt, rangeDays) && matchesSearch(q, search)),
    [rows, rangeDays, search],
  );
  const applySearch = useCallback((value: string) => {
    setSearch(value.slice(0, SEARCH_MAX_CHARS));
    setPage(1);
  }, []);
  const applyRange = (value: number) => { setRangeDays(value); setPage(1); };
  const resize = (value: number) => { setPageSize(value); setPage(1); };
  const applyView = (view: SavedView) => {
    setSearch(view.search || '');
    setRangeDays(view.range || 0);
    setPageSize(view.pageSize || 10);
    setPage(1);
  };
  return { search, rangeDays, pageSize, filtered, slice: paginate(filtered, page, pageSize), applySearch, applyRange, resize, applyView, setPage };
}

type ActivityTableState = ReturnType<typeof useActivityTable>;

function useSavedViews() {
  const [views, setViews] = useState<SavedView[]>(() => sessionSavedViews);
  const save = (view: SavedViewDraft) => {
    const namedView = { ...view, name: `Session view ${sessionViewSequence}` };
    sessionViewSequence += 1;
    const next = [namedView, ...sessionSavedViews].slice(0, SAVED_VIEWS_MAX);
    sessionSavedViews = next;
    setViews(next);
    toast('Session view saved in memory until this tab is refreshed.', 'good');
  };
  return { views, save };
}

function useHiddenCols() {
  const [hidden, setHidden] = useState<ReadonlySet<string>>(readHiddenCols);
  const toggle = (col: string, visible: boolean) => {
    const next = new Set(hidden);
    if (visible) next.delete(col);
    else next.add(col);
    localStorage.setItem(COLS_KEY, JSON.stringify([...next]));
    setHidden(next);
  };
  return { hidden, toggle };
}

function currentView(table: ActivityTableState): SavedViewDraft {
  return {
    search: table.search.trim(),
    range: table.rangeDays,
    pageSize: table.pageSize,
  };
}

// ---- Toolbar ----

interface ToolbarProps {
  table: ActivityTableState;
  views: SavedView[];
  canSyncTickets: boolean;
  ticketSyncBusy: boolean;
  ticketSyncMessage: string;
  onSaveView: () => void;
  onExport: () => void;
  onSyncTickets: () => void;
}

function NumberSelect({ ariaLabel, value, options, fallback, onChange }: {
  ariaLabel: string;
  value: number;
  options: Array<{ value: number; label: string }>;
  fallback: number;
  onChange: (value: number) => void;
}) {
  return (
    <select aria-label={ariaLabel} value={value} onChange={(event) => onChange(Number(event.target.value) || fallback)}>
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

function SavedViewsPicker({ views, onApply }: { views: SavedView[]; onApply: (view: SavedView) => void }) {
  return (
    <select
      aria-label="Session activity views"
      value=""
      onChange={(event) => {
        const view = views[Number(event.target.value)];
        if (view) onApply(view);
      }}
    >
      <option value="">Session views…</option>
      {views.map((view, index) => (
        <option key={view.name} value={index}>
          {view.name}
        </option>
      ))}
    </select>
  );
}

function ToolbarActions({ table, views, canSyncTickets, ticketSyncBusy, onSaveView, onExport, onSyncTickets }: ToolbarProps) {
  return (
    <div className="console-frame-actions">
      <input
        type="search"
        aria-label="Search activity"
        placeholder="Search: employee: dest: status: sev: source: or masked text"
        maxLength={SEARCH_MAX_CHARS}
        value={table.search}
        onChange={(event) => table.applySearch(event.target.value)}
      />
      <SavedViewsPicker views={views} onApply={table.applyView} />
      <button className="ghost" type="button" title="Keep the current filters in memory until this browser tab is refreshed" onClick={onSaveView}>
        Save session view
      </button>
      <NumberSelect ariaLabel="Activity time range" value={table.rangeDays} options={RANGE_OPTIONS} fallback={0} onChange={table.applyRange} />
      <NumberSelect ariaLabel="Rows per page" value={table.pageSize} options={SIZE_OPTIONS} fallback={10} onChange={table.resize} />
      <button className="ghost" type="button" onClick={onExport}>
        Export CSV
      </button>
      {canSyncTickets ? (
        <button className="ghost" type="button" disabled={ticketSyncBusy} onClick={onSyncTickets}>
          {ticketSyncBusy ? 'Syncing tickets…' : 'Sync Jira / Linear'}
        </button>
      ) : null}
    </div>
  );
}

function Toolbar(props: ToolbarProps) {
  return (
    <>
      <div className="console-frame-header">
        <div className="console-frame-title">
          <div>
            <h2>Exam Activity</h2>
            <p>Review recent Texas FCU AI events, decisions, owners, and sanitized member-data context.</p>
          </div>
        </div>
        <ToolbarActions {...props} />
      </div>
      {props.ticketSyncMessage ? (
        <div className="ticket-sync-status" role="status" aria-live="polite">
          {props.ticketSyncMessage}
        </div>
      ) : null}
    </>
  );
}

// ---- Column chooser ----

function ColumnChooser({ hidden, onToggle }: { hidden: ReadonlySet<string>; onToggle: (col: string, visible: boolean) => void }) {
  return (
    <details className="col-chooser">
      <summary>Columns</summary>
      <div className="col-chooser-menu">
        {ACTIVITY_COLS.map((col) => (
          <label key={col}>
            <input type="checkbox" checked={!hidden.has(col)} onChange={(event) => onToggle(col, event.target.checked)} />
            {humanize(col)}
          </label>
        ))}
      </div>
    </details>
  );
}

// ---- Status chip + metadata popover ----

/** Multi-line metadata: status, ids, owner, risk, decision trail. No prompt text. */
function statusDetail(q: ActivityQuery): string {
  const lines = [
    `Status: ${humanize(q.status)}`,
    `Session ID: ${q.id || '-'}`,
    `Owner: ${workflowOwner(q)}`,
    `Risk: ${q.riskScore ?? 0}/100`,
  ];
  if (q.decidedBy) lines.push(`Decided by: ${q.decidedBy} at ${fmt(q.decidedAt)}`);
  if (q.decidedBy && q.decisionNote) lines.push(`Note: ${q.decisionNote}`);
  return lines.join('\n');
}

const POPOVER_WIDTH = 320;
const POPOVER_EST_HEIGHT = 150;

function popoverPosition(anchor: DOMRect): { left: number; top: number } {
  const left = Math.min(Math.max(12, anchor.left), Math.max(12, window.innerWidth - POPOVER_WIDTH - 12));
  const below = anchor.bottom + 8;
  const top = below + POPOVER_EST_HEIGHT > window.innerHeight ? Math.max(12, anchor.top - 8 - POPOVER_EST_HEIGHT) : below;
  return { left, top };
}

function StatusChip({ query, onOpen }: { query: ActivityQuery; onOpen: ChipOpener }) {
  const tone = statusTone(query.status);
  const detail = statusDetail(query);
  const open = (target: HTMLElement) => onOpen(detail, target.getBoundingClientRect());
  return (
    <span
      className={`pill ${tone} status-chip tone-${CHIP_TONE[tone]}`}
      tabIndex={0}
      role="button"
      title={detail}
      onClick={(event) => {
        event.stopPropagation();
        open(event.currentTarget);
      }}
      onKeyDown={(event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        event.stopPropagation();
        open(event.currentTarget);
      }}
    >
      {humanize(query.status)}
    </span>
  );
}

function MetaPopover({ popover, onClose }: { popover: PopoverState; onClose: () => void }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('click', onClose);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('click', onClose);
      document.removeEventListener('keydown', onKey);
    };
  }, [onClose]);
  return (
    <div className="meta-popover" role="dialog" aria-label="Status metadata" style={{ left: popover.left, top: popover.top }}>
      <b>Metadata</b>
      <p>{popover.detail}</p>
    </div>
  );
}

// ---- "Why this score" rationale ----

function rationaleEntries(q: ActivityQuery, meta: DetectorsMeta | null): ScoreBreakdownEntry[] {
  if (Array.isArray(q.scoreBreakdown) && q.scoreBreakdown.length) return q.scoreBreakdown;
  return (q.findings ?? []).map((f) => ({
    kind: 'finding',
    type: f.type,
    severity: f.severity,
    severityLabel: meta?.severityLabels?.[String(f.severity)] || 'medium',
    confidence: f.confidence || ((f.score ?? 0) >= 0.9 ? 'very_likely' : (f.score ?? 0) >= 0.7 ? 'likely' : 'possible'),
    points: Math.round((f.severity ?? 0) * (f.score ?? 0) * 8),
    regulations: meta?.regulations?.[f.type] ?? [],
  }));
}

function RationaleRow({ entry }: { entry: ScoreBreakdownEntry }) {
  return (
    <div className="rationale-row">
      <span className={`sev ${sevClass(entry.severityLabel)}`}>{entry.severityLabel || 'low'}</span>
      <span className="rationale-what">
        <b>{entry.type || '-'}</b>
        {entry.kind === 'category' ? <i>content category</i> : null}
      </span>
      <span className="rationale-conf" title="How sure the engine is: validated match = very likely, contextual = likely, pattern-only = possible">
        {humanize(entry.confidence || 'possible')}
      </span>
      <span className="rationale-pts" title="Points this detection added to the risk score (severity x confidence weight)">
        +{entry.points ?? 0}
      </span>
      <span className="rationale-regs">
        {(entry.regulations ?? []).map((reg) => (
          <span key={reg} className="reg-chip" title="Obligation this data falls under">
            {reg}
          </span>
        ))}
      </span>
    </div>
  );
}

function Rationale({ query, meta }: { query: ActivityQuery; meta: DetectorsMeta | null }) {
  const entries = rationaleEntries(query, meta);
  if (!entries.length) return null;
  return (
    <div className="rationale">
      <div className="rationale-head">
        Why this score: <b>{query.riskScore ?? 0}/100</b>
      </div>
      {entries.map((entry, index) => (
        <RationaleRow key={`${entry.type || 'entry'}-${index}`} entry={entry} />
      ))}
      <div className="rationale-note">
        Each detection adds severity &times; confidence points. Chips cite the law or obligation that makes the data sensitive
        - these appear in the block reasons and audit trail too.
      </div>
    </div>
  );
}

// ---- Detail drawer ----

function detailData(q: ActivityQuery): Array<[string, string]> {
  const detected = Object.keys(q.entityCounts ?? {}).join(', ') || (q.categories ?? []).join(', ') || '-';
  return [
    ['Object', q.id || '-'],
    ['Status', humanize(q.status)],
    ['Timestamp', fmt(q.createdAt)],
    ['Source', sourceLabel(q.source)],
    ['Owner', workflowOwner(q)],
    ['Destination', q.destination || '-'],
    ['Detected', detected],
    ['Risk', `${q.riskScore ?? 0}/100`],
  ];
}

function DetailActions({ query, onPivot }: { query: ActivityQuery; onPivot: (token: string) => void }) {
  return (
    <div className="activity-detail-actions">
      {query.status === 'pending' ? (
        <button className="ghost mini" type="button" onClick={() => navigate('/queue')}>
          INSPECT
        </button>
      ) : null}
      <button className="ghost mini" type="button" onClick={() => navigate('/audit')}>
        VIEW AUDIT
      </button>
      {query.user ? (
        <button className="ghost mini" type="button" onClick={() => onPivot(`user:${query.user}`)}>
          SAME USER
        </button>
      ) : null}
      {query.destination ? (
        <button className="ghost mini" type="button" onClick={() => onPivot(`dest:${query.destination}`)}>
          SAME DESTINATION
        </button>
      ) : null}
    </div>
  );
}

interface DetailRowProps {
  query: ActivityQuery;
  colSpan: number;
  meta: DetectorsMeta | null;
  onPivot: (token: string) => void;
}

function DetailRow({ query, colSpan, meta, onPivot }: DetailRowProps) {
  return (
    <tr className="activity-detail-row">
      <td colSpan={colSpan}>
        <div className="activity-detail">
          <div className="activity-detail-grid">
            {detailData(query).map(([label, value]) => (
              <div key={label} className="datum">
                <label>{label}</label>
                <b>{value}</b>
              </div>
            ))}
          </div>
          <Rationale query={query} meta={meta} />
          <DetailActions query={query} onPivot={onPivot} />
        </div>
      </td>
    </tr>
  );
}

// ---- Table ----

function ActivityCell({ query, col, onChip }: { query: ActivityQuery; col: ActivityCol; onChip: ChipOpener }) {
  switch (col) {
    case 'time':
      return <td className="mono">{fmt(query.createdAt)}</td>;
    case 'source':
      return <td>{sourceLabel(query.source)}</td>;
    case 'user':
      return <td>{query.user || '-'}</td>;
    case 'destination':
      return <td className="mono">{query.destination || '-'}</td>;
    case 'owner':
      return <td>{workflowOwner(query)}</td>;
    case 'severity':
      return (
        <td>
          <span className={`sev ${sevClass(query.maxSeverityLabel)}`}>{query.maxSeverityLabel || 'low'}</span>
        </td>
      );
    case 'risk':
      return <td className="mono">{query.riskScore ?? 0}</td>;
    case 'detected':
      return <td>{Object.keys(query.entityCounts ?? {}).join(', ') || '-'}</td>;
    case 'status':
      return (
        <td>
          <StatusChip query={query} onOpen={onChip} />
          <span className="row-affordance">VIEW</span>
        </td>
      );
  }
}

interface ActivityRowProps {
  query: ActivityQuery;
  cols: ActivityCol[];
  expanded: boolean;
  isNew: boolean;
  onToggle: () => void;
  onChip: ChipOpener;
}

function ActivityRow({ query, cols, expanded, isNew, onToggle, onChip }: ActivityRowProps) {
  const classes = ['activity-row', severityRowClass(query), expanded ? 'selected' : '', isNew ? 'is-new' : '']
    .filter(Boolean)
    .join(' ');
  return (
    <tr
      className={classes}
      tabIndex={0}
      onClick={(event) => {
        if ((event.target as HTMLElement).closest('textarea,input,button,select,a,[role="button"]')) return;
        onToggle();
      }}
      onKeyDown={(event) => {
        if (event.target !== event.currentTarget || (event.key !== 'Enter' && event.key !== ' ')) return;
        event.preventDefault();
        onToggle();
      }}
    >
      {cols.map((col) => (
        <ActivityCell key={col} query={query} col={col} onChip={onChip} />
      ))}
    </tr>
  );
}

interface ActivityTableProps {
  slice: PageSlice;
  cols: ActivityCol[];
  expandedId: string;
  recentId: string;
  meta: DetectorsMeta | null;
  onToggleRow: (id: string) => void;
  onPivot: (token: string) => void;
  onChip: ChipOpener;
}

function ActivityTable({ slice, cols, expandedId, recentId, meta, onToggleRow, onPivot, onChip }: ActivityTableProps) {
  const span = Math.max(1, cols.length);
  return (
    <div className="activity-table-wrap">
      <table>
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col}>{COL_LABELS[col]}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {slice.rows.length ? (
            slice.rows.map((q) => (
              <Fragment key={q.id}>
                <ActivityRow query={q} cols={cols} expanded={expandedId === q.id} isNew={recentId === q.id} onToggle={() => onToggleRow(q.id)} onChip={onChip} />
                {expandedId === q.id ? <DetailRow query={q} colSpan={span} meta={meta} onPivot={onPivot} /> : null}
              </Fragment>
            ))
          ) : (
            <tr>
              <td colSpan={span} className="empty">
                No matching activity
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ---- Pager (legacy .table-pager with chevron ghost buttons) ----

function Chevron({ direction }: { direction: 'prev' | 'next' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d={direction === 'prev' ? 'm15 6-6 6 6 6' : 'm9 6 6 6-6 6'} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Pager({ slice, onPage }: { slice: PageSlice; onPage: (page: number) => void }) {
  if (!slice.total) {
    return (
      <div className="table-pager" aria-live="polite">
        <span>No rows</span>
      </div>
    );
  }
  return (
    <div className="table-pager" aria-live="polite">
      <span>
        Showing {slice.start + 1}-{slice.end} of {slice.total}
      </span>
      <div className="pager-controls" aria-label="Pagination controls">
        <button className="ghost mini pager-button" type="button" disabled={slice.page === 1} onClick={() => onPage(slice.page - 1)} aria-label="Previous page">
          <Chevron direction="prev" />
        </button>
        <span className="pager-page">
          Page {slice.page} of {slice.totalPages}
        </span>
        <button className="ghost mini pager-button" type="button" disabled={slice.page === slice.totalPages} onClick={() => onPage(slice.page + 1)} aria-label="Next page">
          <Chevron direction="next" />
        </button>
      </div>
    </div>
  );
}

// ---- View ----

interface ActivityBodyProps {
  state: ActivityDataState;
  rows: ActivityQuery[] | null;
  table: ActivityTableState;
  cols: ActivityCol[];
  hidden: ReadonlySet<string>;
  onToggleCol: (col: string, visible: boolean) => void;
  expandedId: string;
  recentId: string;
  meta: DetectorsMeta | null;
  onToggleRow: (id: string) => void;
  onChip: ChipOpener;
}

function ActivityBody(props: ActivityBodyProps) {
  const { state, rows, table } = props;
  if (state === 'loading') return <div className="app-loading">Loading activity…</div>;
  if (state === 'unavailable' || !rows) {
    return <EmptyState title="Activity unavailable" detail="No verified activity snapshot is available. Refresh to retry." />;
  }
  if (state === 'stale' && !rows.length) {
    return <EmptyState title="Activity snapshot stale" detail="The last verified snapshot was empty, but the latest refresh failed. No current empty-state conclusion can be drawn." />;
  }
  if (!rows.length) return <EmptyState title="No gated member-data events yet" detail="The current verified snapshot contains no activity events." />;
  return (
    <>
      {state === 'stale' ? (
        <div className="ticket-sync-status" role="alert">
          Activity refresh failed. Showing verified activity received so far; current events may be missing.
        </div>
      ) : null}
      <ColumnChooser hidden={props.hidden} onToggle={props.onToggleCol} />
      <ActivityTable
        slice={table.slice}
        cols={props.cols}
        expandedId={props.expandedId}
        recentId={props.recentId}
        meta={props.meta}
        onToggleRow={props.onToggleRow}
        onPivot={table.applySearch}
        onChip={props.onChip}
      />
      <Pager slice={table.slice} onPage={table.setPage} />
    </>
  );
}

export default function Activity() {
  const { me } = useSession();
  const { rows, state, recentId } = useActivityRows();
  const list = useMemo(() => rows ?? [], [rows]);
  const table = useActivityTable(list);
  const savedViews = useSavedViews();
  const cols = useHiddenCols();
  const [expandedId, setExpandedId] = useState('');
  const [popover, setPopover] = useState<PopoverState | null>(null);
  const [ticketSyncBusy, setTicketSyncBusy] = useState(false);
  const [ticketSyncMessage, setTicketSyncMessage] = useState('');
  const meta = useDetectorsMeta(Boolean(expandedId));

  const visibleCols = ACTIVITY_COLS.filter((col) => !cols.hidden.has(col));
  const toggleRow = (id: string) => setExpandedId((prev) => (prev === id ? '' : id));
  const openChip = useCallback((detail: string, anchor: DOMRect) => setPopover({ detail, ...popoverPosition(anchor) }), []);
  const closeChip = useCallback(() => setPopover(null), []);
  const runTicketSync = async () => {
    setTicketSyncBusy(true);
    setTicketSyncMessage('Synchronizing configured Jira and Linear ticket status…');
    try {
      const result = await syncTicketStatuses();
      if (!result) {
        setTicketSyncMessage('Ticket synchronization is unavailable. Retry when the control plane is ready.');
      } else if (result.status === 'busy') {
        setTicketSyncMessage('Ticket synchronization is already running. Wait for the active check to finish.');
      } else if (result.reason === 'no_ticket_channels') {
        setTicketSyncMessage('No Jira or Linear ticket channels are configured. No records were changed.');
      } else if (result.status === 'skipped') {
        setTicketSyncMessage('Ticket synchronization is unavailable because its data store is not ready.');
      } else if (result.status === 'partial') {
        setTicketSyncMessage(
          `Ticket synchronization partial (${ticketSyncStopLabel(result.reason)}): ${statusCheckCount(result.checksAttempted)} attempted across ${result.checked} of ${result.matched} matching records; ${result.succeeded} succeeded, ${result.failed} failed; ${result.updated} updated.`,
        );
      } else {
        setTicketSyncMessage(
          `Ticket synchronization complete: ${statusCheckCount(result.checksAttempted)} completed across ${result.checked} matching records; ${result.updated} updated.`,
        );
      }
    } finally {
      setTicketSyncBusy(false);
    }
  };

  const metaLine = state === 'loading'
    ? 'Loading'
    : state === 'unavailable'
      ? 'Unavailable'
      : `${table.filtered.length} shown / ${list.length} events${state === 'stale' ? ' / stale snapshot' : ''}`;
  return (
    <div className="activity-view">
      <Toolbar
        table={table}
        views={savedViews.views}
        canSyncTickets={me?.role === 'security_admin'}
        ticketSyncBusy={ticketSyncBusy}
        ticketSyncMessage={ticketSyncMessage}
        onSaveView={() => savedViews.save(currentView(table))}
        onExport={() => exportActivityCsv(table.filtered)}
        onSyncTickets={() => void runTicketSync()}
      />
      <Panel title="Gated Member-Data Events" meta={metaLine}>
        <ActivityBody
          state={state}
          rows={rows}
          table={table}
          cols={visibleCols}
          hidden={cols.hidden}
          onToggleCol={cols.toggle}
          expandedId={expandedId}
          recentId={recentId}
          meta={meta}
          onToggleRow={toggleRow}
          onChip={openChip}
        />
      </Panel>
      {popover ? <MetaPopover popover={popover} onClose={closeChip} /> : null}
    </div>
  );
}
