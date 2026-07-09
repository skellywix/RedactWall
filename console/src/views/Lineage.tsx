import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiJson } from '../lib/api';
import { EmptyState, Panel } from '../components/Panel';
import { useEventStream } from '../lib/sse';
import './Lineage.css';

/**
 * Data lineage API. Route contract from server/app.js:
 *   GET /api/lineage?limit=  (any logged-in role) -> { limit, lineage }
 *     limit is boundedApiLimit(query.limit, 1000), clamped 1..5000; the
 *     legacy dashboard always sends 1000. lineage groups the newest `limit`
 *     queries via evidence.buildLineage() into sanitized aggregate buckets
 *     (no prompt bodies), sorted events DESC, maxRiskScore DESC, key ASC and
 *     capped at 25 buckets per group. byAccountType/byOriginApp also exist in
 *     the response but the legacy tab never renders them, so they are not
 *     typed here.
 */

interface LineageBucket {
  key: string;
  events: number;
  blocked: number;
  redacted: number;
  allowed: number;
  warned: number;
  maxRiskScore: number;
  users: number;
  destinations: number;
  sources: number;
  categories: string[];
  lastSeen: string | null;
}

interface LineageReport {
  byUser: LineageBucket[];
  byDestination: LineageBucket[];
  bySensor: LineageBucket[];
  byCategory: LineageBucket[];
  byChannel: LineageBucket[];
  byDecision: LineageBucket[];
}

const LINEAGE_PAGE_SIZE = 10;

function bucketList(value?: LineageBucket[]): LineageBucket[] {
  return Array.isArray(value) ? value : [];
}

async function fetchLineage(): Promise<LineageReport | null> {
  const body = await apiJson<{ lineage?: Partial<LineageReport> }>('/api/lineage?limit=1000');
  if (!body?.lineage) return null;
  const groups = body.lineage;
  return {
    byUser: bucketList(groups.byUser),
    byDestination: bucketList(groups.byDestination),
    bySensor: bucketList(groups.bySensor),
    byCategory: bucketList(groups.byCategory),
    byChannel: bucketList(groups.byChannel),
    byDecision: bucketList(groups.byDecision),
  };
}

/** Port of the legacy dashboard lineageText(): the searchable text of a bucket. */
function lineageBucketText(bucket: LineageBucket): string {
  return [
    bucket.key,
    ...(bucket.categories || []),
    bucket.events,
    bucket.blocked,
    bucket.redacted,
    bucket.allowed,
    bucket.warned,
    bucket.maxRiskScore,
  ].join(' ').toLowerCase();
}

function matchesFilter(bucket: LineageBucket, term: string): boolean {
  return !term || lineageBucketText(bucket).includes(term);
}

interface LineageTotals {
  events: number;
  users: number;
  destinations: number;
  blocked: number;
  redacted: number;
  allowed: number;
}

function decisionEvents(decisions: LineageBucket[], key: string): number {
  return decisions.find((row) => row.key === key)?.events ?? 0;
}

/** Port of the legacy lineageTotals(): user/destination counts are bucket counts (capped 25). */
function lineageTotals(report: LineageReport): LineageTotals {
  const decisions = report.byDecision;
  return {
    events: decisions.reduce((sum, row) => sum + (row.events || 0), 0),
    users: report.byUser.length,
    destinations: report.byDestination.length,
    blocked: decisionEvents(decisions, 'blocked'),
    redacted: decisionEvents(decisions, 'redacted'),
    allowed: decisionEvents(decisions, 'allowed'),
  };
}

function summaryCards(totals: LineageTotals): Array<{ value: number; label: string; meta: string }> {
  return [
    { value: totals.events, label: 'Exam events', meta: 'recent sanitized records' },
    { value: totals.users, label: 'Employees', meta: 'unique lineage buckets' },
    { value: totals.destinations, label: 'AI destinations', meta: 'tools and apps' },
    { value: totals.blocked, label: 'Blocked', meta: 'member-data stops' },
    { value: totals.redacted, label: 'Redacted', meta: 'tokenized or masked' },
    { value: totals.allowed, label: 'Allowed', meta: 'below thresholds' },
  ];
}

interface LineageGroup {
  key: keyof LineageReport;
  title: string;
  caption: string;
  columnLabel: string;
  emptyLabel: string;
}

const GROUPS: LineageGroup[] = [
  { key: 'byUser', title: 'Employees', caption: 'Observed activity without prompt bodies', columnLabel: 'Employee', emptyLabel: 'No employee lineage yet.' },
  { key: 'byDestination', title: 'AI Destinations', caption: 'AI tools and apps involved', columnLabel: 'Destination', emptyLabel: 'No destination lineage yet.' },
  { key: 'bySensor', title: 'Sensors', caption: 'Control points that saw traffic', columnLabel: 'Sensor', emptyLabel: 'No sensor lineage yet.' },
  { key: 'byCategory', title: 'Member-Data Categories', caption: 'Detected sensitive-data themes', columnLabel: 'Category', emptyLabel: 'No category lineage yet.' },
  { key: 'byChannel', title: 'Channels', caption: 'Prompt, file, response, and agent paths', columnLabel: 'Channel', emptyLabel: 'No channel lineage yet.' },
  { key: 'byDecision', title: 'Decisions', caption: 'How policy resolved the traffic', columnLabel: 'Decision', emptyLabel: 'No decision lineage yet.' },
];

interface PageSlice {
  rows: LineageBucket[];
  page: number;
  total: number;
  totalPages: number;
  start: number;
  end: number;
}

function paginate(rows: LineageBucket[], page: number, pageSize: number): PageSlice {
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  return { rows: rows.slice(start, end), page: safePage, total, totalPages, start, end };
}

function useLineageData() {
  const [report, setReport] = useState<LineageReport | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      const next = await fetchLineage();
      setReport((prev) => next ?? prev); // legacy keeps stale data on failure
      setLoaded(true);
    } finally {
      setBusy(false);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  useEventStream({ query: load, decision: load });
  return { report, loaded, busy, load };
}

interface LineageToolbarProps {
  search: string;
  busy: boolean;
  onSearch: (value: string) => void;
  onRefresh: () => void;
}

function LineageToolbar({ search, busy, onSearch, onRefresh }: LineageToolbarProps) {
  return (
    <div className="lineage-toolbar">
      <label className="lineage-search">
        Search
        <input
          type="search"
          placeholder="Search employees or destinations"
          value={search}
          onChange={(event) => onSearch(event.target.value)}
        />
      </label>
      <button className="ghost lineage-refresh" type="button" disabled={busy} onClick={onRefresh}>
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Refresh
      </button>
    </div>
  );
}

function SummaryStrip({ totals }: { totals: LineageTotals }) {
  return (
    <div className="lineage-summary">
      {summaryCards(totals).map((card) => (
        <div className="mini-kpi" key={card.label}>
          <b>{card.value}</b>
          <span>{card.label}</span>
          <em>{card.meta}</em>
        </div>
      ))}
    </div>
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
        <button className="ghost mini" type="button" disabled={slice.page === 1} onClick={() => onPage(slice.page - 1)} aria-label="Previous page">
          Prev
        </button>
        <span className="pager-page">
          Page {slice.page} of {slice.totalPages}
        </span>
        <button className="ghost mini" type="button" disabled={slice.page === slice.totalPages} onClick={() => onPage(slice.page + 1)} aria-label="Next page">
          Next
        </button>
      </div>
    </div>
  );
}

function BucketRow({ bucket }: { bucket: LineageBucket }) {
  return (
    <tr>
      <td className="mono">{bucket.key || '-'}</td>
      <td className="mono">{bucket.events || 0}</td>
      <td className="mono">{bucket.blocked || 0}</td>
      <td className="mono">{bucket.redacted || 0}</td>
      <td className="mono">{bucket.maxRiskScore || 0}</td>
    </tr>
  );
}

interface LineageTableProps {
  group: LineageGroup;
  rows: LineageBucket[];
  filter: string;
}

function LineageTable({ group, rows, filter }: LineageTableProps) {
  const [page, setPage] = useState(1);
  useEffect(() => {
    setPage(1);
  }, [filter]);
  const filtered = useMemo(() => rows.filter((bucket) => matchesFilter(bucket, filter)), [rows, filter]);
  const slice = paginate(filtered, page, LINEAGE_PAGE_SIZE);
  return (
    <Panel title={group.title} meta={group.caption}>
      <div className="lineage-table-wrap">
        <table>
          <thead>
            <tr>
              <th>{group.columnLabel}</th>
              <th>Events</th>
              <th>Blocked</th>
              <th>Redacted</th>
              <th>Max Risk</th>
            </tr>
          </thead>
          <tbody>
            {slice.rows.length ? (
              slice.rows.map((bucket) => <BucketRow key={bucket.key} bucket={bucket} />)
            ) : (
              <tr>
                <td colSpan={5} className="empty">{group.emptyLabel}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager slice={slice} onPage={setPage} />
    </Panel>
  );
}

function renderSummary(loaded: boolean, totals: LineageTotals | null) {
  if (!loaded) return <div className="app-loading">Loading lineage…</div>;
  if (!totals) {
    return <EmptyState title="Lineage unavailable" detail="Could not load lineage aggregates. Refresh to retry." />;
  }
  return <SummaryStrip totals={totals} />;
}

export default function Lineage() {
  const { report, loaded, busy, load } = useLineageData();
  const [search, setSearch] = useState('');
  const filter = search.trim().toLowerCase();
  const totals = useMemo(() => (report ? lineageTotals(report) : null), [report]);
  const meta = !loaded ? 'Loading' : busy ? 'Analyzing' : `${totals?.events ?? 0} events`;

  return (
    <div className="lineage-view lineage-grid">
      <div className="wide-panel">
        <Panel title="Member Data Lineage" meta={meta}>
          <p className="app-note">Sanitized aggregates across employees, sensors, AI destinations, member-data categories, and decisions.</p>
          <LineageToolbar search={search} busy={busy} onSearch={setSearch} onRefresh={load} />
          {renderSummary(loaded, totals)}
        </Panel>
      </div>
      {report
        ? GROUPS.map((group) => <LineageTable key={group.key} group={group} rows={report[group.key]} filter={filter} />)
        : null}
    </div>
  );
}
