import { useCallback, useEffect, useMemo, useState } from 'react';
import { exportEvidencePack, fetchAuditLog, type AuditEntry, type AuditIntegrity, type AuditLog } from '../api/audit';
import { EmptyState, Panel } from '../components/Panel';
import { useEventStream } from '../lib/sse';
import { toast } from '../lib/toast';
import './Audit.css';

const PAGE_SIZES = [10, 25, 50, 100];

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '-');
const humanize = (value: string) => (value || '-').replace(/_/g, ' ');

/** Port of the legacy dashboard statusTone(); audit actions mirror query statuses uppercased. */
const GOOD_ACTIONS = new Set(['approved', 'allowed', 'justified', 'warned_sent', 'redacted', 'response_redacted', 'sensor_heartbeat']);
const BAD_ACTIONS = new Set([
  'denied', 'blocked_by_user', 'destination_blocked', 'file_upload_blocked', 'action_blocked',
  'injection_blocked', 'response_flagged', 'response_blocked', 'seat_limit_blocked', 'ocr_required',
]);
const WARN_ACTIONS = new Set(['pending', 'shadow_ai', 'paste_flagged']);

function actionTone(action: string): 'good' | 'bad' | 'warn' | 'info' {
  const s = action.toLowerCase();
  if (GOOD_ACTIONS.has(s)) return 'good';
  if (BAD_ACTIONS.has(s)) return 'bad';
  if (WARN_ACTIONS.has(s)) return 'warn';
  return 'info';
}

function distinctValues(entries: AuditEntry[], pick: (entry: AuditEntry) => string): string[] {
  return [...new Set(entries.map(pick).filter(Boolean))].sort();
}

interface PageSlice {
  rows: AuditEntry[];
  page: number;
  total: number;
  totalPages: number;
  start: number;
  end: number;
}

function paginate(rows: AuditEntry[], page: number, pageSize: number): PageSlice {
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  return { rows: rows.slice(start, end), page: safePage, total, totalPages, start, end };
}

function useAuditLog() {
  const [log, setLog] = useState<AuditLog | null>(null);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    setLog(await fetchAuditLog());
    setLoaded(true);
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  useEventStream({ query: load, decision: load });
  return { log, loaded };
}

/** Filter + pagination state. A filter whose value vanished from the data falls back to 'all', as legacy did. */
function useAuditTable(entries: AuditEntry[]) {
  const [actionFilter, setActionFilter] = useState('all');
  const [actorFilter, setActorFilter] = useState('all');
  const [pageSize, setPageSize] = useState(10);
  const [page, setPage] = useState(1);
  const actions = useMemo(() => distinctValues(entries, (e) => e.action), [entries]);
  const actors = useMemo(() => distinctValues(entries, (e) => e.actor), [entries]);
  const action = actions.includes(actionFilter) ? actionFilter : 'all';
  const actor = actors.includes(actorFilter) ? actorFilter : 'all';
  const filtered = useMemo(
    () => entries.filter((e) => (action === 'all' || e.action === action) && (actor === 'all' || e.actor === actor)),
    [entries, action, actor],
  );
  const setAction = (value: string) => { setActionFilter(value); setPage(1); };
  const setActor = (value: string) => { setActorFilter(value); setPage(1); };
  const resize = (value: number) => { setPageSize(value); setPage(1); };
  return { actions, actors, action, actor, pageSize, filtered, slice: paginate(filtered, page, pageSize), setAction, setActor, resize, setPage };
}

interface FilterSelectProps {
  label: string;
  allLabel: string;
  value: string;
  options: string[];
  format?: (value: string) => string;
  onChange: (value: string) => void;
}

function FilterSelect({ label, allLabel, value, options, format, onChange }: FilterSelectProps) {
  return (
    <label>
      {label}
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="all">{allLabel}</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {format ? format(option) : option}
          </option>
        ))}
      </select>
    </label>
  );
}

interface AuditToolbarProps {
  table: ReturnType<typeof useAuditTable>;
  exporting: boolean;
  onExport: () => void;
}

function AuditToolbar({ table, exporting, onExport }: AuditToolbarProps) {
  return (
    <div className="audit-toolbar">
      <FilterSelect label="Action" allLabel="All actions" value={table.action} options={table.actions} format={humanize} onChange={table.setAction} />
      <FilterSelect label="Actor" allLabel="All actors" value={table.actor} options={table.actors} onChange={table.setActor} />
      <label>
        Rows
        <select value={table.pageSize} onChange={(event) => table.resize(Number(event.target.value))}>
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size} rows
            </option>
          ))}
        </select>
      </label>
      <button className="audit-export" type="button" disabled={exporting} onClick={onExport}>
        {exporting ? 'Exporting…' : 'Export evidence pack'}
      </button>
    </div>
  );
}

function IntegrityChip({ integrity }: { integrity: AuditIntegrity }) {
  if (integrity.ok) {
    return (
      <div className="audit-integrity tone-good" role="status">
        Chain verified: {integrity.count} cryptographically linked entries
      </div>
    );
  }
  const reason = integrity.reason === 'evidence' ? 'evidence hash mismatch' : 'broken hash chain';
  return (
    <div className="audit-integrity tone-bad" role="status">
      Integrity check failed at {integrity.brokenAt || 'unknown entry'} ({reason})
    </div>
  );
}

function AuditTable({ rows }: { rows: AuditEntry[] }) {
  return (
    <div className="audit-table-wrap">
      <table className="audit-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Query</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((entry) => (
            <tr key={entry.id}>
              <td className="audit-mono">{fmt(entry.ts)}</td>
              <td>
                <span className={`audit-chip tone-${actionTone(entry.action)}`}>{humanize(entry.action)}</span>
              </td>
              <td>{entry.actor || '-'}</td>
              <td className="audit-mono">{entry.queryId || '-'}</td>
              <td className="audit-detail">{entry.detail || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Pager({ slice, onPage }: { slice: PageSlice; onPage: (page: number) => void }) {
  if (!slice.total) return null;
  return (
    <div className="audit-pager" aria-live="polite">
      <span>
        Showing {slice.start + 1}-{slice.end} of {slice.total}
      </span>
      <div className="audit-pager-controls" aria-label="Pagination controls">
        <button type="button" disabled={slice.page === 1} onClick={() => onPage(slice.page - 1)} aria-label="Previous page">
          Prev
        </button>
        <span>
          Page {slice.page} of {slice.totalPages}
        </span>
        <button type="button" disabled={slice.page === slice.totalPages} onClick={() => onPage(slice.page + 1)} aria-label="Next page">
          Next
        </button>
      </div>
    </div>
  );
}

export default function Audit() {
  const { log, loaded } = useAuditLog();
  const entries = useMemo(() => log?.entries ?? [], [log]);
  const table = useAuditTable(entries);
  const [exporting, setExporting] = useState(false);

  const runExport = async () => {
    setExporting(true);
    try {
      const error = await exportEvidencePack();
      if (error) toast(error, 'error');
      else toast('Evidence pack downloaded.', 'good');
    } finally {
      setExporting(false);
    }
  };

  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Loading audit log…</div>;
    if (!log) return <EmptyState title="Audit log unavailable" detail="Could not load the audit trail. Refresh to retry." />;
    if (!entries.length) return <EmptyState title="No examiner audit entries yet" detail="Admin, policy, and member-data decision activity appears here as it is recorded." />;
    if (!table.filtered.length) return <EmptyState title="No matching audit entries" detail="No entries match the current action and actor filters." />;
    return (
      <>
        <AuditTable rows={table.slice.rows} />
        <Pager slice={table.slice} onPage={table.setPage} />
      </>
    );
  };

  const meta = !loaded ? 'Loading' : `${table.filtered.length} shown / ${entries.length} entries`;
  return (
    <div className="audit-view">
      <Panel title="Examiner Audit Chain" meta={meta}>
        <AuditToolbar table={table} exporting={exporting} onExport={runExport} />
        {log ? <IntegrityChip integrity={log.integrity} /> : null}
        {renderBody()}
        {log?.retention ? <p className="audit-retention">{log.retention}</p> : null}
      </Panel>
    </div>
  );
}
