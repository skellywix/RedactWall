import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { exportEvidencePack, fetchAuditLog, type AuditEntry, type AuditIntegrity, type AuditLog } from '../api/audit';
import { canReadAuditExports, verifyReceipt } from '../api/evidence';
import { EmptyState, Panel } from '../components/Panel';
import { useSession } from '../lib/session';
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
  canExport: boolean;
  sessionLoading: boolean;
  onExport: () => void;
}

function AuditToolbar({ table, exporting, canExport, sessionLoading, onExport }: AuditToolbarProps) {
  const exportUnavailable = !sessionLoading && !canExport;
  return (
    <div className="audit-toolbar">
      <FilterSelect label="Action" allLabel="All actions" value={table.action} options={table.actions} format={humanize} onChange={table.setAction} />
      <FilterSelect label="Actor" allLabel="All actors" value={table.actor} options={table.actors} onChange={table.setActor} />
      <label>
        Rows
        <select aria-label="Rows" value={table.pageSize} onChange={(event) => table.resize(Number(event.target.value))}>
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size} rows
            </option>
          ))}
        </select>
      </label>
      <button
        className="audit-export"
        type="button"
        disabled={exporting || sessionLoading || !canExport}
        aria-describedby={exportUnavailable ? 'auditExportPermission' : undefined}
        onClick={onExport}
      >
        {exporting ? 'Exporting…' : 'Export evidence pack'}
      </button>
      {exportUnavailable ? (
        <span className="audit-permission" id="auditExportPermission" role="note">
          Export requires a Global Administrator or Examiner/Auditor session.
        </span>
      ) : null}
    </div>
  );
}

const RECEIPT_INPUT_LIMIT = 4096;

type ReceiptState =
  | { kind: 'idle'; message: string }
  | { kind: 'valid'; message: string }
  | { kind: 'invalid'; message: string }
  | { kind: 'unavailable'; message: string }
  | { kind: 'forbidden'; message: string }
  | { kind: 'session'; message: string };

const RECEIPT_REASON: Record<string, string> = {
  'signature mismatch': 'The receipt signature does not match its signed fields.',
  'unsupported receipt version': 'This receipt version is not supported by this control plane.',
  'unknown receipt status': 'The receipt has an unsupported clearance status.',
  'malformed prompt hash': 'The receipt prompt hash is malformed.',
  'malformed policy hash': 'The receipt policy hash is malformed.',
  'malformed issue time': 'The receipt issue time is malformed.',
  'not a receipt object': 'The submitted value is not a receipt object.',
};

type ParsedReceipt =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; message: string };

function parsedReceipt(value: string): ParsedReceipt {
  if (value.length > RECEIPT_INPUT_LIMIT) {
    return { ok: false, message: 'Receipt JSON exceeds the 4,096-character verification limit.' };
  }
  if (!value.trim()) {
    return { ok: false, message: 'Enter one complete RedactWall receipt as a JSON object.' };
  }
  try {
    const parsed: unknown = JSON.parse(value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ok: true, value: parsed as Record<string, unknown> };
    }
  } catch {
    // The same generic format message covers invalid JSON and non-object JSON.
  }
  return { ok: false, message: 'Enter one complete RedactWall receipt as a JSON object.' };
}

function ReceiptVerifier() {
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [state, setState] = useState<ReceiptState>({
    kind: 'idle',
    message: 'Paste a prompt-free RedactWall safe-to-send receipt. This page does not persist the submitted JSON.',
  });

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    const parsed = parsedReceipt(value);
    if (!parsed.ok) {
      setState({ kind: 'invalid', message: parsed.message });
      return;
    }
    setBusy(true);
    setState({ kind: 'idle', message: 'Verifying receipt signature…' });
    try {
      const result = await verifyReceipt(parsed.value);
      if (result.kind === 'valid') {
        setState({ kind: 'valid', message: 'Receipt verified. Its signed fields have not been altered.' });
      } else if (result.kind === 'invalid') {
        setState({
          kind: 'invalid',
          message: RECEIPT_REASON[String(result.reason || '')]
            || (result.reason
              ? 'Receipt verification failed. Its signature or signed fields are invalid.'
              : 'Receipt format is invalid. Check every required signed field and its format.'),
        });
      } else if (result.kind === 'forbidden') {
        setState({
          kind: 'forbidden',
          message: 'This session was not permitted to verify the receipt. Refresh the page or sign in again.',
        });
      } else if (result.kind === 'session') {
        setState({ kind: 'session', message: 'Your session expired. Redirecting to sign in…' });
      } else {
        setState({
          kind: 'unavailable',
          message: 'Receipt verification is unavailable. Retry when the control plane is ready.',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const clear = () => {
    setValue('');
    setState({ kind: 'idle', message: 'Receipt input cleared from this page.' });
  };

  const changeReceipt = (nextValue: string) => {
    const boundedValue = nextValue.slice(0, RECEIPT_INPUT_LIMIT + 1);
    setValue(boundedValue);
    if (boundedValue.length > RECEIPT_INPUT_LIMIT) {
      setState({ kind: 'invalid', message: 'Receipt JSON exceeds the 4,096-character verification limit.' });
      return;
    }
    setState({
      kind: 'idle',
      message: boundedValue.trim()
        ? 'Receipt changed. Verify the current JSON before relying on its status.'
        : 'Paste a prompt-free RedactWall safe-to-send receipt. This page does not persist the submitted JSON.',
    });
  };

  return (
    <section className="receipt-verifier" aria-labelledby="receiptVerifierTitle">
      <div className="receipt-verifier-copy">
        <div>
          <h2 id="receiptVerifierTitle">Verify safe-to-send receipt</h2>
          <p>Confirm that a metadata-only clearance receipt was issued here and has not been edited.</p>
        </div>
        <span className="receipt-privacy">Prompt bodies excluded</span>
      </div>
      <form noValidate onSubmit={submit}>
        <label htmlFor="receiptJson">Receipt JSON</label>
        <textarea
          id="receiptJson"
          value={value}
          spellCheck={false}
          autoComplete="off"
          disabled={busy}
          aria-describedby="receiptVerificationStatus"
          aria-invalid={state.kind === 'invalid' ? 'true' : undefined}
          placeholder='{"v":1,"id":"q_…","status":"allowed",…}'
          onChange={(event) => changeReceipt(event.target.value)}
        />
        <div className="receipt-actions">
          <button className="system-button primary" type="submit" disabled={busy || !value.trim()}>
            {busy ? 'Verifying…' : 'Verify receipt'}
          </button>
          <button className="system-button secondary" type="button" disabled={busy || !value} onClick={clear}>
            Clear
          </button>
        </div>
      </form>
      <div id="receiptVerificationStatus" className={`receipt-result is-${state.kind}`} role="status" aria-live="polite">
        {state.message}
      </div>
    </section>
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
  const reason = integrity.reason ? humanize(integrity.reason) : 'integrity verification failure';
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
  const { me, loading: sessionLoading } = useSession();
  const { log, loaded } = useAuditLog();
  const entries = useMemo(() => log?.entries ?? [], [log]);
  const table = useAuditTable(entries);
  const [exporting, setExporting] = useState(false);
  const canExport = canReadAuditExports(me?.role);

  const runExport = async () => {
    if (!canExport) return;
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
        <AuditToolbar
          table={table}
          exporting={exporting}
          canExport={canExport}
          sessionLoading={sessionLoading}
          onExport={runExport}
        />
        {log ? <IntegrityChip integrity={log.integrity} /> : null}
        {renderBody()}
        {log?.retention ? <p className="audit-retention">{log.retention}</p> : null}
      </Panel>
      <ReceiptVerifier />
    </div>
  );
}
