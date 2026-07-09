import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { EmptyState } from '../components/Panel';
import { apiJson, apiSend } from '../lib/api';
import { downloadCsv, csvStamp } from '../lib/csv';
import { navigate } from '../lib/router';
import { useSession } from '../lib/session';
import { toast } from '../lib/toast';
import './Catalog.css';

/**
 * AI App Catalog view. Route contract from server/app.js + server/app-catalog.js:
 *   GET  /api/catalog                  -> { apps: CatalogApp[] } (any authenticated role)
 *   POST /api/catalog                  -> body {destination, appName?}; Security Admin; { app }
 *   POST /api/catalog/import           -> body {csv}; Security Admin; { imported, skipped, total, apps }
 *   POST /api/catalog/:host/review     -> body {decision, reason}; Security Admin; live policy change
 *   POST /api/catalog/:host/override   -> body {score, note} sets, {score: null} clears; Security Admin
 * CSRF is automatic via lib/api.ts; no password step-up anywhere on this tab.
 * This tab consumes NO SSE events (legacy refreshes only on activation, Refresh, and mutations).
 */

interface CatalogRiskAttributes {
  trainsOnData: string;
  personalTier: boolean;
  flags: string[];
}

interface CatalogApp {
  id: number;
  destination: string;
  appName: string;
  provider: string | null;
  region: string | null;
  riskScore: number | null;
  riskTier: string;
  baseRiskScore: number | null;
  riskOverride: number | null;
  overrideNote: string | null;
  overriddenBy: string | null;
  riskAttributes: CatalogRiskAttributes | null;
  sanctionedStatus: string;
  knownAiHost: boolean;
  owner: string | null;
  notes: string | null;
  eventCount: number;
  sources: Record<string, number>;
  firstSeen: string;
  lastSeen: string;
}

interface CatalogResponse {
  apps: CatalogApp[];
}

interface ImportResult {
  imported: number;
  skipped: number;
  total: number;
}

type Decision = 'allow' | 'govern' | 'block';

const RISK_TONE: Record<string, string> = {
  critical: 'tone-critical', high: 'tone-high', moderate: 'tone-medium',
  low: 'tone-low', minimal: 'tone-low', unrated: 'tone-neutral',
};
const STATUS_TONE: Record<string, string> = {
  blocked: 'tone-critical', unsanctioned: 'tone-high', under_review: 'tone-neutral',
  tolerated: 'tone-medium', sanctioned: 'tone-low',
};
const ATTR_LABEL: Record<string, string> = {
  trains_on_data: 'Trains on data', personal_account_tier: 'Personal tier',
  data_residency_cn: 'Data in CN', data_residency_eu: 'Data in EU',
};

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');

// ---- Sorting (legacy sortedCatalogApps semantics) ----

type SortKey = 'appName' | 'provider' | 'riskScore' | 'sanctionedStatus' | 'eventCount';
type SortDir = 1 | -1;

interface SortState {
  key: SortKey;
  dir: SortDir;
}

function compareApps(a: CatalogApp, b: CatalogApp, sort: SortState): number {
  const va = a[sort.key] ?? '';
  const vb = b[sort.key] ?? '';
  if (typeof va === 'number' || typeof vb === 'number') return ((Number(va) || 0) - (Number(vb) || 0)) * sort.dir;
  return String(va).localeCompare(String(vb)) * sort.dir;
}

function sortApps(apps: CatalogApp[], sort: SortState): CatalogApp[] {
  return [...apps].sort((a, b) => compareApps(a, b, sort));
}

/** New key sorts text columns ascending, numeric/status columns descending; same key flips. */
function nextSort(prev: SortState, key: SortKey): SortState {
  if (prev.key === key) return { key, dir: -prev.dir as SortDir };
  return { key, dir: key === 'appName' || key === 'provider' ? 1 : -1 };
}

// ---- API calls ----

function fetchCatalog(): Promise<CatalogResponse | null> {
  return apiJson<CatalogResponse>('/api/catalog');
}

/** Shared by the inline confirm and the bulk bar; failure toast matches legacy submitCatalogReview. */
async function submitReview(host: string, decision: Decision, reason: string): Promise<boolean> {
  const body = await apiSend<{ decision: string }>(
    `/api/catalog/${encodeURIComponent(host)}/review`, 'POST', { decision, reason },
  );
  if (body) return true;
  toast(`Could not save the ${decision} decision for ${host}.`, 'error');
  return false;
}

// ---- CSV export (client-side only, metadata only — never prompt text) ----

function exportCatalogCsv(sorted: CatalogApp[]): void {
  const lines: Array<Array<string | number>> = [
    ['App', 'Host', 'Provider', 'Risk tier', 'Risk score', 'Status', 'Events', 'Sources'],
    ...sorted.map((a) => [
      a.appName || a.destination, a.destination, a.provider || '', a.riskTier, a.riskScore ?? '',
      a.sanctionedStatus, a.eventCount || 0, Object.keys(a.sources || {}).join('; '),
    ]),
  ];
  downloadCsv(`redactwall-ai-apps-${csvStamp()}.csv`, lines);
}

// ---- Loader hook (no SSE: legacy catalog never listens to /api/stream) ----

function useCatalogApps() {
  const [apps, setApps] = useState<CatalogApp[] | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      const body = await fetchCatalog();
      if (body) setApps(body.apps ?? []); // null keeps the previous render, as legacy loadCatalog did
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { apps, loaded, busy, load };
}

// ---- Selection / review / override state + handlers ----

interface PendingReview {
  host: string;
  decision: Decision;
  reason: string;
}

function useCatalogActions(load: () => void) {
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set());
  const [pending, setPending] = useState<PendingReview | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [bulkReason, setBulkReason] = useState('');
  const [acting, setActing] = useState(false);

  const toggleSelect = (host: string, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(host);
      else next.delete(host);
      return next;
    });
  };

  const selectAll = (apps: CatalogApp[], checked: boolean) => {
    setSelected(checked ? new Set(apps.map((a) => a.destination)) : new Set());
  };

  /** Drop selections for hosts no longer in the catalog, as legacy loadCatalog did. */
  const pruneTo = useCallback((apps: CatalogApp[]) => {
    setSelected((prev) => new Set([...prev].filter((host) => apps.some((a) => a.destination === host))));
  }, []);

  const toggleExpand = (host: string) => setExpanded((prev) => (prev === host ? null : host));

  const requestReview = (host: string, decision: Decision) => {
    setPending({ host, decision, reason: `${decision} decision from console` });
  };

  const setReviewReason = (reason: string) => setPending((prev) => (prev ? { ...prev, reason } : prev));

  const cancelReview = () => setPending(null);

  const confirmReview = async () => {
    if (!pending) return;
    const { host, decision } = pending;
    const reason = pending.reason.trim() || `${decision} decision from console`;
    setPending(null);
    setActing(true);
    const ok = await submitReview(host, decision, reason);
    setActing(false);
    if (!ok) return;
    toast(`${host} is now "${decision}".`, 'good');
    load();
  };

  /** Sequential per-host posts, as legacy runCatalogBulk — the route is single-host. */
  const runBulk = async (decision: Decision) => {
    const hosts = [...selected];
    const reason = bulkReason.trim() || `bulk ${decision} decision from console`;
    setActing(true);
    let done = 0;
    for (const host of hosts) {
      if (await submitReview(host, decision, reason)) done += 1;
    }
    setActing(false);
    toast(`${decision} applied to ${done} of ${hosts.length} app(s).`, done === hosts.length ? 'good' : 'error');
    setSelected(new Set());
    load();
  };

  /** score null clears; note is required (and sent) only when setting. */
  const setOverride = async (host: string, score: number | null, note?: string) => {
    setActing(true);
    const body = await apiSend<{ ok: boolean }>(
      `/api/catalog/${encodeURIComponent(host)}/override`, 'POST', note === undefined ? { score } : { score, note },
    );
    setActing(false);
    if (!body) return; // legacy surfaces only the shared 403 toast on failure
    toast(score == null ? `Override cleared for ${host}.` : `Score override recorded for ${host}.`, 'good');
    load();
  };

  return {
    selected, pending, expanded, bulkReason, acting,
    toggleSelect, selectAll, pruneTo, toggleExpand,
    requestReview, setReviewReason, cancelReview, confirmReview, runBulk, setOverride, setBulkReason,
  };
}

type CatalogActions = ReturnType<typeof useCatalogActions>;

// ---- Header ----

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

interface CatalogHeaderProps {
  busy: boolean;
  onImport: () => void;
  onAdd: () => void;
  onRefresh: () => void;
}

function CatalogHeader({ busy, onImport, onAdd, onRefresh }: CatalogHeaderProps) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>AI Vendor Catalog</h2>
          <p>
            Discovered AI vendors and internal assistants with app-risk attributes, sanctioned status, and one-click
            govern / allow / block for Texas FCU teams. Discovery is metadata only.
          </p>
        </div>
      </div>
      <div className="console-frame-actions">
        <button className="system-button secondary" type="button" onClick={onImport}>Import proxy/DNS CSV</button>
        <button className="system-button secondary" type="button" onClick={onAdd}>Add app</button>
        <button className="system-button secondary" type="button" disabled={busy} onClick={onRefresh}>
          <RefreshIcon />
          Refresh
        </button>
      </div>
    </div>
  );
}

// ---- KPI strip ----

function Kpi({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiRow({ apps }: { apps: CatalogApp[] }) {
  const shadow = apps.filter((a) => a.sanctionedStatus === 'under_review').length;
  const high = apps.filter((a) => a.riskTier === 'critical' || a.riskTier === 'high').length;
  const governed = apps.filter((a) => ['sanctioned', 'tolerated', 'blocked'].includes(a.sanctionedStatus)).length;
  return (
    <div className="insights-kpis">
      <Kpi label="AI vendors discovered" value={apps.length} hint="across all sources" />
      <Kpi label="Awaiting review" value={shadow} hint="shadow AI" />
      <Kpi label="Elevated / high risk" value={high} hint="by risk tier" />
      <Kpi label="Governed" value={governed} hint="allow / govern / block" />
    </div>
  );
}

// ---- Add / import form panels ----

interface FormPanelProps {
  onSaved: () => void;
  onClose: () => void;
}

function AddForm({ onSaved, onClose }: FormPanelProps) {
  const [host, setHost] = useState('');
  const [name, setName] = useState('');
  const submit = async () => {
    const destination = host.trim();
    if (!destination) return toast('Enter the AI app host first.', 'error');
    const appName = name.trim();
    const body = await apiSend<{ app: CatalogApp | null }>(
      '/api/catalog', 'POST', appName ? { destination, appName } : { destination },
    );
    if (body) {
      toast(`${destination} added to the catalog.`, 'good');
      onSaved();
    } else toast(`Could not add ${destination}.`, 'error');
  };
  return (
    <div className="panel catalog-form">
      <div className="panel-head"><div><h2>Add AI vendor</h2><span>Register an AI host the sensors have not discovered yet</span></div></div>
      <div className="catalog-form-body">
        <input type="text" placeholder="cu-assistant.internal" aria-label="AI app host" value={host} onChange={(event) => setHost(event.target.value)} />
        <input type="text" placeholder="Display name (optional)" aria-label="Display name" value={name} onChange={(event) => setName(event.target.value)} />
        <button className="system-button primary" type="button" onClick={submit}>Add app</button>
        <button className="ghost" type="button" onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
}

function ImportForm({ onSaved, onClose }: FormPanelProps) {
  const [csv, setCsv] = useState('');
  const submit = async () => {
    const text = csv.trim();
    if (!text) return toast('Paste at least one hostname first.', 'error');
    const body = await apiSend<ImportResult>('/api/catalog/import', 'POST', { csv: text });
    if (body) {
      toast(`Imported ${body.imported} app(s), skipped ${body.skipped}.`, 'good');
      onSaved();
    } else toast('Import failed - check the format (host or host,count per line).', 'error');
  };
  return (
    <div className="panel catalog-form">
      <div className="panel-head"><div><h2>Import from Texas FCU proxy/DNS log</h2><span>One hostname per line, or host,count pairs - metadata only</span></div></div>
      <div className="catalog-form-body catalog-form-column">
        <textarea rows={4} placeholder={'cu-assistant.internal\nchat.example.ai,42'} aria-label="Hostnames to import" value={csv} onChange={(event) => setCsv(event.target.value)} />
        <div className="catalog-form-actions">
          <button className="system-button primary" type="button" onClick={submit}>Import</button>
          <button className="ghost" type="button" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ---- Bulk bar (lives in the table panel head, shown only with a selection) ----

interface BulkBarProps {
  count: number;
  reason: string;
  acting: boolean;
  onReason: (value: string) => void;
  onDecision: (decision: Decision) => void;
}

function BulkBar({ count, reason, acting, onReason, onDecision }: BulkBarProps) {
  return (
    <div className="catalog-bulk">
      <span>{count} selected</span>
      <input type="text" placeholder="Reason (recorded in audit)" aria-label="Bulk decision reason" value={reason} onChange={(event) => onReason(event.target.value)} />
      <button className="ghost mini" type="button" disabled={acting} onClick={() => onDecision('allow')}>Allow</button>
      <button className="ghost mini" type="button" disabled={acting} onClick={() => onDecision('govern')}>Govern</button>
      <button className="ghost mini danger" type="button" disabled={acting} onClick={() => onDecision('block')}>Block</button>
    </div>
  );
}

// ---- Table ----

interface SortableThProps {
  label: string;
  k: SortKey;
  sort: SortState;
  onSort: (key: SortKey) => void;
}

function SortableTh({ label, k, sort, onSort }: SortableThProps) {
  const active = sort.key === k;
  const dir = sort.dir > 0 ? 'asc' : 'desc';
  return (
    <th
      data-catalog-sort={k}
      className={active ? 'sorted' : undefined}
      data-sort-dir={active ? dir : undefined}
      aria-sort={active ? (sort.dir > 0 ? 'ascending' : 'descending') : undefined}
      onClick={() => onSort(k)}
    >
      {label}
    </th>
  );
}

function AttrChips({ flags }: { flags: string[] }) {
  if (!flags.length) return <span className="insights-attr-muted">—</span>;
  return (
    <>
      {flags.map((flag) => (
        <span key={flag} className="insights-attr">{ATTR_LABEL[flag] || flag}</span>
      ))}
    </>
  );
}

function GovernButtons({ host, acting, onReview }: { host: string; acting: boolean; onReview: (host: string, decision: Decision) => void }) {
  return (
    <>
      <button className="ghost mini" type="button" disabled={acting} onClick={() => onReview(host, 'allow')}>Allow</button>
      <button className="ghost mini" type="button" disabled={acting} onClick={() => onReview(host, 'govern')}>Govern</button>
      <button className="ghost mini danger" type="button" disabled={acting} onClick={() => onReview(host, 'block')}>Block</button>
    </>
  );
}

interface ReviewConfirmProps {
  pending: PendingReview;
  acting: boolean;
  onReason: (reason: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
}

/** Inline two-step confirm; the reason arrives focused and selected, as legacy. */
function ReviewConfirm({ pending, acting, onReason, onConfirm, onCancel }: ReviewConfirmProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);
  return (
    <>
      <input ref={inputRef} className="catalog-reason" type="text" placeholder="Reason (audited)" aria-label="Review reason" value={pending.reason} onChange={(event) => onReason(event.target.value)} />
      <button className="ghost mini" type="button" disabled={acting} onClick={onConfirm}>Confirm {pending.decision}</button>
      <button className="ghost mini" type="button" onClick={onCancel}>Cancel</button>
    </>
  );
}

function GovernCell({ app, actions }: { app: CatalogApp; actions: CatalogActions }) {
  const { pending } = actions;
  if (pending && pending.host === app.destination) {
    return (
      <td className="catalog-actions">
        <ReviewConfirm pending={pending} acting={actions.acting} onReason={actions.setReviewReason} onConfirm={actions.confirmReview} onCancel={actions.cancelReview} />
      </td>
    );
  }
  return (
    <td className="catalog-actions">
      <GovernButtons host={app.destination} acting={actions.acting} onReview={actions.requestReview} />
    </td>
  );
}

function CatalogRow({ app, actions }: { app: CatalogApp; actions: CatalogActions }) {
  return (
    <tr>
      <td className="catalog-check">
        <input type="checkbox" checked={actions.selected.has(app.destination)} aria-label={`Select ${app.destination}`} onChange={(event) => actions.toggleSelect(app.destination, event.target.checked)} />
      </td>
      <td>
        <button className="catalog-app-link" type="button" title="Open app details" onClick={() => actions.toggleExpand(app.destination)}>
          {app.appName || app.destination}
          {app.riskOverride != null ? ' *' : ''}
        </button>
        <div className="catalog-host">{app.destination}</div>
      </td>
      <td>{app.provider || '—'}</td>
      <td>
        <span className={`insights-chip ${RISK_TONE[app.riskTier] || 'tone-neutral'}`}>{app.riskTier}</span>{' '}
        <span className="catalog-score">{app.riskScore == null ? '' : app.riskScore}</span>
      </td>
      <td><AttrChips flags={app.riskAttributes?.flags ?? []} /></td>
      <td><span className={`insights-chip ${STATUS_TONE[app.sanctionedStatus] || 'tone-neutral'}`}>{app.sanctionedStatus.replace(/_/g, ' ')}</span></td>
      <td>{app.eventCount || 0}</td>
      <td className="catalog-sources">{Object.keys(app.sources || {}).join(', ') || '—'}</td>
      <GovernCell app={app} actions={actions} />
    </tr>
  );
}

// ---- Detail drawer row ----

function DetailDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="datum">
      <label>{label}</label>
      <b>{value}</b>
    </div>
  );
}

function sourceBreakdown(app: CatalogApp): string {
  return Object.entries(app.sources || {}).map(([source, count]) => `${source} (${count})`).join(', ') || '-';
}

function computedScore(app: CatalogApp): string {
  const base = app.baseRiskScore ?? '-';
  return app.riskOverride != null ? `${base} (overridden to ${app.riskOverride})` : String(base);
}

function DetailGrid({ app }: { app: CatalogApp }) {
  return (
    <div className="activity-detail-grid">
      <DetailDatum label="Host" value={app.destination} />
      <DetailDatum label="Provider" value={app.provider || '-'} />
      <DetailDatum label="Region" value={app.region || '-'} />
      <DetailDatum label="Computed score" value={computedScore(app)} />
      <DetailDatum label="First seen" value={fmt(app.firstSeen)} />
      <DetailDatum label="Last seen" value={fmt(app.lastSeen)} />
      <DetailDatum label="Owner" value={app.owner || '-'} />
      <DetailDatum label="Events" value={`${app.eventCount || 0} via ${sourceBreakdown(app)}`} />
    </div>
  );
}

interface OverrideFormProps {
  app: CatalogApp;
  acting: boolean;
  onOverride: (host: string, score: number | null, note?: string) => void;
}

function OverrideForm({ app, acting, onOverride }: OverrideFormProps) {
  const [score, setScore] = useState(app.riskOverride == null ? '' : String(app.riskOverride));
  const [note, setNote] = useState(app.overrideNote || '');
  const submit = () => {
    const parsed = Number(score);
    const trimmed = note.trim();
    if (!Number.isFinite(parsed) || !trimmed) return toast('An override needs a 0-100 score and a justification note.', 'error');
    onOverride(app.destination, parsed, trimmed);
  };
  return (
    <div className="catalog-override">
      <b>Analyst score override</b>
      <input type="number" min={0} max={100} placeholder="0-100" aria-label="Override score" value={score} onChange={(event) => setScore(event.target.value)} />
      <input type="text" placeholder="Business justification (required, audited)" aria-label="Override justification" value={note} onChange={(event) => setNote(event.target.value)} />
      <button className="ghost mini" type="button" disabled={acting} onClick={submit}>Set override</button>
      {app.riskOverride != null ? (
        <button className="ghost mini" type="button" disabled={acting} onClick={() => onOverride(app.destination, null)}>Clear</button>
      ) : null}
    </div>
  );
}

interface DetailRowProps {
  app: CatalogApp;
  isAdmin: boolean;
  acting: boolean;
  onOverride: (host: string, score: number | null, note?: string) => void;
}

function DetailRow({ app, isAdmin, acting, onOverride }: DetailRowProps) {
  const flags = app.riskAttributes?.flags ?? [];
  const overrideKey = `${app.riskOverride ?? ''}|${app.overrideNote ?? ''}`; // remount on server change, as legacy re-render did
  return (
    <tr className="catalog-detail-row">
      <td colSpan={9}>
        <div className="activity-detail">
          <DetailGrid app={app} />
          {flags.length ? <div className="chips"><AttrChips flags={flags} /></div> : null}
          {app.overriddenBy ? <div className="reasons">Override by {app.overriddenBy}: {app.overrideNote || ''}</div> : null}
          {app.notes ? <div className="reasons">Notes: {app.notes}</div> : null}
          {isAdmin ? <OverrideForm key={overrideKey} app={app} acting={acting} onOverride={onOverride} /> : null}
          <div className="activity-detail-actions">
            <button className="ghost mini" type="button" onClick={() => navigate(`/activity?q=${encodeURIComponent(`dest:${app.destination}`)}`)}>
              VIEW ACTIVITY
            </button>
          </div>
        </div>
      </td>
    </tr>
  );
}

// ---- Table + panel ----

interface CatalogTableProps {
  apps: CatalogApp[];
  sort: SortState;
  onSort: (key: SortKey) => void;
  actions: CatalogActions;
  isAdmin: boolean;
}

function CatalogRows({ apps, actions, isAdmin }: { apps: CatalogApp[]; actions: CatalogActions; isAdmin: boolean }) {
  if (!apps.length) {
    return (
      <tr>
        <td colSpan={9} className="insights-empty">No AI vendors discovered yet. Import a proxy/DNS log or wait for sensor sightings.</td>
      </tr>
    );
  }
  return (
    <>
      {apps.map((app) => (
        <Fragment key={app.destination}>
          <CatalogRow app={app} actions={actions} />
          {actions.expanded === app.destination ? (
            <DetailRow app={app} isAdmin={isAdmin} acting={actions.acting} onOverride={actions.setOverride} />
          ) : null}
        </Fragment>
      ))}
    </>
  );
}

function CatalogTable({ apps, sort, onSort, actions, isAdmin }: CatalogTableProps) {
  return (
    <table>
      <thead>
        <tr>
          <th className="catalog-check">
            <input type="checkbox" aria-label="Select all apps" checked={apps.length > 0 && actions.selected.size === apps.length} onChange={(event) => actions.selectAll(apps, event.target.checked)} />
          </th>
          <SortableTh label="App" k="appName" sort={sort} onSort={onSort} />
          <SortableTh label="Provider" k="provider" sort={sort} onSort={onSort} />
          <SortableTh label="Risk" k="riskScore" sort={sort} onSort={onSort} />
          <th>Attributes</th>
          <SortableTh label="Status" k="sanctionedStatus" sort={sort} onSort={onSort} />
          <SortableTh label="Events" k="eventCount" sort={sort} onSort={onSort} />
          <th>Sources</th>
          <th>Govern</th>
        </tr>
      </thead>
      <tbody>
        <CatalogRows apps={apps} actions={actions} isAdmin={isAdmin} />
      </tbody>
    </table>
  );
}

interface TablePanelProps extends CatalogTableProps {
  loaded: boolean;
  busy: boolean;
  failed: boolean;
}

function TablePanel({ apps, sort, onSort, actions, isAdmin, loaded, busy, failed }: TablePanelProps) {
  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Discovering AI apps…</div>;
    if (failed) return <EmptyState title="Catalog unavailable" detail="Could not load the app catalog. Refresh to retry." />;
    return <CatalogTable apps={apps} sort={sort} onSort={onSort} actions={actions} isAdmin={isAdmin} />;
  };
  return (
    <div className={`panel wide-panel${busy ? ' is-loading' : ''}`} data-loading-label="DISCOVERING">
      <div className="panel-head">
        <div>
          <h2>Discovered AI vendors</h2>
          <span>Risk score, attributes, discovery source, and FCU governance decision - click a column to sort</span>
        </div>
        {actions.selected.size > 0 ? (
          <BulkBar count={actions.selected.size} reason={actions.bulkReason} acting={actions.acting} onReason={actions.setBulkReason} onDecision={actions.runBulk} />
        ) : null}
        <button className="ghost mini" type="button" onClick={() => exportCatalogCsv(apps)}>Export CSV</button>
      </div>
      {renderBody()}
    </div>
  );
}

// ---- View ----

export default function Catalog() {
  const { me } = useSession();
  const { apps, loaded, busy, load } = useCatalogApps();
  const actions = useCatalogActions(load);
  const [sort, setSort] = useState<SortState>({ key: 'eventCount', dir: -1 });
  const [openForm, setOpenForm] = useState<'add' | 'import' | null>(null);
  const { pruneTo } = actions;

  useEffect(() => {
    if (apps) pruneTo(apps);
  }, [apps, pruneTo]);

  const sorted = useMemo(() => sortApps(apps ?? [], sort), [apps, sort]);
  const isAdmin = me?.role === 'security_admin';
  const onSort = (key: SortKey) => setSort((prev) => nextSort(prev, key));
  const closeForm = () => setOpenForm(null);
  const saved = () => {
    setOpenForm(null);
    load();
  };

  return (
    <div className="catalog-view">
      <CatalogHeader
        busy={busy}
        onImport={() => setOpenForm((prev) => (prev === 'import' ? null : 'import'))}
        onAdd={() => setOpenForm((prev) => (prev === 'add' ? null : 'add'))}
        onRefresh={load}
      />
      {apps ? <KpiRow apps={apps} /> : null}
      {openForm === 'add' ? <AddForm onSaved={saved} onClose={closeForm} /> : null}
      {openForm === 'import' ? <ImportForm onSaved={saved} onClose={closeForm} /> : null}
      <TablePanel apps={sorted} sort={sort} onSort={onSort} actions={actions} isAdmin={isAdmin} loaded={loaded} busy={busy} failed={!apps} />
    </div>
  );
}
