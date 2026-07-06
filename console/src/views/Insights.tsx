import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { EmptyState } from '../components/Panel';
import { apiJson } from '../lib/api';
import { downloadCsv, csvStamp } from '../lib/csv';
import { useEventStream } from '../lib/sse';
import { toast } from '../lib/toast';
import './Insights.css';

/**
 * AI Usage Insights: read-only analytics over recent gated prompts — KPIs,
 * stacked daily series, decision donut, risk bands, top-N bars, two tables.
 * Route contract from server/app.js:
 *   GET /api/insights?windowDays=<N> -> insights.summarize() report. The server
 *     clamps windowDays to 1..90 and echoes the clamped value as `windowDays`,
 *     so KPI hints render from the response, never from the selected option.
 *   SSE /api/stream `query` events reload the report (decision/stats do not).
 * Metadata only (counts, hosts, usernames) — no prompt content, no mutations,
 * no step-up. CSV exports are client-side over the last loaded report.
 * Response fields unused by this view (generatedAt, confidence, accountTypes,
 * personalAccount*) are omitted from the interfaces below.
 */

interface InsightsTotals {
  considered: number;
  scored: number;
  avgRisk: number;
  blocked: number;
  redacted: number;
  allowed: number;
  shadow: number;
}

interface DecisionCount {
  id: string;
  count: number;
}

interface SeriesDay {
  date: string;
  allowed: number;
  redacted: number;
  warned: number;
  flagged: number;
  blocked: number;
  shadow: number;
  total: number;
}

interface RiskBand {
  id: string;
  label: string;
  count: number;
}

interface TopEntry {
  key: string;
  count: number;
}

interface DestinationRisk {
  provider: string;
  riskTier: number;
  riskTierLabel: string;
  flags: string[];
}

interface TopDestination {
  destination: string;
  count: number;
  risk: DestinationRisk | null;
}

interface TopUser {
  user: string;
  events: number;
  blocked: number;
  avgRisk: number;
  maxSeverity: number;
}

interface InsightsReport {
  windowDays: number;
  totals: InsightsTotals;
  decisions: DecisionCount[];
  series: SeriesDay[];
  riskBands: RiskBand[];
  topDetectors: TopEntry[];
  topCategories: TopEntry[];
  topDestinations: TopDestination[];
  shadowByProvider: TopEntry[];
  topUsers: TopUser[];
}

function fetchInsights(windowDays: number): Promise<InsightsReport | null> {
  return apiJson<InsightsReport>(`/api/insights?windowDays=${encodeURIComponent(String(windowDays))}`);
}

// ---- Constants (tones are the legacy hard-coded chart hexes, not theme vars) ----

const STACK_ORDER = ['allowed', 'redacted', 'warned', 'flagged', 'blocked', 'shadow'] as const;
type DecisionId = (typeof STACK_ORDER)[number];

const DECISION_META: Record<DecisionId, { label: string; tone: string }> = {
  allowed: { label: 'Allowed', tone: '#3fb27f' },
  redacted: { label: 'Redacted', tone: '#3f8cff' },
  warned: { label: 'Warned', tone: '#e0a23b' },
  flagged: { label: 'Flagged', tone: '#c98b2e' },
  blocked: { label: 'Blocked', tone: '#e0555f' },
  shadow: { label: 'Shadow AI', tone: '#a15de0' },
};

const RISK_TONE: Record<string, string> = {
  none: '#6b7686',
  low: '#3fb27f',
  medium: '#e0a23b',
  high: '#e07a3b',
  critical: '#e0555f',
};

const FLAG_LABELS: Record<string, string> = {
  trains_on_data: 'Trains on data',
  personal_account_tier: 'Personal tier',
  data_residency_cn: 'Data in CN',
  data_residency_eu: 'Data in EU',
};

/** Options beyond 90 are kept for legacy parity; the server clamps to 90 days. */
const WINDOW_OPTIONS = [7, 30, 90, 180, 365];

function decisionMeta(id: string): { label: string; tone: string } | null {
  return (DECISION_META as Record<string, { label: string; tone: string }>)[id] ?? null;
}

// ---- CSV export (from the last loaded report; never includes prompt text) ----

function exportSeriesCsv(report: InsightsReport | null): void {
  if (!report?.series.length) {
    toast('No insights data loaded yet.', 'error');
    return;
  }
  const lines: Array<Array<string | number>> = [
    ['Day', 'Allowed', 'Redacted', 'Warned', 'Flagged', 'Blocked', 'Shadow', 'Total'],
    ...report.series.map((d) => [
      d.date, d.allowed || 0, d.redacted || 0, d.warned || 0, d.flagged || 0, d.blocked || 0, d.shadow || 0, d.total || 0,
    ]),
  ];
  // Label the file with the server-clamped window (max 90), not the selected
  // window (up to 365) — the CSV must not claim more coverage than it contains.
  downloadCsv(`redactwall-insights-${report.windowDays}d-${csvStamp()}.csv`, lines);
}

function exportExecCsv(report: InsightsReport | null): void {
  if (!report) {
    toast('No insights data loaded yet.', 'error');
    return;
  }
  const lines: Array<Array<string | number>> = [
    ['Metric', 'Value'],
    ['Window (days)', report.windowDays],
    ...report.decisions.map((d): [string, number] => [`Decisions: ${d.id}`, d.count]),
    ...report.topDestinations.slice(0, 10).map((t): [string, number] => [`Top destination: ${t.destination}`, t.count]),
    ...report.topUsers.slice(0, 10).map((u): [string, number] => [`Top user: ${u.user}`, u.events]),
    ...report.riskBands.map((b): [string, number] => [`Risk band: ${b.label}`, b.count]),
  ];
  downloadCsv(`redactwall-executive-summary-${csvStamp()}.csv`, lines);
}

// ---- Loader hook ----

function useInsights() {
  const [windowDays, setWindowDays] = useState(30);
  const [report, setReport] = useState<InsightsReport | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      const next = await fetchInsights(windowDays);
      if (next) setReport(next); // fetch failure keeps the last render, as legacy
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, [windowDays]);
  useEffect(() => {
    load();
  }, [load]);
  useEventStream({ query: load });
  return { windowDays, setWindowDays, report, loaded, busy, load };
}

// ---- Header ----

interface HeaderProps {
  windowDays: number;
  busy: boolean;
  onWindow: (days: number) => void;
  onRefresh: () => void;
  onExportSeries: () => void;
  onExportExec: () => void;
}

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function HeaderActions({ windowDays, busy, onWindow, onRefresh, onExportSeries, onExportExec }: HeaderProps) {
  return (
    <div className="console-frame-actions">
      <label className="insights-window-label" htmlFor="insightsWindow">
        Window
      </label>
      <select id="insightsWindow" aria-label="Insights time window" value={windowDays} onChange={(event) => onWindow(Number(event.target.value) || 30)}>
        {WINDOW_OPTIONS.map((days) => (
          <option key={days} value={days}>
            Last {days} days
          </option>
        ))}
      </select>
      <button className="ghost" type="button" title="Download the daily decision series for the selected window" onClick={onExportSeries}>
        Export CSV
      </button>
      <button className="ghost" type="button" title="Download an executive summary: decision totals, top destinations and users, risk bands" onClick={onExportExec}>
        Executive summary
      </button>
      <button className="system-button secondary" type="button" disabled={busy} onClick={onRefresh}>
        <RefreshIcon />
        {busy ? 'Aggregating…' : 'Refresh'}
      </button>
    </div>
  );
}

function InsightsHeader(props: HeaderProps) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>AI Usage Insights</h2>
          <p>Real-time analytics on AI activity, data exposure risk, detections, and shadow-AI — metadata only, no prompt content.</p>
        </div>
      </div>
      <HeaderActions {...props} />
    </div>
  );
}

// ---- KPI row ----

function Kpi({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiRow({ report }: { report: InsightsReport }) {
  const t = report.totals;
  return (
    <div className="insights-kpis">
      <Kpi label="AI interactions" value={t.considered || 0} hint={`last ${report.windowDays} days`} />
      <Kpi label="Avg exposure risk" value={t.avgRisk || 0} hint="of 100" />
      <Kpi label="Blocked" value={t.blocked || 0} hint="held or denied" />
      <Kpi label="Redacted" value={t.redacted || 0} hint="tokenized & sent" />
      <Kpi label="Shadow-AI hits" value={t.shadow || 0} hint="ungoverned tools" />
    </div>
  );
}

// ---- Stacked daily series (dependency-free inline SVG, CSP-safe) ----

const CHART_W = 720;
const CHART_H = 200;
const CHART_PAD = 24;

interface SeriesScale {
  max: number;
  x: (i: number) => number;
  y: (v: number) => number;
  barWidth: number;
}

function seriesScale(series: SeriesDay[]): SeriesScale {
  const days = series.length || 1;
  const max = Math.max(1, ...series.map((d) => d.total));
  const x = (i: number) => CHART_PAD + (i * (CHART_W - CHART_PAD * 2)) / Math.max(1, days - 1);
  const y = (v: number) => CHART_H - CHART_PAD - (v / max) * (CHART_H - CHART_PAD * 2);
  const barWidth = Math.max(3, (CHART_W - CHART_PAD * 2) / days - 4);
  return { max, x, y, barWidth };
}

function DayColumn({ day, index, scale }: { day: SeriesDay; index: number; scale: SeriesScale }) {
  const left = scale.x(index) - scale.barWidth / 2;
  let acc = 0;
  const segments: ReactNode[] = [];
  for (const id of STACK_ORDER) {
    const value = day[id] || 0;
    if (!value) continue;
    const top = scale.y(acc + value);
    const height = Math.max(1, (value / scale.max) * (CHART_H - CHART_PAD * 2));
    segments.push(
      <rect key={id} x={left.toFixed(1)} y={top.toFixed(1)} width={scale.barWidth.toFixed(1)} height={height.toFixed(1)} fill={DECISION_META[id].tone} rx="1">
        <title>{`${day.date} · ${DECISION_META[id].label}: ${value}`}</title>
      </rect>,
    );
    acc += value;
  }
  return <>{segments}</>;
}

function SeriesChart({ series }: { series: SeriesDay[] }) {
  const scale = seriesScale(series);
  const ticks = [0, Math.round(scale.max / 2), scale.max];
  return (
    <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="AI activity over time">
      {ticks.map((value, i) => (
        <text key={i} x="4" y={(scale.y(value) + 3).toFixed(1)} className="insights-axis">
          {value}
        </text>
      ))}
      {series.map((day, i) => (
        <DayColumn key={day.date} day={day} index={i} scale={scale} />
      ))}
      {series.length ? (
        <text x={CHART_PAD} y={CHART_H - 6} className="insights-axis">
          {series[0].date.slice(5)}
        </text>
      ) : null}
      {series.length ? (
        <text x={CHART_W - CHART_PAD} y={CHART_H - 6} textAnchor="end" className="insights-axis">
          {series[series.length - 1].date.slice(5)}
        </text>
      ) : null}
    </svg>
  );
}

/** Legacy shows all six decision swatches here regardless of count. */
function SeriesLegend({ decisions }: { decisions: DecisionCount[] }) {
  return (
    <div className="insights-legend">
      {decisions.map((d) => {
        const meta = decisionMeta(d.id);
        if (!meta) return null;
        return (
          <span key={d.id} className="insights-swatch">
            <i style={{ background: meta.tone }} />
            {meta.label}
          </span>
        );
      })}
    </div>
  );
}

// ---- Decision-mix donut ----

const DONUT_R = 64;

function donutArcs(decisions: DecisionCount[], total: number): ReactNode[] {
  const circumference = 2 * Math.PI * DONUT_R;
  let offset = 0;
  return decisions
    .filter((d) => d.count > 0)
    .map((d) => {
      const meta = decisionMeta(d.id);
      const frac = d.count / total;
      const dashOffset = (-offset * circumference).toFixed(2);
      offset += frac;
      if (!meta) return null;
      return (
        <circle key={d.id} cx={90} cy={90} r={DONUT_R} fill="none" stroke={meta.tone} strokeWidth={20} transform="rotate(-90 90 90)"
          strokeDasharray={`${(frac * circumference).toFixed(2)} ${(circumference - frac * circumference).toFixed(2)}`} strokeDashoffset={dashOffset}>
          <title>{`${meta.label}: ${d.count}`}</title>
        </circle>
      );
    });
}

function DonutLegend({ decisions }: { decisions: DecisionCount[] }) {
  return (
    <div className="insights-legend">
      {decisions
        .filter((d) => d.count > 0)
        .map((d) => {
          const meta = decisionMeta(d.id);
          if (!meta) return null;
          return (
            <span key={d.id} className="insights-swatch">
              <i style={{ background: meta.tone }} />
              {meta.label} <b>{d.count}</b>
            </span>
          );
        })}
    </div>
  );
}

function DecisionDonut({ decisions }: { decisions: DecisionCount[] }) {
  const total = decisions.reduce((sum, d) => sum + d.count, 0);
  if (!total) return <div className="insights-empty">No activity in this window.</div>;
  return (
    <>
      <svg viewBox="0 0 180 180" className="insights-donut" role="img" aria-label="Decision mix">
        {donutArcs(decisions, total)}
        <text x={90} y={88} textAnchor="middle" className="insights-donut-total">
          {total}
        </text>
        <text x={90} y={106} textAnchor="middle" className="insights-donut-sub">
          events
        </text>
      </svg>
      <DonutLegend decisions={decisions} />
    </>
  );
}

// ---- Risk bands + top-N horizontal bars ----

function RiskBands({ bands }: { bands: RiskBand[] }) {
  const max = Math.max(1, ...bands.map((b) => b.count));
  return (
    <div className="insights-riskbars">
      {bands.map((band) => (
        <div key={band.id} className="insights-riskbar">
          <span className="insights-riskbar-label">{band.label}</span>
          <span className="insights-riskbar-track">
            <span className="insights-riskbar-fill" style={{ width: `${Math.round((band.count / max) * 100)}%`, background: RISK_TONE[band.id] }} />
          </span>
          <span className="insights-riskbar-count">{band.count}</span>
        </div>
      ))}
    </div>
  );
}

function TopBars({ items }: { items: TopEntry[] }) {
  if (!items.length) return <div className="insights-empty">None recorded.</div>;
  const max = Math.max(1, ...items.map((item) => item.count));
  return (
    <>
      {items.map((item) => (
        <div key={item.key} className="insights-hbar">
          <span className="insights-hbar-label" title={item.key}>
            {item.key}
          </span>
          <span className="insights-hbar-track">
            <span className="insights-hbar-fill" style={{ width: `${Math.round((item.count / max) * 100)}%` }} />
          </span>
          <span className="insights-hbar-count">{item.count}</span>
        </div>
      ))}
    </>
  );
}

// ---- Destination + user tables ----

function riskChipTone(tier: number): string {
  if (tier >= 4) return 'tone-critical';
  if (tier === 3) return 'tone-high';
  if (tier === 2) return 'tone-medium';
  return 'tone-low';
}

function RiskChip({ risk }: { risk: DestinationRisk | null }) {
  if (!risk) return <span className="insights-chip tone-neutral">Unrated</span>;
  return <span className={`insights-chip ${riskChipTone(risk.riskTier)}`}>{risk.riskTierLabel || 'unknown'}</span>;
}

function FlagAttrs({ risk }: { risk: DestinationRisk | null }) {
  if (!risk) return <span className="insights-attr-muted">—</span>;
  return (
    <>
      {risk.flags.map((flag) => (
        <span key={flag} className="insights-attr">
          {FLAG_LABELS[flag] || flag}
        </span>
      ))}
    </>
  );
}

function DestinationsTable({ rows }: { rows: TopDestination[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Destination</th>
          <th>Provider</th>
          <th>Risk</th>
          <th>Attributes</th>
          <th>Events</th>
        </tr>
      </thead>
      <tbody>
        {rows.length ? (
          rows.map((row) => (
            <tr key={row.destination}>
              <td>{row.destination}</td>
              <td>{row.risk ? row.risk.provider : '—'}</td>
              <td><RiskChip risk={row.risk} /></td>
              <td><FlagAttrs risk={row.risk} /></td>
              <td>{row.count}</td>
            </tr>
          ))
        ) : (
          <tr>
            <td colSpan={5} className="insights-empty">No destinations recorded.</td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

function UsersTable({ rows }: { rows: TopUser[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Events</th>
          <th>Blocked</th>
          <th>Avg risk</th>
        </tr>
      </thead>
      <tbody>
        {rows.length ? (
          rows.map((row) => (
            <tr key={row.user}>
              <td>{row.user}</td>
              <td>{row.events}</td>
              <td>{row.blocked}</td>
              <td>{row.avgRisk}</td>
            </tr>
          ))
        ) : (
          <tr>
            <td colSpan={4} className="insights-empty">No user activity recorded.</td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

// ---- Panel grid (legacy .panel markup — fully styled by console-base.css) ----

interface InsightPanelProps {
  title: string;
  subtitle: string;
  wide?: boolean;
  children: ReactNode;
}

function InsightPanel({ title, subtitle, wide, children }: InsightPanelProps) {
  return (
    <div className={wide ? 'panel wide-panel' : 'panel'}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          <span>{subtitle}</span>
        </div>
      </div>
      {children}
    </div>
  );
}

function ChartsRow({ report }: { report: InsightsReport }) {
  return (
    <>
      <InsightPanel wide title="AI Activity Over Time" subtitle="Decisions per day across the window">
        <div className="insights-chart">
          <SeriesChart series={report.series} />
        </div>
        <SeriesLegend decisions={report.decisions} />
      </InsightPanel>
      <InsightPanel title="Decision Mix" subtitle="How prompts were resolved">
        <div className="insights-chart">
          <DecisionDonut decisions={report.decisions} />
        </div>
      </InsightPanel>
      <InsightPanel title="Data Exposure Risk" subtitle="Risk-score distribution">
        <div className="insights-chart">
          <RiskBands bands={report.riskBands} />
        </div>
      </InsightPanel>
    </>
  );
}

function BreakdownRow({ report }: { report: InsightsReport }) {
  return (
    <>
      <InsightPanel title="Top Detected Data Types" subtitle="Structured findings by type">
        <div className="insights-bars">
          <TopBars items={report.topDetectors} />
        </div>
      </InsightPanel>
      <InsightPanel title="Sensitive Categories" subtitle="Semantic and intent classes">
        <div className="insights-bars">
          <TopBars items={report.topCategories} />
        </div>
      </InsightPanel>
      <InsightPanel wide title="Top Destinations" subtitle="Where AI traffic goes, with app-risk attributes">
        <DestinationsTable rows={report.topDestinations} />
      </InsightPanel>
      <InsightPanel title="Shadow AI by Provider" subtitle="Ungoverned AI usage discovered">
        <div className="insights-bars">
          <TopBars items={report.shadowByProvider} />
        </div>
      </InsightPanel>
      <InsightPanel title="Highest-Risk Users" subtitle="By average risk × volume">
        <UsersTable rows={report.topUsers} />
      </InsightPanel>
    </>
  );
}

export default function Insights() {
  const { windowDays, setWindowDays, report, loaded, busy, load } = useInsights();

  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Aggregating insights…</div>;
    if (!report) return <EmptyState title="Insights unavailable" detail="Could not load insights. Refresh to retry." />;
    return (
      <>
        <KpiRow report={report} />
        <div className="insights-grid">
          <ChartsRow report={report} />
          <BreakdownRow report={report} />
        </div>
      </>
    );
  };

  return (
    <div className="insights-view">
      <InsightsHeader
        windowDays={windowDays}
        busy={busy}
        onWindow={setWindowDays}
        onRefresh={load}
        onExportSeries={() => exportSeriesCsv(report)}
        onExportExec={() => exportExecCsv(report)}
      />
      {renderBody()}
    </div>
  );
}
