import { useCallback, useEffect, useMemo, useState } from 'react';
import { EmptyState } from '../components/Panel';
import { apiJson } from '../lib/api';
import { downloadCsv, csvStamp } from '../lib/csv';
import { navigate } from '../lib/router';
import { toast } from '../lib/toast';
import './Compliance.css';

/**
 * Compliance Posture: AI-governance framework coverage mapped to live
 * RedactWall evidence. Read-only. Route contract from server/app.js:
 *   GET /api/compliance -> { controlMappings: ControlMapping[] } — 8 static
 *     control mappings (server/control-map.js) evaluated against the active
 *     policy, detector inventory, audit-chain verification, and coverage.
 *     Any console role can read it; no query params, no CSRF (GET).
 *   GET /api/export/evidence — opened in a new tab only (Security Admin or
 *     Auditor; other roles get a JSON 403 in that tab, as legacy did). The
 *     response is never parsed here.
 * No SSE (legacy reloads only on tab activation/Refresh), no mutations, no
 * step-up. CSV export is client-side over the last loaded controls —
 * server-vetted metadata only, no prompt content.
 */

type ControlState = 'covered' | 'attention' | 'not_provided';

interface ControlMapping {
  id: string;
  title: string;
  state: ControlState;
  controlFamilies: string[];
  evidence: string[];
  summary: string;
  lastVerifiedAt: string | null;
}

interface ComplianceResponse {
  controlMappings: ControlMapping[];
}

async function fetchCompliance(): Promise<ControlMapping[] | null> {
  const body = await apiJson<ComplianceResponse>('/api/compliance');
  return body && Array.isArray(body.controlMappings) ? body.controlMappings : null;
}

// ---- Constants (ported verbatim from dashboard.js renderCompliance) ----

const STATE_TONE: Record<ControlState, string> = {
  covered: 'tone-low',
  attention: 'tone-high',
  not_provided: 'tone-neutral',
};

const FRAMEWORKS: Array<{ key: string; match: RegExp }> = [
  { key: 'NIST AI RMF', match: /NIST AI RMF/i },
  { key: 'ISO/IEC 42001', match: /ISO\/IEC 42001|ISO 42001/i },
  { key: 'EU AI Act', match: /EU AI Act/i },
  { key: 'OWASP LLM Top 10', match: /OWASP LLM/i },
  { key: 'MITRE ATLAS', match: /MITRE ATLAS/i },
  { key: 'GLBA / NCUA', match: /GLBA|NCUA/i },
  { key: 'HIPAA', match: /HIPAA/i },
  { key: 'PCI DSS', match: /PCI/i },
];

// ---- CSV export (from the last loaded controls; framework labels and summaries only) ----

function exportControlsCsv(controls: ControlMapping[] | null): void {
  if (!controls?.length) {
    toast('No compliance data loaded yet.', 'error');
    return;
  }
  const lines: Array<Array<string | number>> = [
    ['Control', 'State', 'Frameworks', 'Summary'],
    ...controls.map((c) => [c.title, c.state, (c.controlFamilies || []).join('; '), c.summary || '']),
  ];
  downloadCsv(`redactwall-controls-${csvStamp()}.csv`, lines);
}

// ---- Loader hook (no SSE: legacy refreshes only on activation and the Refresh button) ----

function useComplianceControls() {
  const [controls, setControls] = useState<ControlMapping[] | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      setControls(await fetchCompliance());
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { controls, loaded, busy, load };
}

// ---- Header ----

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ComplianceHeader({ busy, onRefresh }: { busy: boolean; onRefresh: () => void }) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>Compliance Posture</h2>
          <p>
            AI-governance framework coverage — NIST AI RMF, ISO/IEC 42001, EU AI Act, OWASP LLM Top 10, MITRE ATLAS —
            plus the financial/health control families, mapped to live RedactWall evidence. Prompt-free.
          </p>
        </div>
      </div>
      <div className="console-frame-actions">
        <a className="system-button secondary" href="/api/export/evidence" target="_blank" rel="noopener">
          Export evidence pack
        </a>
        <button className="system-button secondary" type="button" disabled={busy} onClick={onRefresh}>
          <RefreshIcon />
          {busy ? 'Mapping…' : 'Refresh'}
        </button>
      </div>
    </div>
  );
}

// ---- KPI strip ----

function Kpi({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiRow({ controls }: { controls: ControlMapping[] }) {
  const covered = controls.filter((c) => c.state === 'covered').length;
  const attention = controls.filter((c) => c.state === 'attention').length;
  const pct = controls.length ? Math.round((covered / controls.length) * 100) : 0;
  return (
    <div className="insights-kpis">
      <Kpi label="Controls covered" value={`${covered}/${controls.length}`} hint={`${pct}% coverage`} />
      <Kpi label="Needs attention" value={String(attention)} hint="action required" />
      <Kpi label="AI frameworks" value="5" hint="NIST/ISO 42001/EU AI Act/OWASP/ATLAS" />
      <Kpi label="Evidence" value="prompt-free" hint="hashes & metadata only" />
    </div>
  );
}

// ---- Recommended next steps (open = anything not covered, incl. not_provided; max 4) ----

function RecommendationCard({ control }: { control: ControlMapping }) {
  return (
    <button
      className="stat alert"
      type="button"
      title="Open Configuration to close this gap"
      onClick={() => navigate('/policy')}
    >
      <div className="l">
        <span className="status-light tone-warn" aria-hidden="true" />
        Recommended
      </div>
      <div className="n" style={{ fontSize: '15px' }}>{control.title}</div>
      <div className="m">{(control.summary || '').slice(0, 90)}</div>
      <div className="stat-rule" />
    </button>
  );
}

function RecommendationsPanel({ controls, onExportCsv }: { controls: ControlMapping[]; onExportCsv: () => void }) {
  const open = controls.filter((c) => c.state !== 'covered').slice(0, 4);
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Recommended next steps</h2>
          <span>Controls needing attention - each card opens Configuration</span>
        </div>
        <button className="ghost mini" type="button" onClick={onExportCsv}>
          Export controls CSV
        </button>
      </div>
      <div className="stats" style={{ padding: '14px 16px' }}>
        {open.length ? (
          open.map((control) => <RecommendationCard key={control.id} control={control} />)
        ) : (
          <div className="empty">All mapped controls are covered - nothing to recommend right now.</div>
        )}
      </div>
    </div>
  );
}

// ---- Framework roll-up (frameworks with zero matching controls are skipped) ----

interface FrameworkRollup {
  key: string;
  covered: number;
  total: number;
  pct: number;
}

function rollupFrameworks(controls: ControlMapping[]): FrameworkRollup[] {
  return FRAMEWORKS.flatMap((fw) => {
    const rel = controls.filter((c) => (c.controlFamilies || []).some((family) => fw.match.test(family)));
    if (!rel.length) return [];
    const covered = rel.filter((c) => c.state === 'covered').length;
    return [{ key: fw.key, covered, total: rel.length, pct: Math.round((covered / rel.length) * 100) }];
  });
}

function frameworkTone(pct: number): string {
  return pct >= 100 ? 'tone-low' : pct >= 50 ? 'tone-medium' : 'tone-high';
}

function FrameworkRow({ fw }: { fw: FrameworkRollup }) {
  return (
    <div className="compliance-fw">
      <div className="compliance-fw-head">
        <span>{fw.key}</span>
        <span className={`insights-chip ${frameworkTone(fw.pct)}`}>
          {fw.covered}/{fw.total}
        </span>
      </div>
      <span className="insights-riskbar-track">
        <span className="insights-riskbar-fill" style={{ width: `${fw.pct}%`, background: 'var(--blue)' }} />
      </span>
    </div>
  );
}

function FrameworksPanel({ controls }: { controls: ControlMapping[] }) {
  const rollups = useMemo(() => rollupFrameworks(controls), [controls]);
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>AI-governance frameworks</h2>
          <span>Coverage across the frameworks incumbents do not map in-console</span>
        </div>
      </div>
      <div className="compliance-frameworks">
        {rollups.map((fw) => (
          <FrameworkRow key={fw.key} fw={fw} />
        ))}
      </div>
    </div>
  );
}

// ---- Control cards (one panel per mapping, server order) ----

function ControlCard({ control }: { control: ControlMapping }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>{control.title}</h2>
          <span>{(control.evidence || []).slice(0, 3).join(', ')}</span>
        </div>
        <span className={`insights-chip ${STATE_TONE[control.state] || 'tone-neutral'}`}>
          {control.state.replace('_', ' ')}
        </span>
      </div>
      <div className="compliance-body">
        <p className="compliance-summary">{control.summary || ''}</p>
        <div className="compliance-families">
          {(control.controlFamilies || []).map((family) => (
            <span key={family} className="insights-attr">
              {family}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Compliance() {
  const { controls, loaded, busy, load } = useComplianceControls();

  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Mapping compliance controls…</div>;
    if (!controls) {
      return <EmptyState title="Compliance mapping unavailable" detail="Could not load control mappings. Refresh to retry." />;
    }
    return (
      <>
        <KpiRow controls={controls} />
        <RecommendationsPanel controls={controls} onExportCsv={() => exportControlsCsv(controls)} />
        <FrameworksPanel controls={controls} />
        <div className="insights-grid">
          {controls.map((control) => (
            <ControlCard key={control.id} control={control} />
          ))}
        </div>
      </>
    );
  };

  return (
    <div className="compliance-view">
      <ComplianceHeader busy={busy} onRefresh={load} />
      {renderBody()}
    </div>
  );
}
