import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  canReadAuditExports,
  downloadTrustPackage,
  type TrustPackageDownloadResult,
  type TrustPackageFormat,
} from '../api/evidence';
import { EmptyState } from '../components/Panel';
import { apiJsonBounded } from '../lib/api';
import { downloadCsv, csvStamp } from '../lib/csv';
import { navigate } from '../lib/router';
import { useSession } from '../lib/session';
import { toast } from '../lib/toast';
import './Compliance.css';

/**
 * Compliance Posture: AI-governance framework coverage mapped to live
 * RedactWall evidence. Read-only. Route contract from server/app.js:
 *   GET /api/compliance -> { disclaimer, controlMappings: ControlMapping[] } — the
 *     "evidence pointers, not certification" disclaimer plus the static
 *     control mappings (server/control-map.js CONTROL_MAPPINGS, incl. the
 *     credit-union families) evaluated against the active policy, detector
 *     inventory, audit-chain verification, coverage, and EDM status.
 *     Any console role can read it; no query params, no CSRF (GET).
 *   GET /api/export/evidence is exposed only to Security Admin and Auditor
 *     sessions. Other roles receive a truthful disabled permission state.
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

interface ComplianceData {
  controls: ControlMapping[];
  disclaimer: string;
}

const CONTROL_STATES = new Set<ControlState>(['covered', 'attention', 'not_provided']);
const CONTROL_MAPPINGS_MAX = 100;
const CONTROL_LIST_MAX = 16;
const COMPLIANCE_RESPONSE_MAX_BYTES = 512 * 1024;

function boundedText(value: unknown, max: number): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= max ? value : null;
}

function boundedTextList(value: unknown, maxChars: number): string[] | null {
  if (!Array.isArray(value) || !value.length || value.length > CONTROL_LIST_MAX) return null;
  const items = value.map((item) => boundedText(item, maxChars));
  return items.every((item): item is string => item !== null) ? items : null;
}

function decodeControlMapping(value: unknown): ControlMapping | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const id = boundedText(row.id, 80);
  const title = boundedText(row.title, 180);
  const summary = boundedText(row.summary, 1_200);
  const controlFamilies = boundedTextList(row.controlFamilies, 220);
  const evidence = boundedTextList(row.evidence, 220);
  const state = typeof row.state === 'string' && CONTROL_STATES.has(row.state as ControlState)
    ? row.state as ControlState
    : null;
  if (!id || !/^[a-z0-9_/-]+$/.test(id) || !title || !summary || !state || !controlFamilies || !evidence) return null;
  const lastVerifiedAt = row.lastVerifiedAt === null ? null : boundedText(row.lastVerifiedAt, 40);
  if (row.lastVerifiedAt !== null && lastVerifiedAt === null) return null;
  if (lastVerifiedAt !== null && !Number.isFinite(Date.parse(lastVerifiedAt))) return null;
  return { id, title, state, controlFamilies, evidence, summary, lastVerifiedAt };
}

function decodeComplianceResponse(value: unknown): ComplianceData | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (!Array.isArray(body.controlMappings) || body.controlMappings.length > CONTROL_MAPPINGS_MAX) return null;
  const controls = body.controlMappings.map(decodeControlMapping);
  if (!controls.every((control): control is ControlMapping => control !== null)) return null;
  if (new Set(controls.map((control) => control.id)).size !== controls.length) return null;
  const disclaimer = body.disclaimer === undefined ? '' : boundedText(body.disclaimer, 1_200);
  return disclaimer === null ? null : { controls, disclaimer };
}

async function fetchCompliance(): Promise<ComplianceData | null> {
  return decodeComplianceResponse(await apiJsonBounded<unknown>('/api/compliance', COMPLIANCE_RESPONSE_MAX_BYTES));
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
  { key: 'FFIEC', match: /FFIEC/i },
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
  const [disclaimer, setDisclaimer] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      const data = await fetchCompliance();
      setControls(data ? data.controls : null);
      setDisclaimer(data ? data.disclaimer : '');
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { controls, disclaimer, loaded, busy, load };
}

// ---- Header ----

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ComplianceHeader({ busy, canExport, sessionLoading, onRefresh }: {
  busy: boolean;
  canExport: boolean;
  sessionLoading: boolean;
  onRefresh: () => void;
}) {
  const exportPermission = sessionLoading
    ? 'Checking evidence export permission…'
    : 'Global Administrator or Examiner/Auditor access is required to export evidence.';
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>NCUA / GLBA Controls</h2>
          <p>
            Texas Federal Credit Union control coverage for NCUA Part 748, GLBA safeguards, board oversight, incident
            readiness, and AI-governance frameworks. Prompt-free evidence mapped from live RedactWall telemetry.
          </p>
        </div>
      </div>
      <div className="console-frame-actions">
        {canExport ? (
          <a className="system-button secondary" href="/api/export/evidence" target="_blank" rel="noopener">
            Export evidence pack
          </a>
        ) : (
          <button
            className="system-button secondary"
            type="button"
            disabled
            aria-describedby="complianceExportPermission"
          >
            Export evidence pack
          </button>
        )}
        <button className="system-button secondary" type="button" disabled={busy} onClick={onRefresh}>
          <RefreshIcon />
          {busy ? 'Mapping…' : 'Refresh'}
        </button>
        {!canExport ? (
          <span className="compliance-export-permission" id="complianceExportPermission" role="note">
            {exportPermission}
          </span>
        ) : null}
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
      <Kpi label="FCU controls covered" value={`${covered}/${controls.length}`} hint={`${pct}% coverage`} />
      <Kpi label="Needs examiner prep" value={String(attention)} hint="action required" />
      <Kpi label="AI frameworks" value="5" hint="NIST/ISO 42001/EU AI Act/OWASP/ATLAS" />
      <Kpi label="Evidence" value="prompt-free" hint="hashes & metadata only" />
    </div>
  );
}

type TrustDownloadState = {
  kind: 'idle' | 'loading' | TrustPackageDownloadResult['kind'];
  message: string;
};

function trustDownloadMessage(result: TrustPackageDownloadResult, format: TrustPackageFormat): TrustDownloadState {
  const label = format.toUpperCase();
  if (result.kind === 'downloaded') return { kind: result.kind, message: `${label} security trust package download started.` };
  if (result.kind === 'forbidden') {
    return { kind: result.kind, message: 'This session is not permitted to download the security trust package.' };
  }
  if (result.kind === 'session') return { kind: result.kind, message: 'Your session expired. Redirecting to sign in…' };
  if (result.kind === 'oversize') {
    return { kind: result.kind, message: 'The security trust package exceeded the safe download limit and was not saved.' };
  }
  if (result.kind === 'malformed') {
    return { kind: result.kind, message: 'The security trust package response was malformed and was not saved.' };
  }
  return { kind: result.kind, message: 'The security trust package is unavailable. Retry when the control plane is ready.' };
}

function TrustPackagePanel({ canExport, sessionLoading }: { canExport: boolean; sessionLoading: boolean }) {
  const [activeFormat, setActiveFormat] = useState<TrustPackageFormat | null>(null);
  const [downloadState, setDownloadState] = useState<TrustDownloadState>({
    kind: 'idle',
    message: 'Choose JSON for review or ZIP for a complete handoff bundle.',
  });
  const permission = sessionLoading
    ? 'Checking export permission…'
    : 'Global Administrator or Examiner/Auditor access is required to export this package.';
  const runDownload = async (format: TrustPackageFormat) => {
    if (!canExport || activeFormat) return;
    setActiveFormat(format);
    setDownloadState({ kind: 'loading', message: `Preparing the ${format.toUpperCase()} security trust package…` });
    try {
      setDownloadState(trustDownloadMessage(await downloadTrustPackage(format), format));
    } finally {
      setActiveFormat(null);
    }
  };
  return (
    <section className="compliance-trust-package" aria-labelledby="trustPackageTitle" aria-busy={Boolean(activeFormat)}>
      <div>
        <span className="compliance-eyebrow">Vendor risk and examiner handoff</span>
        <h2 id="trustPackageTitle">Security Trust Package</h2>
        <p>
          Export the current self-attested control posture, validation commands, documentation pointers,
          and bounded dependency inventory. Prompt bodies, secrets, raw findings, and raw audit details are excluded.
        </p>
      </div>
      <div className="compliance-trust-actions">
        {canExport ? (
          <>
            <button
              className="system-button secondary"
              type="button"
              data-testid="trust-package-json"
              disabled={Boolean(activeFormat)}
              aria-describedby="trustPackageDownloadStatus"
              onClick={() => void runDownload('json')}
            >
              {activeFormat === 'json' ? 'Preparing JSON…' : 'Download JSON'}
            </button>
            <button
              className="system-button primary"
              type="button"
              data-testid="trust-package-zip"
              disabled={Boolean(activeFormat)}
              aria-describedby="trustPackageDownloadStatus"
              onClick={() => void runDownload('zip')}
            >
              {activeFormat === 'zip' ? 'Preparing ZIP…' : 'Download ZIP'}
            </button>
          </>
        ) : (
          <>
            <button className="system-button secondary" type="button" disabled aria-describedby="trustPackagePermission">Download JSON</button>
            <button className="system-button primary" type="button" disabled aria-describedby="trustPackagePermission">Download ZIP</button>
          </>
        )}
        {!canExport ? <span id="trustPackagePermission" role="note">{permission}</span> : null}
        {canExport ? (
          <span
            className={`compliance-download-status is-${downloadState.kind}`}
            id="trustPackageDownloadStatus"
            role="status"
            aria-live="polite"
          >
            {downloadState.message}
          </span>
        ) : null}
      </div>
    </section>
  );
}

// ---- Recommended next steps (open = anything not covered, incl. not_provided; max 4) ----

function RecommendationCard({ control }: { control: ControlMapping }) {
  return (
    <button
      className="stat alert"
      type="button"
      title="Open Policy Configuration to close this gap"
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
          <span>Controls needing attention before an exam - each card opens Policy Configuration</span>
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
          <h2>AI governance frameworks</h2>
          <span>Secondary framework coverage for Texas FCU AI oversight</span>
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

function ComplianceDisclaimer({ text }: { text: string }) {
  if (!text) return null;
  return (
    <p
      className="compliance-disclaimer"
      role="note"
      style={{
        margin: '0 0 12px',
        padding: '10px 14px',
        fontSize: '13px',
        lineHeight: 1.5,
        color: 'var(--muted, #5b6472)',
        border: '1px solid var(--border, #d9dee6)',
        borderRadius: '8px',
        background: 'var(--surface-2, #f6f8fb)',
      }}
    >
      {text}
    </p>
  );
}

export default function Compliance() {
  const { me, loading: sessionLoading } = useSession();
  const { controls, disclaimer, loaded, busy, load } = useComplianceControls();
  const canExport = canReadAuditExports(me?.role);

  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Mapping compliance controls…</div>;
    if (!controls) {
      return <EmptyState title="FCU control mapping unavailable" detail="Could not load control mappings. Refresh to retry." />;
    }
    if (!controls.length) {
      return (
        <>
          <ComplianceDisclaimer text={disclaimer} />
          <TrustPackagePanel canExport={canExport} sessionLoading={sessionLoading} />
          <EmptyState
            title="No control mappings reported"
            detail="The control-plane response was valid but contained no control mappings. No coverage conclusion can be drawn."
          />
        </>
      );
    }
    return (
      <>
        <ComplianceDisclaimer text={disclaimer} />
        <KpiRow controls={controls} />
        <TrustPackagePanel canExport={canExport} sessionLoading={sessionLoading} />
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
      <ComplianceHeader busy={busy} canExport={canExport} sessionLoading={sessionLoading} onRefresh={load} />
      {renderBody()}
    </div>
  );
}
