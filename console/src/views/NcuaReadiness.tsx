import { useCallback, useEffect, useState } from 'react';
import UseCasesPanel from '../components/ncua/UseCasesPanel';
import { EmptyState } from '../components/Panel';
import { apiJson } from '../lib/api';
import { navigate } from '../lib/router';
import './NcuaReadiness.css';

/**
 * NCUA Readiness: examiner-readiness report for federal credit unions
 * (PLANS/ncua-readiness-center.md, slice 1). Read-only. Route contract from
 * server/app.js:
 *   GET /api/ncua/readiness -> { entitled: boolean, report } — prompt-free
 *     composition of control mappings, member-data outcomes, shadow-AI
 *     rollups, EDM status, exception review, and audit-chain verification
 *     (server/ncua-readiness.js). Any console role can read it; no query
 *     params, no CSRF (GET). `entitled` reflects license.entitled(); when a
 *     licensed install lacks the ncua_readiness add-on the server withholds
 *     the report (report: null) and this view renders only the upsell state.
 *     Demo mode (unlicensed) is always entitled, so demos stay fully visible.
 *   GET /api/export/evidence?examinerProfile=federal_credit_union — opened in
 *     a new tab only (Security Admin or Auditor; other roles get a JSON 403
 *     in that tab). Never parsed here.
 * No SSE (refresh on demand), no mutations, no step-up. Never renders prompt
 * content — counts, enums, and bounded labels only.
 */

type ControlState = 'covered' | 'attention' | 'not_provided';

interface NcuaControl {
  id: string;
  title: string;
  state: ControlState;
  controlFamilies: string[];
  summary: string;
}

interface NcuaAction {
  id: string;
  label: string;
  detail: string;
  targetTab: string;
  priority: number;
}

interface NcuaReport {
  profile: string;
  generatedAt: string;
  score: number;
  state: 'ready' | 'attention' | 'blocked';
  controls: NcuaControl[];
  panels: {
    memberData: { identifiers: string[]; events: number; prevented: number; redacted: number; released: number };
    shadowAi: { totalApps: number; sanctioned: number; underReview: number; tolerated: number; unsanctioned: number; blocked: number; unreviewedEvents: number };
    edm: { configured: boolean; enabled: boolean; active: boolean; fingerprints: number; minLength?: number; severity?: number };
    useCases: { total: number; approved: number; underReview: number; restricted: number; retired: number; overdue: number; activeTotal: number; vendorReviewed: number; vendorPending: number; vendorNotReviewed: number } | null;
    exceptions: { total: number; active: number; expiringSoon: number; reviewDue: number; expired: number; disabled: number } | null;
    exportHealth: { scheduled: boolean; cadence?: string | null; nextRunAt?: string | null; retentionDays?: number | null };
    audit: { verified: boolean; count: number };
  };
  nextActions: NcuaAction[];
}

interface NcuaResponse {
  entitled: boolean;
  report: NcuaReport;
}

const EXAMINER_PACK_HREF = '/api/export/evidence?examinerProfile=federal_credit_union';

const STATE_TONE: Record<string, string> = {
  covered: 'tone-low',
  ready: 'tone-low',
  attention: 'tone-high',
  blocked: 'tone-high',
  not_provided: 'tone-neutral',
};

function useNcuaReadiness() {
  const [data, setData] = useState<NcuaResponse | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      setData(await apiJson<NcuaResponse>('/api/ncua/readiness'));
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { data, loaded, busy, load };
}

function Header({ busy, onRefresh }: { busy: boolean; onRefresh: () => void }) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>NCUA Readiness</h2>
          <p>
            Examiner readiness for federal credit unions — NCUA Part 748 / GLBA control coverage, member-data
            outcomes, core-banking EDM, and shadow-AI review, from live prompt-free evidence.
          </p>
        </div>
      </div>
      <div className="console-frame-actions">
        <a className="system-button secondary" href={EXAMINER_PACK_HREF} target="_blank" rel="noopener">
          Export examiner pack
        </a>
        <button className="system-button secondary" type="button" disabled={busy} onClick={onRefresh}>
          {busy ? 'Scoring…' : 'Refresh'}
        </button>
      </div>
    </div>
  );
}

function Kpi({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiRow({ report }: { report: NcuaReport }) {
  const { memberData, shadowAi, edm } = report.panels;
  return (
    <div className="insights-kpis">
      <Kpi label="Readiness score" value={`${report.score}/100`} hint={report.state.replace('_', ' ')} />
      <Kpi label="Member-data events prevented" value={`${memberData.prevented}/${memberData.events}`} hint={`${memberData.redacted} redacted, ${memberData.released} released after review`} />
      <Kpi label="Unreviewed AI apps" value={String(shadowAi.unsanctioned + shadowAi.underReview)} hint={`${shadowAi.unreviewedEvents} sightings pending review`} />
      <Kpi
        label="EDM fingerprints"
        value={edm.configured ? String(edm.fingerprints) : 'not set up'}
        hint={edm.active ? 'core-banking watchlist active' : edm.configured ? 'watchlist loaded but DISABLED' : 'member records unfingerprinted'}
      />
    </div>
  );
}

function ControlRow({ control }: { control: NcuaControl }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>{control.title}</h2>
          <span>{(control.controlFamilies || []).slice(0, 2).join(' · ')}</span>
        </div>
        <span className={`insights-chip ${STATE_TONE[control.state] || 'tone-neutral'}`}>
          {control.state.replace('_', ' ')}
        </span>
      </div>
      <div style={{ padding: '0 16px 14px' }}>
        <p style={{ margin: 0 }}>{control.summary}</p>
      </div>
    </div>
  );
}

function EdmPanel({ edm }: { edm: NcuaReport['panels']['edm'] }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>Core-banking EDM</h2>
          <span>Salted fingerprints of member records — plaintext is discarded</span>
        </div>
        <span className={`insights-chip ${edm.active ? 'tone-low' : 'tone-high'}`}>
          {edm.active ? 'active' : edm.configured ? 'disabled' : 'setup needed'}
        </span>
      </div>
      <div style={{ padding: '0 16px 14px' }}>
        {edm.active ? (
          <p style={{ margin: 0 }}>
            {edm.fingerprints} salted fingerprint(s) loaded; exact matches of member identifiers hard-stop on every
            sensor. The salt and fingerprints never appear in exports.
          </p>
        ) : edm.configured ? (
          <p style={{ margin: 0 }}>
            {edm.fingerprints} fingerprint(s) are loaded but the watchlist is <b>disabled</b> — exact-match detection
            is not running. Re-enable it in <code>config/exact-match.json</code> (<code>"enabled": true</code>).
          </p>
        ) : (
          <p style={{ margin: 0 }}>
            Export member IDs, account numbers, and loan numbers from the core system, then run{' '}
            <code>npm run edm:fingerprint -- --in members.txt</code> on the control plane. Only salted one-way
            fingerprints are stored; the plaintext list is discarded.
          </p>
        )}
      </div>
    </div>
  );
}

function CountsPanel({ title, hint, rows, linkLabel, linkPath }: {
  title: string;
  hint: string;
  rows: Array<[string, string | number]>;
  linkLabel: string;
  linkPath: string;
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          <span>{hint}</span>
        </div>
        <button className="ghost mini" type="button" onClick={() => navigate(linkPath)}>
          {linkLabel}
        </button>
      </div>
      <div style={{ padding: '0 16px 14px', display: 'grid', gap: '4px' }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>{label}</span>
            <b>{value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function NextActionsPanel({ actions }: { actions: NcuaAction[] }) {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Close the gaps</h2>
          <span>Controls needing attention before an exam — each opens the owning screen</span>
        </div>
      </div>
      <div className="stats" style={{ padding: '14px 16px' }}>
        {actions.length ? (
          actions.map((action) => (
            <button
              key={action.id}
              className="stat alert"
              type="button"
              onClick={() => navigate(action.targetTab === 'ncua' ? '/ncua' : `/${action.targetTab}`)}
            >
              <div className="l">
                <span className="status-light tone-warn" aria-hidden="true" />
                Priority {action.priority}
              </div>
              <div className="n" style={{ fontSize: '15px' }}>{action.label}</div>
              <div className="m">{action.detail.slice(0, 110)}</div>
              <div className="stat-rule" />
            </button>
          ))
        ) : (
          <div className="empty">Every provided control is covered — you are exam-ready on the mapped evidence.</div>
        )}
      </div>
    </div>
  );
}

function UpsellNotice() {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Not included in this license</h2>
          <span>
            The NCUA Readiness Center is licensed as an add-on (included with Enterprise). Evidence export and every
            security function keep working; ask your account contact for the `ncua_readiness` feature, then install
            the updated license under Integrations.
          </span>
        </div>
        <button className="ghost mini" type="button" onClick={() => navigate('/integrations')}>
          Open Integrations
        </button>
      </div>
    </div>
  );
}

export default function NcuaReadiness() {
  const { data, loaded, busy, load } = useNcuaReadiness();

  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Scoring NCUA readiness…</div>;
    if (data && !data.entitled) return <UpsellNotice />;
    if (!data?.report) {
      return <EmptyState title="Readiness report unavailable" detail="Could not load the NCUA readiness report. Refresh to retry." />;
    }
    const { report } = data;
    const { shadowAi, exceptions, exportHealth, audit } = report.panels;
    return (
      <>
        <KpiRow report={report} />
        <NextActionsPanel actions={report.nextActions} />
        <UseCasesPanel />
        <div className="insights-grid">
          <EdmPanel edm={report.panels.edm} />
          <CountsPanel
            title="Shadow AI"
            hint="AI destinations seen by the sensors, by review status"
            linkLabel="Review in Catalog"
            linkPath="/catalog"
            rows={[
              ['Sanctioned', shadowAi.sanctioned],
              ['Under review', shadowAi.underReview],
              ['Unsanctioned', shadowAi.unsanctioned],
              ['Blocked', shadowAi.blocked],
              ['Sightings pending review', shadowAi.unreviewedEvents],
            ]}
          />
          <CountsPanel
            title="Policy exceptions"
            hint="Exception review lifecycle (owner, reviewer, expiry)"
            linkLabel="Open Configuration"
            linkPath="/policy"
            rows={exceptions ? [
              ['Active', exceptions.active],
              ['Expiring soon', exceptions.expiringSoon],
              ['Review due', exceptions.reviewDue],
              ['Expired', exceptions.expired],
            ] : [['Exceptions defined', 0]]}
          />
          <CountsPanel
            title="Evidence health"
            hint="Audit chain and scheduled examiner-pack exports"
            linkLabel="Open Audit Log"
            linkPath="/audit"
            rows={[
              ['Audit chain', audit.verified ? `verified (${audit.count})` : 'FAILED'],
              ['Scheduled export', exportHealth.scheduled ? (exportHealth.cadence || 'enabled') : 'not scheduled'],
            ]}
          />
        </div>
        <div className="insights-grid">
          {report.controls.map((control) => (
            <ControlRow key={control.id} control={control} />
          ))}
        </div>
      </>
    );
  };

  return (
    <div className="ncua-view">
      <Header busy={busy} onRefresh={load} />
      {renderBody()}
    </div>
  );
}
