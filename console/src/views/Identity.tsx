import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { EmptyState } from '../components/Panel';
import { api, apiSend } from '../lib/api';
import './Identity.css';

/**
 * Identity: read-only SSO/SCIM onboarding helper (port of the legacy identity
 * tab). Route contract from server/app.js:
 *   GET /api/identity/setup-guide?provider=&tenantId= -> IdentitySetupGuide
 *     (any signed-in role, no CSRF). 400 -> { error } which renders in the
 *     summary area while the other panels keep their previous content. The
 *     guide contains env-var NAMES and placeholders only - never live secrets.
 *   POST /api/identity/test {} -> IdentityTestResult (Security Admin only,
 *     CSRF, no step-up). Config completeness only - no outbound calls; the
 *     server records an IDENTITY_CONFIG_TESTED audit entry.
 * No SSE: legacy reloads only on tab activation, Refresh, and control changes.
 * Provider/tenant selections are ephemeral component state - never persisted.
 */

interface IdentityScim {
  tenantUrl: string;
  baseUrl: string;
  authMode: string;
  tokenEnv: string;
  tokenAlias: string;
  uniqueIdentifier: string;
  contentType: string;
  supportedActions: string[];
  steps: string[];
}

interface IdentityOidc {
  applicationType: string;
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  redirectUri: string;
  scopes: string[];
  discovery: string;
  explicitEndpointVars: string[];
  steps: string[];
}

interface IdentityEnvRow {
  key: string;
  alias: string;
  value: string;
}

interface IdentityRoleGroup {
  role: string;
  groups: string[];
}

interface IdentitySetupGuide {
  provider: string;
  label: string;
  baseUrl: string;
  tenant: string;
  tenantLabel: string;
  scim?: IdentityScim;
  oidc?: IdentityOidc;
  env: IdentityEnvRow[];
  roleGroups: IdentityRoleGroup[];
  validation: string[];
  preflightChecks: string[];
  safety: string[];
  docs: string[];
}

interface IdentityCheck {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
}

interface IdentityTestResult {
  checkedAt: string;
  ok: boolean;
  checks: IdentityCheck[];
}

interface GuideFetch {
  guide: IdentitySetupGuide | null;
  error: string | null;
}

/** Mirrors legacy loadIdentitySetup: parse the body even on non-2xx so a 400 { error } reaches the UI. */
async function fetchIdentitySetupGuide(provider: string, tenantId: string): Promise<GuideFetch> {
  const params = new URLSearchParams({ provider });
  if (tenantId) params.set('tenantId', tenantId);
  const res = await api(`/api/identity/setup-guide?${params.toString()}`);
  if (!res) return { guide: null, error: null };
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { guide: null, error: null };
  }
  if (!body || typeof body !== 'object') return { guide: null, error: null };
  const record = body as IdentitySetupGuide & { error?: unknown };
  if (typeof record.error === 'string' && record.error) return { guide: null, error: record.error };
  return res.ok ? { guide: record, error: null } : { guide: null, error: null };
}

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '-');
const humanize = (value: string) => (value || '-').replace(/_/g, ' ');

const PROVIDER_LABELS: Record<string, string> = { entra: 'Microsoft Entra ID', okta: 'Okta' };
const providerLabel = (provider: string) => PROVIDER_LABELS[provider] || humanize(provider);

/** Legacy roleLabel semantics: unknown roles normalize to auditor. */
const ROLE_LABELS: Record<string, string> = {
  security_admin: 'Security Admin',
  approver: 'Approver',
  operator: 'Operator',
  auditor: 'Auditor',
};
const roleGroupLabel = (role: string) => ROLE_LABELS[role] || ROLE_LABELS.auditor;

/** Legacy statusChip tone -> chip tone class: good->secure, warn->warn, bad->critical, else live. */
const CHIP_TONES: Record<string, string> = { good: 'secure', warn: 'warn', bad: 'critical' };

function StatusChip({ tone, label, detail }: { tone: string; label: string; detail: string }) {
  return (
    <span
      className={`pill ${tone} status-chip tone-${CHIP_TONES[tone] || 'live'}`}
      tabIndex={0}
      role="button"
      title={detail || label}
    >
      {label}
    </span>
  );
}

function scimRows(scim?: IdentityScim): Array<[string, string]> {
  return [
    ['Tenant URL', scim?.tenantUrl || ''],
    ['Base URL', scim?.baseUrl || ''],
    ['Authentication', scim?.authMode || ''],
    ['Token env', scim ? `${scim.tokenEnv} / ${scim.tokenAlias}` : ''],
    ['Unique ID', scim?.uniqueIdentifier || ''],
    ['Content type', scim?.contentType || ''],
  ];
}

function oidcRows(oidc?: IdentityOidc): Array<[string, string]> {
  return [
    ['Application type', oidc?.applicationType || ''],
    ['Issuer', oidc?.issuer || ''],
    ['Redirect URI', oidc?.redirectUri || ''],
    ['Scopes', (oidc?.scopes || []).join(' ')],
    ['Discovery', oidc?.discovery || ''],
  ];
}

function KeyValueRows({ rows }: { rows: Array<[string, string]> }) {
  return (
    <>
      {rows.map(([key, value]) => (
        <tr key={key}>
          <th>{key}</th>
          <td className="mono">{value || '-'}</td>
        </tr>
      ))}
    </>
  );
}

interface IdentityPanelProps {
  title: string;
  hint: string;
  wide?: boolean;
  loading?: boolean;
  tools?: ReactNode;
  children: ReactNode;
}

function IdentityPanel({ title, hint, wide, loading, tools, children }: IdentityPanelProps) {
  return (
    <div
      className={`panel${wide ? ' wide-panel' : ''}${loading ? ' is-loading' : ''}`}
      data-loading-label={loading ? 'VERIFYING' : undefined}
    >
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          <span>{hint}</span>
        </div>
        {tools}
      </div>
      {children}
    </div>
  );
}

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function IdentityHeader({ onTest }: { onTest: () => void }) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>Identity &amp; Roles</h2>
          <p>Prepare SCIM, OIDC, Texas FCU team mapping, and reviewer roles without exposing secrets.</p>
        </div>
      </div>
      <div className="console-frame-actions">
        <button
          className="ghost"
          type="button"
          title="Check which sign-in paths are wired; the check is recorded in the audit log"
          onClick={onTest}
        >
          Test configuration
        </button>
      </div>
    </div>
  );
}

function TestChecks({ result }: { result: IdentityTestResult }) {
  return (
    <>
      <div className="reasons">Checked {fmt(result.checkedAt)} - recorded in the audit log</div>
      {result.checks.map((check) => (
        <div className="incident-trail-row" key={check.id}>
          <StatusChip tone={check.ok ? 'good' : 'warn'} label={check.ok ? 'OK' : 'ACTION'} detail={check.detail} />
          <span className="what">
            <b>{check.label}</b> - {check.detail}
          </span>
        </div>
      ))}
    </>
  );
}

function TestPanel({ result }: { result: IdentityTestResult | 'failed' | null }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>Identity readiness check</h2>
          <span>Config completeness only - no calls leave this server</span>
        </div>
      </div>
      <div className="identity-test-result">
        {result === 'failed' ? <div className="empty">Test failed - Security Admin session required.</div> : null}
        {result && result !== 'failed' ? <TestChecks result={result} /> : null}
      </div>
    </div>
  );
}

/** Commits on blur/Enter to match the legacy `change` semantics - never refetches per keystroke. */
function TenantInput({ onCommit }: { onCommit: (value: string) => void }) {
  const [draft, setDraft] = useState('');
  return (
    <input
      type="text"
      aria-label="Tenant or domain"
      placeholder="tenant id or texasfcu.org"
      value={draft}
      onChange={(event) => setDraft(event.target.value)}
      onBlur={() => onCommit(draft.trim())}
      onKeyDown={(event) => {
        if (event.key === 'Enter') onCommit(draft.trim());
      }}
    />
  );
}

interface SetupToolsProps {
  provider: string;
  onProvider: (value: string) => void;
  onTenant: (value: string) => void;
  onRefresh: () => void;
}

function SetupTools({ provider, onProvider, onTenant, onRefresh }: SetupToolsProps) {
  return (
    <div className="queue-tools">
      <select aria-label="Identity provider" value={provider} onChange={(event) => onProvider(event.target.value)}>
        <option value="entra">Microsoft Entra ID</option>
        <option value="okta">Okta</option>
      </select>
      <TenantInput onCommit={onTenant} />
      <button className="ghost" type="button" onClick={onRefresh}>
        <RefreshIcon />
        Refresh
      </button>
    </div>
  );
}

function SummaryKpis({ guide }: { guide: IdentitySetupGuide }) {
  const cards = [
    { label: 'Provider', value: guide.label || providerLabel(guide.provider), meta: guide.tenantLabel || 'Tenant' },
    { label: 'SCIM URL', value: guide.scim?.tenantUrl || '', meta: 'Provisioning' },
    { label: 'Redirect URI', value: guide.oidc?.redirectUri || '', meta: 'Console SSO' },
    { label: 'Preflight', value: (guide.preflightChecks || []).join(', '), meta: 'Checks' },
  ];
  return (
    <div className="identity-summary">
      {cards.map((card) => (
        <div className="mini-kpi" key={card.label}>
          <b>{card.label}</b>
          <em>{card.value || '-'}</em>
          <span>{card.meta}</span>
        </div>
      ))}
    </div>
  );
}

function SummaryBody({ guide, error, loaded }: { guide: IdentitySetupGuide | null; error: string; loaded: boolean }) {
  if (error) {
    return (
      <div className="empty">
        <div className="big">Identity setup unavailable</div>
        {error}
      </div>
    );
  }
  if (guide) return <SummaryKpis guide={guide} />;
  if (!loaded) return null;
  return <EmptyState title="Identity setup unavailable" detail="Could not load the setup guide. Refresh to retry." />;
}

function EnvTable({ rows }: { rows: IdentityEnvRow[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Key</th>
          <th>RedactWall Alias</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            <td className="mono">{row.key}</td>
            <td className="mono">{row.alias}</td>
            <td className="mono">{row.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RoleGroupRow({ row }: { row: IdentityRoleGroup }) {
  const groups = (row.groups || []).join(', ');
  return (
    <tr>
      <td>
        <StatusChip
          tone="info"
          label={roleGroupLabel(row.role)}
          detail={`Permission level: ${roleGroupLabel(row.role)}\nGroups: ${groups || '-'}`}
        />
      </td>
      <td>{groups}</td>
    </tr>
  );
}

function RoleGroupsTable({ rows }: { rows: IdentityRoleGroup[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Role</th>
          <th>Groups</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <RoleGroupRow key={row.role} row={row} />
        ))}
      </tbody>
    </table>
  );
}

function ValidationList({ guide }: { guide: IdentitySetupGuide | null }) {
  const rows = [
    ...(guide?.validation ?? []).map((detail) => ({ label: 'Command', detail })),
    ...(guide?.safety ?? []).map((detail) => ({ label: 'Safety', detail })),
  ];
  return (
    <div className="posture-list">
      {rows.map((row, index) => (
        <div className="posture-item" key={`${row.label}-${index}`}>
          <span>{row.label}</span>
          <b>{row.detail}</b>
        </div>
      ))}
    </div>
  );
}

function GuidePanels({ guide }: { guide: IdentitySetupGuide | null }) {
  return (
    <>
      <IdentityPanel title="SCIM" hint="Provisioning app values">
        <table>
          <tbody>{guide ? <KeyValueRows rows={scimRows(guide.scim)} /> : null}</tbody>
        </table>
      </IdentityPanel>
      <IdentityPanel title="OIDC" hint="Console SSO app values">
        <table>
          <tbody>{guide ? <KeyValueRows rows={oidcRows(guide.oidc)} /> : null}</tbody>
        </table>
      </IdentityPanel>
      <IdentityPanel title="Environment" hint="Server-side settings" wide>
        <EnvTable rows={guide?.env ?? []} />
      </IdentityPanel>
      <IdentityPanel title="Reviewer Groups" hint="Provisioned Texas FCU team names">
        <RoleGroupsTable rows={guide?.roleGroups ?? []} />
      </IdentityPanel>
      <IdentityPanel title="Validation" hint="Readiness checks">
        <ValidationList guide={guide} />
      </IdentityPanel>
    </>
  );
}

/** Guide loader. On a 400 the error renders in the summary while the tables keep their previous guide, as legacy did. */
function useIdentityGuide(provider: string, tenant: string) {
  const [guide, setGuide] = useState<IdentitySetupGuide | null>(null);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await fetchIdentitySetupGuide(provider, tenant);
      if (result.error) setError(result.error);
      else if (result.guide) {
        setGuide(result.guide);
        setError('');
      }
    } finally {
      setLoading(false);
      setLoaded(true);
    }
  }, [provider, tenant]);
  useEffect(() => {
    load();
  }, [load]);
  return { guide, error, loaded, loading, load };
}

export default function Identity() {
  const [provider, setProvider] = useState('entra');
  const [tenant, setTenant] = useState('');
  const { guide, error, loaded, loading, load } = useIdentityGuide(provider, tenant);
  const [testVisible, setTestVisible] = useState(false);
  const [testResult, setTestResult] = useState<IdentityTestResult | 'failed' | null>(null);

  const runTest = async () => {
    setTestVisible(true);
    const result = await apiSend<IdentityTestResult>('/api/identity/test', 'POST', {});
    setTestResult(result ?? 'failed');
  };

  return (
    <div className="identity-view console-frame">
      <IdentityHeader onTest={runTest} />
      {testVisible ? <TestPanel result={testResult} /> : null}
      <div className="identity-grid">
        <IdentityPanel
          title="Identity Setup"
          hint="SCIM, OIDC, and Texas FCU reviewer-routing values"
          wide
          loading={loading}
          tools={<SetupTools provider={provider} onProvider={setProvider} onTenant={setTenant} onRefresh={load} />}
        >
          <SummaryBody guide={guide} error={error} loaded={loaded} />
        </IdentityPanel>
        <GuidePanels guide={guide} />
      </div>
    </div>
  );
}
