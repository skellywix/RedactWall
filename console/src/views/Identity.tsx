import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { EmptyState } from '../components/Panel';
import { api, apiErrorSummary, apiSend } from '../lib/api';
import { useSession } from '../lib/session';
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

interface AdminRole {
  id: string;
  label: string;
  permissions: Record<string, string>;
}

interface AdminUser {
  id: string;
  userName: string;
  displayName: string;
  role: string;
  roleLabel: string;
  active: boolean;
  source: string;
  sourceLabel: string;
  sources: string[];
  orgId: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  events: number;
  licenseState: string;
  licenseReason: string;
  licenseUpdatedAt: string | null;
  mutable: boolean;
}

interface AdminInvitation {
  id: string;
  userName: string;
  displayName: string;
  role: string;
  roleLabel: string;
  status: string;
  expiresAt: string;
  acceptedAt: string | null;
  createdAt: string;
  updatedAt: string;
  inviteUrl?: string;
}

interface AdminDirectory {
  users: AdminUser[];
  invitations: AdminInvitation[];
  seatReport: {
    seatLimit: number;
    seatsUsed: number;
    seatsRemaining: number | null;
    overLimit: boolean;
    tenantId: string | null;
    saasMode: boolean;
  };
}

function absoluteInviteUrl(invite: AdminInvitation | null): string {
  if (!invite?.inviteUrl) return '';
  try { return new URL(invite.inviteUrl, window.location.origin).href; } catch { return ''; }
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

async function fetchRoles(): Promise<AdminRole[]> {
  const res = await api('/api/admin/roles');
  if (!res?.ok) throw new Error('roles unavailable');
  const body = await res.json() as { roles?: unknown };
  if (!Array.isArray(body?.roles)) throw new Error('roles response invalid');
  return body.roles as AdminRole[];
}

async function fetchDirectory(): Promise<AdminDirectory> {
  const res = await api('/api/admin/users');
  if (!res?.ok) throw new Error('directory unavailable');
  const body = await res.json() as Partial<AdminDirectory>;
  if (!body || !Array.isArray(body.users) || !Array.isArray(body.invitations) || !body.seatReport) {
    throw new Error('directory response invalid');
  }
  return body as AdminDirectory;
}

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '-');
const humanize = (value: string) => (value || '-').replace(/_/g, ' ');

const PROVIDER_LABELS: Record<string, string> = { entra: 'Microsoft Entra ID', okta: 'Okta' };
const providerLabel = (provider: string) => PROVIDER_LABELS[provider] || humanize(provider);

const ROLE_LABELS: Record<string, string> = {
  security_admin: 'Global Administrator',
  operator: 'Operations Administrator',
  approver: 'Member Data Reviewer',
  auditor: 'Read-only Examiner/Auditor',
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

function IdentityHeader({ onTest, canManage }: { onTest: () => void; canManage: boolean }) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>Users &amp; Roles</h2>
          <p>Administer Texas FCU staff access, reviewer roles, IdP setup, and break-glass readiness.</p>
        </div>
      </div>
      {canManage ? <div className="console-frame-actions">
        <button
          className="ghost"
          type="button"
          title="Check which sign-in paths are wired; the check is recorded in the audit log"
          onClick={onTest}
        >
          Test configuration
        </button>
      </div> : null}
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

function AdminTabs({ active, onChange }: { active: 'users' | 'setup'; onChange: (tab: 'users' | 'setup') => void }) {
  return (
    <div className="identity-tabs" role="tablist" aria-label="Administration">
      <button className={active === 'users' ? 'active' : ''} type="button" role="tab" aria-selected={active === 'users'} onClick={() => onChange('users')}>
        Users &amp; Roles
      </button>
      <button className={active === 'setup' ? 'active' : ''} type="button" role="tab" aria-selected={active === 'setup'} onClick={() => onChange('setup')}>
        Identity Setup
      </button>
    </div>
  );
}

function RoleMatrix({ roles }: { roles: AdminRole[] }) {
  return (
    <IdentityPanel title="Role Matrix" hint="FCU-facing labels mapped to fixed RedactWall permissions">
      <div className="role-matrix">
        {roles.map((role) => (
          <div className="role-card" key={role.id}>
            <b>{role.label}</b>
            <span className="mono">{role.id}</span>
            <em>{role.permissions.administration}</em>
          </div>
        ))}
      </div>
    </IdentityPanel>
  );
}

function DirectoryKpis({ directory }: { directory: AdminDirectory }) {
  const active = directory.users.filter((user) => user.active).length;
  const reviewers = directory.users.filter((user) => user.role === 'approver' && user.active).length;
  const pending = directory.invitations.filter((invite) => invite.status === 'pending').length;
  const seatLimit = directory.seatReport.seatLimit || 'Unmetered';
  return (
    <div className="identity-summary">
      <div className="mini-kpi"><b>Active Staff Users</b><em>{active}</em><span>FCU console directory</span></div>
      <div className="mini-kpi"><b>Member Data Reviewers</b><em>{reviewers}</em><span>approval-ready staff</span></div>
      <div className="mini-kpi"><b>Pending Invites</b><em>{pending}</em><span>local invite flow</span></div>
      <div className="mini-kpi"><b>License Seats</b><em>{directory.seatReport.seatsUsed} / {seatLimit}</em><span>{directory.seatReport.overLimit ? 'over limit' : 'current usage'}</span></div>
    </div>
  );
}

function UserSource({ user }: { user: AdminUser }) {
  return (
    <div className="source-stack">
      <b>{user.sourceLabel}</b>
      <span>{(user.sources || []).join(', ')}</span>
    </div>
  );
}

interface UserDirectoryProps {
  users: AdminUser[];
  roles: AdminRole[];
  canManage: boolean;
  onRole: (user: AdminUser, role: string) => void;
  onDisable: (user: AdminUser) => void;
  onReactivate: (user: AdminUser) => void;
}

function UserDirectory({ users, roles, canManage, onRole, onDisable, onReactivate }: UserDirectoryProps) {
  return (
    <IdentityPanel title="Staff Directory" hint="SCIM, local invites, break-glass accounts, and observed sensor identities" wide>
      <table className="admin-table">
        <thead>
          <tr>
            <th>Staff User</th>
            <th>Role</th>
            <th>Source</th>
            <th>License</th>
            <th>Activity</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>
                <b>{user.displayName}</b>
                <span className="mono">{user.userName}</span>
              </td>
              <td>
                {canManage && user.mutable ? (
                  <select aria-label={`Role for ${user.userName}`} value={user.role} onChange={(event) => onRole(user, event.target.value)}>
                    {roles
                      .filter((role) => user.source !== 'local_invite' || role.id !== 'security_admin')
                      .map((role) => <option key={role.id} value={role.id}>{role.label}</option>)}
                  </select>
                ) : (
                  <span>{user.roleLabel}</span>
                )}
              </td>
              <td><UserSource user={user} /></td>
              <td>
                <StatusChip tone={user.licenseState === 'released' ? 'warn' : 'info'} label={humanize(user.licenseState)} detail={user.licenseReason || user.licenseState} />
              </td>
              <td>
                <b>{user.events}</b>
                <span>{user.lastSeen ? fmt(user.lastSeen) : 'No sensor activity'}</span>
              </td>
              <td>
                <StatusChip tone={user.active ? 'good' : 'warn'} label={user.active ? 'Active' : 'Inactive'} detail={user.active ? 'Staff user can authenticate or be provisioned' : 'Staff user is disabled'} />
              </td>
              <td>
                {canManage && user.mutable ? (
                  user.active ? (
                    <button className="ghost mini" type="button" onClick={() => onDisable(user)}>Disable</button>
                  ) : (
                    <button className="ghost mini" type="button" onClick={() => onReactivate(user)}>Reactivate</button>
                  )
                ) : (
                  <span className="readonly-note">Read-only</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </IdentityPanel>
  );
}

function InviteForm({ roles, invalidatedInvitationId, onCreated }: { roles: AdminRole[]; invalidatedInvitationId: string | null; onCreated: (invite: AdminInvitation) => void }) {
  const [userName, setUserName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [role, setRole] = useState('auditor');
  const [reason, setReason] = useState('Texas FCU staff access approved');
  const [error, setError] = useState('');
  const [created, setCreated] = useState<AdminInvitation | null>(null);
  const inviteRoles = roles.filter((item) => item.id !== 'security_admin');
  const createdUrl = absoluteInviteUrl(created);

  useEffect(() => {
    if (!invalidatedInvitationId) return;
    setCreated((current) => current?.id === invalidatedInvitationId ? null : current);
  }, [invalidatedInvitationId]);

  const submit = async () => {
    setError('');
    const res = await api('/api/admin/users/invitations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userName, displayName, role, reason }),
    });
    if (!res || !res.ok) {
      setError(await apiErrorSummary(res, 'Could not create invite'));
      return;
    }
    const invite = (await res.json()) as AdminInvitation;
    setCreated(invite);
    setUserName('');
    setDisplayName('');
    onCreated(invite);
  };

  return (
    <IdentityPanel title="Invite Staff User" hint="IdP-first, with local invite fallback for smaller FCUs">
      <div className="invite-form">
        <input aria-label="Staff email" placeholder="staff@texasfcu.org" value={userName} onChange={(event) => setUserName(event.target.value)} />
        <input aria-label="Display name" placeholder="Display name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
        <select aria-label="Role" value={role} onChange={(event) => setRole(event.target.value)}>
          {inviteRoles.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
        </select>
        <input aria-label="Reason" value={reason} onChange={(event) => setReason(event.target.value)} />
        <button className="primary" type="button" onClick={submit}>Create invite</button>
        {error ? <div className="readonly-note">{error}</div> : null}
        {createdUrl ? (
          <div className="invite-url">
            <b>Invite link</b>
            <span className="mono">{createdUrl}</span>
          </div>
        ) : null}
      </div>
    </IdentityPanel>
  );
}

function InvitationTable({ invitations, replacementInvite, canManage, onResend, onRevoke }: { invitations: AdminInvitation[]; replacementInvite: AdminInvitation | null; canManage: boolean; onResend: (invite: AdminInvitation) => void; onRevoke: (invite: AdminInvitation) => void }) {
  const replacementUrl = absoluteInviteUrl(replacementInvite);
  return (
    <IdentityPanel title="Invitations" hint="Pending, accepted, expired, and revoked local invite records">
      <>
        {replacementUrl ? (
          <div className="invite-url" role="status">
            <b>Replacement invite link</b>
            <span className="mono">{replacementUrl}</span>
            <span className="readonly-note">The previous link is no longer valid.</span>
          </div>
        ) : null}
        <table className="admin-table compact">
          <thead>
            <tr><th>Staff User</th><th>Role</th><th>Status</th><th>Expires</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {invitations.map((invite) => (
              <tr key={invite.id}>
                <td><b>{invite.displayName}</b><span className="mono">{invite.userName}</span></td>
                <td>{invite.roleLabel}</td>
                <td><StatusChip tone={invite.status === 'pending' ? 'info' : 'warn'} label={humanize(invite.status)} detail={invite.status} /></td>
                <td>{fmt(invite.expiresAt)}</td>
                <td>
                  {canManage && invite.status === 'pending' ? (
                    <>
                      <button className="ghost mini" type="button" onClick={() => onResend(invite)}>Resend</button>
                      <button className="ghost mini" type="button" onClick={() => onRevoke(invite)}>Revoke</button>
                    </>
                  ) : <span className="readonly-note">Closed</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </>
    </IdentityPanel>
  );
}

function useAdminDirectory() {
  const [directory, setDirectory] = useState<AdminDirectory | null>(null);
  const [roles, setRoles] = useState<AdminRole[] | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextRoles, nextDirectory] = await Promise.all([fetchRoles(), fetchDirectory()]);
      setRoles(nextRoles);
      setDirectory(nextDirectory);
      setError('');
    } catch {
      // Preserve a previously verified snapshot. Zeroes are meaningful license
      // posture, so a failed request must never be rendered as an empty tenant.
      setError('Administration data could not be refreshed.');
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { directory, roles, error, loading, load, setDirectory };
}

function UsersAndRoles({ directory, roles, error, loading, reload, setDirectory, canManage }: {
  directory: AdminDirectory | null;
  roles: AdminRole[] | null;
  error: string;
  loading: boolean;
  reload: () => Promise<void>;
  setDirectory: (directory: AdminDirectory) => void;
  canManage: boolean;
}) {
  const [replacementInvite, setReplacementInvite] = useState<AdminInvitation | null>(null);
  const reason = (label: string) => window.prompt(label, 'Texas FCU administration change approved') || '';
  const patchUser = async (user: AdminUser, body: Record<string, unknown>) => {
    const res = await api(`/api/admin/users/${encodeURIComponent(user.id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res?.ok) setDirectory((await res.json()) as AdminDirectory);
  };
  const postUser = async (user: AdminUser, action: 'disable' | 'reactivate', promptLabel: string) => {
    const why = reason(promptLabel);
    if (!why) return;
    const res = await apiSend<AdminDirectory>(`/api/admin/users/${encodeURIComponent(user.id)}/${action}`, 'POST', { reason: why });
    if (res) setDirectory(res);
  };
  const resend = async (invite: AdminInvitation) => {
    const why = reason('Reason for resending the invite');
    if (!why) return;
    const replacement = await apiSend<AdminInvitation>(`/api/admin/users/invitations/${encodeURIComponent(invite.id)}/resend`, 'POST', { reason: why });
    if (!replacement) return;
    setReplacementInvite(replacement);
    await reload();
  };
  const revoke = async (invite: AdminInvitation) => {
    const why = reason('Reason for revoking the invite');
    if (!why) return;
    const revoked = await apiSend(`/api/admin/users/invitations/${encodeURIComponent(invite.id)}/revoke`, 'POST', { reason: why });
    if (!revoked) return;
    if (replacementInvite?.id === invite.id) setReplacementInvite(null);
    await reload();
  };

  if (!directory || !roles) {
    return (
      <div className={`identity-grid${loading ? ' is-loading' : ''}`} data-loading-label={loading ? 'LOADING' : undefined}>
        <IdentityPanel
          title="Administration data unavailable"
          hint="No verified staff or license snapshot is available"
          wide
          tools={<button className="ghost" type="button" onClick={() => void reload()}><RefreshIcon /> Retry</button>}
        >
          <EmptyState
            title="Could not load users and roles"
            detail="RedactWall did not substitute zero users or unmetered seats. Retry after the administration API is available."
          />
        </IdentityPanel>
      </div>
    );
  }

  return (
    <div className={`identity-grid${loading ? ' is-loading' : ''}`} data-loading-label={loading ? 'LOADING' : undefined}>
      {error ? <div className="readonly-note" role="alert">{error} Showing the last verified snapshot.</div> : null}
      <IdentityPanel title="Administration Overview" hint="Texas FCU staff access and license-visible user footprint" wide tools={<button className="ghost" type="button" onClick={() => void reload()}><RefreshIcon /> Refresh</button>}>
        <DirectoryKpis directory={directory} />
      </IdentityPanel>
      <RoleMatrix roles={roles} />
      {canManage ? (
        <InviteForm
          roles={roles}
          invalidatedInvitationId={replacementInvite?.id || null}
          onCreated={() => {
            setReplacementInvite(null);
            void reload();
          }}
        />
      ) : (
        <IdentityPanel title="Invite Staff User" hint="IdP-first, with local invite fallback for smaller FCUs">
          <p className="readonly-note">Global Administrator access is required to change identity or invitations.</p>
        </IdentityPanel>
      )}
      <UserDirectory
        users={directory.users}
        roles={roles}
        canManage={canManage}
        onRole={(user, role) => {
          const why = reason(`Reason for changing ${user.userName}'s role`);
          if (why) void patchUser(user, { role, reason: why });
        }}
        onDisable={(user) => void postUser(user, 'disable', `Reason for disabling ${user.userName}`)}
        onReactivate={(user) => void postUser(user, 'reactivate', `Reason for reactivating ${user.userName}`)}
      />
      <InvitationTable invitations={directory.invitations} replacementInvite={replacementInvite} canManage={canManage} onResend={resend} onRevoke={revoke} />
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
  const { me } = useSession();
  const canManage = me?.role === 'security_admin';
  const [activeTab, setActiveTab] = useState<'users' | 'setup'>('users');
  const [provider, setProvider] = useState('entra');
  const [tenant, setTenant] = useState('');
  const { guide, error, loaded, loading, load } = useIdentityGuide(provider, tenant);
  const adminStore = useAdminDirectory();
  const [testVisible, setTestVisible] = useState(false);
  const [testResult, setTestResult] = useState<IdentityTestResult | 'failed' | null>(null);

  const runTest = async () => {
    setTestVisible(true);
    const result = await apiSend<IdentityTestResult>('/api/identity/test', 'POST', {});
    setTestResult(result ?? 'failed');
  };

  return (
    <div className="identity-view console-frame">
      <IdentityHeader onTest={runTest} canManage={canManage} />
      <AdminTabs active={activeTab} onChange={setActiveTab} />
      {testVisible ? <TestPanel result={testResult} /> : null}
      {activeTab === 'users' ? (
        <UsersAndRoles
          directory={adminStore.directory}
          roles={adminStore.roles}
          error={adminStore.error}
          loading={adminStore.loading}
          reload={adminStore.load}
          setDirectory={adminStore.setDirectory}
          canManage={canManage}
        />
      ) : (
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
      )}
    </div>
  );
}
