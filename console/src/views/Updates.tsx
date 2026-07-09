import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { api, apiErrorSummary } from '../lib/api';
import { Panel } from '../components/Panel';
import { useSession } from '../lib/session';
import { toast } from '../lib/toast';
import './Updates.css';

/**
 * Software-update console (admin only). Route contract from server/app.js + server/updater.js:
 *   GET  /api/update/status   -> full status {ok, inProgress, config, repo|null, safety, lastRun|null, error}
 *   PUT  /api/update/config   -> body {remoteName, branch, installMode, restartCommand, restartAfterUpdate};
 *                                returns the full status object again on success
 *   POST /api/update/check    -> no body; {updateAvailable, ...}
 *   POST /api/update/apply    -> body {confirmBackup: true}; runs synchronously, can take minutes
 *   POST /api/update/restart  -> no body; 403 when restart execution is disabled on the host
 * Error bodies are {error: <short, already-redacted string>} - safe to toast. No password step-up.
 */

interface UpdateConfig {
  remoteName?: string;
  branch?: string;
  installMode?: string;
  restartCommand?: string;
  restartAfterUpdate?: boolean;
  restartEnabled?: boolean;
  restartCommandSource?: string;
  configPath?: string;
  backupDir?: string;
}

interface UpdateRepo {
  branch?: string;
  head?: string;
  remoteUrl?: string;
  dirtyFiles?: Array<{ status: string; path: string }>;
}

interface AuditIntegrity {
  ok: boolean;
  count: number;
}

interface UpdateSafety {
  backupDir?: string;
  auditIntegrity?: AuditIntegrity;
  sourceTreeClean?: boolean;
  configuredBranch?: boolean;
  githubRemote?: boolean;
}

interface UpdateLastRun {
  status: string;
  stage?: string;
  startedAt?: string;
  completedAt?: string;
  fromCommit?: string;
  toCommit?: string;
  backup?: { manifestFile?: string };
  restartRequired?: boolean;
  error?: string;
}

interface UpdateStatus {
  ok: boolean;
  inProgress: boolean;
  config?: UpdateConfig;
  repo?: UpdateRepo | null;
  safety?: UpdateSafety;
  lastRun?: UpdateLastRun | null;
  error?: string;
}

interface UpdateCheckResult {
  updateAvailable?: boolean;
}

/** Action outcome: exactly one of data/error is set. Error text is server-redacted, safe to toast. */
interface ActionResult<T> {
  data: T | null;
  error: string | null;
}

async function updateSend<T>(path: string, method: string, body: unknown, fallback: string): Promise<ActionResult<T>> {
  const res = await api(path, {
    method,
    ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  });
  if (!res) return { data: null, error: fallback };
  if (!res.ok) return { data: null, error: await apiErrorSummary(res, fallback) };
  try {
    return { data: (await res.json()) as T, error: null };
  } catch {
    return { data: null, error: fallback };
  }
}

/** Status GET keeps the failure body's error string so the "Unavailable" note matches legacy. */
async function fetchUpdateStatus(): Promise<{ status: UpdateStatus | null; error: string }> {
  const res = await api('/api/update/status');
  if (!res) return { status: null, error: 'Update status unavailable.' };
  let body: UpdateStatus | null = null;
  try {
    body = (await res.json()) as UpdateStatus;
  } catch {
    body = null;
  }
  if (!res.ok || !body || typeof body !== 'object') {
    return { status: null, error: body?.error || 'Update status unavailable.' };
  }
  return { status: body, error: '' };
}

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '-');
const humanize = (value: string) => (value || '-').replace(/_/g, ' ');
const shortCommit = (value?: string) => String(value || '').slice(0, 12) || '-';

const INSTALL_MODE_LABELS: Record<string, string> = {
  'npm-ci-omit-dev': 'Install runtime dependencies',
  'npm-ci': 'Install all dependencies',
  skip: 'Skip dependency install',
};

function installModeLabel(mode?: string): string {
  return INSTALL_MODE_LABELS[mode || ''] || humanize(mode || '');
}

/** git@github.com:o/r.git or https://github.com/o/r.git -> https://github.com/o/r */
function githubWebUrl(remoteUrl?: string): string | null {
  const match = String(remoteUrl || '').match(/github\.com[:/]([^/\s]+)\/([^/\s]+?)(?:\.git)?$/);
  return match ? `https://github.com/${match[1]}/${match[2]}` : null;
}

type PillState = 'good' | 'warn' | 'bad';

interface Pill {
  state: PillState;
  label: string;
}

const CHIP_TONE: Record<PillState, string> = { good: 'secure', warn: 'warn', bad: 'critical' };

/** Port of legacy updateStatusState(): pill derivation in priority order. */
function updateStatusState(status: UpdateStatus): Pill {
  if (status.inProgress) return { state: 'warn', label: 'Running' };
  if (status.error) return { state: 'bad', label: 'Needs setup' };
  const safety = status.safety || {};
  const auditBroken = safety.auditIntegrity ? safety.auditIntegrity.ok === false : false;
  if (!safety.githubRemote || !safety.sourceTreeClean || safety.configuredBranch === false || auditBroken) {
    return { state: 'bad', label: 'Blocked' };
  }
  const last = status.lastRun;
  if (last?.status === 'failed' || last?.status === 'restart-failed') return { state: 'bad', label: 'Failed' };
  if (last?.restartRequired) return { state: 'warn', label: 'Restart required' };
  return { state: 'good', label: 'Ready' };
}

interface ActionFlags {
  blocked: boolean;
  updateDisabled: boolean;
  restartDisabled: boolean;
  dirtyDetail: string;
}

function deriveFlags(status: UpdateStatus): ActionFlags {
  const { state } = updateStatusState(status);
  const config = status.config || {};
  const dirtyFiles = status.repo?.dirtyFiles || [];
  const blocked = state === 'bad' || status.inProgress;
  const restartConfigured = !!config.restartCommand || config.restartCommandSource === 'env';
  const restartExecutable = !!config.restartEnabled && restartConfigured;
  return {
    blocked,
    updateDisabled: blocked || status.safety?.auditIntegrity?.ok === false,
    restartDisabled: !restartExecutable || !status.lastRun?.restartRequired || status.inProgress,
    dirtyDetail: dirtyFiles.length
      ? `${dirtyFiles.length} source change(s): ${dirtyFiles.slice(0, 3).map((item) => item.path).join(', ')}`
      : 'Clean',
  };
}

function StatePill({ pill }: { pill: Pill }) {
  return (
    <span className={`pill ${pill.state} status-chip tone-${CHIP_TONE[pill.state]}`} title={`Verification state: ${pill.label}`}>
      {pill.label}
    </span>
  );
}

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M20 12a8 8 0 0 1-13.7 5.6M4 12A8 8 0 0 1 17.7 6.4M17.7 6.4H14M17.7 6.4V2.7M6.3 17.6H10M6.3 17.6v3.7"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="m5 12 4 4L19 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function LogRow({ label, value }: { label: string; value?: string }) {
  return (
    <div className="update-log-row">
      <span>{label}</span>
      <b>{value || '-'}</b>
    </div>
  );
}

function SafetyRow({ label, ok, detail }: { label: string; ok: boolean; detail: string }) {
  return (
    <div className="posture-item">
      <span>{label}</span>
      <b>
        <StatePill pill={{ state: ok ? 'good' : 'bad', label: detail || (ok ? 'Ready' : 'Blocked') }} />
      </b>
    </div>
  );
}

interface GithubCardProps {
  status: UpdateStatus;
  flags: ActionFlags;
  busy: boolean;
  onCheck: () => void;
  onUpdate: () => void;
  onRestart: () => void;
}

function GithubCard({ status, flags, busy, onCheck, onUpdate, onRestart }: GithubCardProps) {
  const repo = status.repo || {};
  const config = status.config || {};
  const webUrl = githubWebUrl(repo.remoteUrl);
  return (
    <div className="config-card pad wide-panel">
      <div className="sensor-head">
        <div>
          <h3>GitHub Update</h3>
          <p>Fast-forward source from the configured GitHub branch after a verified evidence-store backup.</p>
        </div>
        <StatePill pill={updateStatusState(status)} />
      </div>
      <div className="update-log">
        <LogRow label="Remote" value={repo.remoteUrl || `${config.remoteName || 'origin'} (not verified)`} />
        <LogRow label="Branch" value={`${repo.branch || '-'} -> ${config.remoteName || 'origin'}/${config.branch || 'main'}`} />
        <LogRow label="Current" value={shortCommit(repo.head)} />
        <LogRow label="Install" value={installModeLabel(config.installMode)} />
        <LogRow label="Config path" value={config.configPath} />
      </div>
      <div className="update-action-row">
        {webUrl ? (
          <a className="ghost" href={`${webUrl}/releases`} target="_blank" rel="noopener noreferrer">
            Release notes &nearr;
          </a>
        ) : null}
        <button className="ghost" type="button" disabled={flags.blocked || busy} onClick={onCheck}>
          <RefreshIcon />
          Check GitHub
        </button>
        <button className="btn approve" type="button" disabled={flags.updateDisabled || busy} onClick={onUpdate}>
          <RefreshIcon />
          Update from GitHub
        </button>
        <button className="ghost" type="button" disabled={flags.restartDisabled || busy} onClick={onRestart}>
          Restart service
        </button>
      </div>
      {status.error ? <div className="readonly-note">{status.error}</div> : null}
    </div>
  );
}

function PreservationCard({ status, dirtyDetail }: { status: UpdateStatus; dirtyDetail: string }) {
  const repo = status.repo || {};
  const config = status.config || {};
  const safety = status.safety || {};
  const integrity = safety.auditIntegrity;
  const branchDetail = safety.configuredBranch === false
    ? `${repo.branch || '-'} does not match ${config.branch || 'main'}`
    : repo.branch || config.branch || 'main';
  return (
    <div className="config-card pad">
      <h3>Preservation Checks</h3>
      <p>Runtime state is protected before source files move.</p>
      <div className="posture-list">
        <SafetyRow label="GitHub remote" ok={!!safety.githubRemote} detail={safety.githubRemote ? 'GitHub' : 'Not GitHub'} />
        <SafetyRow label="Checked-out branch" ok={safety.configuredBranch !== false} detail={branchDetail} />
        <SafetyRow label="Source tree" ok={!!safety.sourceTreeClean} detail={dirtyDetail} />
        <SafetyRow label="Audit chain" ok={!!integrity?.ok} detail={integrity?.ok ? `${integrity.count} entries` : 'Failed'} />
        <SafetyRow label="Backup target" ok={!!safety.backupDir} detail={safety.backupDir || config.backupDir || '-'} />
        <SafetyRow
          label="Backend restart"
          ok
          detail={config.restartEnabled ? `Enabled via ${config.restartCommandSource}` : 'Manual restart'}
        />
      </div>
    </div>
  );
}

interface ConfigFormState {
  remoteName: string;
  branch: string;
  installMode: string;
  restartCommand: string;
  restartAfterUpdate: boolean;
}

function formFromConfig(config: UpdateConfig): ConfigFormState {
  return {
    remoteName: config.remoteName || 'origin',
    branch: config.branch || 'main',
    installMode: config.installMode || 'npm-ci-omit-dev',
    restartCommand: config.restartCommand || '',
    restartAfterUpdate: !!config.restartAfterUpdate,
  };
}

const INSTALL_MODES: Array<{ value: string; label: string }> = [
  { value: 'npm-ci-omit-dev', label: 'npm ci --omit=dev' },
  { value: 'npm-ci', label: 'npm ci' },
  { value: 'skip', label: 'Skip install' },
];

interface ConfigFieldsProps {
  form: ConfigFormState;
  disabled: boolean;
  onChange: (patch: Partial<ConfigFormState>) => void;
}

function ConfigFields({ form, disabled, onChange }: ConfigFieldsProps) {
  return (
    <div className="field-grid updates-field-grid">
      <label htmlFor="updateRemoteName">Git remote</label>
      <input
        id="updateRemoteName"
        type="text"
        maxLength={80}
        value={form.remoteName}
        disabled={disabled}
        onChange={(event) => onChange({ remoteName: event.target.value })}
      />
      <label htmlFor="updateBranch">GitHub branch</label>
      <input
        id="updateBranch"
        type="text"
        maxLength={128}
        value={form.branch}
        disabled={disabled}
        onChange={(event) => onChange({ branch: event.target.value })}
      />
      <label htmlFor="updateInstallMode">Dependency step</label>
      <select
        id="updateInstallMode"
        value={form.installMode}
        disabled={disabled}
        onChange={(event) => onChange({ installMode: event.target.value })}
      >
        {INSTALL_MODES.map((mode) => (
          <option key={mode.value} value={mode.value}>
            {mode.label}
          </option>
        ))}
      </select>
      <label htmlFor="updateRestartCommand">Restart command</label>
      <input
        id="updateRestartCommand"
        type="text"
        maxLength={256}
        placeholder="systemctl restart redactwall"
        value={form.restartCommand}
        disabled={disabled}
        onChange={(event) => onChange({ restartCommand: event.target.value })}
      />
      <label htmlFor="updateRestartAfter">Auto-run restart command</label>
      <input
        id="updateRestartAfter"
        type="checkbox"
        checked={form.restartAfterUpdate}
        disabled={disabled}
        onChange={(event) => onChange({ restartAfterUpdate: event.target.checked })}
      />
    </div>
  );
}

interface ConfigCardProps {
  config: UpdateConfig;
  disabled: boolean;
  saveStatus: string;
  onSave: (form: ConfigFormState) => void;
}

function ConfigCard({ config, disabled, saveStatus, onSave }: ConfigCardProps) {
  const [form, setForm] = useState(() => formFromConfig(config));
  useEffect(() => {
    setForm(formFromConfig(config));
  }, [config]);
  const patch = (next: Partial<ConfigFormState>) => setForm((prev) => ({ ...prev, ...next }));
  return (
    <div className="config-card pad">
      <h3>Controlled Update Configuration</h3>
      <p>Fill these once for the production host. Settings are stored beside the active evidence database, not in source.</p>
      <ConfigFields form={form} disabled={disabled} onChange={patch} />
      <p className="config-subtitle">Backend restart execution requires REDACTWALL_UPDATE_RESTART_ENABLED=true on the host.</p>
      <div className="update-action-row">
        <button className="btn approve" type="button" disabled={disabled} onClick={() => onSave(form)}>
          <CheckIcon />
          Save configuration
        </button>
        <span className="save-status" role="status">
          {saveStatus}
        </span>
      </div>
    </div>
  );
}

function LastRunLog({ run }: { run: UpdateLastRun }) {
  return (
    <div className="update-log">
      <LogRow label="Status" value={humanize(run.status)} />
      <LogRow label="Stage" value={humanize(run.stage || 'complete')} />
      <LogRow label="Started" value={fmt(run.startedAt)} />
      <LogRow label="Completed" value={fmt(run.completedAt)} />
      <LogRow label="From" value={shortCommit(run.fromCommit)} />
      <LogRow label="To" value={shortCommit(run.toCommit)} />
      <LogRow label="Backup" value={run.backup?.manifestFile || ''} />
      {run.error ? <LogRow label="Error" value={run.error} /> : null}
    </div>
  );
}

function LastRunCard({ lastRun }: { lastRun?: UpdateLastRun | null }) {
  return (
    <div className="config-card pad">
      <h3>Last Run</h3>
      <p>Update activity is also written to the tamper-evident audit log.</p>
      {lastRun?.status ? (
        <LastRunLog run={lastRun} />
      ) : (
        <div className="empty">
          <div className="big">No update runs</div>
          Check GitHub before the first production update.
        </div>
      )}
    </div>
  );
}

type ConfirmKind = 'apply' | 'restart';

const CONFIRM_COPY: Record<ConfirmKind, { title: string; message: string; confirmLabel: string }> = {
  apply: {
    title: 'Update from GitHub',
    message:
      'RedactWall will verify the audit chain, create a database backup, fast-forward source from GitHub, and install dependencies. Continue?',
    confirmLabel: 'Continue',
  },
  restart: {
    title: 'Restart service',
    message: 'Run the configured restart command now? The dashboard may briefly disconnect.',
    confirmLabel: 'Restart',
  },
};

interface ConfirmDialogProps {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/** Replacement for the legacy native confirm() on apply/restart (CSP-safe dialog). */
function ConfirmDialog({ title, message, confirmLabel, onConfirm, onCancel }: ConfirmDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
  }, []);
  return (
    <dialog
      ref={dialogRef}
      className="stepup-dialog"
      aria-label={title}
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <div className="stepup-panel">
        <div>
          <h2>{title}</h2>
          <p>{message}</p>
        </div>
        <div className="stepup-actions">
          <button className="btn" type="button" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn approve" type="button" autoFocus onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </dialog>
  );
}

function useUpdateStore(enabled: boolean) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [loadError, setLoadError] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [pillOverride, setPillOverride] = useState<Pill | null>(null);
  const load = useCallback(async () => {
    if (!enabled) return;
    const result = await fetchUpdateStatus();
    setStatus(result.status);
    setLoadError(result.error);
    setPillOverride(null);
    setLoaded(true);
  }, [enabled]);
  useEffect(() => {
    load();
  }, [load]);
  /** Some mutations return the fresh status object - adopt it exactly as a reload would. */
  const replace = useCallback((next: UpdateStatus) => {
    setStatus(next);
    setLoadError('');
    setPillOverride(null);
    setLoaded(true);
  }, []);
  return { status, loadError, loaded, load, replace, pillOverride, setPillOverride };
}

function useUpdateActions(store: ReturnType<typeof useUpdateStore>) {
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<ConfirmKind | null>(null);
  const [saveStatus, setSaveStatus] = useState('');

  const saveConfig = async (form: ConfigFormState) => {
    setSaveStatus('Saving');
    setBusy(true);
    try {
      const body = {
        remoteName: form.remoteName || 'origin',
        branch: form.branch || 'main',
        installMode: form.installMode || 'npm-ci-omit-dev',
        restartCommand: form.restartCommand || '',
        restartAfterUpdate: form.restartAfterUpdate,
      };
      const result = await updateSend<UpdateStatus>('/api/update/config', 'PUT', body, 'Could not save');
      if (!result.data) {
        setSaveStatus(result.error || 'Could not save');
        return;
      }
      store.replace(result.data);
      setSaveStatus('Saved');
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    store.setPillOverride({ state: 'warn', label: 'Checking' });
    setBusy(true);
    try {
      const result = await updateSend<UpdateCheckResult>('/api/update/check', 'POST', undefined, 'Could not check GitHub');
      // Reload the base status FIRST (it resets pillOverride), then apply the
      // check result so the "Update available"/"Current" pill survives instead of
      // being wiped by the reload milliseconds later.
      await store.load();
      if (!result.data) {
        store.setPillOverride({ state: 'bad', label: 'Check failed' });
        toast(result.error || 'Could not check GitHub', 'error');
      } else if (result.data.updateAvailable) {
        store.setPillOverride({ state: 'warn', label: 'Update available' });
      } else {
        store.setPillOverride({ state: 'good', label: 'Current' });
      }
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    store.setPillOverride({ state: 'warn', label: 'Updating' });
    setBusy(true);
    try {
      const result = await updateSend<unknown>('/api/update/apply', 'POST', { confirmBackup: true }, 'Update failed');
      if (result.error) {
        store.setPillOverride({ state: 'bad', label: 'Update failed' });
        toast(result.error, 'error');
      }
      await store.load();
    } finally {
      setBusy(false);
    }
  };

  /** On success the legacy console does NOT reload - the server may go down mid-restart. */
  const restart = async () => {
    setBusy(true);
    try {
      const result = await updateSend<unknown>('/api/update/restart', 'POST', undefined, 'Restart failed');
      if (result.error) {
        toast(result.error, 'error');
        return;
      }
      store.setPillOverride({ state: 'warn', label: 'Restarting' });
    } finally {
      setBusy(false);
    }
  };

  const confirmAction = () => {
    const kind = confirming;
    setConfirming(null);
    if (kind === 'apply') apply();
    if (kind === 'restart') restart();
  };

  return { busy, confirming, setConfirming, saveStatus, saveConfig, check, confirmAction };
}

interface UpdatesBodyProps {
  sessionLoading: boolean;
  isAdmin: boolean;
  store: ReturnType<typeof useUpdateStore>;
  actions: ReturnType<typeof useUpdateActions>;
}

/** Stable fallback so ConfigCard's reset effect only fires when the status object changes. */
const EMPTY_CONFIG: UpdateConfig = {};

function UpdatesBody({ sessionLoading, isAdmin, store, actions }: UpdatesBodyProps) {
  if (!sessionLoading && !isAdmin) {
    return <div className="readonly-note">Use a Security Admin account to configure and run application updates.</div>;
  }
  if (sessionLoading || !store.loaded) return <div className="app-loading">Loading update status…</div>;
  if (!store.status) return <div className="readonly-note">{store.loadError || 'Update status unavailable.'}</div>;
  const status = store.status;
  const flags = deriveFlags(status);
  return (
    <div className="update-grid">
      <GithubCard
        status={status}
        flags={flags}
        busy={actions.busy}
        onCheck={actions.check}
        onUpdate={() => actions.setConfirming('apply')}
        onRestart={() => actions.setConfirming('restart')}
      />
      <PreservationCard status={status} dirtyDetail={flags.dirtyDetail} />
      <ConfigCard
        config={status.config || EMPTY_CONFIG}
        disabled={status.inProgress || actions.busy}
        saveStatus={actions.saveStatus}
        onSave={actions.saveConfig}
      />
      <LastRunCard lastRun={status.lastRun} />
    </div>
  );
}

function headerMeta(sessionLoading: boolean, isAdmin: boolean, store: ReturnType<typeof useUpdateStore>): ReactNode {
  if (sessionLoading) return 'Loading';
  if (!isAdmin) return <StatePill pill={{ state: 'warn', label: 'Admin only' }} />;
  if (!store.loaded) return 'Loading';
  if (!store.status) return <StatePill pill={{ state: 'bad', label: 'Unavailable' }} />;
  return <StatePill pill={store.pillOverride ?? updateStatusState(store.status)} />;
}

export default function Updates() {
  const { me, loading: sessionLoading } = useSession();
  const isAdmin = me?.role === 'security_admin';
  const store = useUpdateStore(!sessionLoading && isAdmin);
  const actions = useUpdateActions(store);

  return (
    <div className="updates-view">
      <Panel title="Controlled Updates" meta={headerMeta(sessionLoading, isAdmin, store)}>
        <p className="app-note">Pull approved RedactWall releases from GitHub while preserving Texas FCU evidence data, logs, and backups.</p>
        <UpdatesBody sessionLoading={sessionLoading} isAdmin={isAdmin} store={store} actions={actions} />
      </Panel>
      {actions.confirming ? (
        <ConfirmDialog
          {...CONFIRM_COPY[actions.confirming]}
          onConfirm={actions.confirmAction}
          onCancel={() => actions.setConfirming(null)}
        />
      ) : null}
    </div>
  );
}
