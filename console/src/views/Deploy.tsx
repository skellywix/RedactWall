import { useCallback, useEffect, useRef, useState } from 'react';
import { Panel } from '../components/Panel';
import { apiJson } from '../lib/api';
import './Deploy.css';

/**
 * Deploy API. Route contract from server/app.js:
 *   GET /api/deploy/artifacts (operator or security_admin) ->
 *     { artifacts, history, version }. artifacts: the five sensor packages
 *     (browser extension x3, endpoint agent, MCP guard), built and memoized
 *     on first request — expect the first call after server boot to take
 *     several seconds. An entry with `error` set means packaging failed and
 *     the metadata fields are absent.
 *     history: newest-first DEPLOY_ARTIFACT_DOWNLOADED audit-chain entries
 *     (max 20); empty array when nothing has been downloaded yet.
 *   GET /api/deploy/download/:artifact -> ZIP attachment. Reached only by
 *     <a download> navigation, never fetched; the server audits each pull.
 */

interface DeployArtifact {
  id: string;
  label: string;
  kind: 'extension' | 'endpoint' | 'mcp';
  error?: string;
  fileName?: string;
  fileType?: string;
  sizeBytes?: number;
  sha256?: string | null;
  fileCount?: number | null;
  version?: string;
  requires?: string;
  install?: string;
  guide?: string;
}

interface DeployHistoryEntry {
  ts: string;
  actor: string;
  detail: string;
}

interface DeployReport {
  artifacts: DeployArtifact[];
  history: DeployHistoryEntry[];
}

async function fetchDeployReport(): Promise<DeployReport | null> {
  const body = await apiJson<DeployReport>('/api/deploy/artifacts');
  if (!body || !Array.isArray(body.artifacts)) return null;
  return { artifacts: body.artifacts, history: Array.isArray(body.history) ? body.history : [] };
}

const downloadUrl = (id: string) => `/api/deploy/download/${encodeURIComponent(id)}`;

const fmtTime = (iso: string) => new Date(iso).toLocaleString();

/** Port of the legacy deploySize(): tolerates missing or non-finite manifest sizes. */
function deploySize(bytes: number | undefined): string {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) return 'size on build';
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function useDeployReport() {
  const [report, setReport] = useState<DeployReport | null>(null);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    try {
      setReport(await fetchDeployReport());
    } finally {
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { report, loaded };
}

const COPY_FLASH_MS = 1400;

/** Copies the full SHA-256 and flashes a confirmation, like the legacy delegated handler. */
function ShaChip({ sha256 }: { sha256: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    if (!navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(sha256);
    } catch {
      return;
    }
    setCopied(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setCopied(false), COPY_FLASH_MS);
  };
  return (
    <button className="chip mono" type="button" title="Copy full SHA-256 for installer verification" onClick={copy}>
      <b>SHA-256</b> {copied ? 'copied to clipboard' : <>{sha256.slice(0, 16)}&hellip; &#x2398;</>}
    </button>
  );
}

function ArtifactChips({ artifact }: { artifact: DeployArtifact }) {
  return (
    <div className="chips">
      <span className="chip">
        <b>ZIP</b> {deploySize(artifact.sizeBytes)}
      </span>
      <span className="chip">
        <b>v{artifact.version}</b>
      </span>
      {artifact.fileCount ? <span className="chip">{artifact.fileCount} files</span> : null}
      {artifact.requires ? (
        <span className="chip">
          <b>Runs on</b> {artifact.requires}
        </span>
      ) : null}
      {artifact.sha256 ? <ShaChip sha256={artifact.sha256} /> : null}
      <span className="chip">
        <b>Guide</b> {artifact.guide}
      </span>
    </div>
  );
}

function ArtifactCard({ artifact }: { artifact: DeployArtifact }) {
  if (artifact.error) {
    return (
      <div className="q deploy-card">
        <div className="queue-mainline">
          <strong>{artifact.label}</strong>
          <span>packaging unavailable</span>
          <span />
        </div>
      </div>
    );
  }
  return (
    <div className="q deploy-card">
      <div className="queue-mainline">
        <strong>{artifact.label}</strong>
        <span>{artifact.fileName}</span>
        <a className="btn" href={downloadUrl(artifact.id)} download>
          Download .zip
        </a>
      </div>
      <ArtifactChips artifact={artifact} />
      {artifact.install ? (
        <div className="deploy-install">
          <b>Rollout</b> {artifact.install}
        </div>
      ) : null}
    </div>
  );
}

function HistoryList({ history }: { history: DeployHistoryEntry[] }) {
  if (!history.length) {
    return <div className="empty">No downloads recorded yet. Every download is written to the audit chain.</div>;
  }
  return (
    <div className="inspector-grid">
      {history.map((entry, index) => (
        <div className="inspector-field" key={`${entry.ts}-${index}`}>
          <span>{fmtTime(entry.ts)}</span>
          <b>
            {entry.actor} - {entry.detail}
          </b>
        </div>
      ))}
    </div>
  );
}

export default function Deploy() {
  const { report, loaded } = useDeployReport();

  const renderPackages = () => {
    if (!loaded) {
      return <div className="app-loading">Building sensor packages… the first build after a restart takes a few seconds.</div>;
    }
    if (!report) return <div className="empty">Deploy packages are unavailable — retry, or confirm you have the operator or security admin role.</div>;
    return (
      <div className="queue-list deploy-list">
        {report.artifacts.map((artifact) => (
          <ArtifactCard key={artifact.id} artifact={artifact} />
        ))}
      </div>
    );
  };

  const renderHistory = () => {
    if (!loaded) return <div className="app-loading">Loading download history…</div>;
    if (!report) return <div className="empty">Download history is unavailable.</div>;
    return <HistoryList history={report.history} />;
  };

  const packagesMeta = !loaded ? 'Building packages' : `${report?.artifacts.length ?? 0} packages`;
  const historyMeta = !loaded ? 'Loading' : `${report?.history.length ?? 0} downloads`;
  return (
    <div className="deploy-view">
      <Panel title="Sensor packages" meta={packagesMeta}>
        <p className="app-note">Built on demand from this control plane&apos;s exact version; every download is audited.</p>
        {renderPackages()}
      </Panel>
      <Panel title="Download history" meta={historyMeta}>
        <p className="app-note">Who pulled which package, straight from the tamper-evident audit chain.</p>
        {renderHistory()}
      </Panel>
    </div>
  );
}
