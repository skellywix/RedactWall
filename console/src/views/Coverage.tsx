import { useCallback, useEffect, useRef, useState, type CSSProperties, type FormEvent, type ReactNode } from 'react';
import { EmptyState } from '../components/Panel';
import { api, apiJson } from '../lib/api';
import { useSession } from '../lib/session';
import { useEventStream } from '../lib/sse';
import { toast } from '../lib/toast';
import './Coverage.css';

/**
 * Sensor Coverage view. Route contract from server/app.js:
 *   GET  /api/coverage             -> coverage.summarize() report: score, totals, sensors,
 *                                     fleet, endpoint inventories, destinations, posture.
 *   GET  /api/fleet                -> fleet.summary(): { users } per-user sensor presence matrix.
 *   POST /api/destinations/review  -> body { destination, decision: govern|allow|block, reason };
 *                                     security_admin only; 200 returns a fresh { coverage } report,
 *                                     so the client re-renders from the response instead of refetching.
 * Failed reads keep the last-good report (legacy parity: a 500 must not clear rendered data).
 */

interface InstallHealth {
  state?: string;
  failedChecks?: string[];
}

interface CoverageSensor {
  source: string;
  label?: string;
  required?: boolean;
  events?: number;
  lastSeen?: string | null;
  latestVersion?: string | null;
  desiredVersion?: string | null;
  versionHealth?: string;
  versions?: Array<{ version?: string }>;
  platforms?: string[];
  installHealth?: InstallHealth | null;
}

interface CoverageFleetRow extends CoverageSensor {
  user?: string;
  orgId?: string | null;
  state?: string;
}

interface EndpointToolRow {
  id?: string;
  label?: string;
  state?: string;
  detail?: string;
  user?: string;
  orgId?: string | null;
  lastSeen?: string | null;
  platforms?: string[];
}

interface DestinationAggregate {
  destination: string;
  policyState?: string;
  events?: number;
  blocked?: number;
  redacted?: number;
  shadow?: number;
  users?: number;
  source?: string;
  sources?: string[];
  lastSeen?: string | null;
}

interface PostureItem {
  id: string;
  label: string;
  state: string;
  detail: string;
}

interface CoverageTotals {
  events?: number;
  governedDestinations?: number;
  governedActive?: number;
  shadowEvents?: number;
  freshDiscoveryFeeds?: number;
  discoveryFeeds?: number;
  blocked?: number;
  fleetAttention?: number;
}

interface CoverageReport {
  score?: number;
  totals?: CoverageTotals;
  sensors?: CoverageSensor[];
  fleet?: CoverageFleetRow[];
  endpointAiTools?: EndpointToolRow[];
  endpointMcpServers?: EndpointToolRow[];
  endpointFileFlowProfiles?: EndpointToolRow[];
  governedDestinations?: DestinationAggregate[];
  shadowDestinations?: DestinationAggregate[];
  posture?: PostureItem[];
}

interface FleetSensorPresence {
  state: string;
  lastSeen: string | null;
  version: string | null;
}

interface FleetGap {
  sensor: string;
  state: string;
}

interface FleetUser {
  user: string;
  sensors: Record<string, FleetSensorPresence>;
  gaps: FleetGap[];
}

interface FleetSummary {
  users: FleetUser[];
}

type ReviewDecision = 'govern' | 'allow' | 'block';

interface ReviewRequest {
  destination: string;
  decision: ReviewDecision;
}

const FLEET_TIMEOUT_MS = 2500;

function fetchCoverage(): Promise<CoverageReport | null> {
  return apiJson<CoverageReport>('/api/coverage');
}

/** Legacy parity: the fleet fetch is abandoned after 2.5s so a slow matrix never delays the tab. */
async function fetchFleet(): Promise<FleetSummary | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FLEET_TIMEOUT_MS);
  try {
    return await apiJson<FleetSummary>('/api/fleet', { signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function postDestinationReview(request: ReviewRequest, reason: string): Promise<CoverageReport | null> {
  const res = await api('/api/destinations/review', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ destination: request.destination, decision: request.decision, reason }),
  });
  if (!res || !res.ok) return null;
  try {
    const body = (await res.json()) as { coverage?: CoverageReport };
    return body.coverage ?? null;
  } catch {
    return null;
  }
}

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');

type ChipTone = 'secure' | 'warn' | 'critical' | 'live';

function postureToneClass(state?: string): ChipTone {
  return (state || '').toLowerCase() === 'covered' ? 'secure' : 'warn';
}

function fleetToneClass(state?: string): ChipTone {
  const s = (state || '').toLowerCase();
  if (s === 'covered') return 'secure';
  if (s === 'attention' || s === 'missing' || s === 'outdated') return 'critical';
  return 'warn';
}

function inventoryToneClass(state?: string): ChipTone {
  return (state || '').toLowerCase() === 'approved' ? 'secure' : 'critical';
}

function destinationToneClass(state?: string): ChipTone {
  if (state === 'allowed' || state === 'governed') return 'secure';
  if (state === 'blocked' || state === 'file_upload_blocked') return 'critical';
  return 'warn';
}

function presenceToneClass(state: string): ChipTone {
  if (state === 'active') return 'secure';
  return state === 'stale' ? 'warn' : 'critical';
}

function fileFlowToneClass(state?: string): ChipTone {
  if (state === 'covered') return 'secure';
  return state === 'attention' || state === 'missing' ? 'warn' : 'live';
}

function fileFlowStateLabel(state?: string): string {
  if (state === 'covered') return 'Covered';
  if (state === 'attention') return 'Attention';
  return state === 'missing' ? 'Missing' : 'Review';
}

const DESTINATION_POLICY_LABELS: Record<string, string> = {
  allowed: 'Allowed',
  blocked: 'Blocked',
  file_upload_blocked: 'File uploads blocked',
  governed: 'Governed',
  review: 'Needs review',
};

function destinationPolicyLabel(state?: string): string {
  return DESTINATION_POLICY_LABELS[state || ''] || 'Needs review';
}

const SOURCE_LABELS: Record<string, string> = {
  browser_extension: 'Browser',
  endpoint_agent: 'Endpoint',
  mcp_guard: 'MCP',
  audit_log: 'Audit',
  approval_queue: 'Approval',
  policy: 'Policy',
  signal_console: 'Console',
  api: 'API',
  proxy: 'Proxy',
};

function sourceLabel(source?: string): string {
  return SOURCE_LABELS[source || ''] || source || 'API';
}

function sensorMetaLine(s: CoverageSensor): string {
  const parts: string[] = [s.lastSeen ? fmt(s.lastSeen) : 'No events observed'];
  if (s.latestVersion) parts.push(`v${s.latestVersion}`);
  else if (s.events) parts.push('version unknown');
  if (s.desiredVersion) parts.push(`desired v${s.desiredVersion}`);
  if (s.versionHealth === 'mixed') parts.push(`${(s.versions || []).length} versions`);
  if (s.versionHealth === 'outdated') parts.push('outdated');
  if (s.installHealth?.state === 'attention') parts.push(`${s.installHealth.failedChecks?.length || 1} failed checks`);
  else if (s.installHealth?.state === 'covered') parts.push('install checks ok');
  if (s.required) parts.push('required');
  if (s.platforms?.length) parts.push(s.platforms.join(', '));
  return parts.join(' | ');
}

function fleetVersionLine(row: CoverageFleetRow): string {
  const parts: string[] = [];
  if (row.latestVersion) parts.push(`v${row.latestVersion}`);
  else if (row.events) parts.push('version unknown');
  if (row.desiredVersion) parts.push(`desired v${row.desiredVersion}`);
  if (row.platforms?.length) parts.push(row.platforms.join(', '));
  return parts.join(' | ') || '-';
}

function fleetFailedChecks(row: CoverageFleetRow): string {
  const failed = row.installHealth?.failedChecks;
  if (failed && failed.length) return failed.join(', ');
  if (row.installHealth?.state === 'covered') return 'checks ok';
  if (row.state === 'missing') return 'no required sensor evidence';
  if (row.state === 'unknown') return 'no install-health heartbeat';
  return '-';
}

function inventoryMeta(row: EndpointToolRow): string {
  const parts = [row.user || 'unknown', row.orgId || '', (row.platforms || []).join(', '), row.lastSeen ? fmt(row.lastSeen) : ''];
  return parts.filter(Boolean).join(' | ') || '-';
}

/** Legacy quirk kept: file-flow lastSeen is shown raw (not fmt-ed) and local paths are never reported. */
function fileFlowMeta(profile: EndpointToolRow): string {
  const parts: string[] = [];
  if (profile.user) parts.push(profile.user);
  if (profile.orgId) parts.push(profile.orgId);
  if (profile.platforms?.length) parts.push(profile.platforms.join(', '));
  if (profile.lastSeen) parts.push(`Last seen ${profile.lastSeen}`);
  parts.push('Local path: not reported');
  return parts.join(' | ');
}

const aiToolTip = (row: EndpointToolRow) =>
  `Endpoint tool: ${row.label || row.id || 'unknown'}\nPermission state: ${row.state || 'unknown'}\nLast seen: ${fmt(row.lastSeen)}`;

const mcpServerTip = (row: EndpointToolRow) =>
  `Endpoint MCP server: ${row.id || 'unknown'}\nApproval state: ${row.state || 'unknown'}\nLast seen: ${fmt(row.lastSeen)}`;

const FLEET_MATRIX_SENSORS = ['browser_extension', 'endpoint_agent', 'mcp_guard'] as const;

const FLEET_SENSOR_LABEL: Record<string, string> = {
  browser_extension: 'Browser extension',
  endpoint_agent: 'Endpoint agent',
  mcp_guard: 'MCP guard',
};

const MISSING_PRESENCE: FleetSensorPresence = { state: 'missing', lastSeen: null, version: null };

function presenceDetail(info: FleetSensorPresence): string {
  if (info.state === 'active') return `Reporting. Last seen ${fmt(info.lastSeen)}${info.version ? ` (v${info.version})` : ''}`;
  if (info.state === 'stale') return `Went quiet. Last seen ${fmt(info.lastSeen)} - sensor may be uninstalled or broken`;
  return 'Never reported for this user';
}

function kpiCells(t: CoverageTotals): Array<{ label: string; value: string | number }> {
  return [
    { label: 'Events', value: t.events || 0 },
    { label: 'Governed', value: `${t.governedActive || 0}/${t.governedDestinations || 0}` },
    { label: 'Shadow AI', value: t.shadowEvents || 0 },
    { label: 'Feeds fresh', value: `${t.freshDiscoveryFeeds || 0}/${t.discoveryFeeds || 0}` },
    { label: 'Blocked', value: t.blocked || 0 },
    { label: 'Fleet gaps', value: t.fleetAttention || 0 },
  ];
}

const REVIEW_VERBS: Record<ReviewDecision, string> = { govern: 'govern', allow: 'allow', block: 'block' };

const CHECK_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="m5 12 4 4L19 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const DENY_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M6 6l12 12M18 6 6 18" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
  </svg>
);

const SHIELD_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M12 4l7 3v5c0 4.2-2.6 6.8-7 8-4.4-1.2-7-3.8-7-8V7l7-3Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
  </svg>
);

const REFRESH_ICON = (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

function useCoverageData() {
  const [coverage, setCoverage] = useState<CoverageReport | null>(null);
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    try {
      const [nextCoverage, nextFleet] = await Promise.all([fetchCoverage(), fetchFleet()]);
      if (nextFleet) setFleet(nextFleet);
      if (nextCoverage) setCoverage(nextCoverage);
    } finally {
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  useEventStream({ query: load });
  const applyCoverage = useCallback((report: CoverageReport) => setCoverage(report), []);
  return { coverage, fleet, loaded, load, applyCoverage };
}

function useDestinationReview(applyCoverage: (report: CoverageReport) => void) {
  const [request, setRequest] = useState<ReviewRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const open = useCallback((destination: string, decision: ReviewDecision) => setRequest({ destination, decision }), []);
  const cancel = useCallback(() => setRequest(null), []);
  const confirm = async (reason: string) => {
    if (!request) return;
    const pending = request;
    setRequest(null);
    setBusy(true);
    try {
      const fresh = await postDestinationReview(pending, reason);
      if (fresh) applyCoverage(fresh);
      else toast('Destination review could not be saved.', 'error');
    } finally {
      setBusy(false);
    }
  };
  return { request, busy, open, cancel, confirm };
}

interface StatusChipProps {
  tone: ChipTone;
  label: string;
  detail: string;
  light?: boolean;
}

function StatusChip({ tone, label, detail, light }: StatusChipProps) {
  return (
    <span className={`pill status-chip tone-${tone}`} tabIndex={0} role="button" title={detail}>
      {light ? <span className={`status-light tone-${tone}`} aria-hidden="true" /> : null}
      {label}
    </span>
  );
}

interface CoveragePanelProps {
  title: string;
  subtitle: string;
  wide?: boolean;
  headExtra?: ReactNode;
  children: ReactNode;
}

/** Legacy .panel markup: console-base.css styles the head, tables, and rows for free. */
function CoveragePanel({ title, subtitle, wide, headExtra, children }: CoveragePanelProps) {
  return (
    <div className={wide ? 'panel wide-panel' : 'panel'}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          <span>{subtitle}</span>
        </div>
        {headExtra}
      </div>
      {children}
    </div>
  );
}

function InventoryEmpty({ big, detail }: { big: string; detail: string }) {
  return (
    <div className="empty">
      <div className="big">{big}</div>
      {detail}
    </div>
  );
}

const FLEET_MATRIX_SUBTITLE =
  'Sensors report on each other: a user seen by one sensor but not its companions is a coverage gap. ' +
  'Sensors silent past 48h are flagged STALE and fire a SENSOR_STALE alert to subscribed SIEM destinations.';

function FleetMatrixRow({ user }: { user: FleetUser }) {
  return (
    <tr>
      <td>{user.user}</td>
      {FLEET_MATRIX_SENSORS.map((key) => {
        const info = user.sensors[key] ?? MISSING_PRESENCE;
        return (
          <td key={key}>
            <StatusChip tone={presenceToneClass(info.state)} label={info.state.toUpperCase()} detail={presenceDetail(info)} />
          </td>
        );
      })}
      <td>
        {user.gaps.length ? (
          user.gaps.map((gap) => (
            <span className="sev high" key={`${gap.sensor}:${gap.state}`}>
              {`${FLEET_SENSOR_LABEL[gap.sensor] || gap.sensor} ${gap.state}`}
            </span>
          ))
        ) : (
          <span className="sev low">covered</span>
        )}
      </td>
    </tr>
  );
}

function FleetMatrixPanel({ users }: { users: FleetUser[] }) {
  return (
    <CoveragePanel title="Fleet by user" subtitle={FLEET_MATRIX_SUBTITLE}>
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Browser extension</th>
            <th>Endpoint agent</th>
            <th>MCP guard</th>
            <th>Coverage gaps</th>
          </tr>
        </thead>
        <tbody>
          {users.length ? (
            users.map((user) => <FleetMatrixRow key={user.user} user={user} />)
          ) : (
            <tr>
              <td colSpan={5} className="empty">
                No sensors have reported yet. Fleet coverage appears as soon as a sensor sends its first event or heartbeat.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </CoveragePanel>
  );
}

function ScoreCard({ score, totals }: { score: number; totals: CoverageTotals }) {
  return (
    <div className="score-panel">
      <div className="score-ring" style={{ '--score': `${score}%` } as CSSProperties}>
        <b>{score}</b>
      </div>
      <span>Coverage score</span>
      <div className="coverage-kpis">
        {kpiCells(totals).map((cell) => (
          <div className="mini-kpi" key={cell.label}>
            <b>{cell.value}</b>
            <span>{cell.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PostureList({ items }: { items: PostureItem[] }) {
  return (
    <div className="posture-list">
      {items.map((item) => (
        <div className="posture-item" key={item.id}>
          <span>
            {item.label}{' '}
            <StatusChip
              tone={postureToneClass(item.state)}
              label={item.state}
              detail={`System health: ${item.label}\nState: ${item.state}\nDetail: ${item.detail}`}
            />
          </span>
          <b>{item.detail}</b>
        </div>
      ))}
    </div>
  );
}

function PosturePanel({ report, onRefresh }: { report: CoverageReport; onRefresh: () => void }) {
  return (
    <CoveragePanel
      title="AI Coverage Posture"
      subtitle="Governed apps, sensors, and shadow-AI signals"
      headExtra={
        <button className="ghost" id="refreshCoverage" type="button" onClick={onRefresh}>
          {REFRESH_ICON}
          Refresh
        </button>
      }
    >
      <div className="coverage-body">
        <ScoreCard score={report.score ?? 0} totals={report.totals ?? {}} />
        <PostureList items={report.posture ?? []} />
      </div>
    </CoveragePanel>
  );
}

function SensorMixPanel({ sensors }: { sensors: CoverageSensor[] }) {
  return (
    <CoveragePanel title="Sensor Mix" subtitle="Observed control points">
      <div>
        {sensors.map((sensor) => (
          <div className="sensor-row" key={sensor.source}>
            <div>
              <strong>{sensor.label || sensor.source}</strong>
              <span>{sensorMetaLine(sensor)}</span>
            </div>
            <div className="count">{sensor.events || 0}</div>
          </div>
        ))}
      </div>
    </CoveragePanel>
  );
}

function FleetHealthRow({ row }: { row: CoverageFleetRow }) {
  const checks = fleetFailedChecks(row);
  const lastSeen = row.lastSeen ? fmt(row.lastSeen) : '-';
  const state = row.state || 'unknown';
  return (
    <tr>
      <td>{row.user || 'unknown'}</td>
      <td className="mono">{row.orgId || '-'}</td>
      <td>{row.label || sourceLabel(row.source)}</td>
      <td>
        <StatusChip
          tone={fleetToneClass(row.state)}
          label={state}
          detail={`Verification state: ${state}\nUser: ${row.user || 'unknown'}\nFailed checks: ${checks}\nLast seen: ${lastSeen}`}
        />
      </td>
      <td className="mono">{fleetVersionLine(row)}</td>
      <td>{checks}</td>
      <td className="mono">{lastSeen}</td>
    </tr>
  );
}

function FleetHealthPanel({ rows }: { rows: CoverageFleetRow[] }) {
  return (
    <CoveragePanel title="Fleet Install Health" subtitle="Latest required-sensor state by user and tenant" wide>
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Org</th>
            <th>Sensor</th>
            <th>State</th>
            <th>Version</th>
            <th>Failed Checks</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((row, index) => <FleetHealthRow key={`${row.source}:${row.user || ''}:${row.orgId || ''}:${index}`} row={row} />)
          ) : (
            <tr>
              <td colSpan={7} className="empty">
                No fleet sensor evidence yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </CoveragePanel>
  );
}

interface InventoryListProps {
  rows: EndpointToolRow[];
  name: (row: EndpointToolRow) => string;
  tip: (row: EndpointToolRow) => string;
  emptyBig: string;
  emptyDetail: string;
}

function InventoryList({ rows, name, tip, emptyBig, emptyDetail }: InventoryListProps) {
  if (!rows.length) return <InventoryEmpty big={emptyBig} detail={emptyDetail} />;
  return (
    <div>
      {rows.map((row, index) => (
        <div className="tool-row" key={`${row.id || ''}:${row.user || ''}:${index}`}>
          <div>
            <strong>{name(row)}</strong>
            <span>{inventoryMeta(row)}</span>
          </div>
          <div className="tool-state">
            <StatusChip tone={inventoryToneClass(row.state)} label={row.state || 'unknown'} detail={tip(row)} />
            <span>{row.detail || '-'}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function FileFlowList({ rows }: { rows: EndpointToolRow[] }) {
  if (!rows.length) {
    return <EmptyState title="No file-flow profiles" detail="Endpoint watchers appear here without local paths." />;
  }
  return (
    <div>
      {rows.map((profile, index) => (
        <div className="tool-row" key={`${profile.id || ''}:${profile.user || ''}:${index}`}>
          <div>
            <strong>{profile.id || 'unnamed_profile'}</strong>
            <span>{fileFlowMeta(profile)}</span>
          </div>
          <div className="tool-state">
            <StatusChip
              tone={fileFlowToneClass(profile.state)}
              label={fileFlowStateLabel(profile.state)}
              detail={`${profile.detail || fileFlowStateLabel(profile.state)}\nLocal path: not reported`}
              light
            />
            <span>{profile.detail || 'configured profile'}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function GovernedPanel({ rows }: { rows: DestinationAggregate[] }) {
  return (
    <CoveragePanel title="Governed AI Destinations" subtitle="Policy list with observed traffic" wide>
      <table>
        <thead>
          <tr>
            <th>Destination</th>
            <th>Events</th>
            <th>Blocked</th>
            <th>Redacted</th>
            <th>Users</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((row) => (
              <tr key={row.destination}>
                <td className="mono">{row.destination}</td>
                <td className="mono">{row.events ?? 0}</td>
                <td className="mono">{row.blocked ?? 0}</td>
                <td className="mono">{row.redacted ?? 0}</td>
                <td className="mono">{row.users ?? 0}</td>
                <td className="mono">{row.lastSeen ? fmt(row.lastSeen) : '-'}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={6} className="empty">
                No governed destinations are configured.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </CoveragePanel>
  );
}

interface DestinationActionsProps {
  destination: string;
  busy: boolean;
  onReview: (destination: string, decision: ReviewDecision) => void;
}

function DestinationActions({ destination, busy, onReview }: DestinationActionsProps) {
  return (
    <div className="destination-actions">
      <button className="ghost mini" type="button" disabled={busy} data-destination-review="govern" data-destination={destination} onClick={() => onReview(destination, 'govern')}>
        {SHIELD_ICON}
        Govern
      </button>
      <button className="ghost mini" type="button" disabled={busy} data-destination-review="allow" data-destination={destination} onClick={() => onReview(destination, 'allow')}>
        {CHECK_ICON}
        Allow
      </button>
      <button className="ghost mini danger" type="button" disabled={busy} data-destination-review="block" data-destination={destination} onClick={() => onReview(destination, 'block')}>
        {DENY_ICON}
        Block
      </button>
    </div>
  );
}

interface ShadowRowProps {
  row: DestinationAggregate;
  canReview: boolean;
  busy: boolean;
  onReview: (destination: string, decision: ReviewDecision) => void;
}

function ShadowRow({ row, canReview, busy, onReview }: ShadowRowProps) {
  const label = destinationPolicyLabel(row.policyState);
  const lastSeen = row.lastSeen ? fmt(row.lastSeen) : '-';
  const needsReview = (row.policyState || 'review') === 'review';
  return (
    <div className="shadow-row">
      <div>
        <strong>{row.destination}</strong>
        <span>
          {row.users ?? 0} users / {row.sources?.join(', ') || row.source || 'source unknown'} / last {lastSeen}
        </span>
      </div>
      <div className="destination-review">
        <StatusChip
          tone={destinationToneClass(row.policyState)}
          label={label}
          detail={`Destination: ${row.destination}\nPolicy: ${label}\nSource count: ${row.users ?? 0} users\nLast seen: ${lastSeen}`}
        />
        <span className="count">{row.shadow ?? 0}</span>
        {needsReview && canReview ? <DestinationActions destination={row.destination} busy={busy} onReview={onReview} /> : null}
      </div>
    </div>
  );
}

function ShadowPanel({ rows, canReview, busy, onReview }: { rows: DestinationAggregate[] } & Omit<ShadowRowProps, 'row'>) {
  return (
    <CoveragePanel title="Shadow AI" subtitle="Ungoverned AI tools reported by sensors">
      {rows.length ? (
        <div>
          {rows.map((row) => (
            <ShadowRow key={row.destination} row={row} canReview={canReview} busy={busy} onReview={onReview} />
          ))}
        </div>
      ) : (
        <InventoryEmpty big="No shadow AI" detail="No ungoverned AI tools reported." />
      )}
    </CoveragePanel>
  );
}

interface ReasonDialogProps {
  request: ReviewRequest;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}

/** Legacy askDestinationReviewReason(): a blank reason refocuses the textarea; Cancel/Escape abort. */
function ReasonDialog({ request, onConfirm, onCancel }: ReasonDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [reason, setReason] = useState('');

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
  }, []);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = reason.trim();
    if (!trimmed) {
      textareaRef.current?.focus();
      return;
    }
    onConfirm(trimmed);
  };

  return (
    <dialog
      ref={dialogRef}
      className="stepup-dialog"
      aria-label="Record destination reason"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <form className="stepup-panel" onSubmit={submit}>
        <div>
          <h2>Record destination reason</h2>
          <p>
            {REVIEW_VERBS[request.decision]} {request.destination} with a short examiner-facing reason.
          </p>
        </div>
        <label>
          Admin reason
          <textarea ref={textareaRef} name="reason" rows={3} maxLength={240} required autoFocus value={reason} onChange={(event) => setReason(event.target.value)} />
        </label>
        <div className="stepup-actions">
          <button className="btn" type="button" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn approve" type="submit">
            {CHECK_ICON}
            Save review
          </button>
        </div>
      </form>
    </dialog>
  );
}

function CoverageHeader() {
  return (
    <header className="coverage-header">
      <h2>Institution Coverage</h2>
      <p>Track branch browser coverage, endpoint posture, MCP guardrails, governed AI vendors, and shadow-AI gaps.</p>
    </header>
  );
}

const EMPTY_REPORT: CoverageReport = {};

export default function Coverage() {
  const { me } = useSession();
  const data = useCoverageData();
  const review = useDestinationReview(data.applyCoverage);
  const canReview = me?.role === 'security_admin';

  if (!data.loaded) {
    return (
      <div className="coverage-view">
        <CoverageHeader />
        <div className="app-loading">Loading coverage…</div>
      </div>
    );
  }

  const report = data.coverage ?? EMPTY_REPORT;
  return (
    <div className="coverage-view">
      <CoverageHeader />
      <FleetMatrixPanel users={data.fleet?.users ?? []} />
      <div className="coverage-grid">
        <PosturePanel report={report} onRefresh={() => void data.load()} />
        <SensorMixPanel sensors={report.sensors ?? []} />
        <FleetHealthPanel rows={report.fleet ?? []} />
        <CoveragePanel title="Endpoint AI Tools" subtitle="Sanitized local app and agent CLI inventory across institution workstations">
          <InventoryList
            rows={report.endpointAiTools ?? []}
            name={(row) => row.label || row.id || 'Unknown AI tool'}
            tip={aiToolTip}
            emptyBig="No endpoint AI tools"
            emptyDetail="No endpoint AI inventory reported."
          />
        </CoveragePanel>
        <CoveragePanel title="Endpoint MCP Servers" subtitle="Shadow-MCP discovery for institution teams: server id, client, and transport only">
          <InventoryList
            rows={report.endpointMcpServers ?? []}
            name={(row) => row.id || 'unknown server'}
            tip={mcpServerTip}
            emptyBig="No endpoint MCP servers"
            emptyDetail="No endpoint MCP inventory reported."
          />
        </CoveragePanel>
        <CoveragePanel title="Endpoint File Flow" subtitle="Loan-file and member-document watcher profiles without local paths">
          <FileFlowList rows={report.endpointFileFlowProfiles ?? []} />
        </CoveragePanel>
        <GovernedPanel rows={report.governedDestinations ?? []} />
        <ShadowPanel rows={report.shadowDestinations ?? []} canReview={!!canReview} busy={review.busy} onReview={review.open} />
      </div>
      {review.request ? <ReasonDialog request={review.request} onConfirm={review.confirm} onCancel={review.cancel} /> : null}
    </div>
  );
}
