import type { ReactElement } from 'react';
import type { PostureSurface } from '../api/posture';
import { navigate } from '../lib/router';

export interface NavItem {
  path: string;
  label: string;
  icon: ReactElement;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

interface NavRailProps {
  groups: NavGroup[];
  activePath: string;
  pending: number;
  surfaces: PostureSurface[] | null;
  version: string;
}

// Brand mark, verbatim from the legacy rail (server/public/index.html).
const LOGO = (
  <svg viewBox="0 0 24 24" fill="none"><g fill="#fff"><rect x="4.5" y="5.5" width="10" height="3" rx="1.5" /><rect x="16" y="5.5" width="3.5" height="3" rx="1.5" opacity=".5" /><rect x="4.5" y="10.5" width="5" height="3" rx="1.5" opacity=".5" /><rect x="11" y="10.5" width="8.5" height="3" rx="1.5" /><rect x="4.5" y="15.5" width="11" height="3" rx="1.5" /><rect x="17" y="15.5" width="2.5" height="3" rx="1.25" opacity=".5" /></g></svg>
);

interface RailChip {
  tone: 'live' | 'secure' | 'warn' | 'critical';
  label: string;
  detail: string;
  live: boolean;
}

// Chip derivations ported from the legacy renderRailStatus() (dashboard.js).
function hashChainChip(surfaces: PostureSurface[] | null): RailChip {
  const audit = (surfaces ?? []).find((surface) => surface.id === 'surface-audit-evidence');
  if (!audit) {
    return { tone: 'live', label: 'CHECKING', detail: 'CHECKING: audit chain status loads with posture telemetry.', live: false };
  }
  const ok = audit.status === 'online';
  const label = ok ? 'SECURE' : 'REVIEW';
  return { tone: ok ? 'secure' : 'critical', label, detail: `${label}: ${audit.description ?? 'Tamper-evident audit chain'}`, live: false };
}

const SENSOR_SURFACE = /^surface-(browser_extension|endpoint_agent|mcp_guard|proxy)$/;

function localScanChip(surfaces: PostureSurface[] | null): RailChip {
  const sensors = (surfaces ?? []).filter((surface) => SENSOR_SURFACE.test(String(surface.id)));
  if (!sensors.length) {
    return { tone: 'live', label: 'CHECKING', detail: 'CHECKING: sensor scan status loads with posture telemetry.', live: false };
  }
  const online = sensors.filter((surface) => surface.status === 'online').length;
  const label = online ? 'MONITORING' : 'IDLE';
  return {
    tone: online ? 'live' : 'warn',
    label,
    detail: `${label}: ${online}/${sensors.length} local sensors reporting scan traffic.`,
    live: online > 0,
  };
}

function StatusChip({ chip }: { chip: RailChip }) {
  return (
    <button className={`status-chip tone-${chip.tone}`} type="button" title={chip.detail}>
      <span className={`status-light tone-${chip.tone}${chip.live ? ' is-live' : ''}`} aria-hidden="true"></span>
      {chip.label}
    </button>
  );
}

function RailStatus({ surfaces, version }: { surfaces: PostureSurface[] | null; version: string }) {
  return (
    <div className="rail-status">
      <div className="rail-group-label" aria-hidden="true">System status</div>
      <div className="status-line">
        <span>Hash chain</span>
        <StatusChip chip={hashChainChip(surfaces)} />
      </div>
      <div className="status-line">
        <span>Local scan</span>
        <StatusChip chip={localScanChip(surfaces)} />
      </div>
      <div className="status-line">
        <span>Version</span>
        <b>{version}</b>
      </div>
    </div>
  );
}

function NavTab({ item, active, badge }: { item: NavItem; active: boolean; badge: number }) {
  return (
    <button
      type="button"
      className={active ? 'tab active' : 'tab'}
      aria-current={active ? 'page' : undefined}
      onClick={() => navigate(item.path)}
    >
      <span className="tab-icon" aria-hidden="true">{item.icon}</span>
      {item.label}
      {badge > 0 ? <span className="badge">{badge}</span> : null}
    </button>
  );
}

export default function NavRail({ groups, activePath, pending, surfaces, version }: NavRailProps) {
  return (
    <aside className="app-rail">
      <div className="brand">
        <div className="logo" aria-hidden="true">{LOGO}</div>
        <div>
          <h1>RedactWall</h1>
          <p>Texas FCU AI DLP</p>
        </div>
      </div>
      <nav className="tabs" aria-label="Primary">
        {groups.map((group) => (
          <div key={group.label} className="app-rail-group">
            <div className="rail-group-label" aria-hidden="true">{group.label}</div>
            {group.items.map((item) => (
              <NavTab key={item.path} item={item} active={item.path === activePath} badge={item.path === '/queue' ? pending : 0} />
            ))}
          </div>
        ))}
      </nav>
      <RailStatus surfaces={surfaces} version={version} />
    </aside>
  );
}
