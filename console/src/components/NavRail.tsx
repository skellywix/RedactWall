import { Fragment, useRef, type ReactElement, type RefObject } from 'react';
import type { PostureSurface } from '../api/posture';
import { navigate } from '../lib/router';
import type { PostureState } from '../lib/shell';
import { useModalFocus } from './system/useModalFocus';

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
  held: number | null | undefined;
  surfaces: PostureSurface[] | null;
  postureState: PostureState;
  postureUpdatedAt: string;
  version: string;
  mobileOpen: boolean;
  returnFocusRef: RefObject<HTMLButtonElement | null>;
  onClose: () => void;
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

function postureFallbackChip(state: PostureState, updatedAt: string, subject: string): RailChip | null {
  if (state === 'ready') return null;
  if (state === 'stale') {
    return {
      tone: 'warn',
      label: 'LAST VERIFIED',
      detail: `LAST VERIFIED ${updatedAt}: ${subject} is stale; current status is unknown.`,
      live: false,
    };
  }
  if (state === 'unavailable') {
    return { tone: 'critical', label: 'UNAVAILABLE', detail: `UNAVAILABLE: ${subject} could not be verified.`, live: false };
  }
  return { tone: 'live', label: 'CHECKING', detail: `CHECKING: ${subject} is loading.`, live: false };
}

// Chip derivations ported from the legacy renderRailStatus() (dashboard.js).
function hashChainChip(surfaces: PostureSurface[] | null, state: PostureState, updatedAt: string): RailChip {
  const fallback = postureFallbackChip(state, updatedAt, 'audit-chain posture');
  if (fallback) return fallback;
  const audit = (surfaces ?? []).find((surface) => surface.id === 'surface-audit-evidence');
  if (!audit) {
    return { tone: 'warn', label: 'NOT REPORTED', detail: 'NOT REPORTED: the verified posture response omitted audit-chain status.', live: false };
  }
  const ok = audit.status === 'online';
  const label = ok ? 'SECURE' : 'REVIEW';
  return { tone: ok ? 'secure' : 'critical', label, detail: `${label}: ${audit.description ?? 'Tamper-evident audit chain'}`, live: false };
}

const SENSOR_SURFACE = /^surface-(browser_extension|endpoint_agent|mcp_guard|proxy)$/;

function localScanChip(surfaces: PostureSurface[] | null, state: PostureState, updatedAt: string): RailChip {
  const fallback = postureFallbackChip(state, updatedAt, 'local-sensor posture');
  if (fallback) return fallback;
  const sensors = (surfaces ?? []).filter((surface) => SENSOR_SURFACE.test(String(surface.id)));
  if (!sensors.length) {
    return { tone: 'warn', label: 'NOT REPORTED', detail: 'NOT REPORTED: the verified posture response omitted local-sensor status.', live: false };
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
    <span className={`status-chip tone-${chip.tone}`} title={chip.detail} aria-label={chip.detail}>
      <span className={`status-light tone-${chip.tone}${chip.live ? ' is-live' : ''}`} aria-hidden="true"></span>
      {chip.label}
    </span>
  );
}

function RailStatus({ surfaces, postureState, postureUpdatedAt, version }: {
  surfaces: PostureSurface[] | null;
  postureState: PostureState;
  postureUpdatedAt: string;
  version: string;
}) {
  return (
    <div className="rail-status">
      <div className="rail-group-label" aria-hidden="true">System status</div>
      <div className="status-line">
        <span>Hash chain</span>
        <StatusChip chip={hashChainChip(surfaces, postureState, postureUpdatedAt)} />
      </div>
      <div className="status-line">
        <span>Local scan</span>
        <StatusChip chip={localScanChip(surfaces, postureState, postureUpdatedAt)} />
      </div>
      <div className="status-line">
        <span>Version</span>
        <b>{version}</b>
      </div>
    </div>
  );
}

function NavTab({ item, active, badge, onNavigate }: { item: NavItem; active: boolean; badge: number | null | undefined; onNavigate: () => void }) {
  const selectRoute = () => {
    navigate(item.path);
    onNavigate();
  };
  return (
    <button
      type="button"
      className={active ? 'tab active' : 'tab'}
      aria-current={active ? 'page' : undefined}
      onClick={selectRoute}
    >
      <span className="tab-icon" aria-hidden="true">{item.icon}</span>
      {item.label}
      {badge === null
        ? <span className="badge" title="Held queue total not reported" aria-label="Held queue total not reported">?</span>
        : typeof badge === 'number' && badge > 0 ? <span className="badge" aria-label={`${badge} held for review or justification`}>{badge}</span> : null}
    </button>
  );
}

export default function NavRail({ groups, activePath, held, surfaces, postureState, postureUpdatedAt, version, mobileOpen, returnFocusRef, onClose }: NavRailProps) {
  const railRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  useModalFocus({ containerRef: railRef, initialFocusRef: closeRef, returnFocusRef, open: mobileOpen, onDismiss: onClose });

  return (
    <Fragment>
      <div className={mobileOpen ? 'app-nav-backdrop is-open' : 'app-nav-backdrop'} aria-hidden="true" onMouseDown={onClose}></div>
      <aside
        ref={railRef}
        id="primary-navigation"
        className={mobileOpen ? 'app-rail is-mobile-open' : 'app-rail'}
        role={mobileOpen ? 'dialog' : undefined}
        aria-modal={mobileOpen ? true : undefined}
        aria-label={mobileOpen ? 'Navigation menu' : undefined}
        tabIndex={mobileOpen ? -1 : undefined}
      >
        <div className="app-rail-brand-row">
          <div className="brand">
            <div className="logo" aria-hidden="true">{LOGO}</div>
            <div>
              <h1>RedactWall</h1>
              <p>Texas FCU AI DLP</p>
            </div>
          </div>
          <button ref={closeRef} className="app-nav-close ghost" type="button" aria-label="Close navigation menu" onClick={onClose}>
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <nav className="tabs app-rail-nav" aria-label="Primary">
          {groups.map((group) => (
            <div key={group.label} className="app-rail-group">
              <div className="rail-group-label" aria-hidden="true">{group.label}</div>
              {group.items.map((item) => (
                <NavTab
                  key={item.path}
                  item={item}
                  active={item.path === activePath}
                  badge={item.path === '/queue' ? held : 0}
                  onNavigate={onClose}
                />
              ))}
            </div>
          ))}
        </nav>
        <RailStatus surfaces={surfaces} postureState={postureState} postureUpdatedAt={postureUpdatedAt} version={version} />
      </aside>
    </Fragment>
  );
}
