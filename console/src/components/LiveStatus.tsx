import type { ReactElement } from 'react';
import type { LiveState } from '../lib/shell';

interface LiveStatusProps {
  state: LiveState;
  lastUpdated: string;
}

/** Topbar LIVE chip + LAST UPDATED stamp, ported from the legacy setLiveState()/markUpdated(). */
export default function LiveStatus({ state, lastUpdated }: LiveStatusProps): ReactElement {
  const syncing = state === 'reconnecting';
  const tone = syncing ? 'tone-warn' : 'tone-live';
  const label = syncing ? 'SYNCING' : 'LIVE';
  const detail = syncing
    ? 'SYNCING: session telemetry stream is reconnecting.'
    : 'LIVE: session telemetry stream is connected.';
  return (
    <>
      <button className="live" type="button" title={detail}>
        <span className={`status-chip ${tone}`}>
          <span className={`status-light ${tone} is-live`} aria-hidden="true"></span>
          <span id="liveTxt">{label}</span>
        </span>
      </button>
      <span className="last-updated" id="lastUpdated">LAST UPDATED {lastUpdated}</span>
    </>
  );
}
