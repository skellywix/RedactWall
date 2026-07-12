import type { ReactElement } from 'react';
import type { LiveState, PostureState } from '../lib/shell';

interface LiveStatusProps {
  state: LiveState;
  postureState: PostureState;
  lastUpdated: string;
}

/** Stream state plus the independent timestamp of the last verified posture response. */
export default function LiveStatus({ state, postureState, lastUpdated }: LiveStatusProps): ReactElement {
  const syncing = state === 'reconnecting';
  const tone = syncing ? 'tone-warn' : 'tone-live';
  const label = syncing ? 'SYNCING' : 'LIVE';
  const detail = syncing
    ? 'SYNCING: session telemetry stream is reconnecting.'
    : 'LIVE: session telemetry stream is connected.';
  const hasVerifiedTime = Boolean(lastUpdated && lastUpdated !== '-');
  const postureLabel = postureState === 'loading'
    ? 'CHECKING'
    : postureState === 'unavailable'
      ? 'UNAVAILABLE'
      : postureState === 'stale'
        ? hasVerifiedTime ? `LAST VERIFIED ${lastUpdated}` : 'UNAVAILABLE'
        : hasVerifiedTime ? `POSTURE VERIFIED ${lastUpdated}` : 'CHECKING';
  return (
    <>
      <span className="live" role="status" aria-label={label} title={detail}>
        <span className={`status-chip ${tone}`}>
          <span className={`status-light ${tone} is-live`} aria-hidden="true"></span>
          <span id="liveTxt">{label}</span>
        </span>
      </span>
      <span className="last-updated" id="lastUpdated" role="status">{postureLabel}</span>
    </>
  );
}
