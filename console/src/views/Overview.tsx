import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchPostureResult, type PostureReport } from '../api/posture';
import { asStats, fetchStatsResult, type Stats } from '../api/stats';
import LeakMap from '../components/overview/LeakMap';
import { EmptyState, Panel } from '../components/Panel';
import { useEventStream } from '../lib/sse';
import './Overview.css';

type Tone = 'live' | 'secure' | 'warn' | 'critical';
type StatsState = 'loading' | 'ready' | 'stale' | 'unavailable';

interface StatCard {
  key: string;
  value: string | number;
  label: string;
  detail: string;
  tone: Tone;
}

function approvalRate(stats: Stats): string {
  const decisions = stats.approved + stats.denied;
  return decisions ? `${Math.round((stats.approved / decisions) * 100)}%` : '-';
}

function priorityCards(stats: Stats): StatCard[] {
  return [
    {
      key: 'held',
      value: stats.held ?? 'Not reported',
      label: 'Member-data queue',
      detail: stats.held === null
        ? `${stats.pending} approval hold${stats.pending === 1 ? '' : 's'} reported; justification total unavailable`
        : 'held for review or justification',
      tone: 'critical',
    },
    { key: 'blocked', value: stats.todayBlocked, label: 'Guardrail attention today', detail: 'held, denied, flagged, or stopped', tone: 'warn' },
    { key: 'allowed', value: stats.allowed, label: 'Policy-allowed traffic', detail: 'passed enforcement', tone: 'secure' },
    { key: 'total', value: stats.total, label: 'Exam evidence events', detail: 'sanitized records', tone: 'live' },
  ];
}

function reviewCards(stats: Stats): StatCard[] {
  return [
    { key: 'approved', value: stats.approved, label: 'Approved releases', detail: 'admin reviewed', tone: 'secure' },
    { key: 'denied', value: stats.denied, label: 'Denied releases', detail: 'never sent', tone: 'critical' },
    { key: 'rate', value: approvalRate(stats), label: 'Reviewer approval rate', detail: 'admin decisions', tone: 'live' },
  ];
}

function summaryLine(stats: Stats): string {
  const held = stats.held === null ? 'held total not reported' : `${stats.held} held`;
  return `${held} / ${stats.todayBlocked} guardrail attention today / ${stats.total} total`;
}

function PriorityCard({ card }: { card: StatCard }) {
  return (
    <div className={`overview-stat tone-${card.tone}`} title={`${card.label}: ${card.detail}`}>
      <div className="overview-stat-label">
        <span className="overview-stat-light" aria-hidden="true" />
        {card.label}
      </div>
      <div className="overview-stat-value">{card.value}</div>
      <div className="overview-stat-detail">{card.detail}</div>
    </div>
  );
}

function StatBand({ stats, state }: { stats: Stats; state: StatsState }) {
  return (
    <section className="overview-evidence" aria-labelledby="overviewEvidenceTitle">
      <div className="overview-section-head">
        <div><h3 id="overviewEvidenceTitle">Current evidence posture</h3><p>The four counts that need the first operator glance.</p></div>
        <span>{state === 'stale' ? 'Last verified counters' : 'Sanitized live counters'}</span>
      </div>
      <div className="overview-stats">
        {priorityCards(stats).map((card) => <PriorityCard card={card} key={card.key} />)}
      </div>
      <dl className="overview-review-stats" aria-label="Reviewer outcomes">
        {reviewCards(stats).map((card) => (
          <div className={`tone-${card.tone}`} key={card.key}>
            <dt><span className="overview-stat-light" aria-hidden="true" />{card.label}</dt>
            <dd>{card.value}</dd>
            <small>{card.detail}</small>
          </div>
        ))}
      </dl>
    </section>
  );
}

function TopEntities({ entities, state }: { entities: [string, number][]; state: StatsState }) {
  if (!entities.length) {
    return (
      <EmptyState
        title={state === 'stale' ? 'No detections in the last verified snapshot' : 'No member-data detections'}
        detail={state === 'stale' ? 'The latest refresh failed; this is not a current all-clear.' : 'The verified data set has no classified AI prompt findings.'}
      />
    );
  }
  const max = entities[0][1] || 1;
  return (
    <section className="overview-entities" aria-labelledby="overviewEntitiesTitle">
      <div className="overview-section-head">
        <div><h3 id="overviewEntitiesTitle">Top member-data detections</h3><p>Classified event counts, never source values.</p></div>
        <span>metadata only</span>
      </div>
      {entities.map(([name, n]) => (
        <div className="overview-barrow" key={name}>
          <div className="overview-barrow-name">{name}</div>
          <div className="overview-bar" role="img" aria-label={`${name} ${n} detections`}>
            <i style={{ '--w': `${Math.round((n / max) * 100)}%` } as React.CSSProperties} />
          </div>
          <div className="overview-barrow-count">{n}</div>
        </div>
      ))}
    </section>
  );
}

function StatsDataNotice({ state, hasSnapshot, onRetry }: { state: StatsState; hasSnapshot: boolean; onRetry: () => void }) {
  if (state === 'ready') return null;
  if (state === 'loading' && !hasSnapshot) {
    return (
      <div className="overview-stats-notice is-loading" role="status">
        <div><strong>Loading evidence counters</strong><p>Waiting for a verified stats response.</p></div>
      </div>
    );
  }
  const stale = hasSnapshot;
  return (
    <div className={`overview-stats-notice ${stale ? 'is-stale' : 'is-unavailable'}`} role={stale ? 'status' : 'alert'}>
      <div>
        <strong>{stale ? 'Showing last verified counters' : 'Evidence counters unavailable'}</strong>
        <p>{stale ? 'The latest refresh failed. Values below are retained evidence, not live counters.' : 'The stats request failed, so RedactWall did not report a zero-activity state.'}</p>
      </div>
      <button className="system-button secondary" type="button" onClick={onRetry}>Retry counters</button>
    </div>
  );
}

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const statsRef = useRef<Stats | null>(null);
  const [statsState, setStatsState] = useState<StatsState>('loading');
  const [posture, setPosture] = useState<PostureReport | null>(null);
  const [postureState, setPostureState] = useState<'loading' | 'ready' | 'unavailable'>('loading');
  const statsRequestRef = useRef(0);
  const postureRequestRef = useRef(0);

  const loadStats = useCallback(async () => {
    const requestId = ++statsRequestRef.current;
    const result = await fetchStatsResult();
    if (requestId !== statsRequestRef.current) return;
    if (result.ok) {
      statsRef.current = result.stats;
      setStats(result.stats);
      setStatsState('ready');
    } else {
      setStatsState(statsRef.current ? 'stale' : 'unavailable');
    }
  }, []);

  const loadPosture = useCallback(async () => {
    const requestId = ++postureRequestRef.current;
    const nextPosture = await fetchPostureResult();
    if (requestId !== postureRequestRef.current) return;
    if (nextPosture.ok) {
      setPosture(nextPosture.report);
      setPostureState('ready');
    } else {
      setPostureState('unavailable');
    }
  }, []);

  const load = useCallback(async () => {
    await Promise.all([loadStats(), loadPosture()]);
  }, [loadPosture, loadStats]);

  const retryStats = useCallback(() => {
    if (!statsRef.current) setStatsState('loading');
    void loadStats();
  }, [loadStats]);

  const retryPosture = useCallback(() => {
    setPostureState('loading');
    void loadPosture();
  }, [loadPosture]);

  useEffect(() => {
    load();
  }, [load]);
  useEventStream({
    stats: (data) => {
      const next = asStats(data);
      if (next) {
        statsRequestRef.current += 1;
        statsRef.current = next;
        setStats(next);
        setStatsState('ready');
      }
    },
    query: load,
  });

  const leakMap = posture?.leakMap ?? null;
  const mapState = postureState === 'loading'
    ? 'loading'
    : postureState === 'unavailable'
      ? 'unavailable'
      : leakMap && (leakMap.edges.length > 0 || leakMap.segments.length > 0 || leakMap.destinations.length > 0)
        ? 'populated'
        : 'empty';

  const statsMeta = statsState === 'loading'
    ? 'Loading'
    : statsState === 'unavailable'
      ? 'Counters unavailable'
      : stats
        ? `${statsState === 'stale' ? 'Last verified / ' : ''}${summaryLine(stats)}`
        : 'Waiting for verified counters';

  return (
    <Panel title="Texas FCU Overview" meta={statsMeta}>
      <LeakMap map={leakMap} state={mapState} surfaces={posture?.surfaces} onRetry={retryPosture} />
      <StatsDataNotice state={statsState} hasSnapshot={Boolean(stats)} onRetry={retryStats} />
      {stats ? (
        <>
          {statsState === 'ready' && stats.total === 0 ? (
            <EmptyState title="No FCU evidence in the verified snapshot" detail="Counters are verified at zero; activity appears when branch, browser, endpoint, or MCP sensors report." />
          ) : null}
          <StatBand stats={stats} state={statsState} />
          {stats.total > 0 ? <TopEntities entities={stats.topEntities} state={statsState} /> : null}
        </>
      ) : null}
    </Panel>
  );
}
