import { useCallback, useEffect, useState } from 'react';
import { fetchPosture, type PostureReport } from '../api/posture';
import { asStats, fetchStats, type Stats } from '../api/stats';
import LeakMap from '../components/overview/LeakMap';
import { EmptyState, Panel } from '../components/Panel';
import { useEventStream } from '../lib/sse';
import './Overview.css';

type Tone = 'live' | 'secure' | 'warn' | 'critical';

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

/** Mirrors the legacy queue-tab KPI band (dashboard.js loadStats cards). */
function statCards(stats: Stats): StatCard[] {
  return [
    { key: 'pending', value: stats.pending, label: 'Sensitive-data queue', detail: 'held for review', tone: 'critical' },
    { key: 'blocked', value: stats.todayBlocked, label: 'Blocked today', detail: 'member-data stops', tone: 'warn' },
    { key: 'approved', value: stats.approved, label: 'Approved releases', detail: 'admin reviewed', tone: 'secure' },
    { key: 'denied', value: stats.denied, label: 'Denied releases', detail: 'never sent', tone: 'critical' },
    { key: 'allowed', value: stats.allowed, label: 'Clean traffic', detail: 'passed policy', tone: 'secure' },
    { key: 'rate', value: approvalRate(stats), label: 'Reviewer approval rate', detail: 'admin decisions', tone: 'live' },
    { key: 'total', value: stats.total, label: 'Exam evidence events', detail: 'sanitized records', tone: 'live' },
  ];
}

function summaryLine(stats: Stats): string {
  return `${stats.pending} pending / ${stats.todayBlocked} blocked today / ${stats.total} total`;
}

function StatBand({ stats }: { stats: Stats }) {
  return (
    <div className="overview-stats">
      {statCards(stats).map((card) => (
        <div className={`overview-stat tone-${card.tone}`} key={card.key} title={`${card.label}: ${card.detail}`}>
          <div className="overview-stat-label">
            <span className="overview-stat-light" aria-hidden="true" />
            {card.label}
          </div>
          <div className="overview-stat-value">{card.value}</div>
          <div className="overview-stat-detail">{card.detail}</div>
        </div>
      ))}
    </div>
  );
}

function TopEntities({ entities }: { entities: [string, number][] }) {
  if (!entities.length) {
    return <EmptyState title="No member-data detections" detail="Current data set has no classified AI prompt findings." />;
  }
  const max = entities[0][1] || 1;
  return (
    <div className="overview-entities">
      <div className="overview-entities-head">
        <strong>Top member-data detections</strong>
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
    </div>
  );
}

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [posture, setPosture] = useState<PostureReport | null>(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    const [nextStats, nextPosture] = await Promise.all([fetchStats(), fetchPosture()]);
    if (nextStats) setStats(nextStats);
    if (nextPosture) setPosture(nextPosture);
    setLoaded(true);
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useEventStream({
    stats: (data) => {
      const next = asStats(data);
      if (next) setStats(next);
    },
    query: load,
  });

  return (
    <Panel title="Institution Overview" meta={!loaded ? 'Loading' : stats ? summaryLine(stats) : 'Waiting for data'}>
      <LeakMap map={posture?.leakMap ?? null} surfaces={posture?.surfaces} />
      {!stats && loaded ? (
        <EmptyState title="No evidence yet" detail="Live counters appear once branch, browser, endpoint, or MCP sensors report activity." />
      ) : stats ? (
        <>
          <StatBand stats={stats} />
          <TopEntities entities={stats.topEntities} />
        </>
      ) : null}
    </Panel>
  );
}
