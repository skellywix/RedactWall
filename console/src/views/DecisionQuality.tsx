import { useCallback, useEffect, useState } from 'react';
import { fetchPosture, type DecisionQualityReport } from '../api/posture';
import { ControlBar, stateTone } from '../components/ControlBar';
import { EmptyState, Panel } from '../components/Panel';
import { useEventStream } from '../lib/sse';

function summaryLine(quality: DecisionQualityReport): string {
  const s = quality.summary || {};
  return `${s.controlRate || 0}% controlled / ${s.pendingReviews || 0} pending / ${s.overrideWatch || 0} overrides`;
}

export default function DecisionQuality() {
  const [quality, setQuality] = useState<DecisionQualityReport | null>(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    const report = await fetchPosture();
    setQuality(report?.decisionQuality && report.decisionQuality.summary ? report.decisionQuality : null);
    setLoaded(true);
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useEventStream({ query: load });

  const cards = quality?.cards ?? [];
  const hotspots = (quality?.hotspots ?? []).slice(0, 4);

  return (
    <Panel title="Reviewer Decision Quality" meta={!loaded ? 'Loading' : quality ? summaryLine(quality) : 'Waiting for data'}>
      {!quality && loaded ? (
        <EmptyState title="No reviewer decision data" detail="Recent approval, coaching, and override outcomes appear here." />
      ) : (
        <>
          {cards.map((card) => (
            <ControlBar
              key={card.label}
              label={card.label}
              score={card.score}
              detail={card.detail}
              value={card.value}
              tone={stateTone(card.state)}
            />
          ))}
          {hotspots.length > 0 && (
            <>
              <div className="control-row">
                <div>
                  <strong>Member-Data Decision Hotspots</strong>
                  <span>metadata only</span>
                </div>
              </div>
              {hotspots.map((item) => (
                <div className="control-row" key={`${item.kind}:${item.label}`}>
                  <div>
                    <strong>{item.label}</strong>
                    <span>
                      {item.kind} / {item.events} events
                    </span>
                  </div>
                  <div className="control-bar" role="img" aria-label={`${item.label} ${item.events} events`}>
                    <i style={{ '--w': `${Math.max(5, Math.min(100, Number(item.sensitive) || 0))}%` } as React.CSSProperties} />
                  </div>
                  <span>{item.detail || 'metadata-only hotspot'}</span>
                </div>
              ))}
            </>
          )}
        </>
      )}
    </Panel>
  );
}
