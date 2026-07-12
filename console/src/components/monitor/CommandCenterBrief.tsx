import type { ReactNode } from 'react';

export type BriefTone = 'ready' | 'attention' | 'critical' | 'neutral';

export interface CommandCenterBriefItem {
  id: string;
  label: string;
  value: string;
  detail: string;
  tone: BriefTone;
  control?: ReactNode;
  actionLabel?: string;
  onActivate?: () => void;
}

function BriefItem({ item }: { item: CommandCenterBriefItem }) {
  const labelId = `command-brief-${item.id}-label`;
  const valueId = `command-brief-${item.id}-value`;
  const detailId = `command-brief-${item.id}-detail`;
  return (
    <article className={`command-brief-item tone-${item.tone}`} aria-labelledby={labelId} aria-describedby={`${valueId} ${detailId}`}>
      <div className="command-brief-label">
        <span className="command-brief-dot" aria-hidden="true" />
        <span id={labelId}>{item.label}</span>
      </div>
      <strong id={valueId}>{item.value}</strong>
      <p id={detailId}>{item.detail}</p>
      {item.control ? <div className="command-brief-control">{item.control}</div> : null}
      {item.onActivate ? (
        <button className="command-brief-link" type="button" onClick={item.onActivate}>
          {item.actionLabel || 'Open details'}
        </button>
      ) : null}
    </article>
  );
}

export function CommandCenterBrief({ items }: { items: CommandCenterBriefItem[] }) {
  return (
    <section className="command-brief" aria-labelledby="commandBriefTitle">
      <header className="command-brief-head">
        <div>
          <span>Operator brief</span>
          <h3 id="commandBriefTitle">What needs attention now</h3>
        </div>
        <p>Sanitized posture only. Prompt bodies, finding values, and token-vault data stay excluded.</p>
      </header>
      <div className="command-brief-grid">
        {items.map((item) => (
          <BriefItem key={item.id} item={item} />
        ))}
      </div>
    </section>
  );
}
