import type { ReactNode } from 'react';

interface PanelProps {
  title: string;
  meta?: ReactNode;
  children: ReactNode;
}

export function Panel({ title, meta, children }: PanelProps) {
  return (
    <section className="app-panel">
      <header className="app-panel-head">
        <h2>{title}</h2>
        {meta ? <span className="app-panel-meta">{meta}</span> : null}
      </header>
      <div className="app-panel-body">{children}</div>
    </section>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="signal-empty">
      <b>{title}</b>
      <p>{detail}</p>
    </div>
  );
}
