import type { ReactNode } from 'react';

export interface MonitorWorkspaceItem {
  id: string;
  label: string;
  description: string;
}

function revealWorkspace(id: string): void {
  const target = document.getElementById(id);
  if (!(target instanceof HTMLDetailsElement)) return;
  target.open = true;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  target.scrollIntoView({ block: 'start', behavior: reduceMotion ? 'auto' : 'smooth' });
  target.querySelector('summary')?.focus({ preventScroll: true });
}

export function MonitorWorkspaceNav({ items }: { items: MonitorWorkspaceItem[] }) {
  return (
    <nav className="monitor-workspace-nav" aria-label="Command center workspaces">
      <div>
        <span>Full workspace</span>
        <strong>Open a focused work area</strong>
      </div>
      <ul>
        {items.map((item) => (
          <li key={item.id}>
            <button type="button" onClick={() => revealWorkspace(item.id)}>
              <span>{item.label}</span>
              <small>{item.description}</small>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

interface MonitorWorkspaceGroupProps {
  id: string;
  label: string;
  description: string;
  summary: string;
  children: ReactNode;
}

export function MonitorWorkspaceGroup({ id, label, description, summary, children }: MonitorWorkspaceGroupProps) {
  const descriptionId = `${id}-description`;
  return (
    <details className="monitor-workspace" id={id}>
      <summary aria-describedby={descriptionId}>
        <span className="monitor-workspace-index" aria-hidden="true" />
        <span className="monitor-workspace-title">
          <strong>{label}</strong>
          <small id={descriptionId}>{description}</small>
        </span>
        <span className="monitor-workspace-summary">{summary}</span>
        <span className="monitor-workspace-chevron" aria-hidden="true" />
      </summary>
      <div className="monitor-workspace-body">{children}</div>
    </details>
  );
}
