import type { KeyboardEvent } from 'react';
import type { QueueQuery } from '../../api/queries';
import { FindingChips } from './FindingChips';
import { detectedSummary, fmtTime, humanize, sevClass, sourceLabel, statusTone } from './format';

interface QueueRowProps {
  query: QueueQuery;
  selected: boolean;
  selectable: boolean;
  checked: boolean;
  onSelect: () => void;
  onToggle: (checked: boolean) => void;
}

/** One held prompt in the queue list; mirrors the legacy .q article markup. */
export function QueueRow({ query, selected, selectable, checked, onSelect, onToggle }: QueueRowProps) {
  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    onSelect();
  };
  return (
    <article
      className={selected ? 'q selected' : 'q'}
      role="listitem"
      tabIndex={0}
      aria-current={selected || undefined}
      onClick={onSelect}
      onKeyDown={onKeyDown}
    >
      <div className="top risk-meta-row">
        {selectable ? (
          <input
            type="checkbox"
            className="queue-bulk-box"
            checked={checked}
            aria-label="Select for bulk decision"
            onClick={(event) => event.stopPropagation()}
            onChange={(event) => onToggle(event.target.checked)}
          />
        ) : null}
        <span className="select-dot" aria-hidden="true" />
        <span className={`sev ${sevClass(query.maxSeverityLabel)}`}>{query.maxSeverityLabel || 'low'}</span>
        {query.status !== 'pending' ? (
          <span className={`queue-status tone-${statusTone(query.status)}`}>{humanize(query.status)}</span>
        ) : null}
        <span className="risk">
          Risk <b>{query.riskScore ?? 0}</b>/100
        </span>
      </div>
      <div className="queue-mainline">
        <strong>{query.user || 'unknown user'}</strong>
        <span>
          {sourceLabel(query.source)} → {query.destination || 'unknown destination'}
        </span>
        <span>{fmtTime(query.createdAt)}</span>
      </div>
      <div className="prompt queue-prompt-preview">{query.redactedPrompt}</div>
      <FindingChips findings={query.findings} categories={query.categories} />
      <div className="reasons">Detected: {detectedSummary(query)}</div>
    </article>
  );
}
