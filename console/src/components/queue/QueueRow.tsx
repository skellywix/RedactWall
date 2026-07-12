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
  const bulkLabel = `Select incident ${query.id || 'unknown'} for bulk decision`;
  return (
    <article
      className={`${selected ? 'q selected' : 'q'}${selectable ? ' has-bulk-select' : ''}`}
      role="listitem"
    >
      {selectable ? (
        <label className="queue-bulk-target" title={bulkLabel}>
          <input
            type="checkbox"
            className="queue-bulk-box"
            checked={checked}
            aria-label={bulkLabel}
            onChange={(event) => onToggle(event.target.checked)}
          />
        </label>
      ) : null}
      <button
        type="button"
        className="queue-row-select"
        aria-label={`Review incident for ${query.user || 'unknown user'}`}
        aria-pressed={selected}
        aria-controls="queue-selected-detail"
        onClick={onSelect}
      >
        <div className="top risk-meta-row">
          <span className="select-dot" aria-hidden="true" />
          <span className={`sev ${sevClass(query.maxSeverityLabel)}`}>{query.maxSeverityLabel || 'low'}</span>
          <span className={`queue-status tone-${statusTone(query.status)}`}>{humanize(query.status)}</span>
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
      </button>
    </article>
  );
}
