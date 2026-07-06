import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { fetchQueue, type QueueQuery } from '../api/queries';
import { EmptyState, Panel } from '../components/Panel';
import { QueueDetail } from '../components/queue/QueueDetail';
import { QueueRow } from '../components/queue/QueueRow';
import { StepUpModal } from '../components/queue/StepUpModal';
import { canDecide } from '../components/queue/format';
import { stepUpCopy, useQueueActions } from '../components/queue/useQueueActions';
import { useSession } from '../lib/session';
import { useEventStream } from '../lib/sse';
import './Queue.css';

const STATUS_FILTERS: Array<{ value: string; label: string }> = [
  { value: 'pending', label: 'Pending' },
  { value: 'approved', label: 'Approved' },
  { value: 'denied', label: 'Denied' },
  { value: 'flagged', label: 'Flagged' },
  { value: 'redacted', label: 'Redacted' },
  { value: 'warned_sent', label: 'Warned' },
  { value: 'blocked_by_user', label: 'Blocked by user' },
  { value: 'destination_blocked', label: 'Destination blocked' },
  { value: 'file_upload_blocked', label: 'File upload blocked' },
  { value: 'injection_blocked', label: 'Injection blocked' },
  { value: 'ocr_required', label: 'OCR required' },
  { value: 'file_blocked_unscanned', label: 'File blocked (unscanned)' },
  { value: 'shadow_ai', label: 'Shadow AI' },
  { value: 'paste_flagged', label: 'Paste flagged' },
  { value: 'all', label: 'All statuses' },
];

function sortPendingFirst(list: QueueQuery[]): QueueQuery[] {
  return [...list].sort((a, b) => Number(b.status === 'pending') - Number(a.status === 'pending'));
}

function matchesSearch(query: QueueQuery, term: string): boolean {
  const trimmed = term.trim().toLowerCase();
  if (!trimmed) return true;
  const haystack = `${query.user || ''} ${query.destination || ''} ${query.redactedPrompt || ''}`.toLowerCase();
  return trimmed.split(/\s+/).every((word) => haystack.includes(word));
}

function useQueueRows(statusFilter: string) {
  const [rows, setRows] = useState<QueueQuery[] | null>(null);
  const [loaded, setLoaded] = useState(false);
  // Monotonic request id: a slow response for a superseded status filter (or a
  // stale SSE-triggered reload) must never overwrite the newest filter's rows.
  const reqId = useRef(0);
  const load = useCallback(async () => {
    const seq = ++reqId.current;
    const next = await fetchQueue(statusFilter);
    if (seq !== reqId.current) return;
    setRows(next ? sortPendingFirst(next) : []);
    setLoaded(true);
  }, [statusFilter]);
  useEffect(() => {
    load();
  }, [load]);
  useEventStream({ query: load, decision: load, stats: load });
  return { rows, loaded, load };
}

interface QueueToolbarProps {
  status: string;
  onStatus: (value: string) => void;
  search: string;
  onSearch: (value: string) => void;
}

function QueueToolbar({ status, onStatus, search, onSearch }: QueueToolbarProps) {
  return (
    <div className="queue-toolbar">
      <label>
        Status
        <select value={status} onChange={(event) => onStatus(event.target.value)}>
          {STATUS_FILTERS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <label className="queue-search">
        Search
        <input
          type="search"
          placeholder="Filter by user, destination, or redacted text"
          value={search}
          onChange={(event) => onSearch(event.target.value)}
        />
      </label>
    </div>
  );
}

interface BulkBarProps {
  count: number;
  note: string;
  busy: boolean;
  onNote: (value: string) => void;
  onApprove: () => void;
  onDeny: () => void;
}

function BulkBar({ count, note, busy, onNote, onApprove, onDeny }: BulkBarProps) {
  return (
    <div className="queue-bulk-bar" aria-label="Bulk decision bar">
      <span>{count} selected</span>
      <input
        type="text"
        placeholder="Decision note (audited)"
        aria-label="Bulk decision note"
        value={note}
        onChange={(event) => onNote(event.target.value)}
      />
      <button className="btn approve" type="button" disabled={busy} onClick={onApprove}>
        Approve selected
      </button>
      <button className="btn deny" type="button" disabled={busy} onClick={onDeny}>
        Deny selected
      </button>
    </div>
  );
}

export default function Queue() {
  const { me } = useSession();
  const [statusFilter, setStatusFilter] = useState('pending');
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { rows, loaded, load } = useQueueRows(statusFilter);
  const actions = useQueueActions(load, me?.authProvider);
  const { pruneTo, setNote } = actions;

  useEffect(() => {
    if (rows) pruneTo(rows);
  }, [rows, pruneTo]);

  const visible = useMemo(() => (rows ?? []).filter((q) => matchesSearch(q, search)), [rows, search]);
  const selected = visible.find((q) => q.id === selectedId) ?? visible[0] ?? null;
  const effectiveId = selected?.id ?? null;

  // Clear the in-progress decision note whenever the effective incident changes
  // for ANY reason — including the silent fallback to visible[0] after the
  // selected row is decided elsewhere — so a note typed for one incident can
  // never be recorded against another.
  const prevEffectiveId = useRef(effectiveId);
  useEffect(() => {
    if (prevEffectiveId.current !== effectiveId) {
      prevEffectiveId.current = effectiveId;
      setNote('');
    }
  }, [effectiveId, setNote]);
  const pendingCount = (rows ?? []).filter((q) => q.status === 'pending').length;
  const meta = !loaded ? 'Loading' : `${visible.length} shown / ${pendingCount} pending`;

  const selectRow = (id: string) => {
    if (id === selectedId) return;
    setSelectedId(id);
    actions.setNote('');
  };

  const renderRows = () => {
    if (!loaded) return <div className="app-loading">Loading queue…</div>;
    if (!rows?.length) {
      return statusFilter === 'pending' ? (
        <EmptyState title="Queue clear" detail="No prompts are awaiting approval." />
      ) : (
        <EmptyState title="No matches" detail="No prompts have this status yet." />
      );
    }
    if (!visible.length) return <EmptyState title="No matches" detail="No prompts match the current search." />;
    return (
      <div className="queue-rows" role="list" aria-label="Held prompts">
        {visible.map((q) => (
          <QueueRow
            key={q.id}
            query={q}
            selected={q.id === selected?.id}
            selectable={q.status === 'pending' && canDecide(me, q)}
            checked={actions.checked.has(q.id)}
            onSelect={() => selectRow(q.id)}
            onToggle={(value) => actions.toggleChecked(q.id, value)}
          />
        ))}
      </div>
    );
  };

  return (
    <div className="queue-view">
      <Panel title="Approval Queue" meta={meta}>
        <QueueToolbar status={statusFilter} onStatus={setStatusFilter} search={search} onSearch={setSearch} />
        {actions.checked.size > 0 ? (
          <BulkBar
            count={actions.checked.size}
            note={actions.bulkNote}
            busy={actions.busy}
            onNote={actions.setBulkNote}
            onApprove={actions.requestBulkApprove}
            onDeny={actions.bulkDeny}
          />
        ) : null}
        {renderRows()}
      </Panel>
      <Panel title="Selected Incident" meta="Redacted review context">
        <QueueDetail
          query={selected}
          reveal={selected ? actions.reveals.get(selected.id) ?? null : null}
          me={me}
          busy={actions.busy}
          note={actions.note}
          onNote={actions.setNote}
          onApprove={() => selected && void actions.beginStepUp({ kind: 'approve-one', id: selected.id })}
          onDeny={() => selected && actions.deny(selected.id)}
          onReveal={() => selected && void actions.beginStepUp({ kind: 'reveal', id: selected.id })}
          onAssign={actions.assign}
        />
      </Panel>
      {actions.stepUp ? (
        <StepUpModal
          {...stepUpCopy(actions.stepUp)}
          onConfirm={actions.confirmStepUp}
          onCancel={() => actions.setStepUp(null)}
        />
      ) : null}
    </div>
  );
}
