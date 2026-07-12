import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  HELD_QUERY_FILTER,
  fetchQueueResult,
  isHeldQueryStatus,
  type QueueFetchFailure,
  type QueueQuery,
} from '../api/queries';
import { Panel } from '../components/Panel';
import { QueueDetail } from '../components/queue/QueueDetail';
import { QueueRow } from '../components/queue/QueueRow';
import { StepUpModal } from '../components/queue/StepUpModal';
import { canDecide } from '../components/queue/format';
import { stepUpCopy, useQueueActions } from '../components/queue/useQueueActions';
import { useSession } from '../lib/session';
import { useEventStream } from '../lib/sse';
import './Queue.css';

const STATUS_FILTERS: Array<{ value: string; label: string }> = [
  { value: HELD_QUERY_FILTER, label: 'Held for review' },
  { value: 'pending', label: 'Approval required' },
  { value: 'pending_justification', label: 'Justification required' },
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

function sortHeldFirst(list: QueueQuery[]): QueueQuery[] {
  return [...list].sort((a, b) => {
    const heldOrder = Number(isHeldQueryStatus(b.status)) - Number(isHeldQueryStatus(a.status));
    if (heldOrder) return heldOrder;
    const aTime = Date.parse(a.createdAt || '');
    const bTime = Date.parse(b.createdAt || '');
    return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
  });
}

function matchesSearch(query: QueueQuery, term: string): boolean {
  const trimmed = term.trim().toLowerCase();
  if (!trimmed) return true;
  const haystack = `${query.user || ''} ${query.destination || ''} ${query.redactedPrompt || ''}`.toLowerCase();
  return trimmed.split(/\s+/).every((word) => haystack.includes(word));
}

type QueueLoadPhase = 'loading' | 'refreshing' | 'ready' | 'stale' | QueueFetchFailure;

interface QueueSnapshot {
  rows: QueueQuery[];
  verifiedAt: number;
}

interface QueueRowsState {
  filter: string;
  phase: QueueLoadPhase;
  snapshot: QueueSnapshot | null;
}

function useQueueRows(statusFilter: string) {
  const snapshots = useRef(new Map<string, QueueSnapshot>());
  const [state, setState] = useState<QueueRowsState>({
    filter: statusFilter,
    phase: 'loading',
    snapshot: null,
  });
  // Monotonic request id: a slow response for a superseded status filter (or a
  // stale SSE-triggered reload) must never overwrite the newest filter's rows.
  const reqId = useRef(0);
  const load = useCallback(async (background = false) => {
    const seq = ++reqId.current;
    const cached = snapshots.current.get(statusFilter) ?? null;
    if (!background) {
      setState({
        filter: statusFilter,
        phase: cached ? 'refreshing' : 'loading',
        snapshot: cached,
      });
    }
    const result = await fetchQueueResult(statusFilter);
    if (seq !== reqId.current) return;
    if (result.ok) {
      const snapshot = { rows: sortHeldFirst(result.rows), verifiedAt: Date.now() };
      snapshots.current.set(statusFilter, snapshot);
      setState({ filter: statusFilter, phase: 'ready', snapshot });
      return;
    }
    setState({
      filter: statusFilter,
      phase: cached ? 'stale' : result.reason,
      snapshot: cached,
    });
  }, [statusFilter]);
  useEffect(() => {
    void load();
  }, [load]);
  useEventStream({
    query: () => void load(true),
    decision: () => void load(true),
    stats: () => void load(true),
  });
  if (state.filter !== statusFilter) {
    return { rows: null, phase: 'loading' as const, verifiedAt: null, load };
  }
  return {
    rows: state.snapshot?.rows ?? null,
    phase: state.phase,
    verifiedAt: state.snapshot?.verifiedAt ?? null,
    load,
  };
}

interface QueueToolbarProps {
  status: string;
  onStatus: (value: string) => void;
  search: string;
  onSearch: (value: string) => void;
  refreshing: boolean;
  onRefresh: () => void;
}

function QueueToolbar({ status, onStatus, search, onSearch, refreshing, onRefresh }: QueueToolbarProps) {
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
          placeholder="Filter by employee, AI destination, or masked text"
          value={search}
          onChange={(event) => onSearch(event.target.value)}
        />
      </label>
      <button className="btn queue-refresh" type="button" disabled={refreshing} onClick={onRefresh}>
        {refreshing ? 'Refreshing…' : 'Refresh queue'}
      </button>
    </div>
  );
}

interface QueueStateProps {
  kind: 'loading' | 'empty' | 'filtered' | 'unavailable' | 'forbidden' | 'stale';
  title: string;
  detail: string;
  actionLabel?: string;
  onAction?: () => void;
  quiet?: boolean;
}

function QueueState({ kind, title, detail, actionLabel, onAction, quiet = false }: QueueStateProps) {
  const urgent = kind === 'unavailable' || kind === 'forbidden' || kind === 'stale';
  return (
    <div
      className={`queue-state queue-state-${kind}`}
      role={quiet ? undefined : urgent ? 'alert' : 'status'}
      aria-live={quiet ? undefined : urgent ? 'assertive' : 'polite'}
    >
      <div>
        <b>{title}</b>
        <p>{detail}</p>
      </div>
      {actionLabel && onAction ? (
        <button className="btn" type="button" onClick={onAction}>
          {actionLabel}
        </button>
      ) : null}
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
        placeholder="Exam-ready decision note"
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
  const [statusFilter, setStatusFilter] = useState(HELD_QUERY_FILTER);
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const detailRef = useRef<HTMLDivElement>(null);
  const { rows, phase, verifiedAt, load } = useQueueRows(statusFilter);
  const actions = useQueueActions(load, me?.authProvider);
  const { pruneTo, setNote, setStepUp } = actions;
  const cancelStepUp = useCallback(() => setStepUp(null), [setStepUp]);

  useEffect(() => {
    pruneTo(rows ?? []);
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
  const heldCount = (rows ?? []).filter((q) => isHeldQueryStatus(q.status)).length;
  const countMeta = `${visible.length} shown / ${heldCount} held`;
  const meta = phase === 'loading'
    ? 'Loading'
    : phase === 'unavailable'
      ? 'Unavailable'
      : phase === 'forbidden'
        ? 'Access denied'
        : phase === 'refreshing'
          ? `Refreshing · ${countMeta}`
          : phase === 'stale'
            ? `Last verified snapshot · ${countMeta}`
            : countMeta;

  const selectRow = (id: string) => {
    if (id === selectedId) return;
    setSelectedId(id);
    actions.setNote('');
  };

  const retry = () => {
    void load();
  };

  const reviewSelected = () => {
    const target = detailRef.current;
    if (!target) return;
    target.focus({ preventScroll: true });
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
  };

  const renderRows = () => {
    if (phase === 'loading') {
      return <QueueState kind="loading" title="Loading member-data queue" detail="Checking the latest server-verified incidents." />;
    }
    if (phase === 'unavailable') {
      return (
        <QueueState
          kind="unavailable"
          title="Member-data queue unavailable"
          detail="RedactWall could not verify the current queue. No clear-queue claim has been made."
          actionLabel="Retry"
          onAction={retry}
        />
      );
    }
    if (phase === 'forbidden') {
      return (
        <QueueState
          kind="forbidden"
          title="Queue access denied"
          detail="This signed-in role cannot view member-data incidents. No queue status is available."
          actionLabel="Retry"
          onAction={retry}
        />
      );
    }
    const verifiedTime = verifiedAt
      ? new Date(verifiedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : 'earlier';
    if (phase === 'refreshing' && !rows?.length) {
      return (
        <QueueState
          kind="loading"
          title="Refreshing member-data queue"
          detail={`The last verified snapshot at ${verifiedTime} was empty. Checking the current queue now.`}
        />
      );
    }
    if (phase === 'stale' && !rows?.length) {
      return (
        <QueueState
          kind="stale"
          title="Queue refresh failed"
          detail={`The last verified snapshot at ${verifiedTime} contained no matching incidents. Current queue status is unknown.`}
          actionLabel="Retry refresh"
          onAction={retry}
        />
      );
    }
    if (!rows?.length) {
      return statusFilter === HELD_QUERY_FILTER ? (
        <QueueState
          kind="empty"
          title="Member-data queue clear"
          detail="No held member-data prompts are awaiting approval or justification."
        />
      ) : (
        <QueueState
          kind="empty"
          title="No events in this status"
          detail="The latest verified queue has no member-data events with this status."
        />
      );
    }
    const verificationNotice = phase === 'stale' ? (
      <QueueState
        kind="stale"
        title="Queue refresh failed"
        detail={`Showing the last verified snapshot from ${verifiedTime}. Decisions remain server-authoritative.`}
        actionLabel="Retry refresh"
        onAction={retry}
      />
    ) : phase === 'refreshing' ? (
      <div className="queue-refreshing" role="status" aria-live="polite">
        Refreshing while the last verified snapshot remains visible.
      </div>
    ) : null;
    if (!visible.length) {
      return (
        <>
          {verificationNotice}
          <QueueState
            kind="filtered"
            title="No search matches"
            detail="Queue incidents exist, but none match the current search."
            actionLabel="Clear search"
            onAction={() => setSearch('')}
          />
        </>
      );
    }
    return (
      <>
        {verificationNotice}
        <div className="queue-rows" role="list" aria-label="Member-data incidents" aria-busy={phase === 'refreshing'}>
          {visible.map((q) => (
            <QueueRow
              key={q.id}
              query={q}
              selected={q.id === selected?.id}
              selectable={canDecide(me, q)}
              checked={actions.checked.has(q.id)}
              onSelect={() => selectRow(q.id)}
              onToggle={(value) => actions.toggleChecked(q.id, value)}
            />
          ))}
        </div>
      </>
    );
  };

  return (
    <div className="queue-view">
      <div className="queue-list-pane">
        <Panel title="Member Data Queue" meta={meta}>
          <QueueToolbar
            status={statusFilter}
            onStatus={setStatusFilter}
            search={search}
            onSearch={setSearch}
            refreshing={phase === 'loading' || phase === 'refreshing'}
            onRefresh={retry}
          />
          {rows && actions.checked.size > 0 ? (
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
          {selected ? (
            <button className="btn queue-detail-jump" type="button" onClick={reviewSelected}>
              Review selected incident
            </button>
          ) : null}
        </Panel>
      </div>
      <div id="queue-selected-detail" className="queue-detail-pane" ref={detailRef} tabIndex={-1}>
        <Panel title="Selected Member-Data Incident" meta="Redacted review context">
          {rows === null ? (
            <QueueState
              kind={phase === 'loading' ? 'loading' : phase === 'forbidden' ? 'forbidden' : 'unavailable'}
              title={phase === 'loading' ? 'Loading incident context' : 'Incident details unavailable'}
              detail="Details will appear only after the queue is verified."
              quiet
            />
          ) : (
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
          )}
        </Panel>
      </div>
      {actions.stepUp ? (
        <StepUpModal
          {...stepUpCopy(actions.stepUp)}
          onConfirm={actions.confirmStepUp}
          onCancel={cancelStepUp}
        />
      ) : null}
    </div>
  );
}
