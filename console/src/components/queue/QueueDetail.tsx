import { useEffect, useState, type ReactNode } from 'react';
import { fetchAuditForQuery, type QueryAuditResult } from '../../api/audit';
import { isHeldQueryStatus, type AssignmentPatch, type QueueQuery, type RevealResult } from '../../api/queries';
import type { Me } from '../../lib/session';
import { EmptyState } from '../Panel';
import { FindingChips } from './FindingChips';
import { canDecide, canReveal, fmt, humanize, readonlyLabel, revealDisplay, sevClass, sourceLabel } from './format';

interface QueueDetailProps {
  query: QueueQuery | null;
  reveal: RevealResult | null;
  me: Me | null;
  busy: boolean;
  note: string;
  onNote: (value: string) => void;
  onApprove: () => void;
  onDeny: () => void;
  onReveal: () => void;
  onAssign: (id: string, patch: AssignmentPatch) => void;
}

function Datum({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="datum">
      <label>{label}</label>
      <b>{value}</b>
    </div>
  );
}

function DetailGrid({ query }: { query: QueueQuery }) {
  return (
    <div className="detail-grid">
      <Datum label="User" value={query.user || 'unknown'} />
      <Datum label="Destination" value={query.destination || 'unknown'} />
      <Datum label="Sensor" value={sourceLabel(query.source)} />
      <Datum label="Channel" value={humanize(query.channel || '-')} />
      <Datum label="Created" value={fmt(query.createdAt)} />
      <Datum label="Status" value={humanize(query.status)} />
      {query.decidedBy ? <Datum label="Decided by" value={query.decidedBy} /> : null}
      {query.decidedAt ? <Datum label="Decided at" value={fmt(query.decidedAt)} /> : null}
    </div>
  );
}

function RiskMeter({ query }: { query: QueueQuery }) {
  const risk = Math.max(0, Math.min(100, Number(query.riskScore || 0)));
  return (
    <div className="risk-meter" style={{ '--risk-width': `${risk}%` } as React.CSSProperties}>
      <div className="risk-meta-row">
        <span className={`sev ${sevClass(query.maxSeverityLabel)}`}>{query.maxSeverityLabel || 'low'}</span>
        <span className="risk">
          Risk <b>{risk}</b>/100
        </span>
      </div>
      <div className="risk-track">
        <i />
      </div>
    </div>
  );
}

/** The prompt body: redacted preview, or the revealed raw text with sensitive styling. */
function PromptSection({ query, reveal }: { query: QueueQuery; reveal: RevealResult | null }) {
  const display = revealDisplay(reveal);
  if (!display || !reveal) return <div className="prompt">{query.redactedPrompt}</div>;
  return (
    <>
      <div className={`prompt-reveal-status ${display.kind}`}>
        <b>{display.statusLabel}</b>
        <span>{display.statusDetail}</span>
      </div>
      <div className={`prompt ${display.kind}`}>{reveal.rawPrompt}</div>
    </>
  );
}

function RevealControl({ query, reveal, me, busy, onReveal }: { query: QueueQuery; reveal: RevealResult | null; me: Me | null; busy: boolean; onReveal: () => void }) {
  if (me?.role !== 'security_admin') return null;
  const display = revealDisplay(reveal);
  if (display) {
    return (
      <button className="btn reveal" type="button" disabled>
        {display.buttonLabel}
      </button>
    );
  }
  if (!canReveal(me, query)) {
    return (
      <button className="btn reveal" type="button" disabled>
        Raw not retained
      </button>
    );
  }
  return (
    <button className="btn reveal" type="button" disabled={busy} onClick={onReveal}>
      Reveal raw
    </button>
  );
}

function DecisionControls({ query, me, busy, note, onNote, onApprove, onDeny, onReveal, reveal }: QueueDetailProps & { query: QueueQuery }) {
  if (!isHeldQueryStatus(query.status)) {
    return query.decisionNote ? <div className="readonly-note">Note: {query.decisionNote}</div> : null;
  }
  if (!canDecide(me, query)) {
    return <div className="readonly-note">{readonlyLabel(me, query) || 'Read-only view'}</div>;
  }
  return (
    <>
      <textarea
        className="note"
        placeholder="Exam-ready decision note, recorded in audit log"
        aria-label="Decision note"
        value={note}
        onChange={(event) => onNote(event.target.value)}
      />
      <div className="actions">
        <button className="btn approve" type="button" disabled={busy} onClick={onApprove}>
          Approve release
        </button>
        <button className="btn deny" type="button" disabled={busy} onClick={onDeny}>
          Deny
        </button>
        <RevealControl query={query} reveal={reveal} me={me} busy={busy} onReveal={onReveal} />
      </div>
    </>
  );
}

/**
 * Inline reassignment (Security Admin only): route a held prompt to a different
 * approver, group, or role so an out-of-office assignee can't strand it. Fields
 * are prefilled from the current routing; an emptied field clears that routing.
 */
function ReassignControl({ query, me, busy, onAssign }: { query: QueueQuery; me: Me | null; busy: boolean; onAssign: (id: string, patch: AssignmentPatch) => void }) {
  const [user, setUser] = useState('');
  const [group, setGroup] = useState('');
  const [role, setRole] = useState('');
  useEffect(() => {
    setUser(query.assignedUser ?? '');
    setGroup(query.assignedGroup ?? '');
    setRole(query.assignedRole ?? '');
  }, [query.id, query.assignedUser, query.assignedGroup, query.assignedRole]);
  if (me?.role !== 'security_admin' || !isHeldQueryStatus(query.status)) return null;
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    onAssign(query.id, { assignedUser: user.trim(), assignedGroup: group.trim(), assignedRole: role.trim() });
  };
  return (
    <form className="reassign" onSubmit={submit} aria-label="Reassign held prompt">
      <label>
        Assignee
        <input value={user} onChange={(event) => setUser(event.target.value)} placeholder="user id" aria-label="Assigned user" />
      </label>
      <label>
        Group
        <input value={group} onChange={(event) => setGroup(event.target.value)} placeholder="group code" aria-label="Assigned group" />
      </label>
      <label>
        Role
        <select value={role} onChange={(event) => setRole(event.target.value)} aria-label="Assigned role">
          <option value="">Any</option>
          <option value="approver">Approver</option>
          <option value="security_admin">Security Admin</option>
        </select>
      </label>
      <button className="btn" type="submit" disabled={busy}>
        Update assignment
      </button>
    </form>
  );
}

/** Item-level audit trail for the selected incident, oldest event first. */
function QueryAuditTrail({ queryId }: { queryId: string }) {
  const [history, setHistory] = useState<QueryAuditResult | { kind: 'loading' }>({ kind: 'loading' });
  useEffect(() => {
    let cancelled = false;
    setHistory({ kind: 'loading' });
    void fetchAuditForQuery(queryId)
      .then((result) => {
        if (!cancelled) setHistory(result);
      })
      .catch(() => {
        if (!cancelled) setHistory({ kind: 'unavailable', reason: 'unavailable_or_malformed' });
      });
    return () => {
      cancelled = true;
    };
  }, [queryId]);
  if (history.kind === 'loading') {
    return (
      <div className="query-audit" role="status" aria-live="polite">
        <label>Audit trail</label>
        <div className="readonly-note">Loading verified audit history…</div>
      </div>
    );
  }
  if (history.kind === 'unavailable') {
    const detail = history.reason === 'integrity_failure'
      ? 'Audit history integrity could not be verified. Entries are withheld.'
      : 'Audit history is unavailable or malformed. No empty-history conclusion can be drawn.';
    return (
      <div className="query-audit" role="alert">
        <label>Audit trail</label>
        <div className="readonly-note">{detail}</div>
      </div>
    );
  }
  if (!history.entries.length) {
    const detail = history.window.complete
      ? 'Audit chain verified. The complete retained audit set has no entries for this incident.'
      : 'Audit chain verified. No entries were found in the verified recent window; older entries may exist.';
    return (
      <div className="query-audit" role="status">
        <label>Audit trail</label>
        <div className="readonly-note">{detail}</div>
      </div>
    );
  }
  const chronological = [...history.entries].reverse();
  const omittedMatches = history.window.returnedEntries < history.window.matchedEntries;
  let windowNote = '';
  if (!history.window.complete) {
    windowNote = omittedMatches
      ? `Showing ${history.window.returnedEntries} of ${history.window.matchedEntries} matching entries found in the verified recent window; older entries may exist.`
      : `Showing ${history.entries.length} matching entries from the verified recent window; older entries may exist.`;
  } else if (omittedMatches) {
    windowNote = `Showing ${history.window.returnedEntries} of ${history.window.matchedEntries} verified matching entries.`;
  }
  return (
    <div className="query-audit" aria-label="Verified audit trail">
      <label>Audit trail</label>
      {windowNote ? <div className="readonly-note">{windowNote}</div> : null}
      <ul className="query-audit-list">
        {chronological.map((entry) => (
          <li key={entry.id}>
            <time>{fmt(entry.ts)}</time>
            <b>{humanize(entry.action)}</b>
            <span>{entry.actor}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Selected-incident panel body: metadata grid, risk meter, prompt, findings, decision controls. */
export function QueueDetail(props: QueueDetailProps) {
  const { query, reveal, me, busy, onReveal, onAssign } = props;
  if (!query) {
    return <EmptyState title="No selected member-data incident" detail="Select a held prompt to review its redacted context." />;
  }
  return (
    <>
      <DetailGrid query={query} />
      <RiskMeter query={query} />
      <PromptSection query={query} reveal={reveal} />
      <FindingChips findings={query.findings} categories={query.categories} />
      {(query.reasons || []).length ? <div className="reasons">{(query.reasons || []).join('; ')}</div> : null}
      <DecisionControls {...props} query={query} />
      {!isHeldQueryStatus(query.status) ? (
        <div className="actions">
          <RevealControl query={query} reveal={reveal} me={me} busy={busy} onReveal={onReveal} />
        </div>
      ) : null}
      <ReassignControl query={query} me={me} busy={busy} onAssign={onAssign} />
      <QueryAuditTrail key={query.id} queryId={query.id} />
    </>
  );
}
