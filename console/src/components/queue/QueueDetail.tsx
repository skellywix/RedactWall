import type { ReactNode } from 'react';
import type { QueueQuery, RevealResult } from '../../api/queries';
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
  if (query.status !== 'pending') {
    return query.decisionNote ? <div className="readonly-note">Note: {query.decisionNote}</div> : null;
  }
  if (!canDecide(me, query)) {
    return <div className="readonly-note">{readonlyLabel(me, query) || 'Read-only view'}</div>;
  }
  return (
    <>
      <textarea
        className="note"
        placeholder="Decision note, recorded in audit log"
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

/** Selected-incident panel body: metadata grid, risk meter, prompt, findings, decision controls. */
export function QueueDetail(props: QueueDetailProps) {
  const { query, reveal, me, busy, onReveal } = props;
  if (!query) {
    return <EmptyState title="No selected incident" detail="Select a held prompt to review its redacted context." />;
  }
  return (
    <>
      <DetailGrid query={query} />
      <RiskMeter query={query} />
      <PromptSection query={query} reveal={reveal} />
      <FindingChips findings={query.findings} categories={query.categories} />
      {(query.reasons || []).length ? <div className="reasons">{(query.reasons || []).join('; ')}</div> : null}
      <DecisionControls {...props} query={query} />
      {query.status !== 'pending' ? (
        <div className="actions">
          <RevealControl query={query} reveal={reveal} me={me} busy={busy} onReveal={onReveal} />
        </div>
      ) : null}
    </>
  );
}
