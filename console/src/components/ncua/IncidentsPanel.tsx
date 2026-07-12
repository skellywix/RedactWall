import { useCallback, useEffect, useState } from 'react';
import { apiJson, apiSend } from '../../lib/api';
import { useSession } from '../../lib/session';
import { toast } from '../../lib/toast';

/**
 * 72-hour AI incident readiness (PLANS/ncua-readiness-center.md slice 3,
 * 12 CFR 748.1(c)). Route contract from server/app.js:
 *   GET  /api/ncua/incidents -> { entitled, incidents[] } — any console role;
 *     each incident carries a derived prompt-free timeline (who, destination,
 *     decision, data classes, prevented) built from sanitized queries.
 *   POST /api/ncua/incidents (Security Admin + CSRF) — open an incident from
 *     held-event ids; deadlineAt is detectedAt + 72h, set server-side.
 *   POST /api/ncua/incidents/:id/status (Security Admin + CSRF) — advance
 *     open -> under_review -> reported/closed; reporting stamps reportedAt.
 * CSRF is automatic via lib/api.ts. Never renders prompt content.
 */

interface TimelineEvent {
  queryId: string;
  at: string;
  user: string;
  destination: string;
  decision: string;
  prevented: boolean;
  dataClasses: string[];
}

interface IncidentRecord {
  id: string;
  title: string;
  status: 'open' | 'under_review' | 'reported' | 'closed';
  detectedAt: string;
  deadlineAt: string;
  reportedAt?: string | null;
  timeline: TimelineEvent[];
  updatedAt?: string;
}

const STATUS_TONE: Record<string, string> = {
  open: 'tone-high',
  under_review: 'tone-medium',
  reported: 'tone-low',
  closed: 'tone-neutral',
};

function deadlineLabel(incident: IncidentRecord, nowMs: number): string {
  if (incident.status === 'reported' || incident.status === 'closed') {
    return incident.reportedAt ? `reported ${incident.reportedAt.slice(0, 16).replace('T', ' ')}` : 'resolved';
  }
  const remainingMs = Date.parse(incident.deadlineAt) - nowMs;
  if (!Number.isFinite(remainingMs)) return '—';
  if (remainingMs <= 0) return 'OVERDUE';
  if (remainingMs < 3600000) return `${Math.max(1, Math.floor(remainingMs / 60000))}m left on the 72h clock`;
  return `${Math.floor(remainingMs / 3600000)}h left on the 72h clock`;
}

// Re-render every minute so an open tab's countdown stays live and flips to
// OVERDUE when the regulatory deadline passes.
function useMinuteTick(): number {
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 60000);
    return () => window.clearInterval(timer);
  }, []);
  return nowMs;
}

function useIncidents() {
  const [rows, setRows] = useState<IncidentRecord[] | null>(null);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    const body = await apiJson<{ entitled: boolean; incidents: IncidentRecord[] }>('/api/ncua/incidents');
    setRows(body && Array.isArray(body.incidents) ? body.incidents : null);
    setLoaded(true);
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { rows, loaded, load };
}

function OpenIncidentForm({ onSaved }: { onSaved: () => void }) {
  const [title, setTitle] = useState('');
  const [queryIds, setQueryIds] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!title.trim()) {
      toast('An incident title is required.', 'error');
      return;
    }
    setBusy(true);
    try {
      const body = {
        title: title.trim(),
        ...(queryIds.trim() ? { queryIds: queryIds.split(',').map((v) => v.trim()).filter(Boolean) } : {}),
      };
      const saved = await apiSend<{ incident: IncidentRecord }>('/api/ncua/incidents', 'POST', body);
      if (saved?.incident) {
        toast(`Incident opened — report deadline ${saved.incident.deadlineAt.slice(0, 16).replace('T', ' ')}.`, 'good');
        setTitle(''); setQueryIds('');
        onSaved();
      } else {
        toast('Could not open the incident — check the fields (single-line title; event ids only).', 'error');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="ncua-usecase-form">
      <input placeholder="Incident title (one line, no member data)" value={title} onChange={(e) => setTitle(e.target.value)} />
      <input placeholder="Event ids from the queue, comma-separated (optional)" value={queryIds} onChange={(e) => setQueryIds(e.target.value)} />
      <button className="system-button secondary" type="button" disabled={busy} onClick={() => void submit()}>
        {busy ? 'Opening…' : 'Open incident'}
      </button>
    </div>
  );
}

function StatusActions({ incident, onSaved }: { incident: IncidentRecord; onSaved: () => void }) {
  const [busy, setBusy] = useState(false);
  const advance = async (status: IncidentRecord['status']) => {
    setBusy(true);
    try {
      const saved = await apiSend<{ incident: IncidentRecord }>(`/api/ncua/incidents/${encodeURIComponent(incident.id)}/status`, 'POST', { status });
      if (saved?.incident) {
        toast(`Incident marked ${status.replace('_', ' ')}.`, 'good');
        onSaved();
      } else {
        toast('Status change failed.', 'error');
      }
    } finally {
      setBusy(false);
    }
  };
  const next: Array<[IncidentRecord['status'], string]> = incident.status === 'open'
    ? [['under_review', 'Review'], ['reported', 'Mark reported']]
    : incident.status === 'under_review'
      ? [['reported', 'Mark reported'], ['closed', 'Close']]
      : incident.status === 'reported' ? [['closed', 'Close']] : [];
  return (
    <span className="ncua-usecase-review">
      {next.map(([status, label]) => (
        <button key={status} className="ghost mini" type="button" disabled={busy} onClick={() => void advance(status)}>
          {label}
        </button>
      ))}
    </span>
  );
}

export default function IncidentsPanel() {
  const { rows, loaded, load } = useIncidents();
  const { me } = useSession();
  const isAdmin = me?.role === 'security_admin';
  const [adding, setAdding] = useState(false);
  const nowMs = useMinuteTick();

  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>72-hour incident readiness</h2>
          <span>NCUA cyber-incident reporting clock (12 CFR 748.1(c)) with derived prompt-free timelines</span>
        </div>
        {isAdmin && (
          <button className="ghost mini" type="button" onClick={() => setAdding((v) => !v)}>
            {adding ? 'Close' : 'Open incident'}
          </button>
        )}
      </div>
      {adding && isAdmin && <OpenIncidentForm onSaved={() => { setAdding(false); void load(); }} />}
      <div style={{ padding: '0 16px 14px', overflowX: 'auto' }}>
        {!loaded ? (
          <div className="empty">Loading incidents…</div>
        ) : rows === null ? (
          <div className="empty">Could not load incidents — refresh the page to retry.</div>
        ) : !rows.length ? (
          <div className="empty">
            No AI incidents on record. When an event set looks like a reportable exposure, open an incident here -
            the 72-hour reporting clock and a prompt-free timeline are tracked automatically.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Incident</th><th>Status</th><th>Detected</th><th>Deadline</th><th>Events</th>{isAdmin && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((incident) => (
                <tr key={incident.id}>
                  <td>{incident.title}</td>
                  <td><span className={`insights-chip ${STATUS_TONE[incident.status] || 'tone-neutral'}`}>{incident.status.replace('_', ' ')}</span></td>
                  <td>{incident.detectedAt.slice(0, 16).replace('T', ' ')}</td>
                  <td>{deadlineLabel(incident, nowMs)}</td>
                  <td>{incident.timeline.length ? `${incident.timeline.length} (${incident.timeline.filter((e) => e.prevented).length} prevented)` : '—'}</td>
                  {isAdmin && (
                    <td>
                      <StatusActions key={`${incident.id}:${incident.updatedAt || incident.status}`} incident={incident} onSaved={() => void load()} />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
