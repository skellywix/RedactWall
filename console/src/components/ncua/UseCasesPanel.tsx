import { useCallback, useEffect, useState } from 'react';
import { apiJson, apiSend } from '../../lib/api';
import { useSession } from '../../lib/session';
import { toast } from '../../lib/toast';

/**
 * AI use-case inventory (PLANS/ncua-readiness-center.md slice 2). Route
 * contract from server/app.js:
 *   GET  /api/ncua/use-cases -> { entitled, useCases[] } — any console role.
 *   POST /api/ncua/use-cases (Security Admin + CSRF) — upsert keyed by
 *     (destination, department); hostname-only destination, single-line
 *     bounded text, data classes validated against real detector ids.
 *   POST /api/ncua/use-cases/:id/review (Security Admin + CSRF) — review
 *     decision + vendor status + next review date.
 * CSRF is automatic via lib/api.ts; no password step-up. The table renders
 * operator-entered inventory text; nothing here ever shows prompt content.
 */

export interface UseCaseRecord {
  id: string;
  canonicalHost: string;
  department: string;
  owner?: string;
  approvedUse?: string;
  allowedDataClasses?: string[];
  reviewStatus: 'approved' | 'under_review' | 'restricted' | 'retired';
  vendorStatus?: 'reviewed' | 'pending' | 'not_reviewed';
  nextReviewAt?: string | null;
  updatedAt?: string;
}

const REVIEW_TONE: Record<string, string> = {
  approved: 'tone-low',
  under_review: 'tone-medium',
  restricted: 'tone-high',
  retired: 'tone-neutral',
};

function useUseCases() {
  const [rows, setRows] = useState<UseCaseRecord[] | null>(null);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    const body = await apiJson<{ entitled: boolean; useCases: UseCaseRecord[] }>('/api/ncua/use-cases');
    setRows(body && Array.isArray(body.useCases) ? body.useCases : null);
    setLoaded(true);
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { rows, loaded, load };
}

function AddForm({ onSaved }: { onSaved: () => void }) {
  const [destination, setDestination] = useState('');
  const [department, setDepartment] = useState('');
  const [owner, setOwner] = useState('');
  const [approvedUse, setApprovedUse] = useState('');
  const [dataClasses, setDataClasses] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!destination.trim() || !department.trim()) {
      toast('Destination host and department are required.', 'error');
      return;
    }
    setBusy(true);
    try {
      const body = {
        destination: destination.trim().toLowerCase(),
        department: department.trim(),
        ...(owner.trim() ? { owner: owner.trim() } : {}),
        ...(approvedUse.trim() ? { approvedUse: approvedUse.trim() } : {}),
        ...(dataClasses.trim()
          ? { allowedDataClasses: dataClasses.split(',').map((c) => c.trim().toUpperCase()).filter(Boolean) }
          : {}),
      };
      const saved = await apiSend<{ useCase: UseCaseRecord }>('/api/ncua/use-cases', 'POST', body);
      if (saved?.useCase) {
        toast(`Recorded ${saved.useCase.canonicalHost} for ${saved.useCase.department}.`, 'good');
        setDestination(''); setDepartment(''); setOwner(''); setApprovedUse(''); setDataClasses('');
        onSaved();
      } else {
        toast('Could not save the use case — check the fields (hostname only; single-line text; known data classes).', 'error');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="ncua-usecase-form">
      <input placeholder="AI tool host (chat.openai.com)" value={destination} onChange={(e) => setDestination(e.target.value)} />
      <input placeholder="Department (Lending)" value={department} onChange={(e) => setDepartment(e.target.value)} />
      <input placeholder="Owner (name or email)" value={owner} onChange={(e) => setOwner(e.target.value)} />
      <input placeholder="Approved use (one line)" value={approvedUse} onChange={(e) => setApprovedUse(e.target.value)} />
      <input placeholder="Allowed data classes (MEMBER_ID, LOAN_NUMBER)" value={dataClasses} onChange={(e) => setDataClasses(e.target.value)} />
      <button className="system-button secondary" type="button" disabled={busy} onClick={() => void submit()}>
        {busy ? 'Saving…' : 'Add use case'}
      </button>
    </div>
  );
}

function ReviewCell({ row, onSaved }: { row: UseCaseRecord; onSaved: () => void }) {
  const [reviewStatus, setReviewStatus] = useState(row.reviewStatus);
  const [vendorStatus, setVendorStatus] = useState(row.vendorStatus || 'not_reviewed');
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      const saved = await apiSend<{ useCase: UseCaseRecord }>(`/api/ncua/use-cases/${encodeURIComponent(row.id)}/review`, 'POST', {
        reviewStatus,
        vendorStatus,
      });
      if (saved?.useCase) {
        toast(`Review recorded for ${row.canonicalHost} / ${row.department}.`, 'good');
        onSaved();
      } else {
        toast('Review failed.', 'error');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="ncua-usecase-review">
      <select value={reviewStatus} onChange={(e) => setReviewStatus(e.target.value as UseCaseRecord['reviewStatus'])}>
        <option value="approved">approved</option>
        <option value="under_review">under review</option>
        <option value="restricted">restricted</option>
        <option value="retired">retired</option>
      </select>
      <select value={vendorStatus} onChange={(e) => setVendorStatus(e.target.value as NonNullable<UseCaseRecord['vendorStatus']>)}>
        <option value="reviewed">vendor reviewed</option>
        <option value="pending">vendor pending</option>
        <option value="not_reviewed">vendor not reviewed</option>
      </select>
      <button className="ghost mini" type="button" disabled={busy} onClick={() => void save()}>
        Save
      </button>
    </span>
  );
}

export default function UseCasesPanel() {
  const { rows, loaded, load } = useUseCases();
  const { me } = useSession();
  const isAdmin = me?.role === 'security_admin';
  const [adding, setAdding] = useState(false);

  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>AI use-case inventory</h2>
          <span>Who may use which tool for what, by department — the inventory an examiner asks for first</span>
        </div>
        {isAdmin && (
          <button className="ghost mini" type="button" onClick={() => setAdding((v) => !v)}>
            {adding ? 'Close' : 'Add use case'}
          </button>
        )}
      </div>
      {adding && isAdmin && <AddForm onSaved={() => { setAdding(false); void load(); }} />}
      <div style={{ padding: '0 16px 14px', overflowX: 'auto' }}>
        {!loaded ? (
          <div className="empty">Loading inventory…</div>
        ) : !rows?.length ? (
          <div className="empty">
            No AI use cases recorded yet. Inventory each department's approved tools, owners, and allowed data
            classes — distinct records per department keep "ChatGPT in Lending" separate from Marketing.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Department</th><th>Tool</th><th>Owner</th><th>Approved use</th><th>Data classes</th>
                <th>Review</th><th>Vendor</th><th>Next review</th>{isAdmin && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.department}</td>
                  <td>{row.canonicalHost}</td>
                  <td>{row.owner || '—'}</td>
                  <td>{row.approvedUse || '—'}</td>
                  <td>{(row.allowedDataClasses || []).join(', ') || '—'}</td>
                  <td><span className={`insights-chip ${REVIEW_TONE[row.reviewStatus] || 'tone-neutral'}`}>{row.reviewStatus.replace('_', ' ')}</span></td>
                  <td>{(row.vendorStatus || 'not_reviewed').replace('_', ' ')}</td>
                  <td>{row.nextReviewAt ? row.nextReviewAt.slice(0, 10) : '—'}</td>
                  {isAdmin && <td><ReviewCell row={row} onSaved={() => void load()} /></td>}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
