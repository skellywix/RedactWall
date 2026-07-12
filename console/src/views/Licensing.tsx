import { useCallback, useEffect, useState } from 'react';
import { EmptyState } from '../components/Panel';
import { api, apiErrorSummary, apiJsonBounded, apiSend, responseJsonBounded } from '../lib/api';
import { useSession } from '../lib/session';
import {
  decodeSubmittedLicensePayload,
  isCompleteLicenseSeatsResponse,
  isCompleteLicenseStatusResponse,
  isCompleteRenewalResponse,
  licenseStatusMatchesSubmitted,
} from '../lib/strict-console-response';
import './Licensing.css';

interface LicenseStatus {
  state: string;
  plan: string | null;
  seats: number | null;
  customer: string | null;
  customerId: string | null;
  features: string[];
  expires: string | null;
  graceEndsAt: string | null;
  daysRemaining: number | null;
  reason: string | null;
  renewalRequests?: RenewalRequest[];
}

interface RenewalRequest {
  id: string;
  status: string;
  requestedSeats: number | null;
  contactEmail: string;
  createdAt: string;
}

interface SeatUser {
  id: string;
  userName: string;
  displayName: string;
  roleLabel: string;
  sourceLabel: string;
  active: boolean;
  events: number;
  lastSeen: string | null;
  licenseState: string;
  licenseReason: string;
  licenseUpdatedAt: string | null;
}

interface SeatReport {
  license: LicenseStatus;
  tenantId: string | null;
  saasMode: boolean;
  seatLimit: number;
  seatLimitValid: boolean;
  seatsUsed: number;
  seatsRemaining: number | null;
  overLimit: boolean;
  assignedSeats: number;
  releasedSeats: number;
  users: SeatUser[];
}

const LICENSING_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;

const fmt = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '-');
const humanize = (value?: string) => (value || '-').replace(/_/g, ' ');

function StatePill({ state }: { state: string }) {
  const tone = state === 'active' || state === 'assigned' || state === 'in_use' ? 'good' : state === 'released' || state === 'grace' ? 'warn' : 'bad';
  return <span className={`pill ${tone}`}>{humanize(state)}</span>;
}

function Metric({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <div className="mini-kpi">
      <b>{label}</b>
      <em>{value}</em>
      <span>{hint}</span>
    </div>
  );
}

function LicenseCards({ license, seats }: { license: LicenseStatus; seats: SeatReport }) {
  const plan = license.plan || 'Demo';
  const limit = license.seats || seats.seatLimit || 'Unmetered';
  return (
    <div className="identity-summary licensing-cards">
      <Metric label="License State" value={humanize(license.state)} hint={license.reason || 'signed license status'} />
      <Metric label="Plan" value={plan} hint={license.customer || 'Texas FCU customer'} />
      <Metric label="Seats Used" value={`${seats.seatsUsed} / ${limit}`} hint={seats.overLimit ? 'over licensed seats' : 'metered sensor users'} />
      <Metric label="Renewal" value={license.daysRemaining ?? '-'} hint={license.expires ? `expires ${fmt(license.expires)}` : 'no expiration loaded'} />
    </div>
  );
}

function SeatTable({ users, canManage, onAssign, onRelease }: { users: SeatUser[]; canManage: boolean; onAssign: (user: SeatUser) => void; onRelease: (user: SeatUser) => void }) {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>License Users</h2>
          <span>Staff users consuming, assigned to, or released from RedactWall seats</span>
        </div>
      </div>
      <table className="admin-table license-table">
        <thead>
          <tr>
            <th>Staff User</th>
            <th>Role</th>
            <th>Source</th>
            <th>Seat State</th>
            <th>Activity</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td><b>{user.displayName}</b><span className="mono">{user.userName}</span></td>
              <td>{user.roleLabel}</td>
              <td>{user.sourceLabel}</td>
              <td>
                <StatePill state={user.licenseState} />
                {user.licenseReason ? <span className="seat-note">{user.licenseReason}</span> : null}
              </td>
              <td><b>{user.events}</b><span>{user.lastSeen ? fmt(user.lastSeen) : 'No sensor activity'}</span></td>
              <td>
                {!canManage ? (
                  <span className="readonly-note">Read-only</span>
                ) : user.licenseState === 'released' ? (
                  <button className="ghost mini" type="button" onClick={() => onAssign(user)}>Reassign</button>
                ) : (
                  <button className="ghost mini" type="button" onClick={() => onRelease(user)}>Release</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RenewalPanel({ onCreated }: { onCreated: () => void }) {
  const [requestedSeats, setRequestedSeats] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [note, setNote] = useState('');
  const [message, setMessage] = useState('');

  const submit = async () => {
    setMessage('');
    const body = {
      requestedSeats: requestedSeats ? Number(requestedSeats) : undefined,
      contactEmail: contactEmail || undefined,
      note: note || undefined,
    };
    const res = await api('/api/admin/license/renewal-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res || !res.ok) {
      setMessage(await apiErrorSummary(res, 'Could not create renewal request'));
      return;
    }
    const created = await responseJsonBounded<unknown>(res);
    if (!isCompleteRenewalResponse(created)) {
      setMessage('Renewal may have been created, but the response could not be verified. Refresh before retrying.');
      return;
    }
    setMessage(`Renewal request ${(created as { request: RenewalRequest }).request.id} created`);
    setRequestedSeats('');
    setContactEmail('');
    setNote('');
    onCreated();
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>Renewal Request</h2>
          <span>Offline-first renewal package for signed license issuance</span>
        </div>
      </div>
      <div className="licensing-form">
        <input aria-label="Requested seats" inputMode="numeric" placeholder="Requested seats" value={requestedSeats} onChange={(event) => setRequestedSeats(event.target.value)} />
        <input aria-label="Contact email" placeholder="admin@texasfcu.org" value={contactEmail} onChange={(event) => setContactEmail(event.target.value)} />
        <textarea aria-label="Renewal note" placeholder="Renewal note" value={note} onChange={(event) => setNote(event.target.value)} />
        <button className="primary" type="button" onClick={submit}>Request renewal</button>
        {message ? <div className="readonly-note">{message}</div> : null}
      </div>
    </div>
  );
}

function InstallPanel({ onInstalled }: { onInstalled: () => void }) {
  const [licenseText, setLicenseText] = useState('');
  const [reason, setReason] = useState('Renewal license received from RedactWall');
  const [message, setMessage] = useState('');

  const submit = async () => {
    setMessage('');
    const submitted = decodeSubmittedLicensePayload(licenseText);
    if (!submitted) {
      setMessage('Signed license payload could not be verified. The pasted value was not changed.');
      return;
    }
    const res = await api('/api/admin/license/install', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license: licenseText, reason }),
    });
    if (!res || !res.ok) {
      setMessage(await apiErrorSummary(res, 'Could not install license'));
      return;
    }
    const installed = await responseJsonBounded<unknown>(res);
    if (!licenseStatusMatchesSubmitted(installed, submitted)) {
      setMessage('License may have been installed, but the response could not be verified. Refresh licensing before retrying.');
      return;
    }
    setLicenseText('');
    setMessage('Signed license installed');
    onInstalled();
  };

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>Install Signed License</h2>
          <span>Renew, upgrade, or restore the customer license</span>
        </div>
      </div>
      <div className="licensing-form">
        <textarea aria-label="Signed license" placeholder="Paste signed RedactWall license" value={licenseText} onChange={(event) => setLicenseText(event.target.value)} />
        <input aria-label="Install reason" value={reason} onChange={(event) => setReason(event.target.value)} />
        <button className="primary" type="button" onClick={submit}>Install license</button>
        {message ? <div className="readonly-note">{message}</div> : null}
      </div>
    </div>
  );
}

function RenewalHistory({ requests }: { requests: RenewalRequest[] }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>Renewal History</h2>
          <span>Recent requests captured in the audit chain</span>
        </div>
      </div>
      <table className="admin-table compact">
        <thead><tr><th>Request</th><th>Seats</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
          {requests.map((request) => (
            <tr key={request.id}>
              <td className="mono">{request.id}</td>
              <td>{request.requestedSeats || '-'}</td>
              <td><StatePill state={request.status} /></td>
              <td>{fmt(request.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Licensing() {
  const { me } = useSession();
  const canManage = me?.role === 'security_admin';
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [seats, setSeats] = useState<SeatReport | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [licenseBody, seatsBody] = await Promise.all([
        apiJsonBounded<unknown>('/api/admin/license', LICENSING_RESPONSE_MAX_BYTES),
        apiJsonBounded<unknown>('/api/admin/license/seats', LICENSING_RESPONSE_MAX_BYTES),
      ]);
      if (!isCompleteLicenseStatusResponse(licenseBody, true) || !isCompleteLicenseSeatsResponse(seatsBody)) {
        setError('Licensing response could not be verified.');
        return;
      }
      const nextLicense = licenseBody as LicenseStatus;
      const nextSeats = seatsBody as SeatReport;
      const matchingLicense = ['state', 'plan', 'seats', 'customer', 'customerId', 'expires', 'graceEndsAt', 'daysRemaining', 'reason']
        .every((key) => nextLicense[key as keyof LicenseStatus] === nextSeats.license[key as keyof LicenseStatus])
        && JSON.stringify(nextLicense.features) === JSON.stringify(nextSeats.license.features);
      if (!matchingLicense) {
        setError('License and seat responses did not describe the same verified license.');
        return;
      }
      setLicense(nextLicense);
      setSeats(nextSeats);
      setError('');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const seatAction = async (user: SeatUser, action: 'assign' | 'release') => {
    const label = action === 'assign' ? 'Reason for reassigning this license' : 'Reason for releasing this license';
    const reason = window.prompt(label, 'Texas FCU license administration approved') || '';
    if (!reason) return;
    await apiSend(`/api/admin/license/seats/${action}`, 'POST', { userKey: user.userName, reason });
    await load();
  };

  if (!license || !seats) {
    if (loading) return <div className="app-loading">Loading licensing…</div>;
    return <EmptyState title="Licensing unavailable" detail="Could not load a complete license and seat snapshot. No seat totals were inferred. Refresh to retry." />;
  }

  return (
    <div className="licensing-view console-frame">
      <div className="console-frame-header">
        <div className="console-frame-title">
          <div>
            <h2>Licensing</h2>
            <p>Renewals, signed licenses, and Texas FCU staff seat usage.</p>
          </div>
        </div>
        <div className="console-frame-actions">
          <button className="ghost" type="button" onClick={() => void load()}>Refresh</button>
        </div>
      </div>
      {error ? <div className="readonly-note" role="alert">{error} Showing the last verified licensing snapshot.</div> : null}
      <LicenseCards license={license} seats={seats} />
      <SeatTable users={seats.users} canManage={canManage} onAssign={(user) => void seatAction(user, 'assign')} onRelease={(user) => void seatAction(user, 'release')} />
      <div className="licensing-grid">
        {canManage ? (
          <>
            <RenewalPanel onCreated={() => void load()} />
            <InstallPanel onInstalled={() => void load()} />
          </>
        ) : (
          <div className="panel">
            <div className="panel-head"><div><h2>Licensing Administration</h2></div></div>
            <p className="readonly-note">Global Administrator access is required to change licensing.</p>
          </div>
        )}
        <RenewalHistory requests={license.renewalRequests || []} />
      </div>
    </div>
  );
}
