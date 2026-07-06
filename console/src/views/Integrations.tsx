import { useCallback, useEffect, useState } from 'react';
import { api, apiJson, apiSend } from '../lib/api';
import { toast } from '../lib/toast';
import './Integrations.css';

/**
 * Integrations & Delivery: SIEM/SOAR subscription health, email/digest
 * plumbing, and recent delivery history. Route contract from server/app.js:
 *   GET  /api/subscriptions            (operator) -> { destinations, supportedTypes }
 *     destinations are secret-free publicDestinations(); recipients is only
 *     present for type 'email'; urlHost is null for email/unparseable URLs;
 *     eventTypes null means "all event types". Unused response fields
 *     (hasToken) are omitted from the interfaces below.
 *   GET  /api/subscriptions/deliveries (operator) -> { deliveries } newest
 *     first, server default limit 200. Status only — never payload bodies;
 *     dedupeKey/lastError exist in records but the legacy tab never renders
 *     them, so they are not typed here.
 *   POST /api/subscriptions/:id/test   (operator) -> { result } synthetic
 *     prompt-free test event; can take ~30s (retry backoff server-side).
 *   GET  /api/notifications/status     (Security Admin) -> SMTP relay,
 *     email destinations, digest state. 403 for operators — rendered as the
 *     legacy "needs a Security Admin session" line.
 *   POST /api/notifications/test-email (Security Admin) { to } -> { ok, error? }
 *     (send failures come back as 200 { ok:false }; a 400 carries { error }).
 *   POST /api/reports/digest/send      (Security Admin) {} -> { results }.
 * No SSE — legacy only refetches on tab activation, Refresh, or after one of
 * the three POST actions. Subscriptions are read-only here; destinations are
 * managed in config/subscriptions.json on the server.
 */

interface SubscriptionDestination {
  id: string;
  name: string;
  type: string;
  minRisk: number;
  minSeverity: number;
  eventTypes: string[] | null;
  urlHost: string | null;
  recipients?: number;
}

interface SubscriptionsResponse {
  destinations: SubscriptionDestination[];
  supportedTypes: string[];
}

interface DeliveryRecord {
  id: string;
  ts: string;
  destId: string;
  destName?: string;
  type?: string;
  status: string;
  attempts?: number;
  httpStatus?: number | null;
}

interface SmtpStatus {
  configured: boolean;
  host: string | null;
  port: number | null;
  secure: 'starttls' | 'tls' | 'none';
  from: string | null;
  authConfigured: boolean;
}

interface NotificationsStatus {
  smtp: SmtpStatus;
  emailDestinations: { name: string; recipients: number }[];
  digest: {
    intervalHours: number;
    last: { at: string; delivered: number; total: number; actor: string } | null;
  };
}

interface TestOutcome {
  status: string;
  attempts: number;
  at: string;
}

const EMPTY_SUBSCRIPTIONS: SubscriptionsResponse = { destinations: [], supportedTypes: [] };

const DELIVERY_TONE: Record<string, string> = { delivered: 'tone-low', failed: 'tone-critical', deduped: 'tone-neutral' };

const fmtTime = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-');
const recipientCount = (count: number) => `${count} recipient${count === 1 ? '' : 's'}`;

// ---- Fetchers ----

function fetchSubscriptions(): Promise<SubscriptionsResponse | null> {
  return apiJson<SubscriptionsResponse>('/api/subscriptions');
}

function fetchDeliveries(): Promise<{ deliveries: DeliveryRecord[] } | null> {
  return apiJson<{ deliveries: DeliveryRecord[] }>('/api/subscriptions/deliveries');
}

function fetchNotificationsStatus(): Promise<NotificationsStatus | null> {
  return apiJson<NotificationsStatus>('/api/notifications/status');
}

function postSubscriptionTest(id: string): Promise<{ result: { status: string; attempts?: number } } | null> {
  return apiSend<{ result: { status: string; attempts?: number } }>(`/api/subscriptions/${encodeURIComponent(id)}/test`, 'POST');
}

/** Parses the body even on 400 so the server's rejection reason reaches the inline result, as legacy did. */
async function postTestEmail(to: string): Promise<{ ok?: boolean; error?: string } | null> {
  const res = await api('/api/notifications/test-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to }),
  });
  if (!res) return null;
  try {
    return (await res.json()) as { ok?: boolean; error?: string };
  } catch {
    return null;
  }
}

function postDigestSend(): Promise<{ results: { status: string }[] } | null> {
  return apiSend<{ results: { status: string }[] }>('/api/reports/digest/send', 'POST', {});
}

// ---- Data hooks ----

function useIntegrationsData() {
  const [subs, setSubs] = useState<SubscriptionsResponse>(EMPTY_SUBSCRIPTIONS);
  const [deliveries, setDeliveries] = useState<DeliveryRecord[]>([]);
  const [loaded, setLoaded] = useState(false);
  const load = useCallback(async () => {
    const [subsBody, deliveryBody] = await Promise.all([fetchSubscriptions(), fetchDeliveries()]);
    setSubs(subsBody ?? EMPTY_SUBSCRIPTIONS);
    setDeliveries(deliveryBody?.deliveries ?? []);
    setLoaded(true);
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { subs, deliveries, loaded, load };
}

function useNotificationsStatus() {
  const [status, setStatus] = useState<NotificationsStatus | null>(null);
  const [statusLoaded, setStatusLoaded] = useState(false);
  const loadStatus = useCallback(async () => {
    setStatus(await fetchNotificationsStatus());
    setStatusLoaded(true);
  }, []);
  useEffect(() => {
    loadStatus();
  }, [loadStatus]);
  return { status, statusLoaded, loadStatus };
}

/** Per-destination test state: last outcome badge (session-only) + in-flight flag. No toast — the badge is the feedback. */
function useSubscriptionTests(reload: () => Promise<void>) {
  const [results, setResults] = useState<ReadonlyMap<string, TestOutcome>>(new Map());
  const [testing, setTesting] = useState<ReadonlySet<string>>(new Set());
  const runTest = async (id: string) => {
    setTesting((prev) => new Set(prev).add(id));
    const body = await postSubscriptionTest(id);
    const outcome: TestOutcome = body?.result
      ? { status: body.result.status, attempts: body.result.attempts || 0, at: new Date().toLocaleTimeString() }
      : { status: 'failed', attempts: 0, at: new Date().toLocaleTimeString() };
    setResults((prev) => new Map(prev).set(id, outcome));
    setTesting((prev) => {
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    await reload();
  };
  return { results, testing, runTest };
}

// ---- Header + KPIs ----

function RefreshIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function IntegrationsHeader({ onRefresh }: { onRefresh: () => void }) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>Integrations &amp; Delivery</h2>
          <p>SIEM / SOAR subscriptions and the AI Gateway. Every delivered event is prompt-free. Test connectivity and watch delivery health.</p>
        </div>
      </div>
      <div className="console-frame-actions">
        <button className="system-button secondary" type="button" onClick={onRefresh}>
          <RefreshIcon />
          Refresh
        </button>
      </div>
    </div>
  );
}

function Kpi({ value, label, hint }: { value: number; label: string; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiStrip({ subs, deliveries }: { subs: SubscriptionsResponse; deliveries: DeliveryRecord[] }) {
  const delivered = deliveries.filter((d) => d.status === 'delivered').length;
  const failed = deliveries.filter((d) => d.status === 'failed').length;
  return (
    <div className="insights-kpis">
      <Kpi value={subs.destinations.length} label="Subscriptions" hint="named destinations" />
      <Kpi value={delivered} label="Delivered" hint="recent events" />
      <Kpi value={failed} label="Failed" hint="needs attention" />
      <Kpi value={subs.supportedTypes.length} label="Supported" hint="SIEM/SOAR types" />
    </div>
  );
}

// ---- Email & Digest panel ----

function smtpRelayValue(smtp: SmtpStatus): string {
  if (!smtp.configured) return 'not configured - set SMTP_HOST to enable email';
  return `${smtp.host}:${smtp.port} (${smtp.secure}${smtp.authConfigured ? ', authenticated' : ''})`;
}

function emailDestinationsValue(list: NotificationsStatus['emailDestinations']): string {
  if (!list.length) return 'none - add { "type": "email", "to": [...] } to config/subscriptions.json';
  return list.map((dest) => `${dest.name} (${recipientCount(dest.recipients)})`).join(' · ');
}

function digestValue(digest: NotificationsStatus['digest']): string {
  if (!digest.last) return `every ${digest.intervalHours}h - not sent yet this run`;
  const { at, actor, delivered, total } = digest.last;
  return `last sent ${new Date(at).toLocaleString()} by ${actor} - ${delivered}/${total} delivered`;
}

function SmtpField({ label, value }: { label: string; value: string }) {
  return (
    <div className="inspector-field">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function SmtpStatusGrid({ status, loaded }: { status: NotificationsStatus | null; loaded: boolean }) {
  if (!loaded) return <div className="integrations-smtp app-loading">Syncing notification status…</div>;
  if (!status) {
    return (
      <div className="integrations-smtp">
        <div className="empty">Notification status needs a Security Admin session.</div>
      </div>
    );
  }
  return (
    <div className="inspector-grid integrations-smtp" aria-live="polite">
      <SmtpField label="SMTP relay" value={smtpRelayValue(status.smtp)} />
      <SmtpField label="From address" value={status.smtp.from || '-'} />
      <SmtpField label="Email destinations" value={emailDestinationsValue(status.emailDestinations)} />
      <SmtpField label="Daily digest" value={digestValue(status.digest)} />
    </div>
  );
}

/** The typed recipient is echoed only into the local result line — never logged or toasted. */
function TestEmailForm() {
  const [to, setTo] = useState('');
  const [result, setResult] = useState('');
  const [sending, setSending] = useState(false);
  const send = async () => {
    const trimmed = to.trim();
    if (!trimmed) {
      setResult('Enter a recipient address first.');
      return;
    }
    setSending(true);
    setResult('Sending...');
    const body = await postTestEmail(trimmed);
    const ok = Boolean(body?.ok);
    setResult(ok ? `Delivered to ${trimmed}.` : `Failed: ${body?.error || 'check the SMTP settings'}.`);
    toast(ok ? 'Test email delivered.' : 'Test email failed - see the panel for the reason.', ok ? 'good' : 'error');
    setSending(false);
  };
  return (
    <div className="catalog-form-body">
      <input type="text" placeholder="you@example.test" aria-label="Test email recipient" value={to} onChange={(event) => setTo(event.target.value)} />
      <button className="ghost" type="button" disabled={sending} onClick={send}>
        Send test email
      </button>
      <span className="reasons integrations-email-result">{result}</span>
    </div>
  );
}

interface EmailDigestPanelProps {
  status: NotificationsStatus | null;
  statusLoaded: boolean;
  digestBusy: boolean;
  onDigest: () => void;
}

function EmailDigestPanel({ status, statusLoaded, digestBusy, onDigest }: EmailDigestPanelProps) {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Email &amp; Digest</h2>
          <span>Human notifications: SMTP relay health, storm-limited email destinations, and the daily digest</span>
        </div>
        <button
          className="ghost mini"
          type="button"
          disabled={digestBusy}
          title="Dispatch the daily digest to every destination subscribed to the digest event type"
          onClick={onDigest}
        >
          {digestBusy ? 'Sending…' : 'Send digest now'}
        </button>
      </div>
      <SmtpStatusGrid status={status} loaded={statusLoaded} />
      <TestEmailForm />
    </div>
  );
}

// ---- Subscriptions panel ----

function subscriptionHost(dest: SubscriptionDestination): string {
  if (dest.type === 'email') return recipientCount(dest.recipients ?? 0);
  return dest.urlHost || '—';
}

function subscriptionFilter(dest: SubscriptionDestination): string {
  const types = dest.eventTypes ? ` · ${dest.eventTypes.join(',')}` : '';
  return `risk≥${dest.minRisk} · sev≥${dest.minSeverity}${types}`;
}

function TestBadge({ outcome }: { outcome: TestOutcome | null }) {
  if (!outcome) return null;
  const ok = outcome.status === 'delivered';
  return (
    <span className={`sub-test-result ${ok ? 'ok' : 'bad'}`}>
      Last test: {outcome.status} · {outcome.attempts} attempt(s) · {outcome.at}
    </span>
  );
}

interface SubscriptionRowProps {
  dest: SubscriptionDestination;
  outcome: TestOutcome | null;
  testing: boolean;
  onTest: () => void;
}

function SubscriptionRow({ dest, outcome, testing, onTest }: SubscriptionRowProps) {
  return (
    <div className="sub-row">
      <div className="sub-meta">
        <b>{dest.name}</b>
        <span className="insights-attr">{dest.type}</span>
        <span className="sub-host">{subscriptionHost(dest)}</span>
        <span className="sub-filter">{subscriptionFilter(dest)}</span>
      </div>
      <TestBadge outcome={outcome} />
      <button className="ghost mini" type="button" disabled={testing} onClick={onTest}>
        {testing ? 'Sending…' : 'Send test'}
      </button>
    </div>
  );
}

interface SubscriptionsPanelProps {
  destinations: SubscriptionDestination[];
  loaded: boolean;
  tests: ReturnType<typeof useSubscriptionTests>;
}

function SubscriptionsPanel({ destinations, loaded, tests }: SubscriptionsPanelProps) {
  const renderRows = () => {
    if (!loaded) return <div className="app-loading">Syncing subscriptions…</div>;
    if (!destinations.length) {
      return <div className="insights-empty">No subscriptions configured. Add destinations in config/subscriptions.json.</div>;
    }
    return destinations.map((dest) => (
      <SubscriptionRow
        key={dest.id}
        dest={dest}
        outcome={tests.results.get(dest.id) ?? null}
        testing={tests.testing.has(dest.id)}
        onTest={() => tests.runTest(dest.id)}
      />
    ));
  };
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>SIEM / SOAR subscriptions</h2>
          <span>Named destinations from config/subscriptions.json</span>
        </div>
      </div>
      <div>{renderRows()}</div>
    </div>
  );
}

// ---- Delivery history panel ----

function DeliveryRow({ rec }: { rec: DeliveryRecord }) {
  return (
    <tr>
      <td>{fmtTime(rec.ts)}</td>
      <td>{rec.destName || rec.destId}</td>
      <td>{rec.type || ''}</td>
      <td>
        <span className={`insights-chip ${DELIVERY_TONE[rec.status] || 'tone-neutral'}`}>{rec.status}</span>
      </td>
      <td>{rec.attempts || 0}</td>
      <td>{rec.httpStatus || '—'}</td>
    </tr>
  );
}

function DeliveryHistoryPanel({ deliveries, loaded }: { deliveries: DeliveryRecord[]; loaded: boolean }) {
  const renderRows = () => {
    if (!loaded) {
      return (
        <tr>
          <td colSpan={6} className="insights-empty">Syncing deliveries…</td>
        </tr>
      );
    }
    if (!deliveries.length) {
      return (
        <tr>
          <td colSpan={6} className="insights-empty">No deliveries yet.</td>
        </tr>
      );
    }
    return deliveries.map((rec) => <DeliveryRow key={rec.id} rec={rec} />);
  };
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Delivery history</h2>
          <span>Recent outbound deliveries — status only, never payload bodies</span>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Destination</th>
            <th>Type</th>
            <th>Status</th>
            <th>Attempts</th>
            <th>HTTP</th>
          </tr>
        </thead>
        <tbody>{renderRows()}</tbody>
      </table>
      <div className="integrity" aria-label="Delivery status legend">
        Status legend: <b>delivered</b> = destination accepted the event · <b>retrying</b> = temporary failure, retried with backoff ·{' '}
        <b>failed</b> = gave up after retries; use Send test to re-check the destination.
      </div>
    </div>
  );
}

// ---- View ----

export default function Integrations() {
  const { subs, deliveries, loaded, load } = useIntegrationsData();
  const { status, statusLoaded, loadStatus } = useNotificationsStatus();
  const tests = useSubscriptionTests(load);
  const [digestBusy, setDigestBusy] = useState(false);

  const sendDigest = async () => {
    setDigestBusy(true);
    const body = await postDigestSend();
    if (body) {
      const delivered = body.results.filter((r) => r.status === 'delivered').length;
      toast(`Digest dispatched: ${delivered}/${body.results.length} destination(s) delivered.`, 'good');
    } else {
      toast('Digest send failed.', 'error');
    }
    setDigestBusy(false);
    await Promise.all([loadStatus(), load()]);
  };

  return (
    <div className="integrations-view">
      <IntegrationsHeader onRefresh={load} />
      <KpiStrip subs={subs} deliveries={deliveries} />
      <EmailDigestPanel status={status} statusLoaded={statusLoaded} digestBusy={digestBusy} onDigest={sendDigest} />
      <div className="insights-grid">
        <SubscriptionsPanel destinations={subs.destinations} loaded={loaded} tests={tests} />
        <DeliveryHistoryPanel deliveries={deliveries} loaded={loaded} />
      </div>
    </div>
  );
}
