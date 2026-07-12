import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { api, apiErrorSummary, apiJson, apiSend, responseJsonBounded } from '../lib/api';
import { useSession } from '../lib/session';
import { isExactEmailSuccess } from '../lib/strict-console-response';
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

const DELIVERY_TONE: Record<string, string> = { delivered: 'tone-low', failed: 'tone-critical', deduped: 'tone-neutral' };
const DELIVERY_STATUSES = new Set(['delivered', 'failed', 'deduped']);
const TEST_STATUSES = new Set(['delivered', 'failed']);
const MAX_DESTINATIONS = 500;
const MAX_DELIVERIES = 2000;
const MAX_EVENT_TYPES = 64;

type DeliveryDataState = 'loading' | 'ready' | 'stale' | 'unavailable';
type NotificationState = 'permission' | DeliveryDataState;

const fmtTime = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-');
const recipientCount = (count: number) => `${count} recipient${count === 1 ? '' : 's'}`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function boundedString(value: unknown, max: number, allowEmpty = false): string | null {
  if (typeof value !== 'string' || value.length > max || (!allowEmpty && !value.trim())) return null;
  return value;
}

function boundedInteger(value: unknown, min: number, max: number): number | null {
  return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max ? Number(value) : null;
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function boundedStringList(value: unknown, maxItems: number, maxLength: number): string[] | null {
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const strings = value.map((item) => boundedString(item, maxLength));
  if (strings.some((item) => item === null) || new Set(strings).size !== strings.length) return null;
  return strings as string[];
}

function decodeDestination(value: unknown): SubscriptionDestination | null {
  if (!isRecord(value)) return null;
  const id = boundedString(value.id, 64);
  const name = boundedString(value.name, 120);
  const type = boundedString(value.type, 40);
  const minRisk = boundedInteger(value.minRisk, 0, 100);
  const minSeverity = boundedInteger(value.minSeverity, 0, 5);
  const eventTypes = value.eventTypes === null ? null : boundedStringList(value.eventTypes, MAX_EVENT_TYPES, 64);
  const urlHost = value.urlHost === null ? null : boundedString(value.urlHost, 260);
  const recipients = value.recipients === undefined ? undefined : boundedInteger(value.recipients, 1, 1000);
  if (!id || !name || !type || minRisk === null || minSeverity === null || eventTypes === null && value.eventTypes !== null
    || urlHost === null && value.urlHost !== null || value.recipients !== undefined && recipients === null) return null;
  if (type === 'email' && recipients === undefined) return null;
  const destination: SubscriptionDestination = { id, name, type, minRisk, minSeverity, eventTypes, urlHost };
  if (typeof recipients === 'number') destination.recipients = recipients;
  return destination;
}

function decodeSubscriptions(value: unknown): SubscriptionsResponse | null {
  if (!isRecord(value) || !Array.isArray(value.destinations) || value.destinations.length > MAX_DESTINATIONS) return null;
  const destinations = value.destinations.map(decodeDestination);
  const supportedTypes = boundedStringList(value.supportedTypes, 64, 40);
  if (!supportedTypes || destinations.some((item) => item === null)) return null;
  const ids = destinations.map((item) => item!.id);
  const supported = new Set(supportedTypes);
  if (new Set(ids).size !== ids.length || destinations.some((item) => (
    item!.type === 'email'
      ? item!.recipients === undefined || item!.urlHost !== null
      : !supported.has(item!.type) || item!.recipients !== undefined || item!.urlHost === null
  ))) return null;
  return { destinations: destinations as SubscriptionDestination[], supportedTypes };
}

function decodeDelivery(value: unknown): DeliveryRecord | null {
  if (!isRecord(value)) return null;
  const id = boundedString(value.id, 128);
  const destId = boundedString(value.destId, 64);
  const status = boundedString(value.status, 24);
  const destName = value.destName === undefined ? undefined : boundedString(value.destName, 120);
  const type = value.type === undefined ? undefined : boundedString(value.type, 40);
  const attempts = value.attempts === undefined ? undefined : boundedInteger(value.attempts, 0, 8);
  const httpStatus = value.httpStatus === undefined || value.httpStatus === null
    ? value.httpStatus as undefined | null
    : boundedInteger(value.httpStatus, 100, 599);
  if (!id || !destId || !status || !DELIVERY_STATUSES.has(status) || !validTimestamp(value.ts)
    || value.destName !== undefined && destName === null || value.type !== undefined && type === null
    || value.attempts !== undefined && attempts === null || value.httpStatus !== undefined && value.httpStatus !== null && httpStatus === null) return null;
  const delivery: DeliveryRecord = {
    id,
    ts: value.ts,
    destId,
    status,
  };
  if (typeof destName === 'string') delivery.destName = destName;
  if (typeof type === 'string') delivery.type = type;
  if (typeof attempts === 'number') delivery.attempts = attempts;
  if (typeof httpStatus === 'number' || httpStatus === null) delivery.httpStatus = httpStatus;
  return delivery;
}

function decodeDeliveries(value: unknown): { deliveries: DeliveryRecord[] } | null {
  if (!isRecord(value) || !Array.isArray(value.deliveries) || value.deliveries.length > MAX_DELIVERIES) return null;
  const deliveries = value.deliveries.map(decodeDelivery);
  if (deliveries.some((item) => item === null)) return null;
  const ids = deliveries.map((item) => item!.id);
  return new Set(ids).size === ids.length ? { deliveries: deliveries as DeliveryRecord[] } : null;
}

function decodeNotificationsStatus(value: unknown): NotificationsStatus | null {
  if (!isRecord(value) || !isRecord(value.smtp) || !Array.isArray(value.emailDestinations)
    || value.emailDestinations.length > MAX_DESTINATIONS || !isRecord(value.digest)) return null;
  const smtp = value.smtp;
  const configured = smtp.configured;
  const host = smtp.host === null ? null : boundedString(smtp.host, 260);
  const port = smtp.port === null ? null : boundedInteger(smtp.port, 1, 65535);
  const secure = smtp.secure;
  const from = smtp.from === null ? null : boundedString(smtp.from, 320);
  if (typeof configured !== 'boolean' || host === null && smtp.host !== null || port === null && smtp.port !== null
    || typeof secure !== 'string' || !['starttls', 'tls', 'none'].includes(secure) || from === null && smtp.from !== null
    || typeof smtp.authConfigured !== 'boolean'
    || configured && (!host || port === null || !from)
    || !configured && (host !== null || port !== null || from !== null)) return null;
  const emailDestinations = value.emailDestinations.map((item) => {
    if (!isRecord(item)) return null;
    const id = boundedString(item.id, 64);
    const name = boundedString(item.name, 120);
    const recipients = boundedInteger(item.recipients, 1, 1000);
    const eventTypes = item.eventTypes === null ? null : boundedStringList(item.eventTypes, MAX_EVENT_TYPES, 64);
    return id && name && recipients !== null && (eventTypes !== null || item.eventTypes === null)
      ? { id, name, recipients }
      : null;
  });
  if (emailDestinations.some((item) => item === null)) return null;
  const emailDestinationIds = emailDestinations.map((item) => item!.id);
  if (new Set(emailDestinationIds).size !== emailDestinationIds.length) return null;
  const intervalHours = boundedInteger(value.digest.intervalHours, 1, 8760);
  if (intervalHours === null) return null;
  let last: NotificationsStatus['digest']['last'] = null;
  if (value.digest.last !== null) {
    if (!isRecord(value.digest.last) || !validTimestamp(value.digest.last.at)) return null;
    const delivered = boundedInteger(value.digest.last.delivered, 0, MAX_DESTINATIONS);
    const total = boundedInteger(value.digest.last.total, 0, MAX_DESTINATIONS);
    const actor = boundedString(value.digest.last.actor, 128);
    if (delivered === null || total === null || delivered > total || !actor) return null;
    last = { at: value.digest.last.at, delivered, total, actor };
  }
  return {
    smtp: { configured, host, port, secure: secure as SmtpStatus['secure'], from, authConfigured: smtp.authConfigured },
    emailDestinations: emailDestinations.map((item) => ({ name: item!.name, recipients: item!.recipients })),
    digest: { intervalHours, last },
  };
}

function decodeSubscriptionTest(value: unknown, id: string): { result: { status: string; attempts: number } } | null {
  if (!isRecord(value) || !isRecord(value.result) || value.result.destId !== id) return null;
  const status = boundedString(value.result.status, 24);
  const attempts = boundedInteger(value.result.attempts, 0, 8);
  const httpStatus = value.result.httpStatus === null ? null : boundedInteger(value.result.httpStatus, 100, 599);
  if (!status || !TEST_STATUSES.has(status) || attempts === null
    || status === 'delivered' && attempts === 0
    || httpStatus === null && value.result.httpStatus !== null) return null;
  return { result: { status, attempts } };
}

function safeEmailFailure(value: unknown): string | null {
  const error = boundedString(value, 120);
  if (!error) return null;
  if (error === 'smtp_not_configured') return 'SMTP relay is not configured';
  if (error === 'no_valid_recipients' || error === 'provide a recipient address') return 'provide a valid recipient address';
  return 'SMTP delivery failed';
}

function decodeEmailResult(value: unknown, allowValidationError = false): { ok: boolean; error?: string } | null {
  if (isExactEmailSuccess(value)) return { ok: true };
  if (!isRecord(value) || value.ok === true) return null;
  if (value.ok !== false && !(allowValidationError && value.ok === undefined)) return null;
  const error = safeEmailFailure(value.error);
  return error ? { ok: false, error } : null;
}

function decodeDigestResult(value: unknown): { results: { status: string }[] } | null {
  if (!isRecord(value) || !Array.isArray(value.results) || value.results.length > MAX_DESTINATIONS) return null;
  const results = value.results.map((item) => {
    if (!isRecord(item) || typeof item.status !== 'string' || !DELIVERY_STATUSES.has(item.status)) return null;
    return { status: item.status };
  });
  return results.some((item) => item === null) ? null : { results: results as { status: string }[] };
}

// ---- Fetchers ----

async function fetchSubscriptions(): Promise<SubscriptionsResponse | null> {
  return decodeSubscriptions(await apiJson<unknown>('/api/subscriptions'));
}

async function fetchDeliveries(): Promise<{ deliveries: DeliveryRecord[] } | null> {
  return decodeDeliveries(await apiJson<unknown>('/api/subscriptions/deliveries'));
}

async function fetchNotificationsStatus(): Promise<NotificationsStatus | null> {
  return decodeNotificationsStatus(await apiJson<unknown>('/api/notifications/status'));
}

async function postSubscriptionTest(id: string): Promise<{ result: { status: string; attempts: number } } | null> {
  return decodeSubscriptionTest(await apiSend<unknown>(`/api/subscriptions/${encodeURIComponent(id)}/test`, 'POST'), id);
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
    if (res.status === 200) return decodeEmailResult(await responseJsonBounded<unknown>(res));
    if (res.status === 400) return decodeEmailResult(await responseJsonBounded<unknown>(res), true);
    if (!res.ok) return { ok: false, error: await apiErrorSummary(res, 'SMTP delivery failed') };
    return null;
  } catch {
    return null;
  }
}

async function postDigestSend(): Promise<{ results: { status: string }[] } | null> {
  return decodeDigestResult(await apiSend<unknown>('/api/reports/digest/send', 'POST', {}));
}

// ---- Data hooks ----

function useIntegrationsData() {
  const [subs, setSubs] = useState<SubscriptionsResponse | null>(null);
  const [deliveries, setDeliveries] = useState<DeliveryRecord[] | null>(null);
  const [state, setState] = useState<DeliveryDataState>('loading');
  const hasSnapshot = useRef(false);
  const requestVersion = useRef(0);
  const load = useCallback(async () => {
    const version = ++requestVersion.current;
    const [subsBody, deliveryBody] = await Promise.all([fetchSubscriptions(), fetchDeliveries()]);
    if (version !== requestVersion.current) return;
    if (subsBody && Array.isArray(subsBody.destinations) && Array.isArray(subsBody.supportedTypes)
      && deliveryBody && Array.isArray(deliveryBody.deliveries)) {
      hasSnapshot.current = true;
      setSubs(subsBody);
      setDeliveries(deliveryBody.deliveries);
      setState('ready');
      return;
    }
    setState(hasSnapshot.current ? 'stale' : 'unavailable');
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  return { subs, deliveries, state, load };
}

function useNotificationsStatus(enabled: boolean) {
  const [status, setStatus] = useState<NotificationsStatus | null>(null);
  const [state, setState] = useState<NotificationState>(enabled ? 'loading' : 'permission');
  const hasSnapshot = useRef(false);
  const requestVersion = useRef(0);
  const loadStatus = useCallback(async () => {
    const version = ++requestVersion.current;
    if (!enabled) {
      hasSnapshot.current = false;
      setStatus(null);
      setState('permission');
      return;
    }
    if (!hasSnapshot.current) setState('loading');
    const next = await fetchNotificationsStatus();
    if (version !== requestVersion.current) return;
    if (next) {
      hasSnapshot.current = true;
      setStatus(next);
      setState('ready');
      return;
    }
    setState(hasSnapshot.current ? 'stale' : 'unavailable');
  }, [enabled]);
  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);
  return { status, state, loadStatus };
}

/** Per-destination test state: last outcome badge (session-only) + in-flight flag. No toast — the badge is the feedback. */
function useSubscriptionTests(reload: () => Promise<void>) {
  const [results, setResults] = useState<ReadonlyMap<string, TestOutcome>>(new Map());
  const [testing, setTesting] = useState<ReadonlySet<string>>(new Set());
  const inFlight = useRef(new Set<string>());
  const runTest = async (id: string) => {
    if (inFlight.current.has(id)) return;
    inFlight.current.add(id);
    setTesting((prev) => new Set(prev).add(id));
    try {
      const body = await postSubscriptionTest(id);
      const outcome: TestOutcome = body?.result
        ? { status: body.result.status, attempts: body.result.attempts || 0, at: new Date().toLocaleTimeString() }
        : { status: 'unavailable', attempts: 0, at: new Date().toLocaleTimeString() };
      setResults((prev) => new Map(prev).set(id, outcome));
      await reload();
    } finally {
      inFlight.current.delete(id);
      setTesting((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
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
          <h2>Evidence Delivery</h2>
          <p>SIEM, SOAR, email, digest, and AI Gateway delivery for Texas FCU security teams. Every delivered event is prompt-free.</p>
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

function Kpi({ value, label, hint }: { value: ReactNode; label: string; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiStrip({ subs, deliveries, state }: {
  subs: SubscriptionsResponse | null;
  deliveries: DeliveryRecord[] | null;
  state: DeliveryDataState;
}) {
  const fallback = state === 'loading' ? '…' : '—';
  if (!subs || !deliveries) {
    return (
      <div className="insights-kpis" aria-label={`Evidence delivery ${state}`}>
        <Kpi value={fallback} label="Evidence routes" hint="not verified" />
        <Kpi value={fallback} label="Delivered" hint="not verified" />
        <Kpi value={fallback} label="Failed" hint="not verified" />
        <Kpi value={fallback} label="Supported" hint="not verified" />
      </div>
    );
  }
  const delivered = deliveries.filter((d) => d.status === 'delivered').length;
  const failed = deliveries.filter((d) => d.status === 'failed').length;
  return (
    <div className="insights-kpis" aria-label={state === 'stale' ? 'Last verified evidence delivery totals' : 'Verified evidence delivery totals'}>
      <Kpi value={subs.destinations.length} label="Evidence routes" hint="named destinations" />
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

function SmtpStatusGrid({ status, state }: { status: NotificationsStatus | null; state: NotificationState }) {
  if (state === 'loading') return <div className="integrations-smtp app-loading">Syncing notification status…</div>;
  if (!status || state === 'unavailable') {
    return (
      <div className="integrations-smtp" role="alert">
        <div className="empty">Notification status is unavailable. Refresh before treating SMTP or digest delivery as unconfigured.</div>
      </div>
    );
  }
  return (
    <>
      {state === 'stale' ? <div className="readonly-note" role="alert">Showing the last verified notification snapshot after refresh failed.</div> : null}
      <div className="inspector-grid integrations-smtp" aria-live="polite">
        <SmtpField label="SMTP relay" value={smtpRelayValue(status.smtp)} />
        <SmtpField label="From address" value={status.smtp.from || '-'} />
        <SmtpField label="Email destinations" value={emailDestinationsValue(status.emailDestinations)} />
        <SmtpField label="Daily digest" value={digestValue(status.digest)} />
      </div>
    </>
  );
}

/** The typed recipient is echoed only into the local result line — never logged or toasted. */
function TestEmailForm() {
  const [to, setTo] = useState('');
  const [result, setResult] = useState('');
  const [sending, setSending] = useState(false);
  const sendingRef = useRef(false);
  const send = async () => {
    if (sendingRef.current) return;
    const trimmed = to.trim();
    if (!trimmed) {
      setResult('Enter a recipient address first.');
      return;
    }
    sendingRef.current = true;
    setSending(true);
    setResult('Sending...');
    try {
      const body = await postTestEmail(trimmed);
      if (!body) {
        setResult('Result unavailable. Review delivery history before retrying.');
        toast('Test email response could not be verified.', 'error');
        return;
      }
      const ok = body.ok === true;
      setResult(ok ? `Delivered to ${trimmed}.` : `Failed: ${body?.error || 'check the SMTP settings'}.`);
      toast(ok ? 'Test email delivered.' : 'Test email failed - see the panel for the reason.', ok ? 'good' : 'error');
    } finally {
      sendingRef.current = false;
      setSending(false);
    }
  };
  return (
    <div className="catalog-form-body">
      <input type="email" maxLength={320} placeholder="you@example.test" aria-label="Test email recipient" value={to} onChange={(event) => setTo(event.target.value)} />
      <button className="ghost" type="button" disabled={sending} onClick={send}>
        Send test email
      </button>
      <span className="reasons integrations-email-result">{result}</span>
    </div>
  );
}

interface EmailDigestPanelProps {
  status: NotificationsStatus | null;
  state: NotificationState;
  canManage: boolean;
  digestBusy: boolean;
  onDigest: () => void;
}

const NOTIFICATION_PERMISSION_ID = 'notification-admin-permission';

function EmailDigestPanel({ status, state, canManage, digestBusy, onDigest }: EmailDigestPanelProps) {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Email &amp; Board Digest</h2>
          <span>Human notifications: SMTP relay health, storm-limited reviewer destinations, and the daily digest</span>
        </div>
        <button
          className="ghost mini"
          type="button"
          disabled={digestBusy || !canManage}
          aria-describedby={!canManage ? NOTIFICATION_PERMISSION_ID : undefined}
          title="Dispatch the daily digest to every destination subscribed to the digest event type"
          onClick={onDigest}
        >
          {digestBusy ? 'Sending…' : 'Send digest now'}
        </button>
      </div>
      {!canManage ? (
        <div id={NOTIFICATION_PERMISSION_ID} className="system-state system-permission" role="status">
          <strong>Security Admin access required</strong>
          <p>Operators can inspect and test SIEM/SOAR evidence routes. SMTP status, test email, and digest dispatch remain Security Admin actions.</p>
        </div>
      ) : (
        <>
          <SmtpStatusGrid status={status} state={state} />
          <TestEmailForm />
        </>
      )}
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
  destinations: SubscriptionDestination[] | null;
  state: DeliveryDataState;
  tests: ReturnType<typeof useSubscriptionTests>;
}

function SubscriptionsPanel({ destinations, state, tests }: SubscriptionsPanelProps) {
  const renderRows = () => {
    if (state === 'loading') return <div className="app-loading">Syncing subscriptions…</div>;
    if (!destinations) {
      return <div className="system-state system-unavailable" role="alert"><strong>Subscriptions unavailable</strong><p>No verified evidence-route snapshot is available.</p></div>;
    }
    if (!destinations.length) {
      return <div className="insights-empty">{state === 'stale' ? 'The last verified snapshot had no subscriptions; the current state is unknown.' : 'No subscriptions configured. Add destinations in config/subscriptions.json.'}</div>;
    }
    return (
      <>
        {state === 'stale' ? <div className="readonly-note" role="alert">Showing last verified evidence routes after refresh failed.</div> : null}
        {destinations.map((dest) => (
          <SubscriptionRow
            key={dest.id}
            dest={dest}
            outcome={tests.results.get(dest.id) ?? null}
            testing={tests.testing.has(dest.id)}
            onTest={() => tests.runTest(dest.id)}
          />
        ))}
      </>
    );
  };
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>SIEM / SOAR evidence routes</h2>
          <span>Named prompt-free destinations from config/subscriptions.json</span>
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

function DeliveryHistoryPanel({ deliveries, state }: { deliveries: DeliveryRecord[] | null; state: DeliveryDataState }) {
  const renderRows = () => {
    if (state === 'loading') {
      return (
        <tr>
          <td colSpan={6} className="insights-empty">Syncing deliveries…</td>
        </tr>
      );
    }
    if (!deliveries) {
      return (
        <tr>
          <td colSpan={6} className="insights-empty">Delivery history unavailable. No verified empty-state conclusion can be drawn.</td>
        </tr>
      );
    }
    if (!deliveries.length) {
      return (
        <tr>
          <td colSpan={6} className="insights-empty">{state === 'stale' ? 'The last verified snapshot had no deliveries; the current state is unknown.' : 'No deliveries yet.'}</td>
        </tr>
      );
    }
    return (
      <>
        {state === 'stale' ? <tr><td colSpan={6} className="readonly-note">Showing last verified delivery history after refresh failed.</td></tr> : null}
        {deliveries.map((rec) => <DeliveryRow key={rec.id} rec={rec} />)}
      </>
    );
  };
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Evidence delivery history</h2>
          <span>Recent outbound deliveries - status only, never payload bodies</span>
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
        Status legend: <b>delivered</b> = destination accepted the event · <b>deduped</b> = a recent identical event was already accepted ·{' '}
        <b>failed</b> = gave up after retries; use Send test to re-check the destination.
      </div>
    </div>
  );
}

// ---- View ----

export default function Integrations() {
  const { me } = useSession();
  const canManageNotifications = me?.role === 'security_admin';
  const { subs, deliveries, state, load } = useIntegrationsData();
  const { status, state: notificationState, loadStatus } = useNotificationsStatus(canManageNotifications);
  const tests = useSubscriptionTests(load);
  const [digestBusy, setDigestBusy] = useState(false);
  const digestBusyRef = useRef(false);

  const sendDigest = async () => {
    if (!canManageNotifications || digestBusyRef.current) return;
    digestBusyRef.current = true;
    setDigestBusy(true);
    try {
      const body = await postDigestSend();
      if (body) {
        const delivered = body.results.filter((r) => r.status === 'delivered').length;
        const complete = body.results.length > 0 && delivered === body.results.length;
        const message = body.results.length
          ? `Digest dispatch verified: ${delivered}/${body.results.length} destination(s) delivered.`
          : 'Digest dispatch verified with no configured destinations.';
        toast(message, complete ? 'good' : 'warn');
      } else {
        toast('Digest response could not be verified. Review delivery history before retrying.', 'error');
      }
      await Promise.all([loadStatus(), load()]);
    } catch {
      toast('Digest send failed.', 'error');
    } finally {
      digestBusyRef.current = false;
      setDigestBusy(false);
    }
  };

  const refresh = () => Promise.all([load(), loadStatus()]).then(() => undefined);

  return (
    <div className="integrations-view">
      <IntegrationsHeader onRefresh={() => void refresh()} />
      <KpiStrip subs={subs} deliveries={deliveries} state={state} />
      <EmailDigestPanel
        status={status}
        state={notificationState}
        canManage={canManageNotifications}
        digestBusy={digestBusy}
        onDigest={() => void sendDigest()}
      />
      <div className="insights-grid">
        <SubscriptionsPanel destinations={subs?.destinations ?? null} state={state} tests={tests} />
        <DeliveryHistoryPanel deliveries={deliveries} state={state} />
      </div>
    </div>
  );
}
