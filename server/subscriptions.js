'use strict';
/**
 * Posture subscriptions: named SIEM/SOAR destinations with filters, an async
 * retry queue, dedupe, and persisted delivery history.
 *
 * Extends the single SIEM webhook (server/alerts.js) and the multi-channel
 * approval notifier (server/notifiers.js) into a unified, versioned event
 * pipeline. Every payload is prompt-free (the sanitized security event) and
 * HTTPS-only (server/url-policy). Delivery outcomes are recorded WITHOUT payload
 * bodies so the delivery dashboard and evidence stay prompt-free.
 *
 * Destinations are data-only config (config/subscriptions.json), loaded like the
 * custom-detector and exact-match packs.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const db = require('./db');
const formats = require('./siem-formats');
const { outboundHttpsUrl } = require('./url-policy');
const { cancelResponseBody } = require('../sensors/shared/bounded-response');

const CONFIG_PATH = process.env.REDACTWALL_SUBSCRIPTIONS_PATH || process.env.PROMPTWALL_SUBSCRIPTIONS_PATH || process.env.SENTINEL_SUBSCRIPTIONS_PATH
  || path.join(__dirname, '..', 'config', 'subscriptions.json');

const DEFAULT_MAX_ATTEMPTS = 4;
const DEDUPE_WINDOW_MS = 5 * 60 * 1000;
// Bound each delivery attempt so a hung destination cannot freeze the retry
// loop (which otherwise waits on fetch with no timeout across all attempts).
const OUTBOUND_TIMEOUT_MS = (() => {
  const n = Number(process.env.REDACTWALL_SUBSCRIPTION_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : 8000;
})();
function outboundSignal() {
  return typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(OUTBOUND_TIMEOUT_MS) : undefined;
}

function loadRaw() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      if (parsed && Array.isArray(parsed.destinations)) return parsed;
    }
  } catch (e) { /* no subscriptions */ }
  return { destinations: [] };
}

const DEFAULT_EMAIL_PER_HOUR = 30;

function emailDestination(raw, index) {
  const to = (Array.isArray(raw.to) ? raw.to : [raw.to]).map((r) => String(r || '').trim()).filter(Boolean);
  if (!to.length) return null;
  return {
    id: String(raw.id || `dest_${index}`).slice(0, 64),
    name: String(raw.name || raw.id || 'email').slice(0, 120),
    type: 'email',
    to,
    url: null,
    token: null,
    minRisk: Number.isFinite(Number(raw.minRisk)) ? Number(raw.minRisk) : 0,
    minSeverity: Number.isFinite(Number(raw.minSeverity)) ? Number(raw.minSeverity) : 0,
    eventTypes: Array.isArray(raw.eventTypes) ? raw.eventTypes.map(String) : null,
    maxAttempts: Math.max(1, Math.min(8, Number(raw.maxAttempts) || DEFAULT_MAX_ATTEMPTS)),
    maxPerHour: Math.max(1, Math.min(500, Number(raw.maxPerHour) || DEFAULT_EMAIL_PER_HOUR)),
  };
}

// Alert-storm guard: a burst of blocks must not flood an inbox. Per-destination
// sliding hour window; excess is recorded as rate_limited, never silently lost.
const emailSendTimes = new Map();

function emailRateLimited(dest, now = Date.now()) {
  const times = (emailSendTimes.get(dest.id) || []).filter((t) => now - t < 3600 * 1000);
  if (times.length >= dest.maxPerHour) { emailSendTimes.set(dest.id, times); return true; }
  times.push(now);
  emailSendTimes.set(dest.id, times);
  return false;
}

// Digests get a readable body; everything else sends the same prompt-free
// event JSON the SIEM adapters send.
function emailBody(alert) {
  if ((alert.action || alert.status) !== 'digest') return JSON.stringify(formats.toEvent(alert), null, 2);
  const s = alert.summary || {};
  return [
    'RedactWall daily digest',
    '',
    `Pending approvals: ${s.pending ?? 0}`,
    `Blocked today:     ${s.todayBlocked ?? 0}`,
    `Approved (total):  ${s.approved ?? 0}`,
    `Denied (total):    ${s.denied ?? 0}`,
    `Prompts gated:     ${s.totalQueries ?? 0}`,
    '',
    'Open the console for the live Overview and approval queue.',
  ].join('\n');
}

function normalizeDestination(raw, index) {
  if (!raw || typeof raw !== 'object' || raw.enabled === false) return null;
  if (raw.type === 'email') return emailDestination(raw, index);
  const type = formats.supportedTypes().includes(raw.type) ? raw.type : 'webhook';
  const url = outboundHttpsUrl(raw.url);
  if (!url) return null;
  return {
    id: String(raw.id || `dest_${index}`).slice(0, 64),
    name: String(raw.name || raw.id || type).slice(0, 120),
    type,
    url,
    token: raw.token ? String(raw.token) : null,
    customerId: raw.customerId ? String(raw.customerId) : undefined,
    logType: raw.logType ? String(raw.logType) : undefined,
    serviceName: raw.serviceName ? String(raw.serviceName).slice(0, 120) : undefined,
    minRisk: Number.isFinite(Number(raw.minRisk)) ? Number(raw.minRisk) : 0,
    minSeverity: Number.isFinite(Number(raw.minSeverity)) ? Number(raw.minSeverity) : 0,
    eventTypes: Array.isArray(raw.eventTypes) ? raw.eventTypes.map(String) : null,
    maxAttempts: Math.max(1, Math.min(8, Number(raw.maxAttempts) || DEFAULT_MAX_ATTEMPTS)),
  };
}

// dispatch() runs on the request path of every alert-worthy gated prompt, so
// re-reading and re-parsing config/subscriptions.json per call adds synchronous
// disk I/O to the busiest fan-out moment. Cache the normalized list and
// invalidate on the file's mtime+size, matching the other data-only packs.
let _cache = null;

function destinations() {
  let stat = null;
  try { stat = fs.statSync(CONFIG_PATH); } catch { /* no file: no destinations */ }
  const sig = stat ? `${stat.mtimeMs}:${stat.size}` : 'none';
  if (_cache && _cache.sig === sig) return _cache.dests;
  const list = loadRaw().destinations || [];
  const dests = list.map(normalizeDestination).filter(Boolean);
  _cache = { sig, dests };
  return dests;
}

function matches(dest, alert) {
  // Each threshold is an independent floor: a set floor must be cleared; an
  // unset (0) floor is no constraint. (AND-ing them made a lone floor a no-op.)
  if (dest.minRisk > 0 && (alert.riskScore || 0) < dest.minRisk) return false;
  if (dest.minSeverity > 0 && (alert.maxSeverity || 0) < dest.minSeverity) return false;
  if (dest.eventTypes && dest.eventTypes.length) {
    const t = alert.action || alert.status;
    if (!dest.eventTypes.includes(t)) return false;
  }
  return true;
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Deliver one alert to one destination with retry + exponential backoff.
// Returns a prompt-free delivery record (also persisted).
async function deliverTo(dest, alert, opts = {}) {
  const fetchImpl = opts.fetch || fetch;
  const sleep = opts.sleep || wait;
  const dedupeKey = formats.dedupeKey(formats.toEvent(alert));

  if (!opts.force && db.recentDeliverySuccess(dest.id, dedupeKey, new Date(Date.now() - DEDUPE_WINDOW_MS).toISOString())) {
    return db.recordDelivery({ destId: dest.id, destName: dest.name, type: dest.type, dedupeKey, status: 'deduped', attempts: 0 });
  }

  if (dest.type === 'email' && emailRateLimited(dest, opts.now)) {
    return db.recordDelivery({ destId: dest.id, destName: dest.name, type: dest.type, dedupeKey, status: 'failed', attempts: 0, lastError: 'rate_limited' });
  }
  const req = dest.type === 'email' ? null : formats.buildRequest(alert, dest);
  const sendMail = opts.sendMail || require('./email').send;
  let attempts = 0; let lastError = null; let httpStatus = null;
  const maxAttempts = opts.maxAttempts || dest.maxAttempts;
  while (attempts < maxAttempts) {
    attempts += 1;
    try {
      // Email relays get the same prompt-free event the SIEM adapters send.
      const res = dest.type === 'email'
        ? await sendMail({ to: dest.to, subject: formats.summaryLine(alert), text: emailBody(alert) })
        : await fetchImpl(req.url, {
          method: req.method,
          redirect: 'error',
          headers: req.headers,
          body: req.body,
          signal: outboundSignal(),
        });
      httpStatus = res && res.status;
      if (dest.type !== 'email') await cancelResponseBody(res);
      if (res && (res.ok || res.status === 200)) {
        return db.recordDelivery({ destId: dest.id, destName: dest.name, type: dest.type, dedupeKey, status: 'delivered', attempts, httpStatus });
      }
      lastError = dest.type === 'email' ? String(res && res.error || 'smtp_error') : 'http_' + httpStatus;
    } catch (e) {
      lastError = 'network_error';
    }
    if (attempts < maxAttempts) await sleep(Math.min(16000, 500 * Math.pow(2, attempts - 1)));
  }
  return db.recordDelivery({ destId: dest.id, destName: dest.name, type: dest.type, dedupeKey, status: 'failed', attempts, httpStatus, lastError });
}

// Fan an alert out to every matching destination. Best-effort; never throws.
async function dispatch(alert, opts = {}) {
  const dests = destinations().filter((d) => matches(d, alert));
  const results = await Promise.allSettled(dests.map((d) => deliverTo(d, alert, opts)));
  return results.map((r) => (r.status === 'fulfilled' ? r.value : { status: 'failed', lastError: 'dispatch_error' }));
}

// Bounded, secret-free view for the console (never exposes tokens).
function publicDestinations() {
  return destinations().map((d) => ({
    id: d.id, name: d.name, type: d.type, minRisk: d.minRisk, minSeverity: d.minSeverity,
    eventTypes: d.eventTypes, hasToken: !!d.token, urlHost: safeHost(d.url),
    recipients: d.to ? d.to.length : undefined,
  }));
}

function safeHost(url) {
  try { return new URL(url).host; } catch (e) { return null; }
}

function findDestination(id) {
  return destinations().find((d) => d.id === id) || null;
}

module.exports = { CONFIG_PATH, loadRaw, destinations, publicDestinations, findDestination, matches, deliverTo, dispatch, normalizeDestination };
