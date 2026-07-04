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

const CONFIG_PATH = process.env.SENTINEL_SUBSCRIPTIONS_PATH
  || process.env.PROMPTWALL_SUBSCRIPTIONS_PATH
  || path.join(__dirname, '..', 'config', 'subscriptions.json');

const DEFAULT_MAX_ATTEMPTS = 4;
const DEDUPE_WINDOW_MS = 5 * 60 * 1000;

function loadRaw() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      if (parsed && Array.isArray(parsed.destinations)) return parsed;
    }
  } catch (e) { /* no subscriptions */ }
  return { destinations: [] };
}

function normalizeDestination(raw, index) {
  if (!raw || typeof raw !== 'object' || raw.enabled === false) return null;
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
    minRisk: Number.isFinite(Number(raw.minRisk)) ? Number(raw.minRisk) : 0,
    minSeverity: Number.isFinite(Number(raw.minSeverity)) ? Number(raw.minSeverity) : 0,
    eventTypes: Array.isArray(raw.eventTypes) ? raw.eventTypes.map(String) : null,
    maxAttempts: Math.max(1, Math.min(8, Number(raw.maxAttempts) || DEFAULT_MAX_ATTEMPTS)),
  };
}

function destinations() {
  const list = loadRaw().destinations || [];
  return list.map(normalizeDestination).filter(Boolean);
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

  const req = formats.buildRequest(alert, dest);
  let attempts = 0; let lastError = null; let httpStatus = null;
  const maxAttempts = opts.maxAttempts || dest.maxAttempts;
  while (attempts < maxAttempts) {
    attempts += 1;
    try {
      const res = await fetchImpl(req.url, { method: req.method, headers: req.headers, body: req.body });
      httpStatus = res && res.status;
      if (res && res.ok) {
        return db.recordDelivery({ destId: dest.id, destName: dest.name, type: dest.type, dedupeKey, status: 'delivered', attempts, httpStatus });
      }
      lastError = 'http_' + httpStatus;
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
  }));
}

function safeHost(url) {
  try { return new URL(url).host; } catch (e) { return null; }
}

function findDestination(id) {
  return destinations().find((d) => d.id === id) || null;
}

module.exports = { CONFIG_PATH, loadRaw, destinations, publicDestinations, findDestination, matches, deliverTo, dispatch, normalizeDestination };
