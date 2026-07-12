'use strict';
/**
 * Two-way approval-ticket state.
 *
 * Outbound ticket creation (notifiers.js) records an external issue key on the
 * query; this module polls Jira/Linear for that issue's current status and
 * stamps it back onto the query — metadata only. Ticket summaries, comments,
 * and descriptions are never fetched or stored.
 */
const notifiers = require('./notifiers');
const { cancelResponseBody, readBoundedJson } = require('../sensors/shared/bounded-response');
const { sanitizeSensitiveText } = require('./sensitive-text');

const MAX_TICKET_REFS = 8;
const MAX_STATUS_CHARS = 40;
const MAX_TICKET_RESPONSE_BYTES = 256 * 1024;
const MAX_SYNC_QUERIES = 500;
const MAX_SYNC_STATUS_CHECKS = 64;
const TOTAL_SYNC_TIMEOUT_MS = 25 * 1000;
const DONE_CATEGORIES = new Set(['done', 'completed', 'canceled', 'cancelled']);

// Bound each status poll like every other outbound sender so one hung ticket
// endpoint cannot stall the whole sync and the awaiting admin request.
const OUTBOUND_TIMEOUT_MS = (() => {
  const n = Number(process.env.REDACTWALL_TICKET_SYNC_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), 8000) : 8000;
})();

function outboundSignal(sharedSignal) {
  if (typeof AbortSignal === 'undefined' || !AbortSignal.timeout) return sharedSignal;
  const timeoutSignal = AbortSignal.timeout(OUTBOUND_TIMEOUT_MS);
  if (!sharedSignal) return timeoutSignal;
  return typeof AbortSignal.any === 'function'
    ? AbortSignal.any([sharedSignal, timeoutSignal])
    : sharedSignal;
}

function safeStatusText(value, fallback = 'unknown') {
  const text = String(value || '').replace(/[\r\n\t]/g, ' ').trim();
  return sanitizeSensitiveText(text || fallback, MAX_STATUS_CHARS) || fallback;
}

function safeExternalId(value) {
  if (typeof value !== 'string' && !Number.isSafeInteger(value)) return '';
  const text = String(value).trim();
  if (!text || text.length > 120 || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(text)) return '';
  return sanitizeSensitiveText(text, 120) === text ? text : '';
}

function ticketRefsFromDelivery(query, result, now = new Date()) {
  const existing = Array.isArray(query.ticketRefs) ? query.ticketRefs : [];
  const seen = new Set(existing.map((ref) => `${ref.channel}\u0000${ref.externalId}`));
  const added = [];
  for (const item of (result && result.results) || []) {
    const externalId = item && safeExternalId(item.externalId);
    if (!item || !item.sent || !externalId) continue;
    if (!['jira', 'linear'].includes(item.channel)) continue;
    const key = `${item.channel}\u0000${externalId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    added.push({
      channel: item.channel,
      externalId,
      status: 'open',
      statusCategory: 'new',
      createdAt: now.toISOString(),
      syncedAt: null,
    });
  }
  if (!added.length) return null;
  return { ticketRefs: existing.concat(added).slice(0, MAX_TICKET_REFS) };
}

function jiraStatusUrl(channel, externalId) {
  // channel.url already ends in /rest/api/3/issue and preserves any Jira
  // Server/DC context path; append the key rather than rebuilding from origin
  // (which would drop the context path and 404 the poll forever).
  const base = String(channel.url || '').replace(/\/+$/, '');
  return `${base}/${encodeURIComponent(externalId)}?fields=status`;
}

async function fetchJiraStatus(channel, externalId, fetchImpl = fetch, opts = {}) {
  const res = await fetchImpl(jiraStatusUrl(channel, externalId), {
    headers: notifiers.headersForChannel(channel),
    redirect: 'error',
    signal: outboundSignal(opts.signal),
  });
  if (!res || !res.ok) {
    await cancelResponseBody(res);
    return null;
  }
  const body = await readTicketResponse(res, 'Jira ticket status').catch(() => null);
  const status = body && body.fields && body.fields.status;
  if (!status) return null;
  return {
    status: safeStatusText(status.name),
    statusCategory: safeStatusText(status.statusCategory && status.statusCategory.key).toLowerCase(),
  };
}

async function fetchLinearStatus(channel, externalId, fetchImpl = fetch, opts = {}) {
  const res = await fetchImpl(channel.url, {
    method: 'POST',
    headers: notifiers.headersForChannel(channel),
    redirect: 'error',
    signal: outboundSignal(opts.signal),
    body: JSON.stringify({
      query: 'query TicketState($id: String!) { issue(id: $id) { state { name type } } }',
      variables: { id: externalId },
    }),
  });
  if (!res || !res.ok) {
    await cancelResponseBody(res);
    return null;
  }
  const body = await readTicketResponse(res, 'Linear ticket status').catch(() => null);
  const state = body && body.data && body.data.issue && body.data.issue.state;
  if (!state) return null;
  return {
    status: safeStatusText(state.name),
    statusCategory: safeStatusText(state.type).toLowerCase(),
  };
}

async function readTicketResponse(response, label) {
  const { json } = await readBoundedJson(response, {
    maxBytes: MAX_TICKET_RESPONSE_BYTES,
    timeoutMs: OUTBOUND_TIMEOUT_MS,
    label,
  });
  return json;
}

function syncChannels(env = process.env, opts = {}) {
  const channels = notifiers.configuredChannels(env, opts);
  return new Map(channels
    .filter((channel) => channel.type === 'jira' || channel.type === 'linear')
    .map((channel) => [channel.type, channel]));
}

function refNeedsSync(ref) {
  return ref && ref.externalId && !DONE_CATEGORIES.has(String(ref.statusCategory || '').toLowerCase());
}

function boundedPositive(value, fallback, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), maximum);
}

function syncAbortReason(code) {
  const reason = new Error(code);
  reason.code = code;
  return reason;
}

function createSyncBudget(opts = {}) {
  const controller = new AbortController();
  const externalSignal = opts.signal;
  const maxChecks = boundedPositive(opts.maxChecks, MAX_SYNC_STATUS_CHECKS, MAX_SYNC_STATUS_CHECKS);
  const timeoutMs = boundedPositive(opts.totalTimeoutMs, TOTAL_SYNC_TIMEOUT_MS, TOTAL_SYNC_TIMEOUT_MS);
  let checksAttempted = 0;
  let stopReason = '';

  const stop = (reason) => {
    if (controller.signal.aborted) return;
    stopReason = reason;
    controller.abort(syncAbortReason(reason));
  };
  const stopFromExternal = () => stop('client_disconnected');
  if (externalSignal) {
    if (externalSignal.aborted) stopFromExternal();
    else externalSignal.addEventListener('abort', stopFromExternal, { once: true });
  }
  const timer = setTimeout(() => stop('deadline_exceeded'), timeoutMs);

  return {
    signal: controller.signal,
    beginCheck() {
      if (controller.signal.aborted) return false;
      if (checksAttempted >= maxChecks) {
        stop('check_limit_reached');
        return false;
      }
      checksAttempted += 1;
      return true;
    },
    checksAttempted: () => checksAttempted,
    stopReason: () => stopReason,
    cleanup() {
      clearTimeout(timer);
      if (externalSignal) externalSignal.removeEventListener('abort', stopFromExternal);
    },
  };
}

async function syncQueryTickets(query, channels, deps = {}) {
  const fetchImpl = deps.fetchImpl || fetch;
  const now = deps.now || new Date();
  const budget = deps.budget;
  let changed = false;
  let statusChanged = false;
  let succeeded = 0;
  let failed = 0;
  const refs = [];
  const attemptedAt = now.toISOString();
  for (let index = 0; index < query.ticketRefs.length; index += 1) {
    const ref = query.ticketRefs[index];
    const channel = channels.get(ref.channel);
    if (!refNeedsSync(ref)) {
      refs.push(ref);
      continue;
    }
    if (!budget.beginCheck()) {
      refs.push(...query.ticketRefs.slice(index));
      break;
    }
    if (!channel) {
      changed = true;
      failed += 1;
      refs.push({ ...ref, lastAttemptAt: attemptedAt });
      continue;
    }
    const fetchStatus = ref.channel === 'jira' ? fetchJiraStatus : fetchLinearStatus;
    const latest = await fetchStatus(channel, ref.externalId, fetchImpl, { signal: budget.signal }).catch(() => null);
    if (budget.signal.aborted) {
      changed = true;
      refs.push({ ...ref, lastAttemptAt: attemptedAt }, ...query.ticketRefs.slice(index + 1));
      break;
    }
    if (!latest) {
      changed = true;
      failed += 1;
      refs.push({ ...ref, lastAttemptAt: attemptedAt });
      continue;
    }
    succeeded += 1;
    changed = true;
    if (latest.status === ref.status && latest.statusCategory === ref.statusCategory) {
      refs.push({ ...ref, syncedAt: attemptedAt, lastAttemptAt: attemptedAt });
      continue;
    }
    statusChanged = true;
    refs.push({ ...ref, ...latest, syncedAt: attemptedAt, lastAttemptAt: attemptedAt });
  }
  return { changed, statusChanged, succeeded, failed, refs };
}

function syncSummary(status, reason, counts) {
  return {
    status,
    checked: counts.checked,
    matched: counts.matched,
    checksAttempted: counts.checksAttempted,
    updated: counts.updated,
    succeeded: counts.succeeded,
    failed: counts.failed,
    generatedAt: counts.generatedAt,
    ...(reason ? { reason } : {}),
  };
}

function matchingTicketRows(db, limit) {
  const boundedLimit = Number.isSafeInteger(limit)
    ? Math.max(1, Math.min(limit, MAX_SYNC_QUERIES))
    : MAX_SYNC_QUERIES;
  // Production stores filter open ticket references in SQL so the candidate
  // bound applies after filtering, not to the newest unrelated queries. Test
  // doubles and older adapters fall back to a complete snapshot, then apply the
  // same bounded candidate slice in memory.
  const rows = typeof db.listTicketSyncQueries === 'function'
    ? db.listTicketSyncQueries({ limit: boundedLimit })
    : db.listQueries({ all: true });
  const oldestAttempt = (query) => query.ticketRefs.filter(refNeedsSync)
    .map((ref) => typeof ref.lastAttemptAt === 'string' ? ref.lastAttemptAt : '')
    .sort()[0] || '';
  return rows.filter((query) => Array.isArray(query.ticketRefs)
    && query.ticketRefs.some(refNeedsSync))
    .sort((left, right) => oldestAttempt(left).localeCompare(oldestAttempt(right))
      || String(left.createdAt || '').localeCompare(String(right.createdAt || ''))
      || String(left.id || '').localeCompare(String(right.id || '')))
    .slice(0, boundedLimit);
}

function persistTicketChanges(db, query, result, onUpdate) {
  if (!result.changed) return 0;
  const expectedRefs = JSON.stringify(query.ticketRefs);
  const transition = db.mutateQueryWithAudit(
    query.id,
    (fresh) => JSON.stringify(fresh.ticketRefs) === expectedRefs ? { ticketRefs: result.refs } : null,
    (updated) => ({
      action: result.statusChanged ? 'TICKET_STATUS_SYNCED' : 'TICKET_STATUS_CHECKED',
      actor: 'system',
      detail: result.statusChanged
        ? updated.ticketRefs.map((ref) => `${ref.channel}:${ref.externalId}=${ref.status}`).join('; ').slice(0, 300)
        : `ticket status checks completed; succeeded=${result.succeeded}; failed=${result.failed}`,
    }),
  );
  if (transition.outcome !== 'updated') return 0;
  if (typeof onUpdate === 'function') onUpdate(transition.row);
  return result.statusChanged ? 1 : 0;
}

async function processTicketRows(rows, channelMap, deps) {
  const counts = { checked: 0, updated: 0, succeeded: 0, failed: 0 };
  for (const query of rows) {
    if (deps.budget.signal.aborted) break;
    const checksBeforeQuery = deps.budget.checksAttempted();
    const result = await syncQueryTickets(query, channelMap, deps);
    if (deps.budget.checksAttempted() > checksBeforeQuery) counts.checked += 1;
    counts.succeeded += result.succeeded;
    counts.failed += result.failed;
    // syncedAt-only changes are intentionally not persisted: any query content
    // rewrite must be re-anchored by the coupled audit transaction below.
    counts.updated += persistTicketChanges(deps.db, query, result, deps.onUpdate);
  }
  return counts;
}

function completedSyncStatus(stopReason, failed) {
  const reason = stopReason || (failed ? 'provider_failures' : '');
  return {
    status: stopReason === 'client_disconnected' ? 'cancelled' : reason ? 'partial' : 'complete',
    reason,
  };
}

async function syncTicketStatuses({
  db,
  env = process.env,
  fetchImpl,
  now = new Date(),
  limit = MAX_SYNC_QUERIES,
  maxChecks = MAX_SYNC_STATUS_CHECKS,
  totalTimeoutMs = TOTAL_SYNC_TIMEOUT_MS,
  signal,
  onUpdate,
  channels,
} = {}) {
  const generatedAt = now.toISOString();
  const emptyCounts = {
    checked: 0,
    matched: 0,
    checksAttempted: 0,
    updated: 0,
    succeeded: 0,
    failed: 0,
    generatedAt,
  };
  if (!db) return syncSummary('skipped', 'database_unavailable', emptyCounts);
  const channelMap = channels instanceof Map ? channels : syncChannels(env);
  if (!channelMap.size) return syncSummary('skipped', 'no_ticket_channels', emptyCounts);
  const budget = createSyncBudget({ signal, maxChecks, totalTimeoutMs });
  try {
    const rows = matchingTicketRows(db, limit);
    const counts = await processTicketRows(rows, channelMap, { db, fetchImpl, now, budget, onUpdate });
    const outcome = completedSyncStatus(budget.stopReason(), counts.failed);
    return syncSummary(outcome.status, outcome.reason, {
      ...counts,
      matched: rows.length,
      checksAttempted: budget.checksAttempted(),
      generatedAt,
    });
  } finally {
    budget.cleanup();
  }
}

function createTicketSyncRequestHandler(runSync) {
  if (typeof runSync !== 'function') throw new TypeError('ticket sync handler requires a runner');
  let inFlight = false;
  return async function ticketSyncRequest(req, res, next) {
    if (inFlight) {
      return res.status(409).json({ status: 'busy', reason: 'ticket_sync_in_progress' });
    }
    inFlight = true;
    const controller = new AbortController();
    const disconnect = () => {
      if (!controller.signal.aborted) controller.abort(syncAbortReason('client_disconnected'));
    };
    const requestClose = () => {
      if (req.aborted || req.complete === false) disconnect();
    };
    const responseClose = () => {
      if (!res.writableEnded) disconnect();
    };
    req.once('aborted', disconnect);
    req.once('close', requestClose);
    res.once('close', responseClose);
    try {
      const result = await runSync({ signal: controller.signal });
      if (controller.signal.aborted || res.destroyed || res.writableEnded) return undefined;
      return res.json(result);
    } catch (err) {
      if (controller.signal.aborted || res.destroyed) return undefined;
      return next(err);
    } finally {
      req.removeListener('aborted', disconnect);
      req.removeListener('close', requestClose);
      res.removeListener('close', responseClose);
      inFlight = false;
    }
  };
}

module.exports = {
  createTicketSyncRequestHandler,
  fetchJiraStatus,
  fetchLinearStatus,
  jiraStatusUrl,
  syncChannels,
  syncTicketStatuses,
  ticketRefsFromDelivery,
};
