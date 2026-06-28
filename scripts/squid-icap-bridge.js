'use strict';
require('../server/env').loadEnv();
/**
 * Reference ICAP-side bridge (sketch).
 *
 * In production, a c-icap service module receives each REQMOD request from
 * Squid, extracts the user's prompt from the HTTP body, and calls PromptWall.
 * This file shows the HTTP call the ICAP module makes, and how it enforces the
 * verdict inline (hold the request until released).
 *
 * It is intentionally transport-agnostic so it can be wired into c-icap (C),
 * a Node ICAP shim, or an explicit-proxy plugin.
 */
const SENTINEL = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;

function requestTimeoutMs(opts = {}) {
  const n = Number(opts.timeoutMs ?? process.env.SENTINEL_REQUEST_TIMEOUT_MS ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (!Number.isFinite(n)) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.max(50, Math.min(120000, n));
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  if (!fetchImpl || !globalThis.AbortController) return fetchImpl(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs(opts));
  try {
    return await fetchImpl(url, { ...options, signal: controller.signal });
  } catch (e) {
    if (e && e.name === 'AbortError') e.code = 'SENTINEL_TIMEOUT';
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function failClosed(reason) {
  return { decision: 'block', status: 'control_plane_unavailable', reason };
}

async function responseJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/** Extract the user prompt from a captured request body for known AI endpoints. */
function extractPrompt(host, contentType, body) {
  try {
    if (contentType && contentType.includes('application/json')) {
      const j = JSON.parse(body);
      // OpenAI / Anthropic style chat payloads
      if (Array.isArray(j.messages)) {
        return j.messages.filter(m => m.role === 'user').map(m =>
          typeof m.content === 'string' ? m.content
            : Array.isArray(m.content) ? m.content.map(c => c.text || '').join(' ') : ''
        ).join('\n');
      }
      if (typeof j.prompt === 'string') return j.prompt;
      if (typeof j.input === 'string') return j.input;
    }
  } catch { /* fall through */ }
  // Web-UI form posts vary; fall back to raw body text.
  return body;
}

async function gate({
  host,
  user,
  sourceIp,
  contentType,
  body,
  sentinel = SENTINEL,
  key = KEY,
  fetchImpl = globalThis.fetch,
  timeoutMs,
}) {
  if (!fetchImpl) return failClosed('fetch_unavailable');
  const prompt = extractPrompt(host, contentType, body);
  try {
    const r = await fetchWithTimeout(fetchImpl, sentinel + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify({ prompt, user, destination: host, sourceIp, source: 'proxy', channel: 'submit' }),
    }, { timeoutMs });
    if (!r || !r.ok) return failClosed(`gate_http_${r ? r.status : 'missing'}`);
    const verdict = await responseJson(r);
    if (!verdict || typeof verdict.decision !== 'string') return failClosed('gate_invalid_json');
    return verdict; // { id, decision, status, ... }
  } catch (e) {
    return failClosed(e && e.code === 'SENTINEL_TIMEOUT' ? 'gate_timeout' : 'gate_unreachable');
  }
}

/** Block inline: poll until the admin releases, or time out (deny by default). */
async function awaitRelease(id, {
  releaseToken,
  timeoutMs = 5 * 60 * 1000,
  intervalMs = 2000,
  sentinel = SENTINEL,
  key = KEY,
  fetchImpl = globalThis.fetch,
  requestTimeoutMs: perRequestTimeoutMs,
  sleepImpl = (ms) => new Promise((res) => setTimeout(res, ms)),
} = {}) {
  if (!id) return { released: false, reason: 'missing_id' };
  if (!fetchImpl) return { released: false, reason: 'fetch_unavailable' };
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    let r;
    try {
      r = await fetchWithTimeout(fetchImpl, `${sentinel}/api/v1/status/${encodeURIComponent(id)}`, {
        headers: {
          'x-api-key': key,
          ...(releaseToken ? { 'x-release-token': releaseToken } : {}),
        },
      }, { timeoutMs: perRequestTimeoutMs });
    } catch (e) {
      return { released: false, reason: e && e.code === 'SENTINEL_TIMEOUT' ? 'status_timeout' : 'status_unreachable' };
    }
    if (!r || !r.ok) return { released: false, reason: `status_http_${r ? r.status : 'missing'}` };
    const s = await responseJson(r);
    if (!s || typeof s.status !== 'string') return { released: false, reason: 'status_invalid_json' };
    if (s.status === 'approved' || s.status === 'allowed') return { released: true };
    if (s.status === 'denied') return { released: false, reason: 'denied' };
    await sleepImpl(intervalMs);
  }
  return { released: false, reason: 'timeout' };
}

/**
 * ICAP REQMOD handler outline:
 *   const verdict = await gate({...});
 *   if (verdict.decision === 'allow') return ICAP_ALLOW;       // forward unchanged
 *   if (!verdict.id) return ICAP_BLOCK_403;                    // fail closed
 *   const rel = await awaitRelease(verdict.id, { releaseToken: verdict.releaseToken });
 *   return rel.released ? ICAP_ALLOW : ICAP_BLOCK_403;         // release or block
 */
module.exports = { extractPrompt, gate, awaitRelease, fetchWithTimeout, requestTimeoutMs, failClosed };
