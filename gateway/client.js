'use strict';
/**
 * Control-plane client for the AI Gateway.
 *
 * Wraps the PromptWall sensor API (/api/v1/gate, /api/v1/scan-response,
 * /api/v1/rehydrate). Every call carries the ingest key. The gateway treats a
 * network/timeout failure as FAIL CLOSED: gate() returns a block decision so a
 * prompt cannot reach upstream when the control plane is unreachable.
 */

function timeoutSignal(ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

async function postJson(url, key, body, timeoutMs) {
  const t = timeoutSignal(timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key || '' },
      body: JSON.stringify(body),
      signal: t.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { json = null; }
    return { ok: res.ok, status: res.status, json };
  } finally {
    t.clear();
  }
}

function makeClient({ controlPlaneUrl, ingestKey, requestTimeoutMs }) {
  const base = String(controlPlaneUrl || '').replace(/\/+$/, '');

  // Gate a prompt. Returns the control-plane verdict, or a synthetic fail-closed
  // block if the plane is unreachable.
  async function gate(payload) {
    try {
      const r = await postJson(base + '/api/v1/gate', ingestKey, payload, requestTimeoutMs);
      // Fail CLOSED on any non-2xx or a body without a usable verdict. A 401/429/
      // 400 error body is JSON but carries no decision/status — treating it as a
      // verdict would silently forward the raw prompt upstream.
      if (!r.ok || !r.json || (r.json.decision === undefined && r.json.status === undefined)) {
        return failClosed('control plane returned ' + r.status + (r.json && r.json.error ? ': ' + r.json.error : ''));
      }
      return { ...r.json, _httpStatus: r.status };
    } catch (e) {
      return failClosed('control plane unreachable: ' + (e && e.name === 'AbortError' ? 'timeout' : (e && e.message) || 'error'));
    }
  }

  async function scanResponse(payload) {
    try {
      const r = await postJson(base + '/api/v1/scan-response', ingestKey, payload, requestTimeoutMs);
      // Fail CLOSED (block the model output) on any non-2xx or a body without a
      // scan decision — an error body must not release output unscanned.
      if (!r.ok || !r.json || r.json.decision === undefined) {
        return { leaked: true, decision: 'block', blocked: true, reasons: ['control plane scan error ' + (r && r.status)], _failClosed: true };
      }
      return r.json;
    } catch (e) {
      return { leaked: true, decision: 'block', blocked: true, reasons: ['control plane unreachable'], _failClosed: true };
    }
  }

  async function rehydrate(id, text) {
    try {
      const r = await postJson(base + '/api/v1/rehydrate', ingestKey, { id, text }, requestTimeoutMs);
      return r.json || { text, rehydrated: false };
    } catch (e) {
      return { text, rehydrated: false };
    }
  }

  function failClosed(reason) {
    return { decision: 'block', status: 'control_plane_unavailable', reasons: [reason], _failClosed: true };
  }

  return { gate, scanResponse, rehydrate };
}

module.exports = { makeClient };
