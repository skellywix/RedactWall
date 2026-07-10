'use strict';
/**
 * Control-plane client for the AI Gateway.
 *
 * Wraps the RedactWall sensor API (/api/v1/gate, /api/v1/scan-response). Every
 * call carries the ingest key. The gateway treats a network/timeout failure as
 * FAIL CLOSED: gate() returns a block decision so a prompt cannot reach upstream
 * when the control plane is unreachable. health() is an authenticated,
 * non-persisting readiness probe that writes no records.
 */
const { normalizeGatewayUrl } = require('./config');
const { readBoundedJson } = require('../sensors/shared/bounded-response');

const EXPECTED_DETECTOR_IDS = Object.freeze(['US_SSN', 'CREDIT_CARD', 'SECRET_KEY']);

function isRedactWallDetectorInventory(value) {
  if (!Array.isArray(value)) return false;
  const ids = new Set(value
    .filter((item) => item && typeof item === 'object' && typeof item.id === 'string')
    .map((item) => item.id));
  return EXPECTED_DETECTOR_IDS.every((id) => ids.has(id));
}

function isReadyControlPlane(value) {
  return !!value && typeof value === 'object'
    && value.ready === true && value.database === true;
}

function timeoutSignal(ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

async function postJson(url, key, body, timeoutMs, maxBytes) {
  const t = timeoutSignal(timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key || '' },
      body: JSON.stringify(body),
      signal: t.signal,
      redirect: 'error',
    });
    const parsed = await readBoundedJson(res, {
      maxBytes,
      timeoutMs,
      label: 'gateway control-plane response',
    });
    return { ok: res.ok, status: res.status, json: parsed.json };
  } finally {
    t.clear();
  }
}

function makeClient({ controlPlaneUrl, ingestKey, requestTimeoutMs, maxControlPlaneResponseBytes, allowInsecureHttp }) {
  const base = normalizeGatewayUrl(controlPlaneUrl, {
    label: 'gateway control-plane URL',
    allowInsecureDev: allowInsecureHttp === true,
    production: String(process.env.NODE_ENV || '').toLowerCase() === 'production',
  });

  // Gate a prompt. Returns the control-plane verdict, or a synthetic fail-closed
  // block if the plane is unreachable.
  async function gate(payload) {
    try {
      const r = await postJson(base + '/api/v1/gate', ingestKey, payload, requestTimeoutMs, maxControlPlaneResponseBytes);
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
      const r = await postJson(base + '/api/v1/scan-response', ingestKey, payload, requestTimeoutMs, maxControlPlaneResponseBytes);
      // Fail CLOSED (block the model output) on any non-2xx or a body without a
      // scan decision — an error body must not release output unscanned.
      if (!r.ok || !r.json || r.json.decision === undefined) {
        return { leaked: true, decision: 'block', status: 'response_scan_unavailable', blocked: true, reasons: ['control plane scan error ' + (r && r.status)], _failClosed: true };
      }
      return r.json;
    } catch (e) {
      return { leaked: true, decision: 'block', status: 'response_scan_unavailable', blocked: true, reasons: ['control plane unreachable'], _failClosed: true };
    }
  }

  // The authenticated detector inventory proves the ingest key and service
  // identity. The public /readyz response separately proves database and
  // deployment-preflight readiness. Both reads are bounded and non-persisting.
  async function health() {
    const t = timeoutSignal(requestTimeoutMs);
    try {
      const inventory = await getReadinessJson('/api/v1/detectors', true, t.signal);
      if (!inventory.ok || inventory.status !== 200
          || !isRedactWallDetectorInventory(inventory.json)) return { ok: false };
      const ready = await getReadinessJson('/readyz', false, t.signal);
      return { ok: ready.ok && ready.status === 200 && isReadyControlPlane(ready.json) };
    } catch (e) {
      return { ok: false };
    } finally {
      t.clear();
    }
  }

  async function getReadinessJson(path, authenticated, signal) {
    const res = await fetch(base + path, {
      method: 'GET',
      headers: authenticated ? { 'x-api-key': ingestKey || '' } : {},
      signal,
      redirect: 'error',
    });
    const parsed = await readBoundedJson(res, {
      maxBytes: maxControlPlaneResponseBytes,
      timeoutMs: requestTimeoutMs,
      label: 'gateway control-plane readiness response',
    });
    return { ok: res.ok, status: res.status, json: parsed.json };
  }

  function failClosed(reason) {
    return { decision: 'block', status: 'control_plane_unavailable', reasons: [reason], _failClosed: true };
  }

  return { gate, scanResponse, health };
}

module.exports = { makeClient };
