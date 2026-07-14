'use strict';

const { TextDecoder } = require('node:util');
const { cancelResponseBody, headerValue, readBoundedBuffer } = require('../sensors/shared/bounded-response');
const onlineVerdict = require('./connected-online-verdict');
const { outboundHttpsUrlWithoutParameters } = require('./url-policy');
const protocol = require('./vendor-control-protocol');
const {
  normalizePublicKeys,
  verifySignedArtifact,
} = require('./vendor-signed-artifact');

const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_TIMEOUT_MS = 30_000;
const MAX_HEARTBEAT_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_HEARTBEAT_RESPONSE_BYTES = 24_576;
const MAX_CANCELLATION_WAIT_MS = 250;
const HEARTBEAT_RESPONSE_KIND = 'heartbeat.response.v1';
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const DEPLOYMENT_ID_RE = /^dep_[a-f0-9]{32}$/;
const HEARTBEAT_RESPONSE_KEYS = Object.freeze([
  'schemaVersion', 'kind', 'requestMessageId',
  'onlineRegistryVerdict', 'entitlementArtifact',
]);
const TOKEN_RE = /^[A-Za-z0-9._~+/=-]{32,256}$/;
const TOKEN_FIELDS = Object.freeze({
  [protocol.CHANNEL_KINDS.HEARTBEAT]: 'heartbeat',
  [protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT]: 'acknowledgement',
  [protocol.CHANNEL_KINDS.DIAGNOSTIC]: 'diagnostic',
  [protocol.CHANNEL_KINDS.SHADOW_CANDIDATE]: 'shadowCandidate',
});
const TRANSPORT_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ENETDOWN', 'ENETUNREACH', 'EHOSTUNREACH',
  'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET', 'UND_ERR_HEADERS_TIMEOUT',
]);
const PROTOCOL_REJECTION_STATUSES = new Set([400, 404, 405, 413, 415, 422]);
const UNAVAILABLE_STATUSES = new Set([408, 502, 503, 504]);
const EXACT_204_CHANNELS = new Set([
  protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
  protocol.CHANNEL_KINDS.DIAGNOSTIC,
  protocol.CHANNEL_KINDS.SHADOW_CANDIDATE,
]);
const CLIENT_OPTION_KEYS = new Set([
  'baseUrl', 'tokens', 'customerId', 'deploymentId', 'timeoutMs', 'fetchImpl',
  'onlineVerdictPublicKeys', 'entitlementPublicKeys', 'offlineKeyFingerprint', 'now',
]);

function createVendorControlClient(options = {}) {
  const config = checkedConfig(options);
  const lifecycle = {
    closed: false,
    active: new Set(),
  };
  const request = (path, kind, payload) => post(config, lifecycle, path, kind, payload);
  return Object.freeze({
    heartbeat: (payload) => request('/v1/heartbeat', protocol.CHANNEL_KINDS.HEARTBEAT, payload),
    acknowledge: (payload) => request(
      '/v1/acknowledgements', protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT, payload,
    ),
    sendDiagnostic: (payload) => request('/v1/diagnostics', protocol.CHANNEL_KINDS.DIAGNOSTIC, payload),
    sendShadowCandidate: (payload) => request(
      '/v1/shadow-ai/candidates', protocol.CHANNEL_KINDS.SHADOW_CANDIDATE, payload,
    ),
    close: () => closeClient(lifecycle),
  });
}

function checkedConfig(options) {
  assertExplicitOptions(options);
  const baseUrl = checkedBaseUrl(options.baseUrl);
  const tokens = checkedTokens(options.tokens);
  const timeoutMs = boundedTimeout(options.timeoutMs);
  const scope = checkedScope(options.customerId, options.deploymentId);
  const now = checkedClock(options.now);
  const offlineFingerprints = optionalFingerprint(options.offlineKeyFingerprint);
  const onlineKeys = onlineVerdict.normalizeKeyring(options.onlineVerdictPublicKeys, {
    forbiddenPublicKeyFingerprints: offlineFingerprints,
  });
  const forbiddenEntitlementKeys = [
    ...offlineFingerprints,
    ...[...onlineKeys.values()].map(onlineVerdict.keyFingerprint),
  ];
  const entitlementKeys = normalizePublicKeys(options.entitlementPublicKeys, {
    forbiddenPublicKeyFingerprints: forbiddenEntitlementKeys,
    purpose: protocol.CHANNEL_KINDS.ENTITLEMENT,
    strictPurpose: true,
  });
  const fetchImpl = options.fetchImpl === undefined ? globalThis.fetch : options.fetchImpl;
  if (typeof fetchImpl !== 'function') throw configError('vendor_fetch_invalid');
  return Object.freeze({
    baseUrl,
    tokens,
    ...scope,
    timeoutMs,
    now,
    fetch: fetchImpl,
    onlineKeys,
    entitlementKeys,
  });
}

function checkedClock(value) {
  if (value === undefined) return Date.now;
  if (typeof value !== 'function') throw configError('vendor_clock_invalid');
  return value;
}

function assertExplicitOptions(options) {
  if (!plainRecord(options) || Object.getOwnPropertySymbols(options).length) {
    throw configError('vendor_client_options_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(options);
  if (Object.entries(descriptors).some(([key, descriptor]) => !CLIENT_OPTION_KEYS.has(key)
      || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))) {
    throw configError('vendor_client_options_invalid');
  }
}

function optionalFingerprint(value) {
  if (value === undefined) return [];
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw configError('offline_key_fingerprint_invalid');
  }
  return [value];
}

function checkedScope(customerId, deploymentId) {
  if (typeof customerId !== 'string' || !CUSTOMER_ID_RE.test(customerId)) {
    throw configError('customer_invalid');
  }
  if (typeof deploymentId !== 'string' || !DEPLOYMENT_ID_RE.test(deploymentId)) {
    throw configError('deployment_invalid');
  }
  return { customerId, deploymentId };
}

function checkedBaseUrl(value) {
  const normalized = outboundHttpsUrlWithoutParameters(value);
  if (!normalized) throw configError('vendor_url_invalid');
  const url = new URL(normalized);
  if (url.pathname !== '/') throw configError('vendor_url_must_be_origin');
  return url;
}

function boundedTimeout(value) {
  if (value === undefined) return DEFAULT_TIMEOUT_MS;
  if (typeof value !== 'number' || !Number.isInteger(value)
      || value <= 0 || value > MAX_TIMEOUT_MS) {
    throw configError('vendor_timeout_invalid');
  }
  return value;
}

async function post(config, lifecycle, path, expectedKind, payload) {
  if (lifecycle.closed) throw requestError('vendor_client_closed');
  const parsed = protocol.assertChannel(payload, expectedKind);
  assertScope(config, parsed);
  if (expectedKind === protocol.CHANNEL_KINDS.HEARTBEAT) assertHeartbeatFresh(config, parsed);
  const token = tokenFor(config, expectedKind);
  const controller = new AbortController();
  let settle;
  const active = {
    controller,
    shutdownCancelled: false,
    settled: new Promise((resolve) => { settle = resolve; }),
  };
  lifecycle.active.add(active);
  const deadline = Date.now() + config.timeoutMs;
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(transportTimeout());
    }, config.timeoutMs);
  });
  try {
    const operation = sendAndReceive(
      config, path, expectedKind, parsed, token, controller.signal, deadline,
    );
    return await Promise.race([operation, timeout]);
  } catch (error) {
    if (active.shutdownCancelled) return failure('shutdown_cancelled');
    return failure(classifyTransportFailure(error));
  } finally {
    clearTimeout(timer);
    lifecycle.active.delete(active);
    settle();
  }
}

async function closeClient(lifecycle) {
  lifecycle.closed = true;
  const active = [...lifecycle.active];
  for (const request of active) {
    request.shutdownCancelled = true;
    try { request.controller.abort(); } catch {}
  }
  await Promise.allSettled(active.map((request) => request.settled));
  return { ok: true };
}

function assertHeartbeatFresh(config, heartbeat) {
  let nowMs;
  try { nowMs = Reflect.apply(config.now, undefined, []); }
  catch { throw requestError('vendor_clock_invalid'); }
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw requestError('vendor_clock_invalid');
  const sentAtMs = Date.parse(heartbeat.sentAt);
  if (sentAtMs < nowMs - MAX_HEARTBEAT_CLOCK_SKEW_MS
      || sentAtMs > nowMs + MAX_HEARTBEAT_CLOCK_SKEW_MS) {
    throw requestError('heartbeat_sent_at_out_of_range');
  }
}

async function sendAndReceive(config, path, expectedKind, payload, token, signal, deadline) {
  const response = await Reflect.apply(config.fetch, undefined, [
    new URL(path, config.baseUrl),
    requestOptions(payload, token, signal),
  ]);
  const status = responseStatus(response);
  if (status < 200 || status >= 300) return httpFailure(response, remainingMs(deadline));
  if (EXACT_204_CHANNELS.has(expectedKind) && status !== 204) {
    await cancelResponseBodyBounded(response, remainingMs(deadline));
    return failure('protocol_rejected');
  }
  if (expectedKind !== protocol.CHANNEL_KINDS.HEARTBEAT) {
    await cancelResponseBodyBounded(response, remainingMs(deadline));
    return { ok: true, accepted: true };
  }
  if (status !== 200) {
    await cancelResponseBodyBounded(response, remainingMs(deadline));
    return failure('protocol_rejected');
  }
  const parsed = await readHeartbeatResponse(response, remainingMs(deadline));
  return parsed.ok ? verifyHeartbeatResponse(config, payload, parsed.envelope) : parsed;
}

function responseStatus(response) {
  const status = Number(response && response.status);
  return Number.isInteger(status) ? status : 0;
}

function remainingMs(deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw transportTimeout();
  return remaining;
}

function requestOptions(payload, token, signal) {
  return {
    method: 'POST',
    redirect: 'error',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(payload),
    signal,
  };
}

function checkedTokens(value) {
  if (!plainRecord(value) || Object.getOwnPropertySymbols(value).length) {
    throw configError('connector_tokens_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value'))) throw configError('connector_tokens_invalid');
  const allowed = new Set(Object.values(TOKEN_FIELDS));
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key))
      || !keys.includes('heartbeat') || !keys.includes('acknowledgement')) {
    throw configError('connector_tokens_invalid');
  }
  return normalizedTokens(keys, descriptors);
}

function normalizedTokens(keys, descriptors) {
  const tokens = {};
  const seen = new Set();
  for (const key of keys) {
    const token = descriptors[key].value;
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) throw configError('connector_token_invalid');
    if (seen.has(token)) throw configError('connector_token_scope_reused');
    seen.add(token);
    tokens[key] = token;
  }
  return Object.freeze(tokens);
}

function tokenFor(config, kind) {
  const field = TOKEN_FIELDS[kind];
  const token = field && config.tokens[field];
  if (!token) throw configError('channel_credential_missing');
  return token;
}

function assertScope(config, payload) {
  if (payload.customerId !== config.customerId) throw configError('customer_mismatch');
  if (payload.deploymentId !== config.deploymentId) throw configError('deployment_mismatch');
}

async function httpFailure(response, timeoutMs) {
  await cancelResponseBodyBounded(response, timeoutMs);
  const status = responseStatus(response);
  if (status === 401 || status === 403) return failure('authentication_rejected');
  if (status === 409) return failure('version_conflict');
  if (status === 429) return failure('rate_limited');
  if (UNAVAILABLE_STATUSES.has(status)) return failure('transport_unavailable');
  if (PROTOCOL_REJECTION_STATUSES.has(status)) return failure('protocol_rejected');
  return failure('transport_ambiguous');
}

async function cancelResponseBodyBounded(response, timeoutMs) {
  const waitMs = Math.max(1, Math.min(MAX_CANCELLATION_WAIT_MS, timeoutMs));
  let timer;
  const cancellation = Promise.resolve()
    .then(() => cancelResponseBody(response))
    .catch(() => undefined);
  try {
    await Promise.race([
      cancellation,
      new Promise((resolve) => { timer = setTimeout(resolve, waitMs); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function readHeartbeatResponse(response, timeoutMs) {
  const headerCheck = heartbeatResponseHeaders(response);
  if (!headerCheck.ok) {
    await cancelResponseBodyBounded(response, timeoutMs);
    return headerCheck;
  }
  let bytes;
  try {
    bytes = await readBoundedBuffer(response, {
      maxBytes: MAX_HEARTBEAT_RESPONSE_BYTES,
      timeoutMs,
      label: 'vendor heartbeat response',
    });
  } catch (error) {
    if (error.code === 'REDACTWALL_RESPONSE_TOO_LARGE') return failure('response_too_large');
    if (error.code === 'REDACTWALL_RESPONSE_TIMEOUT') return failure('transport_unavailable');
    return failure(classifyTransportFailure(error));
  }
  if (bytes.length !== headerCheck.contentLength) return failure('invalid_schema');
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const envelope = JSON.parse(text);
    return validEnvelopeShape(envelope) && compactJson(text) === JSON.stringify(envelope)
      ? { ok: true, envelope } : failure('invalid_schema');
  } catch {
    return failure('invalid_schema');
  }
}

function heartbeatResponseHeaders(response) {
  const expected = [
    ['content-type', 'application/json; charset=utf-8'],
    ['cache-control', 'no-store'],
    ['pragma', 'no-cache'],
    ['x-content-type-options', 'nosniff'],
  ];
  if (expected.some(([name, value]) => headerValue(response?.headers, name) !== value)) {
    return failure('invalid_schema');
  }
  const rawLength = headerValue(response?.headers, 'content-length');
  if (!/^(?:0|[1-9]\d*)$/.test(rawLength)) return failure('invalid_schema');
  const contentLength = Number(rawLength);
  if (!Number.isSafeInteger(contentLength)) return failure('invalid_schema');
  if (contentLength > MAX_HEARTBEAT_RESPONSE_BYTES) return failure('response_too_large');
  return { ok: true, contentLength };
}

function validEnvelopeShape(value) {
  return plainRecord(value)
    && Object.keys(value).join('\0') === HEARTBEAT_RESPONSE_KEYS.join('\0')
    && value.schemaVersion === 1
    && value.kind === HEARTBEAT_RESPONSE_KIND
    && typeof value.requestMessageId === 'string'
    && typeof value.onlineRegistryVerdict === 'string'
    && value.onlineRegistryVerdict.length > 0
    && (value.entitlementArtifact === null || plainRecord(value.entitlementArtifact));
}

function compactJson(text) {
  let compact = '';
  let inString = false;
  let escaped = false;
  for (const character of text) {
    if (inString) {
      compact += character;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
    } else if (character === '"') {
      inString = true;
      compact += character;
    } else if (!/[\t\n\r ]/.test(character)) {
      compact += character;
    }
  }
  return compact;
}

function verifyHeartbeatResponse(config, request, envelope) {
  if (envelope.requestMessageId !== request.messageId) return failure('invalid_schema');
  let verifiedOnline;
  let verifiedEntitlement = null;
  try {
    verifiedOnline = onlineVerdict.verifySignedOnlineVerdict(
      envelope.onlineRegistryVerdict, config.onlineKeys,
    );
    assertScope(config, verifiedOnline.payload);
    if (envelope.entitlementArtifact !== null) {
      verifiedEntitlement = verifySignedArtifact(
        envelope.entitlementArtifact,
        config.entitlementKeys,
        protocol.CHANNEL_KINDS.ENTITLEMENT,
      );
      assertScope(config, verifiedEntitlement.payload);
    }
  } catch (error) {
    return failure(artifactFailureClass(error));
  }
  return heartbeatSuccess(envelope, verifiedOnline, verifiedEntitlement);
}

function heartbeatSuccess(envelope, verifiedOnline, verifiedEntitlement) {
  const signedEntitlement = envelope.entitlementArtifact === null
    ? null : deepFreeze(envelope.entitlementArtifact);
  return Object.freeze({
    ok: true,
    requestMessageId: envelope.requestMessageId,
    signedOnlineRegistryVerdict: envelope.onlineRegistryVerdict,
    verifiedOnlineRegistryVerdict: deepFreeze(verifiedOnline),
    signedEntitlementArtifact: signedEntitlement,
    verifiedEntitlementArtifact: verifiedEntitlement === null
      ? null : deepFreeze(verifiedEntitlement),
  });
}

function artifactFailureClass(error) {
  const code = String(error && error.code || '');
  if (code === 'registry_signing_key_unknown') return 'unknown_signing_key';
  if (code === 'registry_signature_invalid') return 'invalid_signature';
  if (protocol.FAILURE_CLASSES.includes(code)) return code;
  return 'invalid_schema';
}

function classifyTransportFailure(error) {
  const seen = new Set();
  let current = error;
  for (let depth = 0; current && depth < 8 && !seen.has(current); depth += 1) {
    seen.add(current);
    const details = safeErrorDetails(current);
    if (details.name === 'AbortError' || details.code === 'REDACTWALL_RESPONSE_TIMEOUT'
        || TRANSPORT_CODES.has(details.code)) return 'transport_unavailable';
    current = details.cause;
  }
  return 'transport_ambiguous';
}

function safeErrorDetails(error) {
  try {
    return { name: error.name, code: error.code, cause: error.cause };
  } catch {
    return { name: '', code: '', cause: null };
  }
}

function transportTimeout() {
  const error = new Error('vendor control request timed out');
  error.name = 'AbortError';
  return error;
}

function plainRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object') return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.isFrozen(value) ? value : Object.freeze(value);
}

function failure(failureClass) {
  return Object.freeze({ ok: false, failureClass });
}

function configError(code) {
  const error = new TypeError('vendor control client configuration rejected');
  error.code = code;
  return error;
}

function requestError(code) {
  const error = new TypeError('vendor heartbeat request rejected');
  error.code = code;
  return error;
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  MAX_HEARTBEAT_CLOCK_SKEW_MS,
  MAX_HEARTBEAT_RESPONSE_BYTES,
  createVendorControlClient,
  normalizePublicKeys,
  verifySignedArtifact,
  classifyTransportFailure,
};
