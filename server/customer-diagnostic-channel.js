'use strict';

const protocol = require('./vendor-control-protocol');

const DEFAULT_QUEUE_LIMIT = 256;
const MAX_QUEUE_LIMIT = 1_000;
const SENSITIVE_METADATA_PATTERNS = Object.freeze([
  /\b\d{3}-\d{2}-\d{4}\b/,
  /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})(?:[ -]?\d{4}){2,3}\b/,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\b(?:api[_-]?key|password|private[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token)\b/i,
  /\b(?:bearer|password|secret|token)[_ -]?(?:key|value)?\s*[:=]\s*[^\s]{6,}/i,
  /(?:^|[^a-z0-9])(?:canarytokens?\.com|canary[_-]?token)(?:$|[^a-z0-9])/i,
]);

class CustomerDiagnosticChannel {
  #customerId;
  #deploymentId;
  #limit;
  #items;
  #digestsByMessage;
  #historyLimit;

  constructor(options) {
    this.#customerId = requiredBinding(options, 'customerId');
    this.#deploymentId = requiredBinding(options, 'deploymentId');
    this.#limit = queueLimit(options && options.maxItems);
    this.#items = [];
    this.#digestsByMessage = new Map();
    this.#historyLimit = Math.min(MAX_QUEUE_LIMIT * 4, Math.max(256, this.#limit * 4));
  }

  accept(candidate) {
    const event = assertSafeDiagnostic(candidate, {
      customerId: this.#customerId,
      deploymentId: this.#deploymentId,
    });
    const digest = protocol.payloadDigest(event, protocol.CHANNEL_KINDS.DIAGNOSTIC);
    const duplicate = duplicateDisposition(this.#digestsByMessage, event.messageId, digest);
    if (duplicate) return duplicate;
    if (this.#items.length >= this.#limit) throw channelError('diagnostic_queue_full');
    if (this.#digestsByMessage.size >= this.#historyLimit) {
      throw channelError('diagnostic_history_full');
    }
    const queued = Object.freeze({ digest, event: Object.freeze({ ...event }) });
    this.#items.push(queued);
    this.#digestsByMessage.set(event.messageId, digest);
    return Object.freeze({ accepted: true, duplicate: false, digest });
  }

  recordDelivery(messageId, digest, accepted) {
    if (typeof accepted !== 'boolean') throw channelError('diagnostic_delivery_invalid');
    const index = this.#items.findIndex((item) => item.event.messageId === messageId);
    if (index < 0) {
      const settled = this.#digestsByMessage.get(messageId);
      if (settled === digest) return Object.freeze({ removed: false, duplicate: true });
      throw channelError('diagnostic_delivery_not_current');
    }
    const item = this.#items[index];
    if (item.digest !== digest) throw channelError('diagnostic_delivery_not_current');
    if (accepted !== true) return Object.freeze({ removed: false, duplicate: false });
    this.#items.splice(index, 1);
    return Object.freeze({ removed: true, duplicate: false });
  }

  snapshot() {
    return Object.freeze({
      capacity: this.#limit,
      size: this.#items.length,
      items: Object.freeze(this.#items.slice()),
    });
  }
}

function assertSafeDiagnostic(candidate, expected) {
  const event = assertDiagnostic(candidate);
  assertBinding(event, expected && expected.customerId, expected && expected.deploymentId);
  rejectSensitiveMetadata(event);
  return event;
}

function assertDiagnostic(candidate) {
  try { return protocol.assertChannel(candidate, protocol.CHANNEL_KINDS.DIAGNOSTIC); }
  catch { throw channelError('diagnostic_schema_rejected'); }
}

function assertBinding(event, customerId, deploymentId) {
  if (event.customerId !== customerId) throw channelError('diagnostic_customer_mismatch');
  if (event.deploymentId !== deploymentId) throw channelError('diagnostic_deployment_mismatch');
}

function rejectSensitiveMetadata(event) {
  // The protocol closes every diagnostic field. Only the two configured slug
  // identifiers can carry arbitrary text; UUIDs are opaque random values and
  // may coincidentally resemble formatted payment-card numbers.
  for (const value of [event.customerId, event.deploymentId]) {
    if (SENSITIVE_METADATA_PATTERNS.some((pattern) => pattern.test(value))) {
      throw channelError('diagnostic_sensitive_metadata');
    }
  }
}

function duplicateDisposition(digests, messageId, digest) {
  const current = digests.get(messageId);
  if (!current) return null;
  if (current !== digest) throw channelError('diagnostic_idempotency_conflict');
  return Object.freeze({ accepted: false, duplicate: true, digest });
}

function requiredBinding(options, name) {
  const value = options && options[name];
  if (typeof value !== 'string' || !value) throw channelError('diagnostic_configuration_invalid');
  return value;
}

function queueLimit(value) {
  if (value === undefined) return DEFAULT_QUEUE_LIMIT;
  if (!Number.isInteger(value) || value < 1 || value > MAX_QUEUE_LIMIT) {
    throw channelError('diagnostic_configuration_invalid');
  }
  return value;
}

function channelError(code) {
  const error = new Error('customer diagnostic event rejected');
  error.code = code;
  return error;
}

module.exports = {
  DEFAULT_QUEUE_LIMIT,
  MAX_QUEUE_LIMIT,
  CustomerDiagnosticChannel,
  assertSafeDiagnostic,
};
