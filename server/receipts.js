'use strict';
/**
 * Safe-to-send receipts: a signed, prompt-free proof that a specific outbound
 * text was scanned and cleared under a specific policy at a specific time.
 *
 * The receipt carries only hashes and bounded metadata — never prompt bodies —
 * so a sensor, employee, or examiner can hold on to it without retaining
 * sensitive content. Verification recomputes the HMAC with a key derived from
 * the stable server secret, so any edit to a stored receipt (status, hash,
 * timestamp) fails verification the same way audit-chain tampering does.
 */
const crypto = require('crypto');
const auth = require('./auth');

const RECEIPT_VERSION = 1;
const KEY = auth.deriveKey('promptwall:receipt-key:v1');
const HEX64_RE = /^[0-9a-f]{64}$/;

/** Statuses whose outbound text is cleared to leave the device. */
const RECEIPT_STATUSES = new Set(['allowed', 'redacted', 'warned_sent', 'justified']);

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

/** Stable-order serialization so hashes do not depend on object key order. */
function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  return JSON.stringify(value === undefined ? null : value);
}

function policyHash(pol) {
  return sha256Hex(canonicalJson(pol || {}));
}

function signedFields(receipt) {
  // JSON-encode the field list so no field value (e.g. a user or destination
  // containing a delimiter) can shift content across field boundaries and
  // produce a second receipt with the same signature.
  return JSON.stringify([
    receipt.v, receipt.id, receipt.status, receipt.promptSha256,
    receipt.policySha256, receipt.destination, receipt.user, receipt.issuedAt,
  ]);
}

function signature(receipt) {
  return crypto.createHmac('sha256', KEY).update(signedFields(receipt)).digest('base64url');
}

/**
 * Issue a receipt for text that is cleared to proceed. `outboundText` must be
 * the exact text leaving the device (raw prompt for allow/warn/justify paths,
 * tokenized prompt for redact), so the hash binds the receipt to what was sent.
 */
function issueReceipt({ id, status, outboundText, policy, destination, user }) {
  if (!RECEIPT_STATUSES.has(status)) return null;
  if (typeof outboundText !== 'string' || !outboundText) return null;
  const receipt = {
    v: RECEIPT_VERSION,
    id: String(id),
    status,
    promptSha256: sha256Hex(outboundText),
    policySha256: policyHash(policy),
    destination: String(destination || 'unknown'),
    user: String(user || 'unknown'),
    issuedAt: new Date().toISOString(),
  };
  receipt.sig = signature(receipt);
  return receipt;
}

/** Verify a receipt object. Returns { ok } or { ok: false, reason }. */
function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') return { ok: false, reason: 'not a receipt object' };
  if (receipt.v !== RECEIPT_VERSION) return { ok: false, reason: 'unsupported receipt version' };
  if (!RECEIPT_STATUSES.has(receipt.status)) return { ok: false, reason: 'unknown receipt status' };
  if (!HEX64_RE.test(String(receipt.promptSha256))) return { ok: false, reason: 'malformed prompt hash' };
  if (!HEX64_RE.test(String(receipt.policySha256))) return { ok: false, reason: 'malformed policy hash' };
  if (Number.isNaN(Date.parse(receipt.issuedAt))) return { ok: false, reason: 'malformed issue time' };
  const expected = Buffer.from(signature(receipt));
  const actual = Buffer.from(String(receipt.sig || ''));
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    return { ok: false, reason: 'signature mismatch' };
  }
  return { ok: true };
}

module.exports = { issueReceipt, verifyReceipt, policyHash, sha256Hex, RECEIPT_VERSION, RECEIPT_STATUSES };
