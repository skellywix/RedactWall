'use strict';

// Control-plane decisions and persisted statuses are one security assertion.
// Treating either field independently lets a contradictory response cross the
// upstream boundary, so each phase accepts only the pairs it can safely enact.
const REQUEST_MATRIX = Object.freeze({
  allow: Object.freeze(['', 'allowed', 'justified']),
  warn: Object.freeze(['warned', 'warned_sent']),
  log: Object.freeze(['paste_flagged', 'proxy_observed', 'shadow_ai']),
  redact: Object.freeze(['redacted']),
  block: Object.freeze([
    'control_plane_unavailable',
    'destination_blocked',
    'file_upload_blocked',
    'action_blocked',
    'injection_blocked',
    'file_blocked_unscanned',
    'ocr_required',
    'pending',
    'pending_justification',
    'blocked_by_user',
    'license_revoked',
    'tenant_not_configured',
    'seat_limit_not_configured',
    'tenant_context_required',
    'tenant_mismatch',
    'user_identity_required',
    'user_deactivated',
    'seat_released',
    'seat_limit_blocked',
  ]),
});

const RESPONSE_MATRIX = Object.freeze({
  allow: Object.freeze(['allowed']),
  flag: Object.freeze(['response_flagged']),
  redact: Object.freeze(['response_redacted']),
  block: Object.freeze([
    ...REQUEST_MATRIX.block,
    'response_blocked',
    'response_scan_unavailable',
  ]),
});

function normalizedPair(verdict) {
  if (!verdict || typeof verdict !== 'object' || Array.isArray(verdict)) return null;
  if (typeof verdict.decision !== 'string') return null;
  if (verdict.status != null && typeof verdict.status !== 'string') return null;
  return {
    decision: verdict.decision.trim().toLowerCase(),
    status: String(verdict.status || '').trim().toLowerCase(),
  };
}

function classify(matrix, verdict) {
  const pair = normalizedPair(verdict);
  if (!pair || !matrix[pair.decision] || !matrix[pair.decision].includes(pair.status)) return 'invalid';
  return pair.decision;
}

function classifyRequestVerdict(verdict) {
  return classify(REQUEST_MATRIX, verdict);
}

function classifyResponseVerdict(verdict) {
  const action = classify(RESPONSE_MATRIX, verdict);
  if (action === 'invalid') return action;
  // `blocked` is redundant but security-relevant when supplied. It may be
  // omitted by early access gates, but it may never contradict the pair.
  if (verdict.blocked === true && action !== 'block') return 'invalid';
  if (verdict.blocked === false && action === 'block') return 'invalid';
  return action;
}

module.exports = {
  classifyRequestVerdict,
  classifyResponseVerdict,
  REQUEST_MATRIX,
  RESPONSE_MATRIX,
};
