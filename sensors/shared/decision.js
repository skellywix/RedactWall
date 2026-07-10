'use strict';
/**
 * Shared local block/warn/allow decision for sensors.
 *
 * This is the SAME logic the browser extension applies inline
 * (sensors/browser-extension/content.js `evaluate()`): a hard-stop entity
 * always blocks; otherwise a severity/risk breach maps to the org's
 * enforcement mode. Extracted here so the agent-hooks sensor doesn't become a
 * third hand-rolled copy (CLAUDE.md: do not duplicate logic more than twice).
 * Kept out of detection-engine so the engine's public API stays stable — this
 * is policy interpretation, not detection.
 *
 * Pure: takes an analysis (from detection-engine analyze()) plus a policy
 * object with { alwaysBlock, blockMinSeverity, blockRiskScore, enforcementMode }
 * and returns { action: 'allow' | 'warn' | 'redact' | 'block', hardStop }.
 */
const MANDATORY_ALWAYS_BLOCK = Object.freeze([
  'US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT',
  'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID',
  'UK_NINO', 'UK_NHS_NUMBER', 'CANADA_SIN', 'AUSTRALIA_TFN', 'INDIA_AADHAAR',
  'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN', 'EXACT_MATCH',
]);

function mandatoryAlwaysBlock(value) {
  const configured = Array.isArray(value) ? value : [];
  return [...new Set([...MANDATORY_ALWAYS_BLOCK, ...configured]
    .filter((type) => typeof type === 'string' && type.trim())
    .map((type) => type.trim().toUpperCase()))];
}

function decide(analysis, policy = {}) {
  const findings = (analysis && analysis.findings) || [];
  const categories = (analysis && analysis.categories) || [];
  if (analysis && analysis.opaqueEncoded === true) {
    return { action: 'block', hardStop: true, opaqueEncoded: true };
  }
  if (!findings.length && !categories.length) return { action: 'allow', hardStop: false };

  const alwaysBlock = mandatoryAlwaysBlock(policy.alwaysBlock);
  const hardStop = findings.some((f) => alwaysBlock.includes(f.type));
  const mode = policy.enforcementMode || 'block';

  // REDACT mode neutralizes structured values locally by tokenizing them —
  // including hard-stop entities, which then leave only as tokens (never raw) so
  // the prompt can proceed. This matches the server API/file, browser, and
  // endpoint paths ("reversibly redacts"). A semantic category has no span-level
  // token to swap, so any category hit must block rather than leak confidential
  // context with only the PII tokenized. Hard-stop still hard-blocks in every
  // OTHER mode (handled below).
  if (mode === 'redact') {
    return { action: (findings.length && !categories.length) ? 'redact' : 'block', hardStop };
  }

  const breach = hardStop
    || (analysis.maxSeverity || 0) >= (policy.blockMinSeverity != null ? policy.blockMinSeverity : 2)
    || (analysis.riskScore || 0) >= (policy.blockRiskScore != null ? policy.blockRiskScore : 25);
  if (!breach) return { action: 'allow', hardStop: false };

  // Hard-stop entities always block regardless of mode.
  return { action: hardStop ? 'block' : mode, hardStop };
}

module.exports = { decide, mandatoryAlwaysBlock, MANDATORY_ALWAYS_BLOCK };
