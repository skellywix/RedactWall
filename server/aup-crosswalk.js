'use strict';
/**
 * AI Acceptable-Use Policy (AUP) clause -> enforcing-control crosswalk.
 *
 * RedactWall does NOT author or ship board-adoptable AUP prose — the policy text
 * stays credit-union-owned (Decision 4 in PLANS/credit-union-tuning.md). This
 * machine-readable crosswalk proves that the clauses a board DOES adopt are
 * technically ENFORCED by the product, and lets the examiner pack carry an AUP
 * adoption ATTESTATION (date + reference) without RedactWall drawing a legal
 * conclusion. It is an evidence pointer, not certification.
 */

const AUP_CROSSWALK = [
  {
    id: 'no_member_npi_in_ai',
    clause: 'Member nonpublic personal information (NPI) must not be entered into external AI tools.',
    enforcedBy: ['ai_prompt_dlp', 'member_information_safeguards'],
    policySignals: ['alwaysBlock', 'edm'],
    evidence: ['detectors', 'queries', 'edm'],
  },
  {
    id: 'approved_destinations_only',
    clause: 'Only approved, sanctioned AI destinations may be used for credit-union work.',
    enforcedBy: ['ai_usage_governance'],
    policySignals: ['governedDestinations', 'blockUnapprovedAiDestinations'],
    evidence: ['policy.governedDestinations', 'coverage.shadowAi'],
  },
  {
    id: 'no_personal_ai_accounts',
    clause: 'Personal AI accounts must not be used to process credit-union or member data.',
    enforcedBy: ['ai_usage_governance'],
    policySignals: ['personalAccountAction'],
    evidence: ['policy.personalAccountAction'],
  },
  {
    id: 'block_prompt_injection',
    clause: 'Prompt-injection and jailbreak attempts must be detected and blocked or flagged.',
    enforcedBy: ['prompt_threat_defense'],
    policySignals: ['responseScanMode'],
    evidence: ['detectors.PROMPT_ATTACK', 'queries.injection_blocked'],
  },
  {
    id: 'tamper_evident_logging',
    clause: 'All AI interactions are recorded in a tamper-evident audit trail; controls must not be bypassed.',
    enforcedBy: ['tamper_evident_audit', 'ai_activity_recordkeeping'],
    policySignals: [],
    evidence: ['auditIntegrity', 'receipts'],
  },
  {
    id: 'acknowledge_coaching',
    clause: 'Users must acknowledge policy warnings before proceeding with a flagged prompt.',
    enforcedBy: ['ai_prompt_dlp'],
    policySignals: ['enforcementMode'],
    evidence: ['queries.workflow'],
  },
];

// A board records that it adopted the AUP; RedactWall stores only a bounded
// timestamp + reference string (e.g., a minutes id), never the policy text.
function normalizeAupAttestation(input) {
  if (!input || typeof input !== 'object') return null;
  const raw = String(input.adoptedAt || '');
  // Require a real ISO-8601 date (not just the allowed charset), so a malformed
  // string like "0000000000" can't flip the AUP control toward covered.
  const looksIso = /^\d{4}-\d{2}-\d{2}([T ][0-9:.+Z-]{1,30})?$/.test(raw) && Number.isFinite(Date.parse(raw));
  const adoptedAt = looksIso ? raw : null;
  if (!adoptedAt) return null;
  const reference = typeof input.reference === 'string' ? input.reference.slice(0, 120) : '';
  return { adoptedAt, reference };
}

module.exports = { AUP_CROSSWALK, normalizeAupAttestation };
