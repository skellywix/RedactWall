'use strict';
/**
 * Regulation policy templates. One-click presets that map a compliance regime to
 * concrete enforcement (mode, thresholds, hard-stop entities). Lets a small team
 * adopt a sane posture without hand-tuning detectors. Merge a template over the
 * current policy via PUT /api/policy/apply-template.
 */
const ALL_PII = ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_TIN_EIN', 'US_ITIN', 'US_NPI', 'US_DRIVERS_LICENSE', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN', 'PASSWORD', 'DOB'];

const TEMPLATES = {
  baseline: {
    label: 'Baseline (recommended start)',
    description: 'Block hard financial/credential identifiers; warn on the rest. Good default for most teams.',
    policy: { enforcementMode: 'block', blockMinSeverity: 3, blockRiskScore: 30,
      alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_ITIN', 'MEMBER_ID', 'LOAN_NUMBER', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'], disabledDetectors: [] },
  },
  ncua_glba: {
    label: 'NCUA / GLBA (credit unions, banks)',
    description: 'Strict hold on member nonpublic personal information: SSNs, accounts, routing, cards, DOB, TIN, member IDs, and loan numbers. Block mode, low threshold.',
    policy: { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 20,
      alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_TIN_EIN', 'US_ITIN', 'US_NPI', 'US_DRIVERS_LICENSE', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'DOB', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'], disabledDetectors: [] },
  },
  pci_dss: {
    label: 'PCI-DSS (cardholder data)',
    description: 'Cardholder-data focus: hard-stop PAN, plus redact-friendly handling of related PII.',
    policy: { enforcementMode: 'block', blockMinSeverity: 3, blockRiskScore: 25,
      alwaysBlock: ['CREDIT_CARD', 'BANK_ACCOUNT', 'IBAN', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'], disabledDetectors: [] },
  },
  hipaa: {
    label: 'HIPAA (PHI)',
    description: 'Protected health info: hard-stop direct identifiers; block at medium severity.',
    policy: { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 20,
      alwaysBlock: ['US_SSN', 'US_NPI', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'US_DRIVERS_LICENSE', 'US_PASSPORT', 'DOB', 'BANK_ACCOUNT', 'CREDIT_CARD', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'], disabledDetectors: [] },
  },
  redact_first: {
    label: 'Redact-first (productivity)',
    description: 'Let people keep working: tokenize PII automatically, restore the AI reply locally, log everything.',
    policy: { enforcementMode: 'redact', blockMinSeverity: 2, blockRiskScore: 20,
      alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'US_ITIN', 'MEMBER_ID', 'LOAN_NUMBER', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'], disabledDetectors: [] },
  },
};

function list() {
  return Object.entries(TEMPLATES).map(([id, t]) => ({ id, label: t.label, description: t.description, policy: t.policy }));
}
function get(id) { return TEMPLATES[id] || null; }

module.exports = { TEMPLATES, list, get, ALL_PII };
