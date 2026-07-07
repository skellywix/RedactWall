'use strict';
/**
 * Stable examiner-facing control map.
 *
 * These mappings are product evidence pointers, not compliance certification.
 * They keep export packs readable for regulated buyers without inventing
 * customer-specific legal conclusions.
 */

const CONTROL_MAPPINGS = [
  {
    id: 'ai_prompt_dlp',
    title: 'AI prompt and file DLP enforcement',
    controlFamilies: [
      'GLBA safeguards evidence',
      'NCUA information-security program evidence',
      'HIPAA Security Rule monitoring evidence',
      'PCI DSS data-protection evidence',
    ],
    evidence: ['policy', 'detectors', 'queries', 'lineage'],
  },
  {
    id: 'local_detection_minimization',
    title: 'Local detection and data minimization',
    controlFamilies: [
      'GLBA data minimization evidence',
      'HIPAA minimum-necessary evidence',
      'PCI DSS data-retention evidence',
    ],
    evidence: ['scope', 'queries.promptHash', 'queries.findings', 'audit.detailHash'],
  },
  {
    id: 'approval_workflow',
    title: 'Approval workflow and exception handling',
    controlFamilies: [
      'GLBA access-control evidence',
      'NCUA exception-review evidence',
      'HIPAA workforce security evidence',
    ],
    evidence: ['queries.workflow', 'audit.policyChange', 'lineage.byDecision'],
  },
  {
    id: 'tamper_evident_audit',
    title: 'Tamper-evident audit trail',
    controlFamilies: [
      'GLBA monitoring evidence',
      'NCUA audit evidence',
      'HIPAA information-system activity review evidence',
      'PCI DSS audit-log evidence',
    ],
    evidence: ['auditIntegrity', 'audit.prevHash', 'audit.hash', 'audit.detailHash'],
  },
  {
    id: 'fleet_sensor_coverage',
    title: 'Required sensor coverage and endpoint posture',
    controlFamilies: [
      'GLBA system-monitoring evidence',
      'NCUA endpoint-control evidence',
      'HIPAA technical safeguards evidence',
    ],
    evidence: ['coverage.totals', 'coverage.sensors', 'coverage.fleet', 'coverage.posture'],
  },
  {
    id: 'backup_recoverability',
    title: 'Evidence-store backup and restore readiness',
    controlFamilies: [
      'GLBA availability evidence',
      'NCUA resilience evidence',
      'HIPAA contingency-plan evidence',
      'PCI DSS retention and recovery evidence',
    ],
    evidence: ['backup', 'restoreDrill'],
  },
  {
    id: 'ai_usage_governance',
    title: 'AI usage governance and shadow-AI control',
    controlFamilies: [
      'NIST AI RMF GOVERN/MAP evidence',
      'ISO/IEC 42001 AI management system evidence',
      'EU AI Act Article 4 AI-literacy and acceptable-use evidence',
      'GLBA third-party/vendor oversight evidence',
    ],
    evidence: ['policy.governedDestinations', 'policy.blockUnapprovedAiDestinations', 'coverage.shadowAi', 'destinations.review'],
  },
  {
    id: 'prompt_threat_defense',
    title: 'Prompt-injection and jailbreak defense',
    controlFamilies: [
      'OWASP LLM01 Prompt Injection evidence',
      'OWASP LLM02 Sensitive Information Disclosure evidence',
      'NIST AI RMF MEASURE evidence',
      'MITRE ATLAS adversarial-ML evidence',
    ],
    evidence: ['detectors.PROMPT_ATTACK', 'queries.injection_blocked', 'policy.responseScanMode'],
  },
  {
    id: 'ai_activity_recordkeeping',
    title: 'AI interaction record-keeping and provenance',
    controlFamilies: [
      'EU AI Act Article 12 record-keeping evidence',
      'ISO/IEC 42001 operational-control evidence',
      'NIST AI RMF MANAGE evidence',
    ],
    evidence: ['auditIntegrity', 'receipts', 'queries.workflow'],
  },
  {
    id: 'member_information_safeguards',
    title: 'Member information safeguards (EDM + hard stops)',
    controlFamilies: [
      'NCUA Part 748 Appendix A member-information safeguards evidence',
      'GLBA Safeguards Rule 501(b) evidence',
      'NCUA information-security program evidence',
    ],
    evidence: ['edm', 'policy.alwaysBlock', 'detectors.MEMBER_ID', 'detectors.EXACT_MATCH'],
  },
  {
    id: 'ai_use_inventory',
    title: 'AI use-case inventory and review',
    controlFamilies: [
      'NCUA 2026 AI supervisory-priority inventory evidence',
      'NIST AI RMF MAP evidence',
      'GLBA risk-assessment evidence',
    ],
    evidence: ['useCases'],
  },
  {
    id: 'vendor_service_provider_oversight',
    title: 'AI vendor and service-provider oversight',
    controlFamilies: [
      'NCUA Part 748 service-provider oversight evidence',
      'GLBA third-party oversight evidence',
    ],
    evidence: ['useCases.vendorStatus', 'catalog.review'],
  },
  {
    id: 'incident_readiness',
    title: '72-hour AI incident readiness',
    controlFamilies: [
      'NCUA 12 CFR 748.1(c) cyber-incident reporting evidence',
      'GLBA incident-response evidence',
    ],
    evidence: ['incidents'],
  },
  {
    id: 'board_reporting',
    title: 'Board and executive AI reporting',
    controlFamilies: [
      'NCUA board-oversight evidence',
      'GLBA Safeguards Rule board-reporting evidence',
    ],
    evidence: ['boardPacket'],
  },
];

// Member NPI hard-stop set an examiner expects on a federal credit union
// deployment; the core of the ncua_glba template's alwaysBlock list. Shared
// with server/ncua-readiness.js.
const MEMBER_IDENTIFIERS = ['US_SSN', 'MEMBER_ID', 'LOAN_NUMBER', 'BANK_ACCOUNT', 'ROUTING_NUMBER'];

// Slice-2/3 controls (PLANS/ncua-readiness-center.md) whose evidence inputs do
// not exist yet; they render not_provided with an honest summary until the
// use-case inventory, incident records, and board packet ship.
const PENDING_CONTROL_SUMMARIES = {
  ai_use_inventory: 'AI use-case inventory records are not yet attached; they ship with the NCUA Readiness inventory.',
  vendor_service_provider_oversight: 'Vendor-review status is not yet attached; it ships with the AI use-case inventory.',
  incident_readiness: '72-hour incident records are not yet attached; they ship with the incident-readiness workflow.',
  board_reporting: 'Board packet evidence is not yet attached; it ships with Board Packet exports.',
};

function hasObject(value) {
  return !!value && typeof value === 'object';
}

function stateFromIntegrity(integrity) {
  if (!hasObject(integrity)) return 'not_provided';
  return integrity.ok === true ? 'covered' : 'attention';
}

function stateFromCoverage(coverage) {
  if (!hasObject(coverage)) return 'not_provided';
  const totals = coverage.totals || {};
  const required = Number(totals.requiredSensors) || 0;
  const active = Number(totals.activeRequiredSensors) || 0;
  const gaps = Number(totals.activeSensorVersionGaps) || 0;
  const warnings = Number(totals.activeSensorHealthWarnings) || 0;
  const endpointAiAttention = (Array.isArray(coverage.posture) ? coverage.posture : [])
    .some((item) => item && item.id === 'endpoint_ai_tools' && item.state === 'attention');
  if (!required) return 'attention';
  return active >= required && !gaps && !warnings && !endpointAiAttention ? 'covered' : 'attention';
}

function stateFromBackup(backup, restoreDrill) {
  if (!hasObject(backup) && !hasObject(restoreDrill)) return 'not_provided';
  return backup && backup.ok === true && restoreDrill && restoreDrill.ok === true
    ? 'covered'
    : 'attention';
}

function detectorIds(input) {
  return new Set((input.detectors || []).map((d) => (d && (d.id || d)) || '').filter(Boolean));
}

function stateFromUsageGovernance(input) {
  const p = input.policy;
  if (!p) return 'attention';
  const governed = Array.isArray(p.governedDestinations) ? p.governedDestinations.length : 0;
  return governed > 0 && p.blockUnapprovedAiDestinations !== false ? 'covered' : 'attention';
}

function stateFromPromptThreat(input) {
  if (!input.policy) return 'attention';
  return detectorIds(input).has('PROMPT_ATTACK') ? 'covered' : 'attention';
}

function edmActive(edm) {
  return hasObject(edm) && edm.enabled === true && Number(edm.fingerprints) > 0;
}

function stateFromMemberSafeguards(input) {
  if (!input.policy) return hasObject(input.edm) ? 'attention' : 'not_provided';
  const always = new Set(Array.isArray(input.policy.alwaysBlock) ? input.policy.alwaysBlock : []);
  const identifiersCovered = MEMBER_IDENTIFIERS.every((id) => always.has(id));
  return identifiersCovered && edmActive(input.edm) ? 'covered' : 'attention';
}

function memberSafeguardsSummary(input, state) {
  if (state === 'not_provided') return 'No policy or EDM evidence attached to this pack.';
  if (state === 'covered') return 'Core-banking EDM fingerprints are active and member-identifier hard stops are enforced.';
  const always = new Set(Array.isArray(input.policy && input.policy.alwaysBlock) ? input.policy.alwaysBlock : []);
  const missing = MEMBER_IDENTIFIERS.filter((id) => !always.has(id));
  if (missing.length) return `Hard-stop coverage for member identifiers is incomplete: ${missing.join(', ')}.`;
  return 'Member-identifier hard stops are enforced; core-banking EDM fingerprints are not configured yet (npm run edm:fingerprint).';
}

function stateFor(control, input) {
  if (control.id === 'tamper_evident_audit') return stateFromIntegrity(input.auditIntegrity);
  if (control.id === 'fleet_sensor_coverage') return stateFromCoverage(input.coverage);
  if (control.id === 'backup_recoverability') return stateFromBackup(input.backup, input.restoreDrill);
  if (control.id === 'ai_prompt_dlp') return input.policy && (input.detectors || []).length ? 'covered' : 'attention';
  if (control.id === 'approval_workflow') return input.policy ? 'covered' : 'attention';
  if (control.id === 'local_detection_minimization') return input.scope && input.scope.rawPromptBodiesIncluded === false ? 'covered' : 'attention';
  if (control.id === 'ai_usage_governance') return stateFromUsageGovernance(input);
  if (control.id === 'prompt_threat_defense') return stateFromPromptThreat(input);
  if (control.id === 'ai_activity_recordkeeping') return stateFromIntegrity(input.auditIntegrity);
  if (control.id === 'member_information_safeguards') return stateFromMemberSafeguards(input);
  return 'not_provided';
}

function summaryFor(control, input, state) {
  if (PENDING_CONTROL_SUMMARIES[control.id]) return PENDING_CONTROL_SUMMARIES[control.id];
  if (control.id === 'member_information_safeguards') return memberSafeguardsSummary(input, state);
  if (control.id === 'tamper_evident_audit') {
    const count = Number(input.auditIntegrity && input.auditIntegrity.count) || 0;
    return state === 'covered'
      ? `Audit chain verified across ${count} event(s).`
      : 'Audit-chain verification needs review.';
  }
  if (control.id === 'fleet_sensor_coverage') {
    const totals = input.coverage && input.coverage.totals ? input.coverage.totals : {};
    const required = Number(totals.requiredSensors) || 0;
    const active = Number(totals.activeRequiredSensors) || 0;
    const endpointAi = (Array.isArray(input.coverage && input.coverage.posture) ? input.coverage.posture : [])
      .find((item) => item && item.id === 'endpoint_ai_tools');
    const endpointAiDetail = endpointAi && endpointAi.state === 'attention'
      ? ` Endpoint AI tools: ${endpointAi.detail || 'attention'}.`
      : '';
    return `${active}/${required} required sensor type(s) active in the evidence window.${endpointAiDetail}`;
  }
  if (control.id === 'backup_recoverability') {
    if (state === 'not_provided') return 'No backup or restore-drill evidence attached to this pack.';
    if (state === 'covered') return 'Backup verification and restore-drill verification are both passing.';
    return 'Backup or restore-drill evidence is missing or failing.';
  }
  if (control.id === 'local_detection_minimization') {
    return 'Export uses hashes, masked findings, and bounded metadata instead of prompt bodies or audit detail text.';
  }
  if (control.id === 'approval_workflow') {
    return 'Held decisions, policy changes, routing metadata, and exception evidence are exported without raw prompts.';
  }
  if (control.id === 'ai_usage_governance') {
    const governed = Array.isArray(input.policy && input.policy.governedDestinations) ? input.policy.governedDestinations.length : 0;
    return state === 'covered'
      ? `${governed} AI destination(s) governed with default-deny for unreviewed AI tools; shadow-AI visits are recorded for review.`
      : 'Governed AI destinations or default-deny for unreviewed AI tools need configuration.';
  }
  if (control.id === 'prompt_threat_defense') {
    return state === 'covered'
      ? 'Prompt-injection stripping and jailbreak/instruction-override intent detection run on prompts and AI responses.'
      : 'Prompt-attack intent detection is not enabled in the active detector set.';
  }
  if (control.id === 'ai_activity_recordkeeping') {
    return state === 'covered'
      ? 'Every AI interaction decision is recorded in a tamper-evident hash-chained log with signed safe-to-send receipts.'
      : 'AI interaction record-keeping needs audit-chain verification.';
  }
  return 'Policy, detector inventory, event summaries, and lineage evidence are present for examiner review.';
}

function buildControlMappings(input = {}) {
  return CONTROL_MAPPINGS.map((control) => {
    const state = stateFor(control, input);
    return {
      id: control.id,
      title: control.title,
      state,
      controlFamilies: control.controlFamilies,
      evidence: control.evidence,
      summary: summaryFor(control, input, state),
      lastVerifiedAt: input.generatedAt || null,
    };
  });
}

module.exports = { CONTROL_MAPPINGS, buildControlMappings, MEMBER_IDENTIFIERS, _internal: { stateFor } };
