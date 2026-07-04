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
];

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

function stateFor(control, input) {
  if (control.id === 'tamper_evident_audit') return stateFromIntegrity(input.auditIntegrity);
  if (control.id === 'fleet_sensor_coverage') return stateFromCoverage(input.coverage);
  if (control.id === 'backup_recoverability') return stateFromBackup(input.backup, input.restoreDrill);
  if (control.id === 'ai_prompt_dlp') return input.policy && (input.detectors || []).length ? 'covered' : 'attention';
  if (control.id === 'approval_workflow') return input.policy ? 'covered' : 'attention';
  if (control.id === 'local_detection_minimization') return input.scope && input.scope.rawPromptBodiesIncluded === false ? 'covered' : 'attention';
  return 'not_provided';
}

function summaryFor(control, input, state) {
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

module.exports = { CONTROL_MAPPINGS, buildControlMappings, _internal: { stateFor } };
