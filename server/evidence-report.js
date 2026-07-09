'use strict';
/**
 * Render a schemaVersion-3 examiner evidence pack as a human-readable Markdown
 * report a compliance officer can hand across the table.
 *
 * It reads ONLY bounded, server-generated fields from the (already prompt-free)
 * pack — counts, enums, control states, control-family labels, ISO timestamps,
 * and the disclaimers. It never renders raw records, use-case owner/notes, board
 * minutes, or prompt bodies, so free text cannot leak into the report.
 */

function esc(value) {
  // Table-cell safe: collapse newlines and escape the pipe delimiter.
  return String(value == null ? '' : value).replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');
}

function stateLabel(state) {
  return String(state || '').replace(/_/g, ' ');
}

function renderControlMappings(controls) {
  if (!Array.isArray(controls) || !controls.length) return '';
  const rows = controls.map((c) => `| ${esc(c.title)} | ${esc(stateLabel(c.state))} | ${esc((c.controlFamilies || []).join('; '))} |`);
  return ['## Control mappings', '', '| Control | State | Control families |', '| --- | --- | --- |', ...rows, ''].join('\n');
}

function renderControlTests(controlTests) {
  if (!controlTests || !Array.isArray(controlTests.tests)) return '';
  const rows = controlTests.tests.map((t) => `| ${esc(t.id)} | ${esc(t.method)} | ${esc(t.result)} | ${esc(t.lastTestedAt || '—')} |`);
  const s = controlTests.summary || {};
  return [
    '## Control testing (NCUA Part 748 Appendix A — regularly test key controls)',
    '',
    `${Number(s.passed) || 0}/${Number(s.applicable) || 0} applicable control test(s) passing.`,
    '',
    '| Test | Method | Result | Last verified |',
    '| --- | --- | --- | --- |',
    ...rows,
    '',
    `> ${esc(controlTests.disclaimer)}`,
    '',
  ].join('\n');
}

function renderMarkdown(pack = {}) {
  const scope = pack.scope || {};
  const service = pack.service || {};
  const lines = [
    '# RedactWall examiner evidence report',
    '',
    `- **Service:** ${esc(service.name || 'RedactWall')} ${esc(service.version || '')}`.trimEnd(),
    `- **Generated:** ${esc(pack.generatedAt || '')}`,
    `- **Examiner profile:** ${esc(scope.examinerProfile || 'none')}`,
    `- **Schema version:** ${esc(pack.schemaVersion || '')}`,
    `- **Prompt bodies included:** ${scope.rawPromptBodiesIncluded === true ? 'yes' : 'no'}`,
    '',
  ];
  if (pack.complianceDisclaimer) lines.push(`> ${esc(pack.complianceDisclaimer)}`, '');
  const readiness = pack.ncuaReadiness;
  if (readiness && typeof readiness === 'object') {
    lines.push('## Readiness', '', `- **Score:** ${esc(readiness.score)}`, `- **State:** ${esc(readiness.state)}`, '');
  }
  const cm = renderControlMappings(pack.controlMappings);
  if (cm) lines.push(cm);
  const ct = renderControlTests(pack.controlTests);
  if (ct) lines.push(ct);
  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n').trim()}\n`;
}

module.exports = { renderMarkdown };
