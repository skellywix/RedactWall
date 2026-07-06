'use strict';
/** Console evidence export must call the sanitized export endpoint, never reveal/raw prompts. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const compliance = fs.readFileSync(path.join(root, 'console', 'src', 'views', 'Compliance.tsx'), 'utf8');
const auditApi = fs.readFileSync(path.join(root, 'console', 'src', 'api', 'audit.ts'), 'utf8');

function sourceBetween(text, startNeedle, endNeedle) {
  const start = text.indexOf(startNeedle);
  assert.notStrictEqual(start, -1, `missing ${startNeedle}`);
  const end = text.indexOf(endNeedle, start);
  assert.notStrictEqual(end, -1, `missing ${endNeedle}`);
  return text.slice(start, end);
}

test('Compliance view exposes a sanitized evidence export action', () => {
  // The export action targets the sanitized evidence endpoint, not a raw dump.
  assert.match(compliance, /href="\/api\/export\/evidence"/);
  assert.match(compliance, /Export evidence pack/);
  // Copy affirms the export is prompt-free (hashes & metadata only).
  assert.match(compliance, /Prompt-free/);
  assert.match(compliance, /hashes & metadata only/);
});

test('evidence export code path fetches /api/export/evidence and writes redactwall-evidence', () => {
  const exportBody = sourceBetween(auditApi, 'export async function exportEvidencePack', '\n}');
  assert.match(exportBody, /api\('\/api\/export\/evidence\?queryLimit=1000&auditLimit=1000'\)/);
  assert.match(exportBody, /redactwall-evidence-\$\{stamp\}\.json/);
  assert.match(exportBody, /downloadJson\(pack, /);
});

test('evidence export never calls reveal or raw-prompt APIs', () => {
  const exportBody = sourceBetween(auditApi, 'export async function exportEvidencePack', '\n}');
  assert.doesNotMatch(exportBody, /\/reveal/);
  assert.doesNotMatch(exportBody, /rawPrompt/);
  // The Compliance export action itself carries no raw-prompt/reveal wiring.
  const complianceHeader = sourceBetween(compliance, 'function ComplianceHeader', '\n}');
  assert.doesNotMatch(complianceHeader, /\/reveal/);
  assert.doesNotMatch(complianceHeader, /rawPrompt/);
});
