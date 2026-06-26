'use strict';
/** Dashboard evidence export must call the sanitized export endpoint. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const dashboard = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

test('dashboard exposes a sanitized evidence export download action', () => {
  assert.match(dashboard, /id="exportEvidence"/);
  assert.match(dashboard, /async function exportEvidence\(\)/);
  assert.match(dashboard, /api\('\/api\/export\/evidence\?queryLimit=1000&auditLimit=1000'\)/);
  assert.match(dashboard, /promptsentinel-evidence-\$\{stamp\}\.json/);
  assert.match(dashboard, /JSON\.stringify\(pack, null, 2\)/);
});

test('dashboard export does not call reveal or raw-prompt APIs', () => {
  const exportBody = dashboard.match(/async function exportEvidence\(\)\{[\s\S]*?\n\}/);
  assert.ok(exportBody, 'exportEvidence function exists');
  assert.doesNotMatch(exportBody[0], /\/reveal/);
  assert.doesNotMatch(exportBody[0], /rawPrompt/);
});
