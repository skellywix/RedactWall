'use strict';
/** Dashboard evidence export must call the sanitized export endpoint. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dashboardHtml = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
const dashboardJs = fs.readFileSync(path.join(root, 'public', 'dashboard.js'), 'utf8');

test('dashboard exposes a sanitized evidence export download action', () => {
  assert.match(dashboardHtml, /id="exportEvidence"/);
  assert.match(dashboardJs, /async function exportEvidence\(\)/);
  assert.match(dashboardJs, /api\('\/api\/export\/evidence\?queryLimit=1000&auditLimit=1000'\)/);
  assert.match(dashboardJs, /promptsentinel-evidence-\$\{stamp\}\.json/);
  assert.match(dashboardJs, /JSON\.stringify\(pack, null, 2\)/);
});

test('dashboard export does not call reveal or raw-prompt APIs', () => {
  const exportBody = dashboardJs.match(/async function exportEvidence\(\)\{[\s\S]*?\n\}/);
  assert.ok(exportBody, 'exportEvidence function exists');
  assert.doesNotMatch(exportBody[0], /\/reveal/);
  assert.doesNotMatch(exportBody[0], /rawPrompt/);
});
