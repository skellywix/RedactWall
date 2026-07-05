'use strict';
/** AI Command Center must describe and render sanitized telemetry, not raw prompt logs. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server', 'app.js'), 'utf8');
const index = fs.readFileSync(path.join(root, 'server', 'public', 'index.html'), 'utf8');
const dashboard = fs.readFileSync(path.join(root, 'server', 'public', 'dashboard.js'), 'utf8');
const leakPathMap = fs.readFileSync(path.join(root, 'server', 'public', 'leak-path-map.js'), 'utf8');

function sourceBetween(text, startNeedle, endNeedle) {
  const start = text.indexOf(startNeedle);
  assert.notStrictEqual(start, -1, `missing ${startNeedle}`);
  const end = text.indexOf(endNeedle, start);
  assert.notStrictEqual(end, -1, `missing ${endNeedle}`);
  return text.slice(start, end);
}

test('AI Command Center labels its feed as sanitized metadata', () => {
  assert.match(index, /id="monitorDataScope"[\s\S]*without prompt bodies/);
  assert.match(index, /AI Data Leak Exposure Map/);
  assert.match(index, /See Every Path Sensitive Data Can Take to AI/);

  const monitorDefinitions = sourceBetween(dashboard, 'const monitorItems = [', 'function escapeHtml');
  assert.match(monitorDefinitions, /AI Command Center records sanitized metadata/);
  assert.match(monitorDefinitions, /only masked findings and category metadata are recorded/);
  assert.match(monitorDefinitions, /raw document text was not logged in AI Command Center/);
  assert.doesNotMatch(monitorDefinitions, /prompt was held/i);
  assert.doesNotMatch(monitorDefinitions, /\brawPrompt\b|_rawPrompt|\/reveal/);
});

test('leak path map renders sanitized scenario evidence only', () => {
  assert.match(leakPathMap, /PromptWallLeakPathMap/);
  assert.match(leakPathMap, /masked findings only/);
  assert.match(leakPathMap, /prompt bodies excluded/);
  assert.doesNotMatch(leakPathMap, /\brawPrompt\b|_rawPrompt|\/reveal/);
  assert.doesNotMatch(leakPathMap, /\d{3}-\d{2}-\d{4}/, 'leak map must not embed SSN-shaped fixtures');
  assert.match(index, /id="leakMapStage"/);
  assert.match(index, /aria-label="AI data leak exposure map"/);
});

test('AI Command Center stream handling stays separate from raw reveal', () => {
  const publicQuery = sourceBetween(server, 'function publicQuery', "app.get('/api/queries'");
  assert.match(publicQuery, /rawRetained: Boolean\(_rawPrompt\)/);
  assert.match(publicQuery, /includeRaw/);
  assert.doesNotMatch(server, /publicQuery\([^)]*includeRaw\s*:\s*true/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal'/);

  const streamHandler = sourceBetween(dashboard, 'function connectStream', 'function flash');
  assert.match(streamHandler, /new EventSource\('\/api\/stream'\)/);
  assert.doesNotMatch(streamHandler, /\brawPrompt\b|_rawPrompt|\/reveal/);
});
