'use strict';
/** Texas FCU Command Center must describe and render sanitized telemetry, not raw prompt logs. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server', 'app.js'), 'utf8');
const monitor = fs.readFileSync(path.join(root, 'console', 'src', 'views', 'Monitor.tsx'), 'utf8');
const leakMap = fs.readFileSync(path.join(root, 'console', 'src', 'components', 'overview', 'LeakMap.tsx'), 'utf8');
const sse = fs.readFileSync(path.join(root, 'console', 'src', 'lib', 'sse.ts'), 'utf8');

// Word-boundary matcher: `rawPrompt` as a standalone token or `_rawPrompt`, plus
// the `/reveal` route. Deliberately does NOT flag `rawPromptBodies`, which is a
// sanitized boolean privacy flag (raw bodies excluded), not raw prompt content.
const RAW_REVEAL = /\brawPrompt\b|_rawPrompt|\/reveal/;

function sourceBetween(text, startNeedle, endNeedle) {
  const start = text.indexOf(startNeedle);
  assert.notStrictEqual(start, -1, `missing ${startNeedle}`);
  const end = text.indexOf(endNeedle, start);
  assert.notStrictEqual(end, -1, `missing ${endNeedle}`);
  return text.slice(start, end);
}

test('Texas FCU Command Center feed drives off sanitized posture metadata', () => {
  // Header copy names the privacy stance the console must uphold.
  assert.match(monitor, /Sanitized member-data posture[\s\S]*without prompt bodies/);
  assert.match(monitor, /Texas FCU Command Center/);

  // The feed is built from posture surfaces/events, not canned raw fixtures.
  assert.match(monitor, /const surfaces = report\?\.surfaces \?\? \[\];/);
  assert.match(monitor, /const events = report\?\.events \?\? \[\];/);

  // No part of the view references raw prompt bodies or the reveal route.
  assert.doesNotMatch(monitor, RAW_REVEAL, 'Monitor view must not surface raw prompt text or /reveal');
});

test('Texas FCU Command Center live stream carries only sanitized signals', () => {
  // Monitor consumes the shared SSE hook rather than opening its own raw feed.
  assert.match(monitor, /import \{ useEventStream \} from '\.\.\/lib\/sse'/);
  const streamWiring = sourceBetween(monitor, 'const reloadLive', 'const report = posture.report;');
  assert.match(streamWiring, /posture\.load\(\)/);
  assert.match(streamWiring, /activity\.load\(\)/);
  assert.match(streamWiring, /useEventStream\(\{ query: reloadLive, decision: reloadLive, stats: reloadLive \}\)/);
  assert.doesNotMatch(streamWiring, RAW_REVEAL, 'stream reload must not touch raw prompt or /reveal');

  // The stream transport itself is /api/stream and never carries raw prompt/reveal.
  assert.match(sse, /new EventSource\('\/api\/stream'\)/);
  assert.doesNotMatch(sse, RAW_REVEAL, 'SSE transport must not reference raw prompt or /reveal');
});

test('leak map renders sanitized scenario evidence only', () => {
  assert.match(leakMap, /aria-label="AI data leak exposure map"/);
  assert.match(leakMap, /id="leakMapStage"/);
  assert.match(leakMap, /masked findings only/);
  assert.match(leakMap, /prompt bodies excluded/);
  assert.doesNotMatch(leakMap, RAW_REVEAL, 'leak map must not surface raw prompt text or /reveal');
  assert.doesNotMatch(leakMap, /\d{3}-\d{2}-\d{4}/, 'leak map must not embed SSN-shaped fixtures');
});

test('server keeps raw prompts sealed and reveal behind its own route', () => {
  const publicQuery = sourceBetween(server, 'function publicQuery', "app.get('/api/queries'");
  assert.match(publicQuery, /rawRetained: Boolean\(_rawPrompt\)/);
  assert.match(publicQuery, /includeRaw/);
  assert.doesNotMatch(server, /publicQuery\([^)]*includeRaw\s*:\s*true/);
  assert.match(server, /app\.post\(\s*'\/api\/queries\/:id\/reveal'/);
});
