'use strict';
/**
 * Regression coverage for the HIGH-severity sensor-agent audit findings:
 *  - endpoint extraction must run through the killable parse pool so a crafted
 *    file cannot wedge the agent's event loop (agent.js extractEndpointFile).
 *  - fetchPolicy must await the JSON body so a parse rejection is caught and
 *    returns null instead of escaping as an unhandled rejection that would crash
 *    the long-running agent / break every wrapped MCP tool call.
 */
process.env.REDACTWALL_PARSE_ISOLATION = 'on';
process.env.REDACTWALL_PARSE_POOL_SIZE = '1';
process.env.REDACTWALL_PARSE_KILL_GRACE_MS = '400';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const agent = require('../sensors/endpoint-agent/agent');
const guard = require('../sensors/mcp-guard/guard');
const parsePool = require('../server/parse-pool');

function officeDoc(xmlText) {
  const AdmZip = require('adm-zip');
  const zip = new AdmZip();
  zip.addFile('word/document.xml', Buffer.from('<w:t>' + xmlText + '</w:t>'));
  return zip.toBuffer();
}

// A docx whose XML inflates to tens of MB forces long synchronous inflate+regex
// work during extraction. In-process that stalls the whole event loop and the
// timeout cannot preempt it; through the pool it is SIGKILLed and fails closed.
function pathologicalDoc(megabytes) {
  return officeDoc('spin '.repeat((megabytes * 1024 * 1024) / 5));
}

test.after(() => parsePool.shutdown());

test('endpoint extraction is preempted through the parse pool and fails closed', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-isolation-'));
  const filename = 'spin.docx';
  fs.writeFileSync(path.join(dir, filename), pathologicalDoc(48));

  let maxGapMs = 0;
  let last = Date.now();
  const probe = setInterval(() => {
    const now = Date.now();
    maxGapMs = Math.max(maxGapMs, now - last);
    last = now;
  }, 25);

  const res = await agent.scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    settleMs: 0,
    maxBytes: 64 * 1024 * 1024,
    extract: { timeoutMs: 150 },
    report: async () => ({ id: 'q_unscanned' }),
  });
  clearInterval(probe);

  // Fail closed: a wedged parse is blocked as scan_unavailable, never allowed.
  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(res.status, 'scan_unavailable');
  // The agent's event loop must stay responsive while the child does the work.
  assert.ok(maxGapMs < 1500, `agent event loop stalled for ${maxGapMs}ms`);
});

test('endpoint fetchPolicy returns null when the response body fails to parse', async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => { throw new Error('non-json body'); } });
  // Before the fix this rejected (unhandled rejection in the interval refresh);
  // now the parse failure is caught and the refresh degrades to null.
  const result = await agent.fetchPolicy({ key: 'unit-key', server: 'http://redactwall.test', fetchImpl, silent: true });
  assert.strictEqual(result, null);
});

test('mcp guard fetchPolicy returns null when the response body fails to parse', async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => { throw new Error('non-json body'); } });
  const result = await guard.fetchPolicy({ key: 'unit-key', server: 'http://redactwall.test', fetchImpl, silent: true });
  assert.strictEqual(result, null);
});
