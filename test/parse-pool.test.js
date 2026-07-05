'use strict';
/** Parse-pool isolation: preemptible, fault-isolated extraction for attacker-controlled files. */
const test = require('node:test');
const assert = require('node:assert');

process.env.REDACTWALL_PARSE_ISOLATION = 'on';
process.env.REDACTWALL_PARSE_POOL_SIZE = '1';
process.env.REDACTWALL_PARSE_KILL_GRACE_MS = '400';

const processors = require('../server/processors');
const parsePool = require('../server/parse-pool');

function officeDoc(xmlText) {
  const AdmZip = require('adm-zip');
  const zip = new AdmZip();
  zip.addFile('word/document.xml', Buffer.from('<w:t>' + xmlText + '</w:t>'));
  return zip.toBuffer();
}

// A docx whose XML inflates to many megabytes forces long synchronous
// inflate + regex work in the extraction child.
function pathologicalDoc(megabytes) {
  return officeDoc('spin '.repeat((megabytes * 1024 * 1024) / 5));
}

test.after(() => parsePool.shutdown());

test('pooled extraction matches direct extraction for text, office, and unsupported files', async () => {
  const textBuf = Buffer.from('Member SSN 524-71-9043 pending review.');
  const docBuf = officeDoc('Member &amp; loan SSN 524-71-9043');

  for (const [name, buf] of [['loan.txt', textBuf], ['loan.docx', docBuf], ['archive.bin', textBuf]]) {
    const direct = await processors.extractText(name, buf);
    const pooled = await parsePool.extractText(name, buf);
    assert.deepStrictEqual(pooled, direct, name);
  }
});

test('image files short-circuit to ocr_required without spawning a child', async () => {
  parsePool.shutdown();
  const result = await parsePool.extractText('scan.png', Buffer.from('image bytes'));
  assert.strictEqual(result.error, 'ocr_required');
  assert.strictEqual(result.ocrRequired, true);
  assert.strictEqual(parsePool._internal.workers.size, 0);
});

test('corrupt office files report extract_failed through the pool', async () => {
  const result = await parsePool.extractText('loan.docx', Buffer.from('not a zip archive'));
  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'extract_failed');
  assert.strictEqual(result.text, '');
});

test('a CPU-spinning parse is preempted while the parent stays responsive', async () => {
  const buf = pathologicalDoc(48);

  let maxGapMs = 0;
  let last = Date.now();
  const probe = setInterval(() => {
    const now = Date.now();
    maxGapMs = Math.max(maxGapMs, now - last);
    last = now;
  }, 25);

  const started = Date.now();
  const result = await parsePool.extractText('spin.docx', buf, { timeoutMs: 150 });
  const elapsed = Date.now() - started;
  clearInterval(probe);

  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'timeout');
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.text, '');
  // Preemption bound: child timeout (150ms) + kill grace (400ms) + slack.
  assert.ok(elapsed < 5000, `preemption took ${elapsed}ms`);
  // The event loop must not be blocked by the child's synchronous parse.
  assert.ok(maxGapMs < 1000, `parent event loop stalled for ${maxGapMs}ms`);
});

test('a killed child fails the in-flight task and the next extraction succeeds', async () => {
  const doc = officeDoc('healthy after crash SSN 524-71-9043');
  const inFlight = parsePool.extractText('spin.docx', pathologicalDoc(48), { timeoutMs: 30000 });
  await new Promise((resolve) => setTimeout(resolve, 100));

  const worker = [...parsePool._internal.workers][0];
  assert.ok(worker, 'expected a busy worker');
  process.kill(worker.child.pid, 'SIGKILL');

  const crashed = await inFlight;
  assert.strictEqual(crashed.extractionOk, false);
  assert.strictEqual(crashed.error, 'extract_failed');

  const next = await parsePool.extractText('healthy.docx', doc);
  assert.strictEqual(next.extractionOk, true);
  assert.strictEqual(next.text, 'healthy after crash SSN 524-71-9043');
});

test('queue overflow fails closed instead of queueing unbounded work', async () => {
  process.env.REDACTWALL_PARSE_QUEUE_MAX = '1';
  try {
    const doc = officeDoc('short');
    const busy = parsePool.extractText('spin.docx', pathologicalDoc(48), { timeoutMs: 2000 });
    await new Promise((resolve) => setTimeout(resolve, 100));
    const queued = parsePool.extractText('queued.docx', doc);
    const rejected = await parsePool.extractText('rejected.docx', doc);
    assert.strictEqual(rejected.extractionOk, false);
    assert.strictEqual(rejected.error, 'extract_failed');
    await busy;
    const drained = await queued;
    assert.strictEqual(drained.extractionOk, true);
  } finally {
    delete process.env.REDACTWALL_PARSE_QUEUE_MAX;
  }
});

test('children are recycled after their task budget', async () => {
  process.env.REDACTWALL_PARSE_CHILD_MAX_TASKS = '2';
  try {
    parsePool.shutdown();
    const doc = officeDoc('recycle me');
    await parsePool.extractText('a.docx', doc);
    const firstPid = [...parsePool._internal.workers][0]?.child.pid;
    await parsePool.extractText('b.docx', doc);
    assert.strictEqual(parsePool._internal.workers.size, 0, 'child retired after budget');
    await parsePool.extractText('c.docx', doc);
    const nextPid = [...parsePool._internal.workers][0]?.child.pid;
    assert.ok(nextPid && nextPid !== firstPid, 'fresh child after recycle');
  } finally {
    delete process.env.REDACTWALL_PARSE_CHILD_MAX_TASKS;
  }
});

test('REDACTWALL_PARSE_ISOLATION=off falls back to in-process extraction', async () => {
  process.env.REDACTWALL_PARSE_ISOLATION = 'off';
  try {
    parsePool.shutdown();
    const doc = officeDoc('inline path SSN 524-71-9043');
    const result = await parsePool.extractText('inline.docx', doc);
    assert.strictEqual(result.extractionOk, true);
    assert.strictEqual(result.text, 'inline path SSN 524-71-9043');
    assert.strictEqual(parsePool._internal.workers.size, 0);
  } finally {
    process.env.REDACTWALL_PARSE_ISOLATION = 'on';
  }
});
