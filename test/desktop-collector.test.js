'use strict';
/** Desktop protected-upload collector writes metadata-only native handoff events. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const collector = require('../sensors/endpoint-agent/collectors/protected-upload');
const handoff = require('../sensors/endpoint-agent/native-handoff');

const SECRET = 'native-handoff-secret-000000000000000001';

function tempDir(t, prefix = 'ps-desktop-collector-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function withCleanHandoffEnv(t) {
  const keys = ['SENTINEL_ENV_PATH', 'ENDPOINT_AGENT_HANDOFF_SECRET', 'ENDPOINT_AGENT_HANDOFF_DIR'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  for (const key of keys) delete process.env[key];
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

test('parseArgs accepts repeated files and rejects secret argv handling', () => {
  const parsed = collector.parseArgs([
    '--file', 'a.txt',
    '--file', 'b.txt',
    '--destination', 'Desktop AI',
    '--wait',
    '--json',
  ]);
  assert.deepStrictEqual(parsed.files, ['a.txt', 'b.txt']);
  assert.strictEqual(parsed.destination, 'Desktop AI');
  assert.strictEqual(parsed.wait, true);
  assert.strictEqual(parsed.json, true);
  assert.throws(() => collector.parseArgs(['--secret', SECRET]), /Unknown option/);
});

test('protected upload writes signed handoff events without file content or file path in public result', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const handoffDir = path.join(dir, 'handoff');
  const envPath = path.join(dir, 'endpoint-agent.env');
  const sourceFile = path.join(dir, 'member-524-71-9043.txt');
  fs.writeFileSync(sourceFile, 'Loan packet body with SSN 524-71-9043.');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${handoffDir}`,
  ].join('\n') + '\n');

  const result = await collector.collectProtectedUploads({
    files: [sourceFile],
    envPath,
    destination: 'Desktop AI',
    destinationProcess: 'desktop-ai.exe',
    user: 'analyst@example.test',
    id: 'evt_desktop_collector',
    nonce: 'collector-nonce',
    now: new Date('2026-06-27T20:00:00.000Z'),
  });

  assert.strictEqual(result.status, 'written');
  assert.strictEqual(result.count, 1);
  assert.strictEqual(result.failed, 0);
  assert.deepStrictEqual(result.results, [{
    status: 'written',
    id: 'evt_desktop_collector',
    destination: 'Desktop AI',
    consumed: false,
  }]);
  assert.ok(!JSON.stringify(result).includes('member-524-71-9043'));

  const eventPath = path.join(handoffDir, 'evt_desktop_collector.json');
  const body = fs.readFileSync(eventPath, 'utf8');
  assert.ok(!body.includes('Loan packet body'));
  assert.ok(!body.includes('SSN 524-71-9043'));
  const validated = handoff.readHandoffFile(eventPath, {
    secret: SECRET,
    now: new Date('2026-06-27T20:01:00.000Z'),
  });
  assert.strictEqual(validated.filePath, sourceFile);
  assert.strictEqual(validated.destination.app, 'Desktop AI');
  assert.strictEqual(validated.destination.process, 'desktop-ai.exe');
  assert.strictEqual(validated.user, 'analyst@example.test');
});

test('protected upload handles repeated files as one bounded batch', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const handoffDir = path.join(dir, 'handoff');
  const envPath = path.join(dir, 'endpoint-agent.env');
  const first = path.join(dir, 'first.txt');
  const second = path.join(dir, 'second.txt');
  fs.writeFileSync(first, 'First selected file with member data.');
  fs.writeFileSync(second, 'Second selected file with member data.');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${handoffDir}`,
  ].join('\n') + '\n');

  const result = await collector.collectProtectedUploads({
    files: [first, second],
    envPath,
    destination: 'Desktop AI',
    now: new Date('2026-06-27T20:05:00.000Z'),
  });

  assert.strictEqual(result.status, 'written');
  assert.strictEqual(result.count, 2);
  assert.strictEqual(result.failed, 0);
  assert.strictEqual(result.results.length, 2);
  assert.strictEqual(fs.readdirSync(handoffDir).filter((file) => file.endsWith('.json')).length, 2);
});

test('wait mode reports consumed when the endpoint agent removes the handoff file', async (t) => {
  const dir = tempDir(t);
  const handoffPath = path.join(dir, 'evt.json');
  fs.writeFileSync(handoffPath, '{}');
  setTimeout(() => fs.rmSync(handoffPath, { force: true }), 30);
  const result = await collector.waitForHandoffConsumption(handoffPath, {
    timeoutMs: 1000,
    pollMs: 10,
  });
  assert.deepStrictEqual(result, { consumed: true });
});

test('collector sanitizes missing-file failures and enforces invocation limits', async (t) => {
  const dir = tempDir(t);
  const missing = path.join(dir, 'member-524-71-9043.txt');
  const result = await collector.collectProtectedUploads({
    files: [missing],
    destination: 'Desktop AI',
  });

  assert.strictEqual(result.status, 'failed');
  assert.strictEqual(result.failed, 1);
  assert.strictEqual(result.results[0].error, 'file is not available');
  assert.ok(!JSON.stringify(result).includes('member-524-71-9043'));

  assert.throws(
    () => collector.normalizeFiles(Array.from({ length: collector.MAX_FILES_PER_INVOCATION + 1 }, (_, i) => `file-${i}.txt`)),
    /at most/,
  );
});

test('collector exits nonzero for failed or unconsumed handoff results', () => {
  assert.strictEqual(collector.exitCodeForResult({ status: 'written' }), 0);
  assert.strictEqual(collector.exitCodeForResult({ status: 'queued' }), 1);
  assert.strictEqual(collector.exitCodeForResult({ status: 'failed' }), 1);
});
