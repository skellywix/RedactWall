'use strict';
/** Browser file-intent native messaging host: bounded intents in, signed
 *  content-free handoff events out, replies that never echo paths. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PassThrough } = require('node:stream');
const host = require('../sensors/endpoint-agent/native-messaging-host');
const handoff = require('../sensors/endpoint-agent/native-handoff');

const SECRET = 'native-intent-secret-0000000000000000001';

function tempDir(t, prefix = 'ps-native-intent-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function intent(over = {}) {
  return {
    type: 'upload_intent',
    fileName: 'member-report.pdf',
    sizeBytes: 42,
    destination: 'chatgpt.com',
    destinationUrl: 'https://chatgpt.com/',
    user: 'teller@example.test',
    ...over,
  };
}

test('normalizeIntent bounds fields, strips path components, and refuses payload keys', () => {
  const clean = host.normalizeIntent(intent({ fileName: '../../etc/secrets.pdf' }));
  assert.strictEqual(clean.fileName, 'secrets.pdf', 'only the basename is used for resolution');

  assert.throws(() => host.normalizeIntent(intent({ content: 'raw bytes' })), /not allowed/);
  assert.throws(() => host.normalizeIntent(intent({ prompt: 'text' })), /not allowed/);
  assert.throws(() => host.normalizeIntent(intent({ type: 'exfiltrate' })), /unsupported/);
  assert.throws(() => host.normalizeIntent(intent({ sizeBytes: 0 })), /sizeBytes/);
  assert.throws(() => host.normalizeIntent(intent({ sizeBytes: 1.5 })), /sizeBytes/);
  assert.throws(() => host.normalizeIntent(intent({ fileName: '..' })), /fileName/);
});

test('resolveIntentFile matches direct children by exact name and size only', (t) => {
  const root = tempDir(t);
  const nested = path.join(root, 'nested');
  fs.mkdirSync(nested);
  fs.writeFileSync(path.join(root, 'member-report.pdf'), 'x'.repeat(42));
  fs.writeFileSync(path.join(root, 'other.pdf'), 'x'.repeat(42));
  fs.writeFileSync(path.join(nested, 'member-report.pdf'), 'x'.repeat(42));

  const clean = host.normalizeIntent(intent());
  assert.deepStrictEqual(host.resolveIntentFile(clean, { roots: [root] }), [path.join(root, 'member-report.pdf')]);
  assert.deepStrictEqual(host.resolveIntentFile(host.normalizeIntent(intent({ sizeBytes: 41 })), { roots: [root] }), [], 'size mismatch is no match');
  assert.deepStrictEqual(host.resolveIntentFile(host.normalizeIntent(intent({ fileName: 'missing.pdf' })), { roots: [root] }), []);
  const both = host.resolveIntentFile(clean, { roots: [root, nested] });
  assert.strictEqual(both.length, 2, 'each root is checked, but never recursively');
});

test('intentSearchRoots honors the env override and defaults to home staging folders', () => {
  const custom = host.intentSearchRoots({ ENDPOINT_AGENT_INTENT_SEARCH_DIRS: ['/a', '/b'].join(path.delimiter) });
  assert.deepStrictEqual(custom, [path.resolve('/a'), path.resolve('/b')]);
  const defaults = host.intentSearchRoots({}, '/home/pat');
  assert.deepStrictEqual(defaults, [
    path.resolve('/home/pat/Downloads'),
    path.resolve('/home/pat/Desktop'),
    path.resolve('/home/pat/Documents'),
  ]);
});

test('handleIntentMessage writes a signed content-free handoff on exactly one match', (t) => {
  const root = tempDir(t);
  const spool = path.join(tempDir(t), 'spool');
  const file = path.join(root, 'member-report.pdf');
  fs.writeFileSync(file, 'Confidential member data SSN 524-71-9043 padding!!!'.slice(0, 42));

  const reply = host.handleIntentMessage(intent(), { roots: [root], dir: spool, secret: SECRET });
  assert.strictEqual(reply.ok, true);
  assert.strictEqual(reply.status, 'handoff_written');
  assert.strictEqual(reply.matches, 1);
  assert.ok(!JSON.stringify(reply).includes(root), 'reply never echoes local paths');

  const [eventFile] = fs.readdirSync(spool);
  const body = fs.readFileSync(path.join(spool, eventFile), 'utf8');
  assert.ok(!body.includes('524-71-9043'), 'handoff event carries no file content');
  const validated = handoff.readHandoffFile(path.join(spool, eventFile), { secret: SECRET });
  assert.strictEqual(validated.filePath, file);
  assert.strictEqual(validated.destination.app, 'chatgpt.com');
  assert.strictEqual(validated.destination.process, 'browser');
  assert.strictEqual(validated.user, 'teller@example.test');

  assert.deepStrictEqual(
    host.handleIntentMessage(intent({ fileName: 'missing.pdf' }), { roots: [root], dir: spool, secret: SECRET }),
    { ok: true, status: 'not_found', matches: 0 },
  );
  const second = tempDir(t);
  fs.writeFileSync(path.join(second, 'member-report.pdf'), 'x'.repeat(42));
  const ambiguous = host.handleIntentMessage(intent(), { roots: [root, second], dir: spool, secret: SECRET });
  assert.deepStrictEqual(ambiguous, { ok: true, status: 'ambiguous', matches: 2 });
  const rejected = host.handleIntentMessage(intent({ bytes: 'AAAA' }), { roots: [root], dir: spool, secret: SECRET });
  assert.strictEqual(rejected.ok, false);
  assert.match(rejected.error, /not allowed/);
});

test('frame codec round-trips, handles partial frames, and rejects oversized messages', () => {
  const one = host.encodeFrame({ a: 1 });
  const two = host.encodeFrame({ b: 2 });
  const joined = Buffer.concat([one, two]);
  const all = host.decodeFrames(joined);
  assert.deepStrictEqual(all.messages, [{ a: 1 }, { b: 2 }]);
  assert.strictEqual(all.rest.length, 0);

  const partial = host.decodeFrames(joined.subarray(0, one.length + 3));
  assert.deepStrictEqual(partial.messages, [{ a: 1 }]);
  assert.strictEqual(partial.rest.length, 3);

  const oversized = Buffer.alloc(4);
  oversized.writeUInt32LE(host.MAX_MESSAGE_BYTES + 1, 0);
  assert.throws(() => host.decodeFrames(oversized), /too large/);
});

test('run() answers each framed intent over stdout without leaking to the browser', async (t) => {
  const root = tempDir(t);
  const spool = path.join(tempDir(t), 'spool');
  fs.writeFileSync(path.join(root, 'member-report.pdf'), 'x'.repeat(42));

  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const done = host.run({ stdin, stdout, stderr, roots: [root], dir: spool, secret: SECRET });
  stdin.write(host.encodeFrame(intent()));
  stdin.write(host.encodeFrame(intent({ fileName: 'missing.pdf' })));
  stdin.end();
  const handled = await done;
  assert.strictEqual(handled, 2);

  const replies = host.decodeFrames(stdout.read() || Buffer.alloc(0)).messages;
  assert.strictEqual(replies.length, 2);
  assert.strictEqual(replies[0].status, 'handoff_written');
  assert.strictEqual(replies[1].status, 'not_found');
  assert.ok(!JSON.stringify(replies).includes(root));
});
