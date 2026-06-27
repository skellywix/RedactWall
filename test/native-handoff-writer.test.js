'use strict';
/** Native handoff writer should create signed, content-free upload intents. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const writer = require('../endpoint-agent/write-handoff');
const handoff = require('../endpoint-agent/native-handoff');

const SECRET = 'native-handoff-secret-000000000000000001';

function tempDir(t, prefix = 'ps-native-handoff-writer-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('writes signed native handoff files without reading file content into the event', (t) => {
  const dir = tempDir(t);
  const handoffDir = path.join(dir, 'handoff');
  const sourceFile = path.join(dir, 'loan-file.txt');
  fs.writeFileSync(sourceFile, 'Private upload body with SSN 524-71-9043.');

  const result = writer.writeHandoffFile({
    filePath: sourceFile,
    dir: handoffDir,
    secret: SECRET,
    id: 'evt/writer unit',
    now: new Date('2026-06-26T16:00:00.000Z'),
    destination: 'Desktop AI',
    destinationProcess: 'desktop-ai.exe',
    user: 'analyst@example.test',
    nonce: 'nonce-1',
  });

  assert.match(path.basename(result.path), /^evt_writer_unit\.json$/);
  const body = fs.readFileSync(result.path, 'utf8');
  assert.ok(!body.includes('Private upload body'));
  assert.ok(!body.includes('524-71-9043'));

  const validated = handoff.readHandoffFile(result.path, {
    secret: SECRET,
    now: new Date('2026-06-26T16:01:00.000Z'),
  });
  assert.strictEqual(validated.filePath, sourceFile);
  assert.strictEqual(validated.destination.app, 'Desktop AI');
  assert.strictEqual(validated.destination.process, 'desktop-ai.exe');
  assert.strictEqual(validated.user, 'analyst@example.test');
});

test('loads the handoff secret from endpoint config instead of argv', (t) => {
  const dir = tempDir(t);
  const envPath = path.join(dir, 'endpoint-agent.env');
  const sourceFile = path.join(dir, 'contract.txt');
  fs.writeFileSync(sourceFile, 'Contract file body should stay local.');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${path.join(dir, 'configured-handoff')}`,
  ].join('\n') + '\n');

  const previous = {
    ENDPOINT_AGENT_HANDOFF_SECRET: process.env.ENDPOINT_AGENT_HANDOFF_SECRET,
    ENDPOINT_AGENT_HANDOFF_DIR: process.env.ENDPOINT_AGENT_HANDOFF_DIR,
  };
  delete process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
  delete process.env.ENDPOINT_AGENT_HANDOFF_DIR;
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  const result = writer.writeHandoffFile({
    envPath,
    filePath: sourceFile,
    id: 'evt_env_writer',
    now: new Date('2026-06-26T16:10:00.000Z'),
    destination: 'Desktop AI',
  });

  assert.match(result.path, /configured-handoff/);
  assert.strictEqual(handoff.readHandoffFile(result.path, {
    secret: SECRET,
    now: new Date('2026-06-26T16:11:00.000Z'),
  }).id, 'evt_env_writer');
});

test('rejects unsafe writer arguments and non-file references', (t) => {
  const dir = tempDir(t);
  assert.throws(() => writer.parseArgs(['--secret', SECRET]), /Unknown option/);
  assert.throws(() => writer.writeHandoffFile({
    filePath: dir,
    dir: path.join(dir, 'handoff'),
    secret: SECRET,
    destination: 'Desktop AI',
  }), /must reference a file/);
  assert.throws(() => writer.writeHandoffFile({
    filePath: path.join(dir, 'missing.txt'),
    dir: path.join(dir, 'handoff'),
    secret: SECRET,
    destination: 'Desktop AI',
  }), /ENOENT|no such file/i);
});

test('refuses to overwrite an existing event id in the handoff spool', (t) => {
  const dir = tempDir(t);
  const sourceFile = path.join(dir, 'loan-file.txt');
  fs.writeFileSync(sourceFile, 'Local file body.');
  const opts = {
    filePath: sourceFile,
    dir: path.join(dir, 'handoff'),
    secret: SECRET,
    id: 'evt_duplicate',
    now: new Date('2026-06-26T16:20:00.000Z'),
    destination: 'Desktop AI',
  };
  writer.writeHandoffFile(opts);
  assert.throws(() => writer.writeHandoffFile(opts), /already exists/);
});
