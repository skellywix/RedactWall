'use strict';
/** Native handoff writer should create signed, content-free upload intents. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const writer = require('../sensors/endpoint-agent/write-handoff');
const handoff = require('../sensors/endpoint-agent/native-handoff');

const SECRET = 'native-handoff-secret-000000000000000001';

function tempDir(t, prefix = 'ps-native-handoff-writer-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(['log', message]); },
    error(message) { lines.push(['error', message]); },
  };
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
  const sourceFile = path.join(dir, 'loan-file.txt');
  fs.writeFileSync(sourceFile, 'Local file body.');

  assert.match(writer.usage(), /--destination-process/);
  assert.strictEqual(writer.parseArgs(['--help']).help, true);
  assert.deepStrictEqual(writer.parseArgs([
    '--file', sourceFile,
    '--destination', 'Desktop AI',
    '--destination-process', 'desktop-ai.exe',
    '--destination-url', 'https://desktop.example/upload',
    '--user', 'analyst@example.test',
    '--dir', path.join(dir, 'handoff'),
    '--env', path.join(dir, 'endpoint.env'),
    '--id', 'evt_args',
    '--nonce', 'nonce_args',
  ]), {
    filePath: sourceFile,
    destination: 'Desktop AI',
    destinationProcess: 'desktop-ai.exe',
    destinationUrl: 'https://desktop.example/upload',
    user: 'analyst@example.test',
    dir: path.join(dir, 'handoff'),
    envPath: path.join(dir, 'endpoint.env'),
    id: 'evt_args',
    nonce: 'nonce_args',
  });
  assert.throws(() => writer.parseArgs(['--file']), /requires a value/);
  assert.throws(() => writer.parseArgs(['unexpected']), /Unexpected argument/);
  assert.throws(() => writer.parseArgs(['--secret', SECRET]), /Unknown option/);
  assert.throws(() => writer.absoluteLocalFilePath(), /file path is required/);
  assert.throws(() => writer.absoluteLocalFilePath('\\\\server\\share\\loan-file.txt'), /must be a local path/);
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

test('writer helper defaults and env parse failures are explicit', (t) => {
  const dir = tempDir(t);
  const badEnv = path.join(dir, 'bad.env');
  fs.writeFileSync(badEnv, 'BROKEN LINE\n');
  const previous = {
    SENTINEL_ENV_PATH: process.env.SENTINEL_ENV_PATH,
    PROMPTWALL_ENV_PATH: process.env.PROMPTWALL_ENV_PATH,
  };
  delete process.env.SENTINEL_ENV_PATH;
  delete process.env.PROMPTWALL_ENV_PATH;
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  assert.deepStrictEqual(writer.loadEndpointEnv(), { loaded: false, path: null, keys: [], skipped: [], errors: [] });
  assert.throws(() => writer.loadEndpointEnv(badEnv), /parse error/);
  assert.deepStrictEqual(writer.destinationFromOptions(), { app: 'desktop-ai-app' });
  assert.deepStrictEqual(writer.destinationFromOptions({
    destination: 'Claude Desktop',
    destinationProcess: 'claude.exe',
    destinationUrl: 'https://claude.ai',
  }), {
    app: 'Claude Desktop',
    process: 'claude.exe',
    url: 'https://claude.ai',
  });
  assert.strictEqual(writer.safeEventFileName('evt:/bad id'), 'evt__bad_id');
  assert.match(writer.safeEventFileName(''), /^handoff-\d+$/);
});

test('writer CLI main prints help, success JSON, and sanitized failures', () => {
  const helpIo = captureConsole();
  assert.strictEqual(writer.main(['--help'], { console: helpIo }), 0);
  assert.ok(helpIo.lines.some(([, message]) => message.includes('Usage: node')));

  const okIo = captureConsole();
  assert.strictEqual(writer.main(['--file', 'loan.txt', '--destination', 'Desktop AI'], {
    console: okIo,
    writeHandoffFile(opts) {
      assert.strictEqual(opts.filePath, 'loan.txt');
      return {
        path: 'C:\\handoff\\evt_cli.json',
        event: {
          id: 'evt_cli',
          destination: { app: 'Desktop AI', process: 'desktop-ai.exe' },
        },
      };
    },
  }), 0);
  const body = JSON.parse(okIo.lines[0][1]);
  assert.strictEqual(body.status, 'written');
  assert.strictEqual(body.id, 'evt_cli');
  assert.strictEqual(body.destination, 'Desktop AI');

  const badIo = captureConsole();
  assert.strictEqual(writer.main(['--file'], { console: badIo }), 1);
  assert.ok(badIo.lines.some(([level, message]) => level === 'error' && /requires a value/.test(message)));
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

test('writer rejects oversized events and cleans up failed atomic writes', (t) => {
  const dir = tempDir(t);
  const sourceFile = path.join(dir, 'loan-file.txt');
  fs.writeFileSync(sourceFile, 'Local file body.');
  const originalMax = handoff.MAX_EVENT_BYTES;
  handoff.MAX_EVENT_BYTES = 10;
  try {
    assert.throws(() => writer.writeHandoffFile({
      filePath: sourceFile,
      dir: path.join(dir, 'handoff'),
      secret: SECRET,
      id: 'evt_too_large',
      destination: 'Desktop AI',
    }), /too large/);
  } finally {
    handoff.MAX_EVENT_BYTES = originalMax;
  }

  const atomicDir = path.join(dir, 'atomic');
  fs.mkdirSync(atomicDir);
  const target = path.join(atomicDir, 'atomic.json');
  const originalRename = fs.renameSync;
  fs.renameSync = () => {
    throw new Error('rename denied');
  };
  try {
    assert.throws(
      () => writer._internal.writeAtomicJson(target, '{"ok":true}\n'),
      /rename denied/,
    );
  } finally {
    fs.renameSync = originalRename;
  }
  assert.deepStrictEqual(fs.readdirSync(atomicDir), []);
  assert.deepStrictEqual(fs.readdirSync(path.join(dir, 'handoff')), []);
});
