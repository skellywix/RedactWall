'use strict';
/** Desktop protected-upload collector writes metadata-only native handoff events. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const collector = require('../sensors/endpoint-agent/collectors/protected-upload');
const handoff = require('../sensors/endpoint-agent/native-handoff');

const SECRET = 'native-handoff-secret-000000000000000001';
const POLICY_KEYS = crypto.generateKeyPairSync('ed25519');
const POLICY_PUBLIC_KEY = POLICY_KEYS.publicKey.export({ type: 'spki', format: 'pem' }).toString();

function signedPolicyBundle(policy) {
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  const input = JSON.stringify({ version: 1, issuedAt, expiresAt, policyHash });
  return { version: 1, issuedAt, expiresAt, policy, signature: crypto.sign(null, Buffer.from(input), POLICY_KEYS.privateKey).toString('base64') };
}

function tempDir(t, prefix = 'ps-desktop-collector-') {
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

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function withCleanHandoffEnv(t) {
  const keys = [
    'REDACTWALL_ENV_PATH',
    'PROMPTWALL_ENV_PATH',
    'SENTINEL_ENV_PATH',
    'ENDPOINT_AGENT_HANDOFF_SECRET',
    'ENDPOINT_AGENT_HANDOFF_DIR',
    'ENDPOINT_AGENT_DESKTOP_DESTINATION',
    'REDACTWALL_DESKTOP_DESTINATION',
    'REDACTWALL_URL',
    'PROMPTWALL_URL',
    'SENTINEL_URL',
    'INGEST_API_KEY',
    'REDACTWALL_INGEST_API_KEY',
    'REDACTWALL_REQUEST_TIMEOUT_MS',
    'REDACTWALL_ALLOW_INSECURE_SERVER',
  ];
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
    '--destination-process', 'desktop-ai.exe',
    '--destination-url', 'https://desktop.example/upload',
    '--user', 'analyst@example.test',
    '--env', 'endpoint.env',
    '--timeout-ms', 'not-a-number',
    '--poll-ms', '25',
    '--wait',
    '--json',
    '--quiet',
  ]);
  assert.deepStrictEqual(parsed.files, ['a.txt', 'b.txt']);
  assert.strictEqual(parsed.destination, 'Desktop AI');
  assert.strictEqual(parsed.destinationProcess, 'desktop-ai.exe');
  assert.strictEqual(parsed.destinationUrl, 'https://desktop.example/upload');
  assert.strictEqual(parsed.user, 'analyst@example.test');
  assert.strictEqual(parsed.envPath, 'endpoint.env');
  assert.strictEqual(parsed.timeoutMs, 30000);
  assert.strictEqual(parsed.pollMs, 50);
  assert.strictEqual(parsed.wait, true);
  assert.strictEqual(parsed.json, true);
  assert.strictEqual(parsed.quiet, true);
  assert.match(collector.usage(), /--destination-process/);
  assert.strictEqual(collector.parseArgs(['--help']).help, true);
  assert.deepStrictEqual(collector.parseArgs(['--file']).files, ['']);
  assert.throws(() => collector.parseArgs(['--destination']), /requires a value/);
  assert.throws(() => collector.parseArgs(['--secret', SECRET]), /Unknown option/);
  assert.throws(() => collector.parseArgs(['unexpected']), /Unexpected argument/);
});

test('collector resolves desktop destination from control-plane policy', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${path.join(dir, 'handoff')}`,
    'REDACTWALL_URL=https://redactwall.unit.test',
    'INGEST_API_KEY=policy-key',
  ].join('\n') + '\n');

  let request;
  const destination = await collector.resolveDestination({
    envPath,
    policyPublicKey: POLICY_PUBLIC_KEY,
    policyCachePath: path.join(dir, 'policy-cache', 'bundle.json'),
    fetchImpl: async (url, opts) => {
      request = { url, headers: opts.headers, redirect: opts.redirect };
      return jsonResponse(200, signedPolicyBundle({ desktopCollectorDestination: 'Copilot Desktop' }));
    },
  });

  assert.strictEqual(destination, 'Copilot Desktop');
  assert.strictEqual(request.url, 'https://redactwall.unit.test/api/v1/policy/bundle');
  assert.strictEqual(request.headers['x-api-key'], 'policy-key');
  assert.strictEqual(request.redirect, 'error');
});

test('explicit collector destination overrides policy and local fallback', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${path.join(dir, 'handoff')}`,
    'REDACTWALL_URL=https://redactwall.unit.test',
    'INGEST_API_KEY=policy-key',
    'ENDPOINT_AGENT_DESKTOP_DESTINATION=Local Fallback',
  ].join('\n') + '\n');

  const destination = await collector.resolveDestination({
    envPath,
    destination: 'Explicit Desktop',
    fetchImpl: async () => {
      throw new Error('policy should not be fetched for explicit destinations');
    },
  });

  assert.strictEqual(destination, 'Explicit Desktop');
});

test('collector destination falls back through env and handles policy fetch misses', async (t) => {
  withCleanHandoffEnv(t);
  process.env.ENDPOINT_AGENT_DESKTOP_DESTINATION = 'Env Desktop';
  process.env.REDACTWALL_URL = 'https://redactwall.unit.test/';
  process.env.INGEST_API_KEY = 'policy-key';

  assert.strictEqual(collector.configuredServer(), 'https://redactwall.unit.test/');
  assert.strictEqual(collector.configuredKey(), 'policy-key');
  assert.strictEqual(await collector.fetchPolicyDestination({
    fetchImpl: async () => jsonResponse(503, { desktopCollectorDestination: 'Ignored' }),
  }), '');
  assert.strictEqual(await collector.fetchPolicyDestination({
    fetchImpl: async () => { throw new Error('network down'); },
  }), '');
  assert.strictEqual(await collector.resolveDestination({
    fetchImpl: async () => jsonResponse(200, { desktopCollectorDestination: '' }),
  }), 'Env Desktop');

  delete process.env.ENDPOINT_AGENT_DESKTOP_DESTINATION;
  assert.strictEqual(await collector.fetchPolicyDestination({ fetchImpl: null }), '');
});

test('collector rejects cleartext remote policy URLs and bounds policy bodies', async (t) => {
  withCleanHandoffEnv(t);
  let calls = 0;
  assert.strictEqual(await collector.fetchPolicyDestination({
    server: 'http://redactwall.unit.test',
    key: 'policy-key',
    fetchImpl: async () => { calls += 1; },
  }), '');
  assert.strictEqual(calls, 0);

  let cancelled = 0;
  const stalled = new Response(new ReadableStream({
    cancel() { cancelled += 1; },
  }), { status: 200, headers: { 'content-type': 'application/json' } });
  assert.strictEqual(await collector.fetchPolicyDestination({
    server: 'https://redactwall.unit.test',
    key: 'policy-key',
    policyTimeoutMs: 10,
    fetchImpl: async () => stalled,
  }), '');
  assert.strictEqual(cancelled, 1);

  assert.strictEqual(await collector.fetchPolicyDestination({
    server: 'https://redactwall.unit.test',
    key: 'policy-key',
    fetchImpl: async () => jsonResponse(200, { padding: 'x'.repeat(600 * 1024) }),
  }), '');
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

test('wait mode does not treat queue-file disappearance as terminal success', async (t) => {
  const dir = tempDir(t);
  const handoffPath = path.join(dir, 'evt.json');
  fs.writeFileSync(handoffPath, '{}');
  setTimeout(() => fs.rmSync(handoffPath, { force: true }), 30);
  const result = await collector.waitForHandoffConsumption(handoffPath, {
    timeoutMs: 1000,
    pollMs: 10,
  });
  assert.deepStrictEqual(result, { consumed: false, reason: 'handoff_missing_without_terminal_result' });
});

test('protected upload wait mode reports consumed public results', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const handoffDir = path.join(dir, 'handoff');
  const envPath = path.join(dir, 'endpoint-agent.env');
  const sourceFile = path.join(dir, 'member-upload.txt');
  fs.writeFileSync(sourceFile, 'Local file body.');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${handoffDir}`,
  ].join('\n') + '\n');

  const expectedHandoff = path.join(handoffDir, 'evt_wait_consumed.json');
  setTimeout(async () => {
    const event = handoff.readHandoffFile(expectedHandoff, {
      secret: SECRET,
      now: new Date('2026-06-27T20:15:00.000Z'),
    });
    await handoff.withHandoffClaim(event, expectedHandoff, async () => ({
      id: 'q_wait_consumed', decision: 'allow', status: 'allowed',
    }), { secret: SECRET });
    fs.rmSync(expectedHandoff, { force: true });
  }, 30);
  const result = await collector.collectProtectedUploads({
    files: [sourceFile],
    envPath,
    destination: 'Desktop AI',
    id: 'evt_wait_consumed',
    nonce: 'collector-nonce',
    now: new Date('2026-06-27T20:15:00.000Z'),
    wait: true,
    timeoutMs: 15000,
    pollMs: 50,
  });

  assert.strictEqual(result.status, 'written');
  assert.deepStrictEqual(result.results, [{
    status: 'written',
    id: 'evt_wait_consumed',
    destination: 'Desktop AI',
    consumed: true,
    decision: 'allow',
    terminalStatus: 'allowed',
  }]);
});

test('protected upload wait mode fails when terminal inspection is unavailable', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const handoffDir = path.join(dir, 'handoff');
  const envPath = path.join(dir, 'endpoint-agent.env');
  const sourceFile = path.join(dir, 'member-upload.txt');
  fs.writeFileSync(sourceFile, 'Local file body.');
  fs.writeFileSync(envPath, [
    `ENDPOINT_AGENT_HANDOFF_SECRET=${SECRET}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${handoffDir}`,
  ].join('\n') + '\n');
  const expectedHandoff = path.join(handoffDir, 'evt_wait_blocked.json');
  setTimeout(async () => {
    const event = handoff.readHandoffFile(expectedHandoff, {
      secret: SECRET,
      now: new Date('2026-06-27T20:16:00.000Z'),
    });
    await handoff.withHandoffClaim(event, expectedHandoff, async () => ({
      decision: 'block', status: 'file_missing_or_unreadable',
    }), { secret: SECRET });
    fs.rmSync(expectedHandoff, { force: true });
  }, 30);

  const result = await collector.collectProtectedUploads({
    files: [sourceFile],
    envPath,
    destination: 'Desktop AI',
    id: 'evt_wait_blocked',
    nonce: 'collector-blocked-nonce',
    now: new Date('2026-06-27T20:16:00.000Z'),
    wait: true,
    timeoutMs: 15000,
    pollMs: 50,
  });

  assert.strictEqual(result.status, 'failed');
  assert.strictEqual(result.failed, 1);
  assert.strictEqual(result.results[0].decision, 'block');
  assert.strictEqual(result.results[0].terminalStatus, 'file_missing_or_unreadable');
  assert.strictEqual(collector.exitCodeForResult(result), 1);
});

test('wait mode reports queued when the handoff is not consumed before timeout', async (t) => {
  const dir = tempDir(t);
  const handoffPath = path.join(dir, 'evt.json');
  fs.writeFileSync(handoffPath, '{}');

  const result = await collector.waitForHandoffConsumption(handoffPath, {
    timeoutMs: 1000,
    pollMs: 50,
  });

  assert.deepStrictEqual(result, { consumed: false, reason: 'handoff_not_consumed_before_timeout' });
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
  assert.throws(() => collector.normalizeFiles([' ', '']), /at least one --file/);
});

test('collector returns one sanitized failure per file when destination setup fails', async (t) => {
  withCleanHandoffEnv(t);
  const dir = tempDir(t);
  const first = path.join(dir, 'first.txt');
  const second = path.join(dir, 'second.txt');
  const badEnv = path.join(dir, 'bad.env');
  fs.writeFileSync(first, 'First local body');
  fs.writeFileSync(second, 'Second local body');
  fs.writeFileSync(badEnv, 'BROKEN LINE\n');

  const result = await collector.collectProtectedUploads({
    files: [first, second],
    envPath: badEnv,
  });

  assert.strictEqual(result.status, 'failed');
  assert.strictEqual(result.count, 2);
  assert.strictEqual(result.failed, 2);
  assert.deepStrictEqual(result.results, [
    { status: 'failed', error: 'endpoint env has 1 parse error(s)' },
    { status: 'failed', error: 'endpoint env has 1 parse error(s)' },
  ]);
});

test('collector public errors and human output are bounded', () => {
  assert.strictEqual(collector.publicError(new Error('ENOENT secret-file.txt')), 'file is not available');
  assert.strictEqual(collector.publicError(new Error('EACCES secret-file.txt')), 'file cannot be accessed');
  assert.strictEqual(collector.publicError(new Error('native handoff secret is not configured')), 'native handoff secret is not configured');
  assert.strictEqual(collector.publicError(new Error('unexpected private failure detail')), 'protected upload failed');

  const io = captureConsole();
  collector.printHuman({
    status: 'failed',
    count: 2,
    failed: 1,
    results: [
      { status: 'failed', error: 'file is not available' },
      { status: 'written', id: 'evt_1', destination: 'Desktop AI', consumed: true },
    ],
  }, io);

  assert.deepStrictEqual(io.lines.map(([, message]) => message), [
    'RedactWall protected upload failed: 2 file(s), 1 failed',
    '  - failed: file is not available',
    '  - written: evt_1 -> Desktop AI (inspection complete)',
  ]);
});

test('collector main prints help, JSON, human output, quiet output, and sanitized errors', async () => {
  const helpIo = captureConsole();
  assert.strictEqual(await collector.main(['--help'], { console: helpIo }), 0);
  assert.ok(helpIo.lines.some(([, message]) => message.includes('Usage: node')));

  const result = {
    status: 'written',
    count: 1,
    failed: 0,
    results: [{ status: 'written', id: 'evt_json', destination: 'Desktop AI', consumed: false }],
  };
  const jsonIo = captureConsole();
  assert.strictEqual(await collector.main(['--json'], {
    console: jsonIo,
    collectProtectedUploads: async () => result,
  }), 0);
  assert.deepStrictEqual(JSON.parse(jsonIo.lines[0][1]), result);

  const humanIo = captureConsole();
  assert.strictEqual(await collector.main([], {
    console: humanIo,
    collectProtectedUploads: async () => ({ ...result, status: 'queued' }),
  }), 1);
  assert.strictEqual(humanIo.lines[0][1], 'RedactWall protected upload queued: 1 file(s)');

  const quietIo = captureConsole();
  assert.strictEqual(await collector.main(['--quiet'], {
    console: quietIo,
    collectProtectedUploads: async () => result,
  }), 0);
  assert.deepStrictEqual(quietIo.lines, []);

  const errIo = captureConsole();
  assert.strictEqual(await collector.main(['--destination'], { console: errIo }), 1);
  assert.ok(errIo.lines.some(([level, message]) => level === 'error' && /requires a value/.test(message)));
});

test('collector exits nonzero for failed or unconsumed handoff results', () => {
  assert.strictEqual(collector.exitCodeForResult({ status: 'written' }), 0);
  assert.strictEqual(collector.exitCodeForResult({ status: 'queued' }), 1);
  assert.strictEqual(collector.exitCodeForResult({ status: 'failed' }), 1);
});
