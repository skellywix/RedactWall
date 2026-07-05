'use strict';
/** Playwright runner should relocate when the health port is already occupied. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const {
  DEFAULT_START_PORT,
  findAvailablePort,
  main,
  parsePort,
  releasePortLock,
  reserveAvailablePort,
  _internal,
} = require('../scripts/run-playwright');

function listen(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port }, () => resolve(server));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

test('parsePort accepts valid ports and rejects unsafe values', () => {
  assert.strictEqual(parsePort(String(DEFAULT_START_PORT)), DEFAULT_START_PORT);
  assert.strictEqual(parsePort('0'), null);
  assert.strictEqual(parsePort('65536'), null);
  assert.strictEqual(parsePort('not-a-port'), null);
});

test('findAvailablePort skips an occupied starting port', async (t) => {
  const blocker = await listen(0);
  t.after(() => close(blocker));
  const { port } = blocker.address();

  const available = await findAvailablePort(port);
  assert.notStrictEqual(available, port);
  assert.ok(available > port);

  const probe = await listen(available);
  t.after(() => close(probe));
});

test('reserveAvailablePort skips a live runner reservation', async (t) => {
  const first = await reserveAvailablePort(DEFAULT_START_PORT);
  t.after(() => releasePortLock(first));

  const second = await reserveAvailablePort(first.port);
  t.after(() => releasePortLock(second));

  assert.notStrictEqual(second.port, first.port);
  assert.ok(second.port > first.port);
});

test('port lock helpers recover stale owners and preserve live owners', () => {
  const lockDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-playwright-locks-'));
  try {
    assert.doesNotThrow(() => releasePortLock(null));
    assert.doesNotThrow(() => releasePortLock({ released: true }));

    const stalePath = path.join(lockDir, '4510.lock');
    fs.writeFileSync(stalePath, '{not-json');
    const recovered = _internal.acquirePortLock(4510, {
      lockDir,
      isProcessAlive: () => false,
    });
    assert.strictEqual(recovered.port, 4510);
    releasePortLock(recovered);

    fs.writeFileSync(path.join(lockDir, '4511.lock'), JSON.stringify({ pid: 12345 }));
    const live = _internal.acquirePortLock(4511, {
      lockDir,
      isProcessAlive: () => true,
    });
    assert.strictEqual(live, null);

    const staleButStuck = _internal.acquirePortLock(4512, {
      lockDir,
      mkdirSync() {},
      openSync() {
        const err = new Error('exists');
        err.code = 'EEXIST';
        throw err;
      },
      readLockOwner: () => ({ pid: 98765 }),
      isProcessAlive: () => false,
      rmSync() {},
    });
    assert.strictEqual(staleButStuck, null);

    assert.strictEqual(_internal.readLockOwner(path.join(lockDir, 'missing.lock')), null);
  } finally {
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
});

test('process liveness treats EPERM as alive and ESRCH as dead', () => {
  assert.strictEqual(_internal.isProcessAlive(123, {
    kill() {
      const err = new Error('permission denied');
      err.code = 'EPERM';
      throw err;
    },
  }), true);
  assert.strictEqual(_internal.isProcessAlive(123, {
    kill() {
      const err = new Error('not found');
      err.code = 'ESRCH';
      throw err;
    },
  }), false);
});

test('port discovery reports exhausted probes and releases failed reservations', async () => {
  await assert.rejects(
    () => findAvailablePort(65535, {
      maxPortProbes: 2,
      canBind: async () => false,
    }),
    /No available Playwright port/
  );

  const lock = fakeLock(65535);
  await assert.rejects(
    () => reserveAvailablePort(65535, {
      maxPortProbes: 2,
      acquirePortLock: () => lock,
      canBind: async () => false,
    }),
    /No available Playwright port/
  );
  assert.strictEqual(lock.released, true);
});

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(['log', message]); },
    warn(message) { lines.push(['warn', message]); },
    error(message) { lines.push(['error', message]); },
  };
}

function fakeLock(port) {
  return { fd: -1, lockPath: `missing-${port}.lock`, port, released: false };
}

test('main passes the reserved port and argv to the Playwright CLI', async () => {
  const io = captureConsole();
  const lock = fakeLock(4300);
  const exits = [];
  const child = new EventEmitter();
  let spawnCall;

  const pending = main(['e2e/admin-console.spec.js'], {
    env: { PLAYWRIGHT_PORT: '4300', KEEP: 'yes' },
    console: io,
    process: { env: {}, execPath: 'node-test', once() {}, exit(code) { exits.push(code); } },
    onExit() {},
    reserveAvailablePort: async (startPort) => {
      assert.strictEqual(startPort, 4300);
      return lock;
    },
    resolveCli: () => 'playwright-cli.js',
    spawn: (cmd, args, options) => {
      spawnCall = { cmd, args, options };
      return child;
    },
    exit(code) { exits.push(code); },
  });
  await Promise.resolve();
  child.emit('exit', 0, null);
  const code = await pending;

  assert.strictEqual(code, 0);
  assert.deepStrictEqual(exits, [0]);
  assert.strictEqual(lock.released, true);
  assert.deepStrictEqual(spawnCall.args, ['playwright-cli.js', 'test', 'e2e/admin-console.spec.js']);
  assert.strictEqual(spawnCall.options.env.PLAYWRIGHT_PORT, '4300');
  assert.strictEqual(spawnCall.options.env.KEEP, 'yes');
  assert.strictEqual(spawnCall.options.windowsHide, true);
  assert.deepStrictEqual(io.lines, [['log', '[playwright] using port 4300']]);
});

test('main warns when it relocates from a busy requested port', async () => {
  const io = captureConsole();
  const child = new EventEmitter();
  const pending = main([], {
    env: { PLAYWRIGHT_PORT: '4300' },
    console: io,
    process: { env: {}, execPath: 'node-test', once() {}, exit() {} },
    onExit() {},
    reserveAvailablePort: async () => fakeLock(4301),
    resolveCli: () => 'playwright-cli.js',
    spawn: () => child,
    exit() {},
  });
  await Promise.resolve();
  child.emit('exit', 2, null);

  assert.strictEqual(await pending, 2);
  assert.deepStrictEqual(io.lines, [['warn', '[playwright] port 4300 is busy; using 4301']]);
});

test('main maps child errors, signals, and null exit codes to failures', async () => {
  for (const scenario of [
    { event: 'error', args: [new Error('spawn failed')], message: /spawn failed/ },
    { event: 'exit', args: [null, 'SIGTERM'], message: /SIGTERM/ },
    { event: 'exit', args: [null, null], message: null },
  ]) {
    const io = captureConsole();
    const exits = [];
    const child = new EventEmitter();
    const pending = main([], {
      env: {},
      console: io,
      process: { env: {}, execPath: 'node-test', once() {}, exit(code) { exits.push(code); } },
      onExit() {},
      reserveAvailablePort: async () => fakeLock(4302),
      resolveCli: () => 'playwright-cli.js',
      spawn: () => child,
      exit(code) { exits.push(code); },
    });
    await Promise.resolve();
    child.emit(scenario.event, ...scenario.args);

    assert.strictEqual(await pending, 1);
    assert.deepStrictEqual(exits, [1]);
    if (scenario.message) assert.ok(io.lines.some(([level, message]) => level === 'error' && scenario.message.test(message)));
  }
});
