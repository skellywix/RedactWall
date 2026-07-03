'use strict';
/** Playwright runner should relocate when the health port is already occupied. */
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const {
  DEFAULT_START_PORT,
  findAvailablePort,
  parsePort,
  releasePortLock,
  reserveAvailablePort,
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
