'use strict';
/**
 * Regression: a pending (hold) verdict can poll for release far longer than the
 * socket's idle timeout. The idle timeout must NOT destroy the connection while
 * a message is being handled, otherwise the synthesized allow/block response is
 * never delivered and Squid fails open. Fails before the fix (socket destroyed
 * at socketTimeoutMs), passes after (timeout disarmed while busy).
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const { createIcapServer } = require('../scripts/squid-icap-bridge');

// Control plane: gate holds the prompt, and the release status resolves only
// after a delay LONGER than the ICAP socket idle timeout below.
function startHoldingControlPlane(statusDelayMs) {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/v1/gate') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id: 'q_hold', decision: 'block', status: 'pending', releaseToken: 'rt_hold' }));
      });
      return;
    }
    if (req.url.startsWith('/api/v1/status/')) {
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'allowed' }));
      }, statusDelayMs);
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

function reqmodMessage(prompt) {
  const httpBody = JSON.stringify({ prompt });
  const httpReq = [
    'POST https://chatgpt.com/backend-api/conversation HTTP/1.1',
    'Host: chatgpt.com',
    'Content-Type: application/json',
    `Content-Length: ${Buffer.byteLength(httpBody)}`,
    '', '',
  ].join('\r\n');
  const chunked = `${Buffer.byteLength(httpBody).toString(16)}\r\n${httpBody}\r\n0\r\n\r\n`;
  const head = [
    'REQMOD icap://127.0.0.1/reqmod ICAP/1.0',
    'Host: 127.0.0.1',
    'Allow: 204',
    `Encapsulated: req-hdr=0, req-body=${Buffer.byteLength(httpReq)}`,
    '', '',
  ].join('\r\n');
  return head + httpReq + chunked;
}

function icapExchange(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(payload));
    let data = '';
    const done = () => { socket.destroy(); resolve(data); };
    socket.on('data', (chunk) => {
      data += chunk.toString('latin1');
      if (data.includes('\r\n\r\n')) done();
    });
    socket.on('close', () => resolve(data));
    socket.on('error', reject);
  });
}

test('hold verdict held past the idle timeout still delivers a release response', async (t) => {
  const socketTimeoutMs = 1000; // idle timeout floor is 1000ms
  const statusDelayMs = 1800;   // release resolves only AFTER the idle timeout
  const cp = await startHoldingControlPlane(statusDelayMs);
  const server = createIcapServer({
    key: 'test-key',
    io: { stdout: { write() {} } },
    redactwall: cp.url,
    socketTimeoutMs,
    releaseWaitMs: 10000,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  t.after(() => { server.close(); server.destroyConnections(); cp.server.close(); });

  const res = await icapExchange(port, reqmodMessage('HOLDME please review'));
  // Before the fix the socket is destroyed at socketTimeoutMs and res is empty.
  assert.match(res, /^ICAP\/1\.0 204 No Content\r\n/, `expected a release 204, got: ${JSON.stringify(res.slice(0, 60))}`);
});
