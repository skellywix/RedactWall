'use strict';
const http = require('node:http');
const net = require('node:net');

const DEFAULT_LOOPBACK_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_LOOPBACK_FETCH_ATTEMPTS = 120;
const DEFAULT_LOOPBACK_LISTEN_TIMEOUT_MS = 5000;

function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function responseHeaders(raw = {}) {
  return {
    get(name) {
      const value = raw[String(name || '').toLowerCase()];
      if (Array.isArray(value)) return value.join(', ');
      return value == null ? null : String(value);
    },
  };
}

function normalizeHeaders(headers = {}) {
  if (headers && typeof headers.forEach === 'function') {
    const result = {};
    headers.forEach((value, key) => { result[key] = value; });
    return result;
  }
  return { ...(headers || {}) };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retriableLoopbackError(err) {
  return err && ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT'].includes(err.code);
}

function loopbackHttpFetchOnce(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    let connected = false;
    const req = http.request({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method: opts.method || 'GET',
      headers: normalizeHeaders(opts.headers),
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          headers: responseHeaders(res.headers),
          text: async () => body.toString('utf8'),
          json: async () => JSON.parse(body.toString('utf8')),
          arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
        });
      });
    });
    req.once('socket', (socket) => {
      if (socket.connecting) {
        socket.once('connect', () => {
          connected = true;
          req.setTimeout(0);
        });
      } else {
        connected = true;
        req.setTimeout(0);
      }
    });
    req.setTimeout(Number(process.env.REDACTWALL_LOOPBACK_FETCH_TIMEOUT_MS || DEFAULT_LOOPBACK_FETCH_TIMEOUT_MS), () => {
      if (connected) return;
      const err = new Error(`loopback fetch connect timed out on ${target.host}`);
      err.code = 'ETIMEDOUT';
      req.destroy(err);
    });
    req.once('error', reject);
    if (opts.signal) {
      opts.signal.addEventListener('abort', () => req.destroy(new Error('aborted')), { once: true });
    }
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

async function loopbackHttpFetch(url, opts = {}) {
  let lastError;
  const attempts = positiveNumber(process.env.REDACTWALL_LOOPBACK_FETCH_ATTEMPTS, DEFAULT_LOOPBACK_FETCH_ATTEMPTS);
  for (let i = 0; i < attempts; i += 1) {
    try {
      return await loopbackHttpFetchOnce(url, opts);
    } catch (err) {
      lastError = err;
      if (opts.signal && opts.signal.aborted) throw err;
      if (!retriableLoopbackError(err)) throw err;
      await delay(Math.min(250, 25 * (i + 1)));
    }
  }
  throw lastError;
}

function isLoopbackHttp(url) {
  try {
    const target = new URL(url);
    return target.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(target.hostname);
  } catch {
    return false;
  }
}

function installLoopbackFetch() {
  if (global.fetch && global.fetch.__redactWallLoopbackFetch) return;
  const originalFetch = global.fetch;
  // Windows can intermittently time out through built-in fetch for loopback test ports.
  const loopbackFetch = async (url, opts = {}) => {
    if (isLoopbackHttp(url)) return loopbackHttpFetch(url, opts);
    if (typeof originalFetch !== 'function') throw new Error('fetch is not available');
    return originalFetch(url, opts);
  };
  loopbackFetch.__redactWallLoopbackFetch = true;
  loopbackFetch.__redactWallOriginalFetch = originalFetch;
  global.fetch = loopbackFetch;
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

function hardenServer(server) {
  if (server.__redactWallHardened) return server;
  const sockets = new Set();
  server.keepAliveTimeout = 1;
  server.headersTimeout = 2000;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  const originalClose = server.close.bind(server);
  server.close = (callback) => {
    for (const socket of sockets) socket.destroy();
    return originalClose(callback);
  };
  Object.defineProperty(server, '__redactWallHardened', { value: true });
  return server;
}

function startServer(appUnderTest, host, port) {
  return new Promise((resolve, reject) => {
    const server = hardenServer(appUnderTest.listen(port, host, () => resolve(server)));
    server.once('error', reject);
  });
}

function startNetServer(server, host, port) {
  return new Promise((resolve, reject) => {
    const hardened = hardenServer(server);
    const cleanup = () => {
      hardened.off('error', onError);
      hardened.off('listening', onListening);
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const onListening = () => {
      cleanup();
      resolve(hardened);
    };
    hardened.once('error', onError);
    hardened.once('listening', onListening);
    hardened.listen({ host, port, exclusive: true });
  });
}

function probePort(port, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ port, host });
    const done = (err) => {
      socket.removeAllListeners();
      socket.destroy();
      if (err) reject(err);
      else resolve();
    };
    socket.setTimeout(timeoutMs, () => done(new Error(`loopback probe timed out on ${host}:${port}`)));
    socket.once('connect', () => done());
    socket.once('error', done);
  });
}

function probeHttp(port, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = http.get({
      host,
      port,
      path: '/healthz',
      timeout: timeoutMs,
      headers: { Connection: 'close' },
    }, (res) => {
      res.resume();
      res.once('end', resolve);
    });
    req.once('timeout', () => req.destroy(new Error(`loopback http probe timed out on ${host}:${port}`)));
    req.once('error', reject);
  });
}

async function listen(appUnderTest, opts = {}) {
  installLoopbackFetch();
  const host = opts.host || '127.0.0.1';
  const attempts = opts.attempts || 8;
  const timeoutMs = positiveNumber(
    opts.timeoutMs,
    positiveNumber(process.env.REDACTWALL_LOOPBACK_LISTEN_TIMEOUT_MS, DEFAULT_LOOPBACK_LISTEN_TIMEOUT_MS),
  );
  let lastError;
  for (let i = 0; i < attempts; i += 1) {
    let server;
    try {
      server = await startServer(appUnderTest, host, opts.port == null ? 0 : Number(opts.port));
      await probePort(server.address().port, host, timeoutMs);
      if (opts.httpProbe !== false) {
        await probeHttp(server.address().port, host, timeoutMs);
      }
      return server;
    } catch (err) {
      lastError = err;
      if (server) await closeServer(server);
    }
  }
  throw lastError || new Error('failed to bind loopback test server');
}

async function listenNet(server, opts = {}) {
  const host = opts.host || '127.0.0.1';
  const attempts = opts.attempts || 8;
  const timeoutMs = positiveNumber(
    opts.timeoutMs,
    positiveNumber(process.env.REDACTWALL_LOOPBACK_LISTEN_TIMEOUT_MS, DEFAULT_LOOPBACK_LISTEN_TIMEOUT_MS),
  );
  let lastError;
  for (let i = 0; i < attempts; i += 1) {
    try {
      await startNetServer(server, host, opts.port == null ? 0 : Number(opts.port));
      await probePort(server.address().port, host, timeoutMs);
      return server;
    } catch (err) {
      lastError = err;
      await closeServer(server).catch(() => {});
    }
  }
  throw lastError || new Error('failed to bind loopback test server');
}

module.exports = { listen, listenNet, loopbackHttpFetch };
