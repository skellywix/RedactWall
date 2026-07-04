'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_START_PORT = 4211;
const MAX_PORT_PROBES = 50;
const LOCK_DIR = path.join(os.tmpdir(), 'promptwall-playwright-ports');

function isProcessAlive(pid, deps = {}) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  const kill = deps.kill || process.kill;
  try {
    kill(pid, 0);
    return true;
  } catch (err) {
    return err && err.code === 'EPERM';
  }
}

function readLockOwner(lockPath) {
  try {
    return JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function acquirePortLock(port, deps = {}) {
  const lockDir = deps.lockDir || LOCK_DIR;
  const alive = deps.isProcessAlive || isProcessAlive;
  const mkdirSync = deps.mkdirSync || fs.mkdirSync;
  const openSync = deps.openSync || fs.openSync;
  const writeFileSync = deps.writeFileSync || fs.writeFileSync;
  const remove = deps.rmSync || fs.rmSync;
  const readOwner = deps.readLockOwner || readLockOwner;
  mkdirSync(lockDir, { recursive: true });
  const lockPath = path.join(lockDir, `${port}.lock`);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = openSync(lockPath, 'wx');
      writeFileSync(fd, JSON.stringify({
        pid: process.pid,
        port,
        createdAt: new Date().toISOString(),
      }));
      return { fd, lockPath, port, released: false };
    } catch (err) {
      if (!err || err.code !== 'EEXIST') throw err;
      const owner = readOwner(lockPath);
      if (!alive(Number(owner && owner.pid))) {
        try { remove(lockPath, { force: true }); } catch (_) {}
        continue;
      }
      return null;
    }
  }
  return null;
}

function releasePortLock(lock) {
  if (!lock || lock.released) return;
  lock.released = true;
  try { fs.closeSync(lock.fd); } catch (_) {}
  try { fs.rmSync(lock.lockPath, { force: true }); } catch (_) {}
}

function parsePort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function canBind(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
      server.close(() => resolve(true));
    });
  });
}

async function findAvailablePort(startPort, deps = {}) {
  const probe = deps.canBind || canBind;
  const maxPortProbes = deps.maxPortProbes || MAX_PORT_PROBES;
  for (let offset = 0; offset < maxPortProbes; offset += 1) {
    const port = startPort + offset;
    if (port > 65535) break;
    if (await probe(port)) return port;
  }
  throw new Error(`No available Playwright port found from ${startPort}`);
}

async function reserveAvailablePort(startPort, deps = {}) {
  const acquire = deps.acquirePortLock || acquirePortLock;
  const probe = deps.canBind || canBind;
  const maxPortProbes = deps.maxPortProbes || MAX_PORT_PROBES;
  for (let offset = 0; offset < maxPortProbes; offset += 1) {
    const port = startPort + offset;
    if (port > 65535) break;
    const lock = acquire(port);
    if (!lock) continue;
    if (await probe(port)) return lock;
    releasePortLock(lock);
  }
  throw new Error(`No available Playwright port found from ${startPort}`);
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const proc = deps.process || process;
  const envSource = deps.env || proc.env || process.env;
  const io = deps.console || console;
  const reserve = deps.reserveAvailablePort || reserveAvailablePort;
  const spawnImpl = deps.spawn || spawn;
  const resolveCli = deps.resolveCli || (() => require.resolve('@playwright/test/cli'));
  const onExit = deps.onExit || ((handler) => proc.once('exit', handler));
  const exit = deps.exit || ((code) => proc.exit(code));

  const requestedPort = parsePort(envSource.PLAYWRIGHT_PORT);
  const startPort = requestedPort || DEFAULT_START_PORT;
  const portLock = await reserve(startPort);
  const port = portLock.port;
  const env = { ...envSource, PLAYWRIGHT_PORT: String(port) };
  onExit(() => releasePortLock(portLock));

  if (port !== startPort) {
    io.warn(`[playwright] port ${startPort} is busy; using ${port}`);
  } else {
    io.log(`[playwright] using port ${port}`);
  }

  const cli = resolveCli();
  const child = spawnImpl(proc.execPath, [cli, 'test', ...argv], {
    env,
    stdio: 'inherit',
    windowsHide: true,
  });

  return await new Promise((resolve) => {
    child.once('error', (err) => {
      releasePortLock(portLock);
      io.error(err.message || err);
      exit(1);
      resolve(1);
    });

    child.on('exit', (code, signal) => {
      releasePortLock(portLock);
      if (signal) {
        io.error(`[playwright] exited on signal ${signal}`);
        exit(1);
        resolve(1);
        return;
      }
      const exitCode = code == null ? 1 : code;
      exit(exitCode);
      resolve(exitCode);
    });
  });
}

if (require.main === module) main().catch((err) => { console.error(err.message || err); process.exit(1); });

module.exports = {
  DEFAULT_START_PORT,
  MAX_PORT_PROBES,
  parsePort,
  canBind,
  findAvailablePort,
  main,
  reserveAvailablePort,
  releasePortLock,
  _internal: {
    LOCK_DIR,
    acquirePortLock,
    isProcessAlive,
    readLockOwner,
  },
};
