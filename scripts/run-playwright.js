'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_START_PORT = 4211;
const MAX_PORT_PROBES = 50;
const LOCK_DIR = path.join(os.tmpdir(), 'promptwall-playwright-ports');

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
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

function acquirePortLock(port) {
  fs.mkdirSync(LOCK_DIR, { recursive: true });
  const lockPath = path.join(LOCK_DIR, `${port}.lock`);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = fs.openSync(lockPath, 'wx');
      fs.writeFileSync(fd, JSON.stringify({
        pid: process.pid,
        port,
        createdAt: new Date().toISOString(),
      }));
      return { fd, lockPath, port, released: false };
    } catch (err) {
      if (!err || err.code !== 'EEXIST') throw err;
      const owner = readLockOwner(lockPath);
      if (!isProcessAlive(Number(owner && owner.pid))) {
        try { fs.rmSync(lockPath, { force: true }); } catch (_) {}
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

async function findAvailablePort(startPort) {
  for (let offset = 0; offset < MAX_PORT_PROBES; offset += 1) {
    const port = startPort + offset;
    if (port > 65535) break;
    if (await canBind(port)) return port;
  }
  throw new Error(`No available Playwright port found from ${startPort}`);
}

async function reserveAvailablePort(startPort) {
  for (let offset = 0; offset < MAX_PORT_PROBES; offset += 1) {
    const port = startPort + offset;
    if (port > 65535) break;
    const lock = acquirePortLock(port);
    if (!lock) continue;
    if (await canBind(port)) return lock;
    releasePortLock(lock);
  }
  throw new Error(`No available Playwright port found from ${startPort}`);
}

async function main() {
  const requestedPort = parsePort(process.env.PLAYWRIGHT_PORT);
  const startPort = requestedPort || DEFAULT_START_PORT;
  const portLock = await reserveAvailablePort(startPort);
  const port = portLock.port;
  const env = { ...process.env, PLAYWRIGHT_PORT: String(port) };
  process.once('exit', () => releasePortLock(portLock));

  if (port !== startPort) {
    console.warn(`[playwright] port ${startPort} is busy; using ${port}`);
  } else {
    console.log(`[playwright] using port ${port}`);
  }

  const cli = require.resolve('@playwright/test/cli');
  const child = spawn(process.execPath, [cli, 'test', ...process.argv.slice(2)], {
    env,
    stdio: 'inherit',
    windowsHide: true,
  });

  child.once('error', (err) => {
    releasePortLock(portLock);
    console.error(err.message || err);
    process.exit(1);
  });

  child.on('exit', (code, signal) => {
    releasePortLock(portLock);
    if (signal) {
      console.error(`[playwright] exited on signal ${signal}`);
      process.exit(1);
    }
    process.exit(code == null ? 1 : code);
  });
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}

module.exports = {
  DEFAULT_START_PORT,
  MAX_PORT_PROBES,
  parsePort,
  canBind,
  findAvailablePort,
  reserveAvailablePort,
  releasePortLock,
};
