'use strict';

const { spawn } = require('node:child_process');
const net = require('node:net');

const DEFAULT_START_PORT = 4211;
const MAX_PORT_PROBES = 50;

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

async function main() {
  const requestedPort = parsePort(process.env.PLAYWRIGHT_PORT);
  const startPort = requestedPort || DEFAULT_START_PORT;
  const port = await findAvailablePort(startPort);
  const env = { ...process.env, PLAYWRIGHT_PORT: String(port) };

  if (requestedPort && requestedPort !== port) {
    console.warn(`[playwright] port ${requestedPort} is busy; using ${port}`);
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
    console.error(err.message || err);
    process.exit(1);
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      console.error(`[playwright] exited on signal ${signal}`);
      process.exit(1);
    }
    process.exit(code == null ? 1 : code);
  });
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
