'use strict';
/**
 * Restart-recovery + concurrency proof for the control plane.
 *
 * Spawns the real server as a child process, SIGKILLs it mid-burst, restarts
 * it on the same SQLite store, and proves the audit chain and query rows
 * survived. Then proves 100 parallel gate posts all land exactly once.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');

const REPO_ROOT = path.join(__dirname, '..');
const SERVER_ENTRY = path.join(REPO_ROOT, 'server', 'app.js');
const INGEST_KEY = 'chaos-ingest-key';
const SYNTHETIC_SSN = '524-71-9043';
const READY_TIMEOUT_MS = 20000;
const REQUEST_TIMEOUT_MS = 10000;

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-chaos-test-'));
const children = new Set();

function serverEnv(dbPath, port) {
  return {
    ...process.env,
    SENTINEL_ENV_PATH: path.join(tempRoot, 'no.env'),
    SENTINEL_DB_PATH: dbPath,
    SENTINEL_SECRET: 'chaos-secret-stable',
    SENTINEL_DATA_KEY: 'chaos-data-key-stable',
    ADMIN_PASSWORD: 'chaos-admin-password-1',
    INGEST_API_KEY: INGEST_KEY,
    NODE_ENV: 'test',
    PORT: String(port),
  };
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function startServer(dbPath, port) {
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: REPO_ROOT,
    env: serverEnv(dbPath, port),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', () => {});
  child.stderr.on('data', () => {});
  children.add(child);
  child.once('exit', () => children.delete(child));
  return child;
}

function stopServer(child, signal = 'SIGKILL') {
  return new Promise((resolve) => {
    if (!child || child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once('exit', resolve);
    child.kill(signal);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReady(port) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const ready = await fetch(`http://127.0.0.1:${port}/readyz`, { signal: AbortSignal.timeout(2000) })
      .then((res) => res.ok)
      .catch(() => false);
    if (ready) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for /readyz on port ${port}`);
}

function postGate(port, prompt, user) {
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': INGEST_KEY },
    body: JSON.stringify({ prompt, user, destination: 'chat.openai.com', source: 'api', channel: 'submit' }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
}

function gatePrompt(i) {
  return i % 10 === 9
    ? `member record ${i} includes SSN ${SYNTHETIC_SSN}`
    : `what are the branch opening hours for request ${i}?`;
}

/** Read the store out-of-process, exactly like an operator would after a crash. */
function inspectStore(dbPath) {
  const result = spawnSync(process.execPath, ['-e', `
    const db = require('./server/db');
    const rows = db.listQueries({ all: true });
    const verdict = db.verifyAuditChain();
    console.log(JSON.stringify({
      auditOk: verdict.ok,
      auditCount: verdict.count,
      total: rows.length,
      parsedOk: rows.every((row) => row && typeof row.id === 'string' && typeof row.status === 'string'),
    }));
  `], { cwd: REPO_ROOT, env: serverEnv(dbPath, 0), encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('server recovers after SIGKILL mid-burst with an intact audit chain', async (t) => {
  const dbPath = path.join(tempRoot, 'crash', 'sentinel.db');
  const port = await getFreePort();

  const first = startServer(dbPath, port);
  t.after(() => stopServer(first));
  await waitForReady(port);

  const burst = [];
  for (let i = 0; i < 50; i++) {
    burst.push(postGate(port, gatePrompt(i), `burst-${i}@example.test`).then((res) => res.status).catch(() => 'failed'));
  }
  await sleep(30); // let part of the burst land, then pull the plug mid-flight
  await stopServer(first, 'SIGKILL');
  const outcomes = await Promise.all(burst);
  assert.strictEqual(outcomes.length, 50, 'every burst request must settle after the kill');

  const second = startServer(dbPath, port);
  t.after(() => stopServer(second));
  await waitForReady(port);

  const store = inspectStore(dbPath);
  assert.strictEqual(store.auditOk, true, 'audit hash-chain must verify after a crash');
  assert.strictEqual(store.parsedOk, true, 'no partially-written query rows may survive');
  assert.ok(store.total <= 50, 'no duplicated writes from the interrupted burst');

  const afterRestart = await postGate(port, 'post-recovery benign gate check', 'recovery@example.test');
  assert.strictEqual(afterRestart.status, 200);
  const body = await afterRestart.json();
  assert.ok(body.id);
  assert.ok(['allow', 'block', 'log', 'redact', 'warn'].includes(body.decision));

  await stopServer(second, 'SIGTERM');
});

test('100 concurrent gate posts all respond and land exactly once in the store', async (t) => {
  const dbPath = path.join(tempRoot, 'load', 'sentinel.db');
  const port = await getFreePort();

  const server = startServer(dbPath, port);
  t.after(() => stopServer(server));
  await waitForReady(port);

  const baseline = inspectStore(dbPath).total;
  const responses = await Promise.all(Array.from({ length: 100 }, (_, i) =>
    postGate(port, gatePrompt(i), `load-${i}@example.test`).then(async (res) => ({ status: res.status, body: await res.json() }))));

  assert.strictEqual(responses.length, 100);
  assert.ok(responses.every((r) => r.status === 200), 'every concurrent gate post must get a decision');
  const ids = new Set(responses.map((r) => r.body.id));
  assert.strictEqual(ids.size, 100, 'every decision must reference a distinct stored query');

  const store = inspectStore(dbPath);
  assert.strictEqual(store.total - baseline, 100, 'stored query count must match responses received');
  assert.strictEqual(store.auditOk, true);
  assert.ok(store.auditCount >= 100, 'each gate decision appends an audit entry');

  await stopServer(server, 'SIGTERM');
});

test.after(async () => {
  await Promise.all([...children].map((child) => stopServer(child)));
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
