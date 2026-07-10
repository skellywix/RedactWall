'use strict';
/**
 * Killable child-process pool for attacker-controlled file extraction.
 *
 * server/processors.js races extraction against a timer, but adm-zip and
 * pdf-parse do synchronous CPU work, so on the main thread that timer cannot
 * fire until the parse finishes — a crafted file stalls the whole control
 * plane. This pool runs extraction in server/parse-child.js and enforces the
 * timeout from the parent with SIGKILL, which preempts even synchronous work.
 *
 * Exposes the same extractText(name, buf, opts) contract and error codes as
 * server/processors.js so call sites and sensors need no other changes.
 * REDACTWALL_PARSE_ISOLATION=off only permits bounded plain-text decoding in
 * process; synchronous rich/container parsers always remain isolated.
 */
require('./env').loadEnv();
const { fork } = require('child_process');
const path = require('path');
const processors = require('./processors');

const CHILD_PATH = path.join(__dirname, 'parse-child.js');

const workers = new Set();
const queue = [];
let nextTaskId = 1;

function bounded(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function poolEnabled() {
  const v = String(process.env.REDACTWALL_PARSE_ISOLATION || 'on').toLowerCase();
  return !['off', '0', 'false', 'disabled'].includes(v);
}

function poolSize() { return bounded(process.env.REDACTWALL_PARSE_POOL_SIZE, 1, 1, 4); }
function maxTasksPerChild() { return bounded(process.env.REDACTWALL_PARSE_CHILD_MAX_TASKS, 50, 1, 1000); }
function childHeapMb() { return bounded(process.env.REDACTWALL_PARSE_CHILD_MAX_OLD_SPACE_MB, 256, 64, 4096); }
function queueMax() { return bounded(process.env.REDACTWALL_PARSE_QUEUE_MAX, 16, 1, 256); }
function killGraceMs() { return bounded(process.env.REDACTWALL_PARSE_KILL_GRACE_MS, 500, 50, 10000); }

function childTimeoutMs(opts) {
  return bounded(
    opts.timeoutMs ?? process.env.FILE_EXTRACT_TIMEOUT_MS,
    processors.DEFAULT_EXTRACT_TIMEOUT_MS,
    100,
    60000,
  );
}

function failResult(task, error) {
  return { text: '', processor: task.processorId, supported: true, extractionOk: false, error };
}

function setIdle(worker, isIdle) {
  const target = isIdle ? 'unref' : 'ref';
  try {
    worker.child[target]();
    if (worker.child.channel) worker.child.channel[target]();
  } catch {}
}

function spawnWorker() {
  const child = fork(CHILD_PATH, [], {
    serialization: 'advanced',
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    execArgv: ['--max-old-space-size=' + childHeapMb()],
    env: { ...process.env, REDACTWALL_PARSE_CHILD: '1' },
  });
  const worker = { child, task: null, tasksDone: 0 };
  child.on('message', (msg) => {
    if (msg && msg.type === 'result' && worker.task && worker.task.id === msg.id) settle(worker, msg.result);
  });
  child.on('exit', () => reap(worker, 'extract_failed'));
  child.on('error', () => reap(worker, 'extract_failed'));
  workers.add(worker);
  setIdle(worker, true);
  return worker;
}

function reap(worker, error) {
  workers.delete(worker);
  const task = worker.task;
  worker.task = null;
  if (task) {
    clearTimeout(task.timer);
    task.resolve(failResult(task, error));
  }
  pump();
}

function retire(worker) {
  workers.delete(worker);
  try { worker.child.kill('SIGKILL'); } catch {}
}

function settle(worker, result) {
  const task = worker.task;
  if (!task) return;
  worker.task = null;
  worker.tasksDone += 1;
  clearTimeout(task.timer);
  task.resolve(result);
  if (worker.tasksDone >= maxTasksPerChild()) retire(worker);
  else setIdle(worker, true);
  pump();
}

function preempt(worker) {
  const task = worker.task;
  worker.task = null;
  workers.delete(worker);
  try { worker.child.kill('SIGKILL'); } catch {}
  if (task) task.resolve(failResult(task, 'timeout'));
  pump();
}

// Drop a still-queued task that has waited past its budget without ever being
// assigned to a worker. Without this, a backlog of pathological files could keep
// a legitimate upload queued for queueMax*(timeout+grace) with no wait bound.
function expireQueued(task) {
  const idx = queue.indexOf(task);
  if (idx === -1) return; // already assigned or drained
  queue.splice(idx, 1);
  task.resolve(failResult(task, 'timeout'));
}

function assign(worker, task) {
  clearTimeout(task.queueTimer);
  worker.task = task;
  setIdle(worker, false);
  task.timer = setTimeout(() => preempt(worker), task.totalTimeoutMs);
  try {
    worker.child.send({ type: 'extract', id: task.id, name: task.name, buf: task.buf, opts: task.opts });
  } catch {
    clearTimeout(task.timer);
    reap(worker, 'extract_failed');
  }
}

function pump() {
  while (queue.length) {
    let worker = [...workers].find((w) => !w.task);
    if (!worker && workers.size < poolSize()) worker = spawnWorker();
    if (!worker) return;
    assign(worker, queue.shift());
  }
}

/** Same contract as processors.extractText, but preemptible and fault-isolated. */
async function extractText(name, buf, opts = {}) {
  const p = processors.PROCESSORS.find((x) => x.supports(name));
  if (!p || p.requiresOcr) return processors.extractText(name, buf, opts);
  // The off switch is only safe for bounded, linear plain-text decoding.
  // Container parsers stay in a killable child even when isolation is disabled.
  if (!poolEnabled() && !p.requiresIsolation) return processors.extractText(name, buf, opts);
  if (queue.length >= queueMax()) return failResult({ processorId: p.id }, 'extract_failed');
  return new Promise((resolve) => {
    const task = {
      id: nextTaskId++,
      name, buf, opts, resolve,
      processorId: p.id,
      totalTimeoutMs: childTimeoutMs(opts) + killGraceMs(),
      timer: null,
      queueTimer: null,
    };
    // Bound queue-wait time so a task never lingers longer than its own
    // execution budget before it is even assigned to a worker.
    task.queueTimer = setTimeout(() => expireQueued(task), task.totalTimeoutMs);
    queue.push(task);
    pump();
  });
}

/** Kill all children and fail any queued work. For tests and shutdown paths. */
function shutdown() {
  while (queue.length) {
    const task = queue.shift();
    clearTimeout(task.queueTimer);
    task.resolve(failResult(task, 'extract_failed'));
  }
  for (const worker of [...workers]) {
    const task = worker.task;
    worker.task = null;
    if (task) clearTimeout(task.timer);
    retire(worker);
    if (task) task.resolve(failResult(task, 'extract_failed'));
  }
}

module.exports = { extractText, shutdown, _internal: { workers, queue, poolEnabled } };
