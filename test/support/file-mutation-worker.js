'use strict';

const fs = require('fs');

const WAIT = new Int32Array(new SharedArrayBuffer(4));
const mode = process.argv[2];
const target = process.env.MUTATION_TARGET;
const ready = process.env.MUTATION_READY;
const release = process.env.MUTATION_RELEASE;
const started = process.env.MUTATION_STARTED;
const waiting = process.env.MUTATION_WAITING;
const done = process.env.MUTATION_DONE;
const winnerBytes = process.env.MUTATION_WINNER_BYTES;

function mark(file) {
  if (file) fs.writeFileSync(file, `${process.pid}\n`);
}

function mutationOptions(extra = {}) {
  const options = {
    lockTimeoutMs: 5000,
    onLockContention: () => mark(waiting),
    ...extra,
  };
  if (process.env.MUTATION_HOSTNAME) options.hostname = process.env.MUTATION_HOSTNAME;
  if (process.env.MUTATION_PID) options.pid = Number(process.env.MUTATION_PID);
  if (process.env.MUTATION_PROCESS_START) options.processStart = process.env.MUTATION_PROCESS_START;
  if (Object.prototype.hasOwnProperty.call(process.env, 'MUTATION_GENERATION')) {
    options.generation = process.env.MUTATION_GENERATION === 'null'
      ? null
      : process.env.MUTATION_GENERATION;
  }
  if (process.env.MUTATION_RECLAIM_READY && process.env.MUTATION_RECLAIM_CONTINUE) {
    options.onBeforeReclaim = () => {
      mark(process.env.MUTATION_RECLAIM_READY);
      while (!fs.existsSync(process.env.MUTATION_RECLAIM_CONTINUE)) {
        Atomics.wait(WAIT, 0, 0, 20);
      }
    };
  }
  return options;
}

function captureWinner() {
  if (winnerBytes) fs.copyFileSync(target, winnerBytes);
}

function waitForReleaseSync() {
  while (!fs.existsSync(release)) Atomics.wait(WAIT, 0, 0, 20);
}

async function waitForRelease() {
  while (!fs.existsSync(release)) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function policyValue(enforcementMode) {
  const expected = JSON.parse(fs.readFileSync(process.env.MUTATION_EXPECTED, 'utf8'));
  return { expected, next: { ...expected, enforcementMode } };
}

function runPolicy(failing) {
  const policy = require('../../server/policy');
  const { expected, next } = policyValue(failing ? 'justify' : 'warn');
  if (!failing) mark(started);
  try {
    policy.withPolicyFileMutation(expected, ({ write }) => {
      write(next);
      if (failing) {
        mark(ready);
        waitForReleaseSync();
        throw new Error('synthetic policy audit failure');
      }
      return true;
    }, mutationOptions({ configPath: target }));
    if (failing) throw new Error('failing policy mutation unexpectedly succeeded');
    captureWinner();
  } catch (error) {
    if (!failing || !/synthetic policy audit failure/.test(error.message)) throw error;
  }
  mark(done);
}

function updaterValue(installMode) {
  return {
    remoteName: 'origin',
    branch: 'main',
    installMode,
    restartCommand: '',
    restartAfterUpdate: false,
  };
}

async function runUpdater(failing) {
  const updater = require('../../server/updater');
  if (!failing) mark(started);
  try {
    await updater.saveConfigWithAudit(updaterValue(failing ? 'npm-ci' : 'skip'), async () => {
      if (!failing) return;
      mark(ready);
      await waitForRelease();
      throw new Error('synthetic updater audit failure');
    }, mutationOptions());
    if (failing) throw new Error('failing updater mutation unexpectedly succeeded');
    captureWinner();
  } catch (error) {
    if (!failing || !/could not be audited/.test(error.message)) throw error;
  }
  mark(done);
}

function acquireRawLock() {
  return require('../../server/file-mutation-lock')
    .acquireFileMutationLockSync(target, mutationOptions());
}

function runLockCrash() {
  acquireRawLock();
  mark(ready);
  process.exit(17);
}

async function runLockHold() {
  const lockModule = require('../../server/file-mutation-lock');
  const lock = acquireRawLock();
  mark(ready);
  await waitForRelease();
  lockModule.releaseFileMutationLock(lock);
  mark(done);
}

function runLockReclaim() {
  const lockModule = require('../../server/file-mutation-lock');
  const lock = acquireRawLock();
  mark(ready);
  lockModule.releaseFileMutationLock(lock);
  mark(done);
}

async function main() {
  if (mode === 'policy-fail') return runPolicy(true);
  if (mode === 'policy-success') return runPolicy(false);
  if (mode === 'updater-fail') return runUpdater(true);
  if (mode === 'updater-success') return runUpdater(false);
  if (mode === 'lock-crash') return runLockCrash();
  if (mode === 'lock-hold') return runLockHold();
  if (mode === 'lock-reclaim') return runLockReclaim();
  throw new Error('unknown mutation worker mode');
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
