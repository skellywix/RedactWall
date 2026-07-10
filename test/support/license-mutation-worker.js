'use strict';

const fs = require('node:fs');
const license = require('../../server/license');
const fileMutationLock = require('../../server/file-mutation-lock');

function waitFor(file, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  const signal = new Int32Array(new SharedArrayBuffer(4));
  while (!fs.existsSync(file)) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${file}`);
    Atomics.wait(signal, 0, 0, 10);
  }
}

const options = { path: process.env.LICENSE_PATH };
if (process.env.WORKER_MODE === 'rollback') {
  try {
    license.withLicenseFileMutation(({ write }) => {
      write(process.env.LICENSE_VALUE);
      fs.writeFileSync(process.env.READY_FILE, 'ready');
      waitFor(process.env.RELEASE_FILE);
      throw new Error('synthetic audit commit failure');
    }, options);
    throw new Error('rollback worker unexpectedly committed');
  } catch (error) {
    if (!/synthetic audit commit failure/.test(String(error && error.message))) throw error;
    process.stdout.write('rolled-back');
  }
} else {
  fs.writeFileSync(process.env.ATTEMPT_FILE, 'attempt');
  fileMutationLock._setContentionObserverForTest(() => {
    fs.writeFileSync(process.env.CONTENDED_FILE, 'contended');
  });
  try {
    license.withLicenseFileMutation(({ write }) => {
      write(process.env.LICENSE_VALUE);
    }, options);
  } finally {
    fileMutationLock._setContentionObserverForTest(null);
  }
  process.stdout.write('committed');
}
