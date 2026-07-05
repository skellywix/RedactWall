'use strict';
/**
 * Test coverage for the node suite: runs the standard sequential runner with
 * V8 coverage capture, then merges the per-process profiles into one c8 report.
 *
 *   npm run test:coverage             # full suite + per-file table
 *   npm run test:coverage -- test/detect.test.js   # single file, faster
 *
 * Coverage is scoped to the code sensors and the server actually ship
 * (server/, gateway/, detection-engine/, sensors/). server/public/ and the
 * synced browser bundle are browser-side assets covered by Playwright, not
 * this suite, so they are excluded rather than reported as misleading zeros.
 */
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const INCLUDE = ['server/**/*.js', 'gateway/**/*.js', 'detection-engine/**/*.js', 'sensors/**/*.js'];
const EXCLUDE = ['server/public/**', 'sensors/browser-extension/lib/**', 'test/**', 'node_modules/**'];

function main() {
  const coverageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-v8cov-'));
  try {
    const run = spawnSync(process.execPath, [path.join(__dirname, 'run-node-tests.js'), ...process.argv.slice(2)], {
      cwd: ROOT,
      env: { ...process.env, NODE_V8_COVERAGE: coverageDir },
      stdio: 'inherit',
    });
    if (run.status !== 0) {
      process.exitCode = run.status == null ? 1 : run.status;
      return;
    }
    const report = spawnSync(process.execPath, [
      require.resolve('c8/bin/c8.js'), 'report',
      '--temp-directory', coverageDir,
      '--reporter', 'text',
      '--all',
      ...INCLUDE.flatMap((p) => ['--include', p]),
      ...EXCLUDE.flatMap((p) => ['--exclude', p]),
    ], { cwd: ROOT, stdio: 'inherit' });
    process.exitCode = report.status == null ? 1 : report.status;
  } finally {
    fs.rmSync(coverageDir, { recursive: true, force: true });
  }
}

main();
