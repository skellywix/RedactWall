'use strict';
/**
 * Regression-suite runner (modeled on scripts/run-node-tests.js).
 *
 *   node suite/runner.js            # full run (all node tiers)
 *   node suite/runner.js --full     # same as above
 *   node suite/runner.js --smoke    # only files whose first line has "// @tier smoke"
 *   node suite/runner.js --tier contract|security|detector
 *
 * Each suite/**\/*.suite.js file runs in its own `node --test` child process so
 * one file's env/app instance can never leak into another. The Playwright
 * flows tier lives in suite/flows and runs via `npm run suite:ui` instead.
 */
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const SUITE_DIR = __dirname;
const NODE_TIERS = ['contract', 'security', 'detector'];
const SMOKE_MARKER = '// @tier smoke';

function walkSuiteFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walkSuiteFiles(fullPath));
    else if (entry.isFile() && entry.name.endsWith('.suite.js')) files.push(fullPath);
  }
  return files;
}

function tierOf(file) {
  return path.basename(path.dirname(file));
}

function isSmoke(file) {
  const firstLine = fs.readFileSync(file, 'utf8').split(/\r?\n/, 1)[0];
  return firstLine.includes(SMOKE_MARKER);
}

function parseArgs(argv) {
  if (argv.includes('--smoke')) return { mode: 'smoke' };
  const tierIndex = argv.indexOf('--tier');
  if (tierIndex >= 0) {
    const tier = argv[tierIndex + 1];
    if (!NODE_TIERS.includes(tier)) {
      throw new Error(`unknown tier "${tier}" (expected ${NODE_TIERS.join(', ')})`);
    }
    return { mode: 'tier', tier };
  }
  return { mode: 'full' };
}

function selectFiles(selection) {
  const all = walkSuiteFiles(SUITE_DIR)
    .filter((file) => NODE_TIERS.includes(tierOf(file)))
    .sort((a, b) => a.localeCompare(b));
  if (selection.mode === 'smoke') return all.filter(isSmoke);
  if (selection.mode === 'tier') return all.filter((file) => tierOf(file) === selection.tier);
  return all;
}

function runFile(file) {
  return new Promise((resolve) => {
    let output = '';
    const child = spawn(process.execPath, ['--test', file], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    child.stdout.on('data', (chunk) => { output += chunk.toString('utf8'); });
    child.stderr.on('data', (chunk) => { output += chunk.toString('utf8'); });
    child.once('error', (err) => resolve({ code: 1, output: output + `${err.message || err}\n` }));
    child.on('exit', (code, signal) => resolve({ code: signal ? 1 : (code == null ? 1 : code), output }));
  });
}

async function main() {
  const selection = parseArgs(process.argv.slice(2));
  const files = selectFiles(selection);
  if (!files.length) {
    console.error(`[suite] no files matched (${selection.mode})`);
    process.exitCode = 1;
    return;
  }
  const label = selection.mode === 'tier' ? `tier=${selection.tier}` : selection.mode;
  console.log(`[suite] running ${files.length} file(s) sequentially (${label})`);
  const failed = [];
  for (let i = 0; i < files.length; i += 1) {
    const rel = path.relative(process.cwd(), files[i]);
    console.log(`[suite] ${i + 1}/${files.length} ${rel}`);
    const result = await runFile(files[i]);
    process.stdout.write(result.output);
    if (result.code !== 0) failed.push(rel);
  }
  console.log(`[suite] ${files.length - failed.length}/${files.length} file(s) passed`);
  if (failed.length) {
    console.error(`[suite] FAILED: ${failed.join(', ')}`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
