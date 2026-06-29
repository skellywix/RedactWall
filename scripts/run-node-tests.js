'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const TEST_DIR = path.resolve(__dirname, '..', 'test');
const DEFAULT_DELAY_MS = process.platform === 'win32' ? 25 : 0;
const DEFAULT_RETRIES = process.platform === 'win32' ? 2 : 0;
const DEFAULT_RETRY_DELAY_MS = process.platform === 'win32' ? 500 : 0;

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function walkTestFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkTestFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.test.js')) {
      files.push(fullPath);
    }
  }
  return files;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function writeBufferedOutput(result) {
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
}

function summarizeFailure(output) {
  return output
    .split(/\r?\n/)
    .filter((line) => /\bnot ok\b|error:|code: 'ETIMEDOUT'|false !== true/.test(line))
    .slice(0, 4)
    .map((line) => line.trim())
    .join(' | ');
}

function runNodeTest(args, opts = {}) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const child = spawn(process.execPath, args, {
      env: process.env,
      stdio: opts.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
      windowsHide: true,
    });
    if (opts.capture) {
      child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
      child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    }
    child.once('error', (err) => {
      if (settled) return;
      settled = true;
      stderr += `${err.message || err}\n`;
      resolve({ code: 1, stdout, stderr, signal: null });
    });
    child.on('exit', (code, signal) => {
      if (settled) return;
      settled = true;
      if (signal) {
        console.error(`[node-test] exited on signal ${signal}`);
        resolve({ code: 1, stdout, stderr, signal });
        return;
      }
      resolve({ code: code == null ? 1 : code, stdout, stderr, signal: null });
    });
  });
}

async function runSequentialSuite() {
  const files = walkTestFiles(TEST_DIR)
    .map((file) => path.relative(process.cwd(), file))
    .sort((a, b) => a.localeCompare(b));
  const delayMs = positiveInteger(process.env.PROMPTWALL_NODE_TEST_DELAY_MS, DEFAULT_DELAY_MS);
  const retries = positiveInteger(process.env.PROMPTWALL_NODE_TEST_RETRIES, DEFAULT_RETRIES);
  const retryDelayMs = positiveInteger(process.env.PROMPTWALL_NODE_TEST_RETRY_DELAY_MS, DEFAULT_RETRY_DELAY_MS);
  const recovered = [];

  console.log(`[node-test] running ${files.length} test files sequentially`);
  for (let i = 0; i < files.length; i += 1) {
    const file = files[i];
    console.log(`[node-test] ${i + 1}/${files.length} ${file}`);
    let attempt = 0;
    let result;
    while (attempt <= retries) {
      result = await runNodeTest(['--test', file], { capture: true });
      if (result.code === 0) break;
      if (attempt >= retries) {
        writeBufferedOutput(result);
        return result.code;
      }
      const summary = summarizeFailure(`${result.stdout}\n${result.stderr}`) || `exit ${result.code}`;
      console.warn(`[node-test] retrying ${file} after failed attempt ${attempt + 1}/${retries + 1}: ${summary}`);
      if (retryDelayMs > 0) await delay(retryDelayMs);
      attempt += 1;
    }
    writeBufferedOutput(result);
    if (attempt > 0) recovered.push(`${file} attempt ${attempt + 1}`);
    if (delayMs > 0 && i < files.length - 1) await delay(delayMs);
  }
  if (recovered.length > 0) {
    console.warn(`[node-test] recovered ${recovered.length} transient failure(s): ${recovered.join(', ')}`);
  }
  return 0;
}

async function main() {
  const forwarded = process.argv.slice(2);
  if (forwarded.length > 0) {
    process.exitCode = (await runNodeTest(['--test', '--test-concurrency=1', ...forwarded])).code;
    return;
  }
  process.exitCode = await runSequentialSuite();
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
