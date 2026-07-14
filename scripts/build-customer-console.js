'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CONSOLE_OUTPUT = 'server/public/app';
const CONSOLE_BUILD_RECEIPT = 'server/public/.customer-console-build.json';
const CONSOLE_RECEIPT_KIND = 'redactwall.customer-console-build.v1';
const MAX_CONSOLE_RECEIPT_BYTES = 1024 * 1024;

function defaultBuild(root) {
  const executable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  return spawnSync(executable, ['run', 'build', '--prefix', 'console'], {
    cwd: root,
    encoding: 'utf8',
    stdio: 'inherit',
    windowsHide: true,
  });
}

function collectConsoleFiles(outDir) {
  const stat = fs.lstatSync(outDir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('customer console build did not create a regular output directory');
  }
  const files = [];
  function visit(directory, prefix) {
    const entries = fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`customer console output may not contain symlinks: ${relative}`);
      if (entry.isDirectory()) visit(absolute, relative);
      else if (entry.isFile()) files.push(relative);
      else throw new Error(`customer console output contains an unsupported entry: ${relative}`);
    }
  }
  visit(outDir, '');
  if (files.length < 1) throw new Error('customer console build created an empty output directory');
  return files;
}

function consoleBodyDigest(body) {
  return crypto.createHash('sha256').update(body).digest('hex');
}

function consoleFileRecord(outDir, relativePath) {
  const target = path.join(outDir, ...relativePath.split('/'));
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`customer console output file changed type: ${relativePath}`);
  }
  const body = fs.readFileSync(target);
  return Object.freeze({ path: relativePath, size: body.length, sha256: consoleBodyDigest(body) });
}

function consoleTreeDigest(files) {
  return crypto.createHash('sha256')
    .update(`${CONSOLE_RECEIPT_KIND}\0`, 'utf8')
    .update(JSON.stringify(files), 'utf8')
    .digest('hex');
}

function customerConsoleReceipt(outDir) {
  const files = collectConsoleFiles(outDir).map((relativePath) => consoleFileRecord(outDir, relativePath));
  return Object.freeze({
    schemaVersion: 1,
    kind: CONSOLE_RECEIPT_KIND,
    output: CONSOLE_OUTPUT,
    files: Object.freeze(files),
    treeDigest: consoleTreeDigest(files),
  });
}

function writeCustomerConsoleBuildReceipt(options = {}) {
  const root = path.resolve(options.root || path.join(__dirname, '..'));
  const outDir = path.resolve(options.outDir || path.join(root, ...CONSOLE_OUTPUT.split('/')));
  const receiptPath = path.resolve(options.receiptPath
    || path.join(root, ...CONSOLE_BUILD_RECEIPT.split('/')));
  const receipt = customerConsoleReceipt(outDir);
  fs.mkdirSync(path.dirname(receiptPath), { recursive: true });
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    encoding: 'utf8', flag: 'wx', mode: 0o600,
  });
  return Object.freeze({ outDir, receipt, receiptPath });
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function validateReceiptRecord(record, priorPath) {
  if (!exactKeys(record, ['path', 'sha256', 'size'])
      || typeof record.path !== 'string'
      || !record.path
      || record.path.includes('\\')
      || path.posix.isAbsolute(record.path)
      || path.posix.normalize(record.path) !== record.path
      || record.path.split('/').some((part) => !part || part === '.' || part === '..')
      || (priorPath && priorPath.localeCompare(record.path) >= 0)
      || !Number.isSafeInteger(record.size)
      || record.size < 0
      || !/^[a-f0-9]{64}$/.test(record.sha256)) {
    throw new Error('customer console build receipt file inventory is invalid');
  }
  return Object.freeze({ path: record.path, size: record.size, sha256: record.sha256 });
}

function readCustomerConsoleBuildReceipt(receiptPath) {
  const stat = fs.lstatSync(receiptPath);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size < 2 || stat.size > MAX_CONSOLE_RECEIPT_BYTES) {
    throw new Error('customer console build receipt is not a bounded regular file');
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  } catch (error) {
    throw new Error(`customer console build receipt is unreadable: ${error.message}`);
  }
  if (!exactKeys(parsed, ['files', 'kind', 'output', 'schemaVersion', 'treeDigest'])
      || parsed.schemaVersion !== 1
      || parsed.kind !== CONSOLE_RECEIPT_KIND
      || parsed.output !== CONSOLE_OUTPUT
      || !Array.isArray(parsed.files)
      || parsed.files.length < 1
      || !/^[a-f0-9]{64}$/.test(parsed.treeDigest)) {
    throw new Error('customer console build receipt schema is invalid');
  }
  const files = [];
  for (const record of parsed.files) files.push(validateReceiptRecord(record, files.at(-1)?.path));
  if (consoleTreeDigest(files) !== parsed.treeDigest) {
    throw new Error('customer console build receipt digest is invalid');
  }
  return Object.freeze({ ...parsed, files: Object.freeze(files) });
}

function verifyCustomerConsoleBuildReceipt(options = {}) {
  const root = path.resolve(options.root || path.join(__dirname, '..'));
  const outDir = path.resolve(options.outDir || path.join(root, ...CONSOLE_OUTPUT.split('/')));
  const receiptPath = path.resolve(options.receiptPath
    || path.join(root, ...CONSOLE_BUILD_RECEIPT.split('/')));
  const receipt = readCustomerConsoleBuildReceipt(receiptPath);
  const actualPaths = collectConsoleFiles(outDir);
  const expectedPaths = receipt.files.map((record) => record.path);
  if (actualPaths.length !== expectedPaths.length
      || actualPaths.some((value, index) => value !== expectedPaths[index])) {
    throw new Error('customer console output differs from its exact build receipt');
  }
  for (const expected of receipt.files) {
    const actual = consoleFileRecord(outDir, expected.path);
    if (actual.size !== expected.size || actual.sha256 !== expected.sha256) {
      throw new Error(`customer console output changed after build: ${expected.path}`);
    }
  }
  return Object.freeze({ outDir, receipt, receiptPath });
}

function buildCustomerConsole(options = {}) {
  const root = path.resolve(options.root || path.join(__dirname, '..'));
  const outDir = path.join(root, ...CONSOLE_OUTPUT.split('/'));
  const receiptPath = path.join(root, ...CONSOLE_BUILD_RECEIPT.split('/'));
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.rmSync(receiptPath, { force: true });
  if (fs.existsSync(outDir) || fs.existsSync(receiptPath)) {
    throw new Error('customer console output cleanup failed');
  }
  const result = (options.runBuild || defaultBuild)(root, outDir);
  if (!result || result.status !== 0) {
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.rmSync(receiptPath, { force: true });
    throw new Error(`customer console build failed with status ${result?.status ?? 'unknown'}`);
  }
  try {
    collectConsoleFiles(outDir);
    const written = writeCustomerConsoleBuildReceipt({ root, outDir, receiptPath });
    verifyCustomerConsoleBuildReceipt({ root, outDir, receiptPath });
    return Object.freeze({ outDir, receiptPath: written.receiptPath });
  } catch (error) {
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.rmSync(receiptPath, { force: true });
    throw error;
  }
}

function main() {
  try {
    buildCustomerConsole();
    return 0;
  } catch (error) {
    console.error(error.message);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = {
  CONSOLE_BUILD_RECEIPT,
  CONSOLE_OUTPUT,
  buildCustomerConsole,
  consoleBodyDigest,
  verifyCustomerConsoleBuildReceipt,
  writeCustomerConsoleBuildReceipt,
};
