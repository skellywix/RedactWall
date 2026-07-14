'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  consoleBodyDigest,
  verifyCustomerConsoleBuildReceipt,
} = require('./build-customer-console');
const { inspectCustomerArtifact } = require('./customer-secret-material-detector');

const DEFAULT_MANIFEST = path.join(__dirname, '..', 'packaging', 'customer-runtime-files.json');
const REQUIRED_CUSTOMER_FILES = Object.freeze([
  'package.json',
  'server/app.js',
  'server/vendor-signed-artifact.js',
  'server/connected-policy-state.js',
  'server/connected-policy-store.js',
  'server/policy-control-verifier.js',
  'server/customer-diagnostic-channel.js',
  'server/customer-diagnostic-integrity.js',
  'server/customer-diagnostic-outbox.js',
  'server/customer-diagnostic-runtime.js',
  'server/customer-diagnostic-storage.js',
  'server/customer-shadow-ai-sqlite.js',
  'server/customer-shadow-ai-storage.js',
  'server/shadow-ai-catalog-state.js',
  'server/shadow-ai-sqlite-core.js',
  'server/customer-audit-response-signer.js',
  'server/customer-audit-support-acknowledgement.js',
  'server/customer-audit-support-broker.js',
  'server/customer-audit-support-store.js',
  'server/audit-support-control-verifier.js',
  'scripts/backup-store.js',
  'scripts/customer-secret-material-detector.js',
  'scripts/export-evidence-pack.js',
  'scripts/check-license-trust-anchor.js',
  'scripts/docker-entrypoint.sh',
  'scripts/verify-customer-image-content.js',
  'gateway/server.js',
  'sensors/browser-extension/manifest.json',
]);
const REQUIRED_CUSTOMER_PACKAGE_SCRIPTS = Object.freeze([
  'backup', 'evidence:pack', 'gateway', 'license:trust-check', 'start',
]);
const FORBIDDEN_CUSTOMER_PACKAGE_SCRIPTS = new Set([
  'license:issue', 'setup', 'setup:check', 'setup:prod', 'silo:deploy',
  'silo:artifacts:init', 'silo:maintenance', 'test',
]);

function plainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function checkedRelativePath(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0')
      || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)
      || value.split('/').some((part) => !part || part === '.' || part === '..')
      || path.posix.normalize(value) !== value) {
    throw new Error(`${label} must be a canonical relative POSIX path`);
  }
  return value;
}

function checkedSortedUniquePaths(values, label) {
  if (!Array.isArray(values) || values.length < 1) throw new Error(`${label} must be a non-empty array`);
  const checked = values.map((value) => checkedRelativePath(value, label));
  const sorted = [...checked].sort();
  if (new Set(checked).size !== checked.length || checked.some((value, index) => value !== sorted[index])) {
    throw new Error(`${label} must be sorted and unique`);
  }
  return checked;
}

function checkedPackageScripts(value, authoredFiles) {
  if (!plainObject(value)) throw new Error('packageScripts must be an object');
  const names = Object.keys(value);
  if (names.length < 1 || names.some((name, index) => (
    !/^[a-z][a-z0-9:-]{0,63}$/.test(name)
      || name !== [...names].sort()[index]
      || typeof value[name] !== 'string'
  ))) throw new Error('packageScripts must be a sorted command map');
  const files = new Set(authoredFiles);
  for (const [name, command] of Object.entries(value)) {
    if (FORBIDDEN_CUSTOMER_PACKAGE_SCRIPTS.has(name)
        || !/^(?:node|bash|powershell\.exe)\s/.test(command)
        || /[;&|`$<>\r\n]/.test(command)) {
      throw new Error(`customer package script is forbidden: ${name}`);
    }
    const references = command.match(/\b(?:gateway|scripts|sensors|server)\/[A-Za-z0-9_.\/-]+/g) || [];
    if (references.length !== 1 || !files.has(references[0])) {
      throw new Error(`customer package script target is not staged: ${name}`);
    }
  }
  for (const required of REQUIRED_CUSTOMER_PACKAGE_SCRIPTS) {
    if (!Object.prototype.hasOwnProperty.call(value, required)) {
      throw new Error(`customer package script is missing: ${required}`);
    }
  }
  return Object.freeze(Object.fromEntries(Object.entries(value)));
}

function readManifest(manifestPath = DEFAULT_MANIFEST) {
  const resolved = path.resolve(manifestPath);
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  } catch (error) {
    throw new Error(`customer runtime manifest is unreadable: ${error.message}`);
  }
  if (!plainObject(parsed) || !exactKeys(parsed, [
    'artifact', 'authoredFiles', 'generatedTrees', 'packageScripts', 'schemaVersion',
  ]) || parsed.schemaVersion !== 1 || parsed.artifact !== 'redactwall-customer-runtime') {
    throw new Error('customer runtime manifest schema is invalid');
  }
  const authoredFiles = checkedSortedUniquePaths(parsed.authoredFiles, 'authoredFiles');
  const generatedTrees = parsed.generatedTrees;
  if (!Array.isArray(generatedTrees) || generatedTrees.length !== 1
      || !plainObject(generatedTrees[0])
      || !exactKeys(generatedTrees[0], ['destination', 'source'])) {
    throw new Error('generatedTrees must contain exactly the console application tree');
  }
  const generatedTree = Object.freeze({
    source: checkedRelativePath(generatedTrees[0].source, 'generatedTrees source'),
    destination: checkedRelativePath(generatedTrees[0].destination, 'generatedTrees destination'),
  });
  if (generatedTree.source !== 'server/public/app'
      || generatedTree.destination !== 'server/public/app') {
    throw new Error('generatedTrees must bind server/public/app to the same runtime path');
  }
  const fileSet = new Set(authoredFiles);
  for (const required of REQUIRED_CUSTOMER_FILES) {
    if (!fileSet.has(required)) throw new Error(`customer runtime manifest is missing ${required}`);
  }
  const packageScripts = checkedPackageScripts(parsed.packageScripts, authoredFiles);
  return Object.freeze({
    schemaVersion: 1,
    artifact: parsed.artifact,
    authoredFiles: Object.freeze(authoredFiles),
    generatedTrees: Object.freeze([generatedTree]),
    packageScripts,
  });
}

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative);
}

function assertNoSymlinkPath(root, relativePath, expectDirectory = false) {
  const resolvedRoot = path.resolve(root);
  const target = path.resolve(resolvedRoot, ...relativePath.split('/'));
  if (!inside(resolvedRoot, target)) throw new Error(`runtime source escapes root: ${relativePath}`);
  let cursor = resolvedRoot;
  for (const part of relativePath.split('/')) {
    cursor = path.join(cursor, part);
    let stat;
    try {
      stat = fs.lstatSync(cursor);
    } catch (error) {
      throw new Error(`runtime source is missing: ${relativePath}`);
    }
    if (stat.isSymbolicLink()) throw new Error(`runtime source may not traverse a symlink: ${relativePath}`);
  }
  const stat = fs.statSync(target);
  if (expectDirectory ? !stat.isDirectory() : !stat.isFile()) {
    throw new Error(`runtime source has the wrong type: ${relativePath}`);
  }
  return { target, stat };
}

function assertSafeRuntimeFile(relativePath, body) {
  const finding = inspectCustomerArtifact(relativePath, body);
  if (!finding) return;
  if (finding.kind === 'credential_file') {
    throw new Error(`customer runtime may not contain credential file ${relativePath}`);
  }
  if (finding.kind === 'private_key_material') {
    throw new Error(`customer runtime may not contain private key material in ${relativePath}`);
  }
  throw new Error(`customer runtime artifact exceeds the bounded scan ceiling: ${relativePath}`);
}

function customerPackageBody(body, packageScripts) {
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch (error) {
    throw new Error(`customer package metadata is invalid: ${error.message}`);
  }
  if (!plainObject(parsed) || !plainObject(parsed.scripts)) {
    throw new Error('customer package metadata is invalid');
  }
  for (const [name, command] of Object.entries(packageScripts)) {
    if (parsed.scripts[name] !== command) throw new Error(`customer package script drifted: ${name}`);
  }
  const output = { ...parsed, scripts: { ...packageScripts } };
  delete output.devDependencies;
  return Buffer.from(`${JSON.stringify(output, null, 2)}\n`, 'utf8');
}

function copyAuthoredFile(root, outDir, relativePath, packageScripts) {
  const { target: source, stat } = assertNoSymlinkPath(root, relativePath, false);
  const destination = path.join(outDir, ...relativePath.split('/'));
  const sourceBody = fs.readFileSync(source);
  const body = relativePath === 'package.json'
    ? customerPackageBody(sourceBody, packageScripts) : sourceBody;
  assertSafeRuntimeFile(relativePath, body);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, body, { flag: 'wx', mode: stat.mode & 0o777 });
}

function copyGeneratedTree(root, outDir, tree) {
  assertNoSymlinkPath(root, tree.source, true);
  const verified = verifyCustomerConsoleBuildReceipt({ root });
  const files = verified.receipt.files;
  for (const expected of files) {
    const relative = expected.path;
    const sourceRelative = `${tree.source}/${relative}`;
    const destinationRelative = `${tree.destination}/${relative}`;
    const { target: source, stat } = assertNoSymlinkPath(root, sourceRelative, false);
    const destination = path.join(outDir, ...destinationRelative.split('/'));
    const body = fs.readFileSync(source);
    if (stat.size !== expected.size || body.length !== expected.size
        || consoleBodyDigest(body) !== expected.sha256) {
      throw new Error(`customer console output changed during staging: ${relative}`);
    }
    assertSafeRuntimeFile(destinationRelative, body);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, body, { flag: 'wx', mode: stat.mode & 0o777 });
  }
  return files.map((entry) => `${tree.destination}/${entry.path}`);
}

function literalRelativeDependencies(source) {
  const dependencies = [];
  const pattern = /(?:require\s*\(\s*|import\s*\(\s*|(?:import|export)\s+(?:[^'\"]*?\s+from\s+)?)["'](\.{1,2}\/[^"']+)["']/g;
  let match;
  while ((match = pattern.exec(source))) dependencies.push(match[1]);
  return dependencies;
}

function dirnameJoinDependencies(source) {
  const dependencies = [];
  const expression = /path\.(?:join|resolve)\(\s*__dirname\s*,\s*((?:(?:['"][^'"]+['"])\s*,?\s*)+)\)/g;
  let match;
  while ((match = expression.exec(source))) {
    const argumentsText = match[1];
    const values = [];
    const literal = /(['"])([^'"]+)\1/g;
    let item;
    while ((item = literal.exec(argumentsText))) values.push(item[2]);
    const residue = argumentsText.replace(literal, '').replace(/[\s,]/g, '');
    if (!residue && values.length) {
      const joined = path.posix.normalize(values.join('/'));
      if (joined.endsWith('.js')) dependencies.push(`./${joined}`);
    }
  }
  return dependencies;
}

function resolveStagedDependency(outDir, fromFile, specifier) {
  const base = path.resolve(outDir, path.dirname(fromFile), specifier);
  if (!inside(path.resolve(outDir), base)) return null;
  const candidates = [base, `${base}.js`, `${base}.json`, path.join(base, 'index.js')];
  return candidates.find((candidate) => {
    try {
      return fs.statSync(candidate).isFile();
    } catch (_) {
      return false;
    }
  }) || null;
}

function verifyLocalDependencyClosure(outDir, authoredFiles) {
  const authored = new Set(authoredFiles);
  for (const relativePath of authoredFiles) {
    if (!relativePath.endsWith('.js')) continue;
    const body = fs.readFileSync(path.join(outDir, ...relativePath.split('/')), 'utf8');
    const dependencies = [
      ...literalRelativeDependencies(body),
      ...dirnameJoinDependencies(body),
    ];
    for (const specifier of dependencies) {
      const resolved = resolveStagedDependency(outDir, relativePath, specifier);
      const resolvedRelative = resolved
        ? path.relative(outDir, resolved).split(path.sep).join('/')
        : null;
      if (!resolved || !authored.has(resolvedRelative)) {
        throw new Error(`customer runtime local dependency is not staged: ${relativePath} -> ${specifier}`);
      }
    }
  }
}

function listStagedFiles(root) {
  const files = [];
  function visit(directory, prefix) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = path.join(directory, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) visit(absolute, relative);
      else if (entry.isFile()) files.push(relative);
      else throw new Error(`staged runtime contains an unsupported entry: ${relative}`);
    }
  }
  visit(root, '');
  return files.sort();
}

function stageCustomerRuntime(options = {}) {
  const root = path.resolve(options.root || path.join(__dirname, '..'));
  const outDir = path.resolve(options.outDir || '');
  const manifestPath = path.resolve(options.manifestPath || path.join(root, 'packaging', 'customer-runtime-files.json'));
  if (!options.outDir || outDir === root || inside(root, outDir)
      || inside(outDir, root) || fs.existsSync(outDir)) {
    throw new Error('customer runtime output must be a new directory outside the source tree');
  }
  const manifest = readManifest(manifestPath);
  fs.mkdirSync(outDir, { recursive: false, mode: 0o700 });
  let complete = false;
  try {
    for (const relativePath of manifest.authoredFiles) {
      copyAuthoredFile(root, outDir, relativePath, manifest.packageScripts);
    }
    const generatedFiles = manifest.generatedTrees.flatMap((tree) => copyGeneratedTree(root, outDir, tree));
    verifyLocalDependencyClosure(outDir, manifest.authoredFiles);
    const expected = [...manifest.authoredFiles, ...generatedFiles].sort();
    const actual = listStagedFiles(outDir);
    if (expected.length !== actual.length || expected.some((item, index) => item !== actual[index])) {
      throw new Error('customer runtime staged output differs from the positive inventory');
    }
    complete = true;
    return Object.freeze({ outDir, files: Object.freeze(actual), manifest });
  } finally {
    if (!complete) fs.rmSync(outDir, { recursive: true, force: true });
  }
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--root') options.root = argv[++index];
    else if (arg === '--out') options.outDir = argv[++index];
    else if (arg === '--manifest') options.manifestPath = argv[++index];
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.outDir) throw new Error('Usage: node scripts/stage-customer-runtime.js --out <new-directory>');
  return options;
}

function main(argv = process.argv.slice(2), consoleImpl = console) {
  try {
    const result = stageCustomerRuntime(parseArgs(argv));
    consoleImpl.log(`Staged ${result.files.length} customer runtime files in ${result.outDir}`);
    return 0;
  } catch (error) {
    consoleImpl.error(error.message);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = {
  DEFAULT_MANIFEST,
  REQUIRED_CUSTOMER_FILES,
  REQUIRED_CUSTOMER_PACKAGE_SCRIPTS,
  customerPackageBody,
  listStagedFiles,
  main,
  readManifest,
  stageCustomerRuntime,
  verifyLocalDependencyClosure,
};
