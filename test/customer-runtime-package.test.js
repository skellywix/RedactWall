'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const {
  CONSOLE_BUILD_RECEIPT,
  buildCustomerConsole,
  verifyCustomerConsoleBuildReceipt,
  writeCustomerConsoleBuildReceipt,
} = require('../scripts/build-customer-console');
const {
  containsPrivateJwk,
  inspectCustomerArtifact,
} = require('../scripts/customer-secret-material-detector');
const {
  GNUTLS_PRIVATE_VECTOR_EXCEPTION,
  IMAGE_SCAN_ROOTS,
  containsPrivatePem,
  scanCustomerImage,
  scanCustomerImageRoots,
  validateGnutlsExceptionEvidence,
} = require('../scripts/verify-customer-image-content');
const {
  SCAN_COMMAND,
  validateCustomerDockerfile,
} = require('../scripts/validate-customer-dockerfile');

const {
  REQUIRED_CUSTOMER_FILES,
  listStagedFiles,
  readManifest,
  stageCustomerRuntime,
  verifyLocalDependencyClosure,
} = require('../scripts/stage-customer-runtime');

const root = path.join(__dirname, '..');
const manifestPath = path.join(root, 'packaging', 'customer-runtime-files.json');
const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');
const dockerignore = fs.readFileSync(path.join(root, '.dockerignore'), 'utf8');
const FORBIDDEN_CUSTOMER_FILES = Object.freeze([
  'scripts/license-issue.js',
  'server/audit-support-acknowledgement.js',
  'server/audit-support-control-artifacts.js',
  'server/customer-audit-response.js',
  'server/shadow-ai-sqlite.js',
  'server/vendor-audit-support-authority.js',
  'server/vendor-audit-support-sqlite.js',
  'server/vendor-authority-manifest.js',
  'server/vendor-diagnostic-customer-key-registry.js',
  'server/vendor-diagnostic-intelligence.js',
  'server/vendor-diagnostic-key-factory.js',
  'server/vendor-diagnostic-runtime.js',
  'server/vendor-diagnostic-sqlite.js',
  'server/vendor-diagnostic-witness-factory.js',
  'server/vendor-entitlement-lifecycle.js',
  'server/vendor-policy-authority.js',
  'server/vendor-policy-external-state.js',
  'server/vendor-policy-protocol.js',
  'server/vendor-policy-sqlite.js',
  'server/vendor-shadow-ai-intelligence.js',
  'server/vendor-shadow-ai-sqlite.js',
]);
const REQUIRED_SPLIT_CUSTOMER_FILES = Object.freeze([
  'server/connected-policy-state.js',
  'server/connected-policy-store.js',
  'server/policy-control-verifier.js',
  'server/customer-diagnostic-channel.js',
  'server/customer-diagnostic-outbox.js',
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
]);
function tempDirectory(t, prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function createDirectoryLink(t, target, link) {
  try {
    fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
    return true;
  } catch (error) {
    if (error.code !== 'EPERM') throw error;
    t.skip('directory symlinks are unavailable in this test environment');
    return false;
  }
}

function gpgHomeArgument(directory) {
  if (process.platform !== 'win32') return directory;
  const match = directory.match(/^([A-Za-z]):[\\/](.*)$/);
  return match ? `/${match[1].toLowerCase()}/${match[2].replace(/\\/g, '/')}` : directory;
}

function unquotedPrivateJwk(jwk) {
  return `{kty:${JSON.stringify(jwk.kty)},crv:${JSON.stringify(jwk.crv)},x:${JSON.stringify(jwk.x)},d:${JSON.stringify(jwk.d)}}`;
}

function refreshConsoleBuildReceipt(fixture) {
  const receiptPath = path.join(fixture, ...CONSOLE_BUILD_RECEIPT.split('/'));
  fs.rmSync(receiptPath, { force: true });
  return writeCustomerConsoleBuildReceipt({ root: fixture });
}

function mixedPrivateJwk(jwk) {
  return `{"kty":${JSON.stringify(jwk.kty)},crv:${JSON.stringify(jwk.crv)},"x":${JSON.stringify(jwk.x)},d:${JSON.stringify(jwk.d)}}`;
}

function copyInventoryFixture(t) {
  const fixture = tempDirectory(t, 'redactwall-customer-runtime-source-');
  const manifest = readManifest(manifestPath);
  for (const relativePath of manifest.authoredFiles) {
    const source = path.join(root, ...relativePath.split('/'));
    const destination = path.join(fixture, ...relativePath.split('/'));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(source, destination);
  }
  const generated = path.join(fixture, 'server', 'public', 'app');
  fs.mkdirSync(path.join(generated, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(generated, 'index.html'), '<!doctype html><title>RedactWall</title>\n');
  fs.writeFileSync(path.join(generated, 'assets', 'app.js'), "'use strict';\n");
  refreshConsoleBuildReceipt(fixture);
  return { fixture, manifest };
}

function writeMinimalFixture(t, appBody) {
  const fixture = tempDirectory(t, 'redactwall-customer-runtime-minimal-');
  const authoredFiles = [...new Set([
    ...REQUIRED_CUSTOMER_FILES,
    'packaging/customer-runtime-files.json',
  ])].sort();
  const packageScripts = {
    backup: 'node scripts/backup-store.js create',
    'evidence:pack': 'node scripts/export-evidence-pack.js',
    gateway: 'node gateway/server.js',
    'license:trust-check': 'node scripts/check-license-trust-anchor.js',
    start: 'node server/app.js',
  };
  const manifest = {
    schemaVersion: 1,
    artifact: 'redactwall-customer-runtime',
    packageScripts,
    authoredFiles,
    generatedTrees: [{
      source: 'server/public/app',
      destination: 'server/public/app',
    }],
  };
  for (const relativePath of authoredFiles) {
    const target = path.join(fixture, ...relativePath.split('/'));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    let body = relativePath.endsWith('.json') ? '{}\n' : "'use strict';\n";
    if (relativePath === 'package.json') {
      body = `${JSON.stringify({
        name: 'customer-runtime-fixture',
        version: '1.0.0',
        private: true,
        main: 'server/app.js',
        scripts: packageScripts,
        devDependencies: { forbidden: '1.0.0' },
      }, null, 2)}\n`;
    }
    if (relativePath === 'server/app.js') body = appBody;
    if (relativePath === 'scripts/docker-entrypoint.sh') body = '#!/bin/sh\n';
    fs.writeFileSync(target, body);
  }
  fs.writeFileSync(
    path.join(fixture, 'packaging', 'customer-runtime-files.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  fs.mkdirSync(path.join(fixture, 'server', 'public', 'app'), { recursive: true });
  fs.writeFileSync(path.join(fixture, 'server', 'public', 'app', 'index.html'), '<!doctype html>\n');
  refreshConsoleBuildReceipt(fixture);
  return { fixture, manifestPath: path.join(fixture, 'packaging', 'customer-runtime-files.json') };
}

test('customer runtime manifest is an exact positive inventory with split customer authorities only', () => {
  const manifest = readManifest(manifestPath);
  const files = new Set(manifest.authoredFiles);
  assert.ok(manifest.authoredFiles.length > 150, 'the complete customer runtime is explicitly enumerated');
  for (const required of REQUIRED_SPLIT_CUSTOMER_FILES) assert.ok(files.has(required), required);
  for (const forbidden of FORBIDDEN_CUSTOMER_FILES) assert.strictEqual(files.has(forbidden), false, forbidden);
  assert.ok(files.has('server/vendor-signed-artifact.js'), 'public signed-artifact verifier remains available');
  assert.ok(files.has('server/vendor-control-client.js'), 'customer-to-vendor transport remains available');
  assert.ok(files.has('scripts/ai-llm-gateway.js'), 'deployable app-to-LLM gateway remains available');
  assert.ok(files.has('scripts/ai-gateway-rate-limiter.js'), 'gateway rate limiter remains available');
  assert.ok(files.has('scripts/squid-icap-bridge.js'), 'deployable ICAP backstop remains available');
  assert.ok(files.has('scripts/import-ai-discovery.js'), 'customer-local Shadow AI import remains available');
  assert.ok(files.has('scripts/backup-store.js'), 'AWS recovery command remains available');
  assert.ok(files.has('scripts/export-evidence-pack.js'), 'AWS evidence command remains available');
  assert.ok(files.has('scripts/run-evidence-pack.sh'), 'AWS host timer helper remains available');
  assert.ok(files.has('test/fixtures/semantic-eval.json'), 'runtime detector-quality proof retains its synthetic corpus');
  for (const indirectRuntime of [
    'server/parse-child.js',
    'server/storage/pg-worker.js',
    'sensors/mcp-guard/connectors/database-readonly-worker.js',
  ]) assert.ok(files.has(indirectRuntime), indirectRuntime);
  assert.strictEqual(manifest.generatedTrees[0].source, 'server/public/app');
  assert.ok(manifest.authoredFiles.every((file) => !file.startsWith('owner-platform/')));
  assert.deepStrictEqual(Object.keys(manifest.packageScripts), [...Object.keys(manifest.packageScripts)].sort());
  for (const forbiddenScript of [
    'license:issue', 'setup', 'setup:prod', 'silo:deploy', 'test', 'console:build',
  ]) assert.strictEqual(Object.hasOwn(manifest.packageScripts, forbiddenScript), false, forbiddenScript);
});

test('customer runtime staging copies only inventory and generated console files', (t) => {
  const { fixture, manifest } = copyInventoryFixture(t);
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-output-parent-'), 'runtime');
  const result = stageCustomerRuntime({
    root: fixture,
    outDir: output,
    manifestPath: path.join(fixture, 'packaging', 'customer-runtime-files.json'),
  });
  const expected = [
    ...manifest.authoredFiles,
    'server/public/app/assets/app.js',
    'server/public/app/index.html',
  ].sort();
  assert.deepStrictEqual(result.files, expected);
  assert.deepStrictEqual(listStagedFiles(output), expected);
  const customerPackage = JSON.parse(fs.readFileSync(path.join(output, 'package.json'), 'utf8'));
  assert.deepStrictEqual(customerPackage.scripts, manifest.packageScripts);
  assert.strictEqual(Object.hasOwn(customerPackage, 'devDependencies'), false);
  for (const forbidden of FORBIDDEN_CUSTOMER_FILES) {
    assert.strictEqual(fs.existsSync(path.join(output, ...forbidden.split('/'))), false, forbidden);
  }
  const checks = ['server/app.js', 'gateway/server.js', 'server/storage/pg-worker.js'];
  for (const relativePath of checks) {
    const checked = spawnSync(process.execPath, ['--check', path.join(output, ...relativePath.split('/'))], {
      encoding: 'utf8',
      windowsHide: true,
    });
    assert.strictEqual(checked.status, 0, checked.stderr || checked.stdout);
  }
});

test('customer runtime manifest rejects a reintroduced vendor issuance command', (t) => {
  const fixture = tempDirectory(t, 'redactwall-customer-package-command-');
  const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  parsed.packageScripts['license:issue'] = 'node scripts/check-license-trust-anchor.js';
  parsed.packageScripts = Object.fromEntries(Object.entries(parsed.packageScripts).sort());
  const changedManifest = path.join(fixture, 'manifest.json');
  fs.writeFileSync(changedManifest, `${JSON.stringify(parsed)}\n`);
  assert.throws(() => readManifest(changedManifest), /customer package script is forbidden: license:issue/);
});

test('customer console build starts from an absent output and drops a rogue sentinel', (t) => {
  const fixture = tempDirectory(t, 'redactwall-customer-console-');
  const output = path.join(fixture, 'server', 'public', 'app');
  const sentinel = path.join(output, 'rogue-vendor-authority.js');
  const staleReceipt = path.join(fixture, ...CONSOLE_BUILD_RECEIPT.split('/'));
  fs.mkdirSync(output, { recursive: true });
  fs.writeFileSync(sentinel, 'must not ship\n');
  fs.writeFileSync(staleReceipt, '{"stale":true}\n');
  buildCustomerConsole({
    root: fixture,
    runBuild(_root, outDir) {
      assert.strictEqual(fs.existsSync(sentinel), false, 'sentinel is gone before the builder runs');
      assert.strictEqual(fs.existsSync(staleReceipt), false, 'stale receipt is gone before the builder runs');
      fs.mkdirSync(path.join(outDir, 'assets'), { recursive: true });
      fs.writeFileSync(path.join(outDir, 'index.html'), '<!doctype html>\n');
      fs.writeFileSync(path.join(outDir, 'assets', 'app.js'), "'use strict';\n");
      return { status: 0 };
    },
  });
  assert.strictEqual(fs.existsSync(sentinel), false);
  assert.strictEqual(fs.existsSync(path.join(output, 'index.html')), true);
  assert.strictEqual(fs.existsSync(path.join(fixture, ...CONSOLE_BUILD_RECEIPT.split('/'))), true);
  assert.strictEqual(verifyCustomerConsoleBuildReceipt({ root: fixture }).receipt.files.length, 2);
});

test('customer runtime rejects vendor authorities inserted into the generated tree after its build receipt', (t) => {
  const mutations = [
    ['server/vendor-policy-authority.js', 'vendor-policy-authority.js'],
    ['server/vendor-entitlement-lifecycle.js', 'vendor-entitlement-lifecycle.js'],
    ['server/vendor-audit-support-authority.js', 'owner-control-route.js'],
  ];
  for (const [sourceRelative, generatedName] of mutations) {
    const { fixture } = copyInventoryFixture(t);
    const generated = path.join(fixture, 'server', 'public', 'app', 'assets', generatedName);
    fs.copyFileSync(path.join(root, ...sourceRelative.split('/')), generated);
    const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-generated-rogue-'), 'runtime');
    assert.throws(() => stageCustomerRuntime({
      root: fixture,
      outDir: output,
      manifestPath: path.join(fixture, 'packaging', 'customer-runtime-files.json'),
    }), /customer console output differs from its exact build receipt/);
    assert.strictEqual(fs.existsSync(output), false);
  }
});

test('customer runtime rejects replacement of a receipt-bound console asset with vendor code', (t) => {
  const { fixture } = copyInventoryFixture(t);
  const generated = path.join(fixture, 'server', 'public', 'app', 'assets', 'app.js');
  fs.copyFileSync(path.join(root, 'server', 'vendor-policy-authority.js'), generated);
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-generated-replacement-'), 'runtime');
  assert.throws(() => stageCustomerRuntime({
    root: fixture,
    outDir: output,
    manifestPath: path.join(fixture, 'packaging', 'customer-runtime-files.json'),
  }), /customer console output changed after build: assets\/app\.js/);
  assert.strictEqual(fs.existsSync(output), false);
});

test('customer runtime manifest rejects traversal paths', (t) => {
  const fixture = tempDirectory(t, 'redactwall-customer-runtime-traversal-');
  const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  parsed.authoredFiles[0] = '../vendor-private-key.pem';
  const changedManifest = path.join(fixture, 'manifest.json');
  fs.writeFileSync(changedManifest, `${JSON.stringify(parsed)}\n`);
  assert.throws(() => readManifest(changedManifest), /canonical relative POSIX path/);
});

test('customer runtime staging rejects an authored directory symlink', (t) => {
  const minimal = writeMinimalFixture(t, "'use strict';\n");
  const external = tempDirectory(t, 'redactwall-customer-runtime-external-gateway-');
  fs.renameSync(path.join(minimal.fixture, 'gateway'), path.join(external, 'gateway'));
  if (!createDirectoryLink(t, path.join(external, 'gateway'), path.join(minimal.fixture, 'gateway'))) return;
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-symlink-parent-'), 'runtime');
  assert.throws(() => stageCustomerRuntime({
    root: minimal.fixture,
    outDir: output,
    manifestPath: minimal.manifestPath,
  }), /may not traverse a symlink/);
  assert.strictEqual(fs.existsSync(output), false);
});

test('customer runtime staging rejects a generated console symlink', (t) => {
  const minimal = writeMinimalFixture(t, "'use strict';\n");
  const generated = path.join(minimal.fixture, 'server', 'public', 'app');
  const external = tempDirectory(t, 'redactwall-customer-runtime-external-console-');
  fs.renameSync(generated, path.join(external, 'app'));
  if (!createDirectoryLink(t, path.join(external, 'app'), generated)) return;
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-generated-link-parent-'), 'runtime');
  assert.throws(() => stageCustomerRuntime({
    root: minimal.fixture,
    outDir: output,
    manifestPath: minimal.manifestPath,
  }), /may not traverse a symlink/);
  assert.strictEqual(fs.existsSync(output), false);
});

test('customer runtime staging rejects a listed credential file extension', (t) => {
  const minimal = writeMinimalFixture(t, "'use strict';\n");
  const parsed = JSON.parse(fs.readFileSync(minimal.manifestPath, 'utf8'));
  parsed.authoredFiles.push('server/connected-private.key');
  parsed.authoredFiles.sort();
  fs.writeFileSync(minimal.manifestPath, `${JSON.stringify(parsed, null, 2)}\n`);
  fs.writeFileSync(path.join(minimal.fixture, 'server', 'connected-private.key'), 'not-even-a-key\n');
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-extension-parent-'), 'runtime');
  assert.throws(() => stageCustomerRuntime({
    root: minimal.fixture,
    outDir: output,
    manifestPath: minimal.manifestPath,
  }), /credential file/);
  assert.strictEqual(fs.existsSync(output), false);
});

test('customer runtime staging fails when a listed module has an unstaged local dependency', (t) => {
  const staged = tempDirectory(t, 'redactwall-customer-runtime-closure-');
  fs.mkdirSync(path.join(staged, 'server'), { recursive: true });
  fs.writeFileSync(path.join(staged, 'server', 'app.js'), "require('./missing-authority');\n");
  assert.throws(
    () => verifyLocalDependencyClosure(staged, ['server/app.js']),
    /server\/app\.js -> \.\/missing-authority/,
  );
});

test('customer runtime staging rejects private key material even when a manifest lists it', (t) => {
  const fixture = writeMinimalFixture(t, [
    "'use strict';",
    'const embedded = `-----BEGIN PRIVATE KEY-----',
    'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB',
    '-----END PRIVATE KEY-----`;',
    'module.exports = embedded;',
    '',
  ].join('\n'));
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-key-parent-'), 'runtime');
  assert.throws(
    () => stageCustomerRuntime({
      root: fixture.fixture,
      outDir: output,
      manifestPath: fixture.manifestPath,
    }),
    /private key material/,
  );
  assert.strictEqual(fs.existsSync(output), false, 'failed staging removes only its newly-created output');
});

test('shared detector rejects embedded private JWK and JWKS material in arbitrary text', () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const cases = [
    Buffer.from(`prefix:${JSON.stringify({ nested: { keys: [privateJwk] } })}:suffix`),
    Buffer.from(`window.__fixture = ${JSON.stringify({ keys: [privateJwk] })};`),
    Buffer.from(`const embedded = '${JSON.stringify(privateJwk).replaceAll("'", "\\'")}';`),
    Buffer.from(`const escaped = ${JSON.stringify(JSON.stringify({ nested: privateJwk }))};`),
    Buffer.from(`arbitrary-extension\u0000${JSON.stringify(privateJwk)}\u0000tail`),
    Buffer.from(`const symmetric=${JSON.stringify({
      kty: 'oct',
      k: Buffer.alloc(32, 0x41).toString('base64url'),
    })};`),
    Buffer.from(`const publicFirst=${JSON.stringify({
      kty: 'OKP', crv: 'Ed25519', x: privateJwk.x,
    })};const privateSecond=${JSON.stringify(privateJwk)};`),
    Buffer.from(`const privateLiteral=${unquotedPrivateJwk(privateJwk)};`),
    Buffer.from(`prefix:${mixedPrivateJwk(privateJwk)}:suffix`),
    Buffer.from(`const symmetric={kty:"oct",k:${JSON.stringify(
      Buffer.alloc(32, 0x42).toString('base64url'),
    )}};`),
    Buffer.from(`const publicFirst={kty:"OKP",crv:"Ed25519",x:${JSON.stringify(
      privateJwk.x,
    )}};const privateSecond=${unquotedPrivateJwk(privateJwk)};`),
  ];
  for (const body of cases) {
    assert.strictEqual(containsPrivateJwk(body), true);
    assert.deepStrictEqual(inspectCustomerArtifact('assets/generated.opaque', body), {
      kind: 'private_key_material',
    });
  }
  assert.strictEqual(containsPrivateJwk(Buffer.from([
    'const publicMetadata = {',
    '  kty: "OKP", crv: "Ed25519",',
    '  x: "11qYAYdk9JtS3U4Jx_FV2A-zxRGhZ2aZ8cF8wK9f1TI"',
    '};',
  ].join('\n'))), false);
  assert.strictEqual(containsPrivateJwk(Buffer.from([
    `const publicMetadata={kty:"OKP",crv:"Ed25519",x:${JSON.stringify(privateJwk.x)}};`,
    `const unrelatedPrivateScalar={d:${JSON.stringify(privateJwk.d)}};`,
  ].join(''))), false, 'fields from adjacent objects are not combined');
  assert.strictEqual(
    containsPrivateJwk(Buffer.from('{kty:"OKP"]')),
    false,
    'malformed dependency text cannot stop detector progress',
  );
});

test('customer runtime staging rejects authored unquoted private JWK object literals', (t) => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const fixture = writeMinimalFixture(t, [
    "'use strict';",
    `const embedded=${unquotedPrivateJwk(privateJwk)};`,
    'module.exports=embedded;',
    '',
  ].join('\n'));
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-unquoted-jwk-'), 'runtime');
  assert.throws(() => stageCustomerRuntime({
    root: fixture.fixture,
    outDir: output,
    manifestPath: fixture.manifestPath,
  }), /private key material/);
  assert.strictEqual(fs.existsSync(output), false);
});

test('customer runtime staging applies the shared detector to generated console assets', (t) => {
  const minimal = writeMinimalFixture(t, "'use strict';\n");
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const asset = path.join(minimal.fixture, 'server', 'public', 'app', 'generated.opaque');
  fs.writeFileSync(asset, `window.__private=${unquotedPrivateJwk(privateJwk)};\n`);
  refreshConsoleBuildReceipt(minimal.fixture);
  const output = path.join(tempDirectory(t, 'redactwall-customer-runtime-jwk-parent-'), 'runtime');
  assert.throws(() => stageCustomerRuntime({
    root: minimal.fixture,
    outDir: output,
    manifestPath: minimal.manifestPath,
  }), /private key material/);
  assert.strictEqual(fs.existsSync(output), false);
});

test('customer image scan covers dependencies and usr-local private keys and credentials', (t) => {
  const imageRoot = tempDirectory(t, 'redactwall-customer-image-');
  const dependency = path.join(imageRoot, 'app', 'node_modules', 'example');
  const local = path.join(imageRoot, 'usr', 'local', 'lib', 'example');
  fs.mkdirSync(dependency, { recursive: true });
  fs.mkdirSync(local, { recursive: true });
  fs.writeFileSync(path.join(dependency, 'index.js'), "const example = '-----BEGIN PRIVATE KEY-----\\nXXXX\\n-----END PRIVATE KEY-----';\n");
  assert.ok(scanCustomerImage(imageRoot).files >= 1, 'benign documentation pattern is not a key');

  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privatePath = path.join(local, 'opaque-fixture.txt');
  fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  assert.throws(() => scanCustomerImage(imageRoot), /private key material: usr[\\/]local/);
  fs.rmSync(privatePath);

  const privateJwk = privateKey.export({ format: 'jwk' });
  for (const [filename, source] of [
    ['private.json', JSON.stringify({ keys: [privateJwk] })],
    ['private.jwk', JSON.stringify(privateJwk)],
    ['private.jwks', JSON.stringify({ keys: [privateJwk] })],
    ['private.txt', JSON.stringify({ nested: { keys: [privateJwk] } })],
    ['symmetric.txt', JSON.stringify({ kty: 'oct', k: Buffer.alloc(32, 0x41).toString('base64url') })],
    ['unquoted-private.opaque', `prefix=${unquotedPrivateJwk(privateJwk)};suffix`],
    ['mixed-private.min.js', `window.privateKey=${mixedPrivateJwk(privateJwk)};`],
    ['unquoted-oct.asset', `const secret={kty:"oct",k:${JSON.stringify(
      Buffer.alloc(32, 0x43).toString('base64url'),
    )}};`],
    ['adjacent-private.bundle', `const publicKey={kty:"OKP",crv:"Ed25519",x:${JSON.stringify(
      privateJwk.x,
    )}};const privateKey=${unquotedPrivateJwk(privateJwk)};`],
  ]) {
    const jwkPath = path.join(local, filename);
    fs.writeFileSync(jwkPath, `${source}\n`);
    assert.throws(() => scanCustomerImage(imageRoot), /private key material/);
    fs.rmSync(jwkPath);
  }

  const credentialPath = path.join(dependency, '.env.production');
  fs.writeFileSync(credentialPath, 'OWNER_PRIVATE_KEY=fixture\n');
  assert.throws(() => scanCustomerImage(imageRoot), /credential file: app[\\/]node_modules/);
});

test('customer image scan covers every durable root and skips only virtual runtime mounts', (t) => {
  assert.deepStrictEqual(IMAGE_SCAN_ROOTS, ['/']);
  const imageRoot = tempDirectory(t, 'redactwall-customer-authority-roots-');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  for (const durableRoot of [
    'app', 'data', 'etc', 'gateway-data', 'home', 'license', 'opt', 'root',
    'run', 'tmp', 'usr/share', 'var/lib',
  ]) {
    const directory = path.join(imageRoot, ...durableRoot.split('/'));
    fs.mkdirSync(directory, { recursive: true });
    const artifact = path.join(directory, 'hostile.opaque');
    fs.writeFileSync(artifact, privatePem);
    assert.throws(() => scanCustomerImage(imageRoot), /private key material/, durableRoot);
    fs.rmSync(artifact);
  }
  for (const virtualRoot of ['dev', 'proc', 'sys']) {
    const directory = path.join(imageRoot, virtualRoot);
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'runtime-only.opaque'), privatePem);
  }
  assert.strictEqual(scanCustomerImageRoots([imageRoot]).files, 0);
});

test('GnuTLS exception requires canonical package ownership, integrity, and exact content identity', () => {
  const exact = {
    relativePath: GNUTLS_PRIVATE_VECTOR_EXCEPTION.relativePath,
    realPath: GNUTLS_PRIVATE_VECTOR_EXCEPTION.absolutePath,
    stat: {
      isFile: true,
      isSymbolicLink: false,
      uid: 0,
      gid: 0,
      mode: GNUTLS_PRIVATE_VECTOR_EXCEPTION.mode,
      nlink: 1,
      size: GNUTLS_PRIVATE_VECTOR_EXCEPTION.size,
    },
    packageOwner: GNUTLS_PRIVATE_VECTOR_EXCEPTION.packageOwner,
    packageStatus: GNUTLS_PRIVATE_VECTOR_EXCEPTION.packageStatus,
    manifestStat: {
      isFile: true,
      isSymbolicLink: false,
      uid: 0,
      gid: 0,
      mode: 0o644,
      nlink: 1,
    },
    manifestMatches: 1,
    md5: GNUTLS_PRIVATE_VECTOR_EXCEPTION.md5,
    sha256: GNUTLS_PRIVATE_VECTOR_EXCEPTION.sha256,
  };
  assert.strictEqual(validateGnutlsExceptionEvidence(exact), true);
  for (const mutated of [
    { relativePath: `opt/${path.posix.basename(exact.relativePath)}` },
    { realPath: '/opt/relocated-vector.so' },
    { stat: { ...exact.stat, uid: 1000 } },
    { stat: { ...exact.stat, nlink: 2 } },
    { packageOwner: 'unowned' },
    { packageStatus: 'ii  replacement:amd64 0' },
    { manifestMatches: 0 },
    { md5: '0'.repeat(32) },
    { sha256: '0'.repeat(64) },
  ]) {
    assert.throws(
      () => validateGnutlsExceptionEvidence({ ...exact, ...mutated }),
      /GnuTLS package exception rejected/,
    );
  }
});

test('customer image scanner recognizes structurally valid OpenPGP secret-key armor', () => {
  const secretPacket = Buffer.concat([Buffer.from([0xc5, 0x08]), Buffer.alloc(8, 0x41)]);
  const armor = [
    '-----BEGIN PGP PRIVATE KEY BLOCK-----',
    '',
    secretPacket.toString('base64'),
    '-----END PGP PRIVATE KEY BLOCK-----',
    '',
  ].join('\n');
  assert.strictEqual(containsPrivatePem(Buffer.from(armor)), true);
});

test('customer image scanner rejects a real GnuPG-exported Ed25519 secret key', (t) => {
  const available = spawnSync('gpg', ['--version'], { encoding: 'utf8', windowsHide: true });
  if (available.status !== 0) {
    t.skip('gpg is unavailable; structural OpenPGP coverage remains mandatory above');
    return;
  }
  const home = tempDirectory(t, 'redactwall-customer-gpg-');
  fs.chmodSync(home, 0o700);
  const gpgHome = gpgHomeArgument(home);
  const identity = `RedactWall Packaging Fixture ${crypto.randomUUID()} <packaging@example.invalid>`;
  const generated = spawnSync('gpg', [
    '--batch', '--homedir', gpgHome, '--pinentry-mode', 'loopback', '--passphrase', '',
    '--quick-generate-key', identity, 'ed25519', 'sign', '0',
  ], { encoding: 'utf8', timeout: 30_000, windowsHide: true });
  assert.strictEqual(generated.status, 0, generated.stderr);
  const exported = spawnSync('gpg', [
    '--batch', '--homedir', gpgHome, '--armor', '--export-secret-keys', identity,
  ], { encoding: 'utf8', timeout: 30_000, windowsHide: true });
  spawnSync('gpgconf', ['--homedir', gpgHome, '--kill', 'gpg-agent'], { windowsHide: true });
  assert.strictEqual(exported.status, 0, exported.stderr);
  assert.match(exported.stdout, /BEGIN PGP PRIVATE KEY BLOCK/);
  assert.strictEqual(containsPrivatePem(Buffer.from(exported.stdout)), true);
});

test('Docker final stage consumes only the validated customer runtime staging tree', () => {
  assert.match(dockerfile, /^# syntax=docker\/dockerfile:1\.7$/m);
  assert.match(dockerfile, /^COPY package\.json package-lock\.json \.\/$/m);
  assert.match(dockerfile, /^COPY console\/package\.json console\/package-lock\.json \.\/console\/$/m);
  assert.match(dockerfile, /^COPY scripts\/build-customer-console\.js \.\/scripts\/build-customer-console\.js$/m);
  assert.match(dockerfile, /^COPY console\/ \.\/console\/$/m);
  assert.match(dockerfile, /node scripts\/stage-customer-runtime\.js --out \/tmp\/customer-runtime/);
  assert.match(dockerfile, /RUN node scripts\/build-customer-console\.js/);
  assert.match(dockerfile, /RUN node scripts\/validate-customer-dockerfile\.js Dockerfile/);
  assert.ok(
    dockerfile.indexOf('RUN node scripts/build-customer-console.js')
      < dockerfile.indexOf('COPY . .'),
    'the console build completes before vendor and server source enters the builder',
  );
  const validation = validateCustomerDockerfile(dockerfile);
  assert.strictEqual(validation.scanCommand, SCAN_COMMAND);
  assert.match(dockerignore, /^test\/\*$/m);
  assert.match(dockerignore, /^test\/fixtures\/\*$/m);
  assert.match(dockerignore, /^!test\/fixtures\/semantic-eval\.json$/m);
  assert.match(dockerignore, /^server\/public\/app$/m);
  assert.match(dockerignore, /^server\/public\/\.customer-console-build\.json$/m);
  assert.ok(
    dockerfile.indexOf('/tmp/customer-runtime/ ./')
      < dockerfile.indexOf('node scripts/check-license-trust-anchor.js'),
    'the public offline trust-anchor gate runs against the staged customer runtime',
  );
  assert.match(dockerfile, /rm -f \/etc\/ssl\/private\/ssl-cert-snakeoil\.key/);
  for (const rootPath of IMAGE_SCAN_ROOTS) assert.match(SCAN_COMMAND, new RegExp(`--root ${rootPath.replace('/', '\\/')}`));
  assert.ok(
    dockerfile.indexOf('mkdir -p /data')
      < dockerfile.indexOf('node scripts/verify-customer-image-content.js'),
    'the immutable image scan runs after the final filesystem mutation',
  );
});

test('Docker complete source gate rejects builder and runtime ingress mutations', () => {
  const allowed = 'COPY --from=artifact-builder --chown=node:node /tmp/customer-runtime/ ./';
  const beforeScan = '# Scan the complete durable filesystem after the final COPY and mutation.';
  const mutations = [
    dockerfile.replace(allowed, `${allowed}\ncopy --from=artifact-builder /app/server/vendor-policy-authority.js ./server/`),
    dockerfile.replace(allowed, `${allowed}\nAdD server/vendor-policy-authority.js ./server/`),
    dockerfile.replace(allowed, `${allowed}\ncOpY --from=artifact-builder \\\n+      /app/server/vendor-policy-authority.js \\\n+      ./server/`),
    dockerfile.replace(beforeScan, `RUN --mount=type=bind,from=artifact-builder,source=/app/server,target=/mnt,ro cp /mnt/vendor-policy-authority.js /app/server/\n${beforeScan}`),
    dockerfile.replace(beforeScan, `RUN --mount=type=bind,source=server,target=/mnt,ro cp /mnt/vendor-policy-authority.js /app/server/\n${beforeScan}`),
    dockerfile.replace(beforeScan, `RUN printf vendor > /app/server/vendor-policy-authority.js\n${beforeScan}`),
    dockerfile.replace(beforeScan, `ENV OWNER_PRIVATE_SIGNING_KEY=forbidden\n${beforeScan}`),
    dockerfile.replace('FROM postgres:17-bookworm AS runtime', 'FROM example.invalid/vendor-runtime:latest AS runtime'),
    dockerfile.replace('# syntax=docker/dockerfile:1.7', '# syntax=example.invalid/hostile/frontend:latest'),
    dockerfile.replace('COPY console/ ./console/', 'COPY console/ ./console/\nCOPY server/vendor-policy-authority.js ./console/vendor-policy-authority.js'),
    dockerfile.replace('RUN node scripts/build-customer-console.js', 'COPY . .\nRUN node scripts/build-customer-console.js'),
    dockerfile.replace('COPY scripts/build-customer-console.js ./scripts/build-customer-console.js', 'COPY scripts/ ./scripts/'),
    dockerfile.replace('COPY . .', 'copy server/vendor-policy-authority.js /tmp/vendor-authority.js\nCOPY . .'),
    dockerfile.replace('COPY . .', 'cOpY server/vendor-policy-authority.js \\\n+      /tmp/vendor-authority.js\nCOPY . .'),
    dockerfile.replace('COPY . .', 'ADD server/vendor-policy-authority.js /tmp/vendor-authority.js\nCOPY . .'),
    dockerfile.replace('COPY . .', 'ONBUILD COPY . /tmp/late-context\nCOPY . .'),
    dockerfile.replace('COPY . .', 'RUN --mount=type=bind,source=server,target=/mnt cp /mnt/vendor-policy-authority.js /usr/local/bin/rogue\nCOPY . .'),
    dockerfile.replace('COPY . .', 'RUN --mount=type=bind,from=artifact-builder,source=/app,target=/mnt cp /mnt/server/vendor-policy-authority.js /usr/local/bin/rogue\nCOPY . .'),
    dockerfile.replace('WORKDIR /app', 'ENV OWNER_PRIVATE_SIGNING_KEY=forbidden\nWORKDIR /app'),
    dockerfile.replace('WORKDIR /app', 'RUN printf hostile > /usr/local/bin/rogue\nWORKDIR /app'),
    dockerfile.replace('FROM node:22-bookworm-slim AS production-dependencies', 'FROM example.invalid/changed-builder:latest AS production-dependencies'),
    dockerfile.replace('FROM node:22-bookworm-slim AS production-dependencies', 'FROM node:22-bookworm-slim AS injected\nRUN true\nFROM node:22-bookworm-slim AS production-dependencies'),
  ];
  for (const mutated of mutations) {
    assert.throws(() => validateCustomerDockerfile(mutated), /customer Dockerfile rejected/);
  }
});

test('Docker gate rejects every instruction after the final authority scan', () => {
  const mutated = dockerfile.replace('\nUSER node', '\nRUN touch /app/post-scan-bypass\nUSER node');
  assert.throws(() => validateCustomerDockerfile(mutated), /instructions after the authority scan/);
});
