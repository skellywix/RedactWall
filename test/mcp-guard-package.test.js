'use strict';
/** MCP guard package must be pilot-ready and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AdmZip = require('adm-zip');

const {
  packageMcpGuard,
  parseArgs,
  sha256,
  validateRuntimeFiles,
} = require('../scripts/package-mcp-guard');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-mcp-guard-package-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('package script writes a prompt-free MCP guard zip and integrity manifest', (t) => {
  const outDir = tempDir(t);
  const result = packageMcpGuard({ outDir, now: new Date('2026-06-26T12:00:00.000Z') });
  assert.ok(fs.existsSync(result.zipPath));
  assert.ok(fs.existsSync(result.manifestPath));

  const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  const zipBody = fs.readFileSync(result.zipPath);
  assert.strictEqual(manifest.kind, 'promptsentinel-mcp-guard-package');
  assert.strictEqual(manifest.sha256, sha256(zipBody));
  assert.strictEqual(manifest.appVersion, JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version);
  assert.strictEqual(manifest.checks.explicitIngestKeyRequired, true);
  assert.strictEqual(manifest.checks.sharedEngineIncluded, true);
  assert.strictEqual(manifest.checks.demoCodeExcluded, true);
  assert.strictEqual(manifest.checks.developmentIngestKeyAbsent, true);
  assert.strictEqual(manifest.checks.promptBodiesAbsent, true);

  const zip = new AdmZip(result.zipPath);
  const entries = zip.getEntries().map((entry) => entry.entryName).sort();
  for (const required of ['package.json', 'mcp-guard/guard.js', 'shared/detect.js', 'src/env.js']) {
    assert.ok(entries.includes(required), required);
    assert.ok(manifest.files.some((file) => file.path === required), required);
  }

  const guard = zip.readAsText('mcp-guard/guard.js');
  assert.match(guard, /process\.env\.INGEST_API_KEY \|\| ''/);
  assert.doesNotMatch(guard, /demo when run directly|dev-ingest-key|524-71-9043|4111 1111 1111 1111/);
  assert.doesNotMatch(JSON.stringify(manifest), /prompt\s*:/i);
  assert.doesNotMatch(JSON.stringify(manifest), /524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY/);
});

test('package validation refuses prompt bodies or development keys', () => {
  assert.throws(
    () => validateRuntimeFiles([
      { path: 'package.json', body: Buffer.from('{}') },
      { path: 'src/env.js', body: Buffer.from('module.exports = {};') },
      { path: 'shared/detect.js', body: Buffer.from('module.exports = {};') },
      { path: 'mcp-guard/guard.js', body: Buffer.from("const KEY = process.env.INGEST_API_KEY || '';\nconst sample = '524-71-9043';") },
    ]),
    /synthetic SSN demo value/
  );

  assert.throws(
    () => validateRuntimeFiles([
      { path: 'package.json', body: Buffer.from('{}') },
      { path: 'src/env.js', body: Buffer.from('module.exports = {};') },
      { path: 'shared/detect.js', body: Buffer.from('module.exports = {};') },
      { path: 'mcp-guard/guard.js', body: Buffer.from("const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';") },
    ]),
    /development ingest key/
  );
});

test('package args support explicit output directories', () => {
  const parsed = parseArgs(['--out', 'dist/custom-mcp']);
  assert.match(parsed.outDir, /dist[\\/]custom-mcp$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
});
