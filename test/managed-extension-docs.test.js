'use strict';
/** Managed extension deployment docs/examples must stay aligned with schema. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const schema = JSON.parse(fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'schema.json'), 'utf8'));
const managed = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'browser-managed-storage.policy.json'), 'utf8'));
const firefoxManaged = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'firefox-managed-storage.policy.json'), 'utf8'));
const chromeExtensionSettings = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'chrome-extension-settings.example.json'), 'utf8'));
const edgeExtensionSettings = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'edge-extension-settings.example.json'), 'utf8'));
const firefoxExtensionSettings = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'firefox-extension-settings.example.json'), 'utf8'));
const guide = fs.readFileSync(path.join(root, 'docs', 'deployment', 'MANAGED_EXTENSION_DEPLOYMENT.md'), 'utf8');
const releaseChecklist = fs.readFileSync(path.join(root, 'docs', 'deployment', 'EXTENSION_RELEASE_CHECKLIST.md'), 'utf8');

test('managed storage example uses only schema-backed keys', () => {
  const allowed = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(managed)) assert.ok(allowed.has(key), key);
  for (const key of ['serverUrl', 'ingestKey', 'orgId']) assert.ok(key in managed, key);
  assert.strictEqual(managed.ingestKey, 'REPLACE_WITH_LONG_RANDOM_INGEST_KEY');
});

test('Firefox managed storage example uses schema-backed keys', () => {
  const values = firefoxManaged.policies['3rdparty'].Extensions['redactwall@example.com'];
  const allowed = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(values)) assert.ok(allowed.has(key), key);
  assert.strictEqual(values.ingestKey, 'REPLACE_WITH_LONG_RANDOM_INGEST_KEY');
});

test('extension force-install examples have placeholder ids and update/install urls', () => {
  assert.ok(chromeExtensionSettings.ExtensionSettings['<extension-id>']);
  assert.strictEqual(chromeExtensionSettings.ExtensionSettings['<extension-id>'].installation_mode, 'force_installed');
  assert.match(chromeExtensionSettings.ExtensionSettings['<extension-id>'].update_url, /^https:\/\//);
  assert.ok(edgeExtensionSettings.ExtensionSettings['<extension-id>']);
  assert.strictEqual(edgeExtensionSettings.ExtensionSettings['<extension-id>'].installation_mode, 'force_installed');
  assert.match(edgeExtensionSettings.ExtensionSettings['<extension-id>'].update_url, /edge\.microsoft\.com/);
  assert.strictEqual(firefoxExtensionSettings.policies.ExtensionSettings['redactwall@example.com'].installation_mode, 'force_installed');
  assert.match(firefoxExtensionSettings.policies.ExtensionSettings['redactwall@example.com'].install_url, /^https:\/\//);
});

test('managed deployment guide warns about secret-bearing policy', () => {
  assert.match(guide, /Never put a real ingest key in source control/);
  assert.match(guide, /Treat managed policy as secret-bearing configuration/);
  assert.match(guide, /browser install-health heartbeat/i);
  assert.match(guide, /Coverage tab shows `browser_extension` install health/);
  assert.match(guide, /release:extension:check/);
  assert.match(guide, /Chrome, Edge, and Firefox/);
});

test('release checklist covers private rollout, update channel, and rollback', () => {
  assert.match(releaseChecklist, /Browser extension release checklist/);
  assert.match(releaseChecklist, /npm run release:extension:check/);
  assert.match(releaseChecklist, /https:\/\/clients2\.google\.com\/service\/update2\/crx/);
  assert.match(releaseChecklist, /https:\/\/edge\.microsoft\.com\/extensionwebstorebase\/v1\/crx/);
  assert.match(releaseChecklist, /redactwall@example\.com/);
  assert.match(releaseChecklist, /Fleet Install Health/);
  assert.match(releaseChecklist, /Rollback/);
});
