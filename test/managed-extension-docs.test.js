'use strict';
/** Managed extension deployment docs/examples must stay aligned with schema. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const schema = JSON.parse(fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'schema.json'), 'utf8'));
const managed = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'chrome-managed-storage.policy.json'), 'utf8'));
const extensionSettings = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'examples', 'chrome-extension-settings.example.json'), 'utf8'));
const guide = fs.readFileSync(path.join(root, 'docs', 'MANAGED_EXTENSION_DEPLOYMENT.md'), 'utf8');

test('managed storage example uses only schema-backed keys', () => {
  const allowed = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(managed)) assert.ok(allowed.has(key), key);
  for (const key of ['serverUrl', 'ingestKey', 'orgId']) assert.ok(key in managed, key);
  assert.strictEqual(managed.ingestKey, 'REPLACE_WITH_LONG_RANDOM_INGEST_KEY');
});

test('extension force-install example has placeholder id and update url', () => {
  assert.ok(extensionSettings.ExtensionSettings);
  assert.ok(extensionSettings.ExtensionSettings['<extension-id>']);
  assert.strictEqual(extensionSettings.ExtensionSettings['<extension-id>'].installation_mode, 'force_installed');
  assert.match(extensionSettings.ExtensionSettings['<extension-id>'].update_url, /^https:\/\//);
});

test('managed deployment guide warns about secret-bearing policy', () => {
  assert.match(guide, /Never put a real ingest key in source control/);
  assert.match(guide, /Treat managed policy as secret-bearing configuration/);
  assert.match(guide, /browser install-health heartbeat/i);
  assert.match(guide, /Coverage tab shows `browser_extension` install health/);
});
