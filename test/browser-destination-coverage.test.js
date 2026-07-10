'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const extensionDir = path.join(root, 'sensors', 'browser-extension');
const manifest = JSON.parse(fs.readFileSync(path.join(extensionDir, 'manifest.json'), 'utf8'));
const background = fs.readFileSync(path.join(extensionDir, 'background.js'), 'utf8');

test('administrator-configured HTTPS destinations have runtime interception wiring', () => {
  assert.ok(manifest.permissions.includes('scripting'));
  assert.ok(manifest.permissions.includes('declarativeNetRequest'));
  assert.deepStrictEqual(manifest.optional_host_permissions, ['https://*/*']);
  assert.match(background, /registerContentScripts/);
  assert.match(background, /updateDynamicRules/);
});

