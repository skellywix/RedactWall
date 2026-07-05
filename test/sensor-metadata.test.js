'use strict';
/** Sensor metadata sanitizers: bounded, trimmed, and null-when-empty. */
const test = require('node:test');
const assert = require('node:assert');
const { safeSensor, safeSensorVersionGap, safeTextField } = require('../server/sensor-metadata');

test('safeTextField trims, enforces a max length, and rejects non-strings', () => {
  assert.strictEqual(safeTextField('  hello  '), 'hello');
  assert.strictEqual(safeTextField(''), null);
  assert.strictEqual(safeTextField('   '), null);
  assert.strictEqual(safeTextField(42), null);
  assert.strictEqual(safeTextField(null), null);
  assert.strictEqual(safeTextField('x'.repeat(200)).length, 80);
  assert.strictEqual(safeTextField('x'.repeat(200), 10).length, 10);
});

test('safeSensor keeps only known fields and drops empties', () => {
  assert.deepStrictEqual(safeSensor({
    name: 'browser_extension',
    version: '0.3.0',
    packageVersion: '',
    platform: 'chrome_mv3',
    secretField: 'should be dropped',
  }), {
    name: 'browser_extension',
    version: '0.3.0',
    platform: 'chrome_mv3',
  });
});

test('safeSensor returns null for missing or empty input', () => {
  assert.strictEqual(safeSensor(null), null);
  assert.strictEqual(safeSensor('nope'), null);
  assert.strictEqual(safeSensor({}), null);
  assert.strictEqual(safeSensor({ name: '   ' }), null);
});

test('safeSensorVersionGap bounds versions to 8 and normalizes event counts', () => {
  const gap = safeSensorVersionGap({
    source: 'fleet',
    label: 'browser extension',
    versionHealth: 'behind',
    latestVersion: '0.3.0',
    desiredVersion: '0.3.0',
    versions: Array.from({ length: 12 }, (_, i) => ({ version: `0.${i}.0`, events: i - 2, lastSeen: '2026-07-04' })),
    platforms: ['win32', 'darwin', 'linux', 'chrome', 'edge', 'firefox', 'safari', 'ios', 'android'],
  });
  assert.strictEqual(gap.versions.length, 8);
  assert.strictEqual(gap.platforms.length, 8);
  assert.strictEqual(gap.versions[0].events, 0, 'negative event counts clamp to 0');
  assert.strictEqual(gap.versions[3].events, 1);
  assert.strictEqual(gap.source, 'fleet');
});

test('safeSensorVersionGap drops versions without a version string and returns null when empty', () => {
  const gap = safeSensorVersionGap({ versions: [{ events: 5 }], platforms: ['', '  '] });
  assert.strictEqual(gap, null);
  assert.strictEqual(safeSensorVersionGap(null), null);
  assert.strictEqual(safeSensorVersionGap({}), null);
});

test('safeSensorVersionGap truncates a long lastSeen to 64 chars', () => {
  const gap = safeSensorVersionGap({ source: 's', versions: [{ version: '1.0.0', lastSeen: 'z'.repeat(200) }] });
  assert.strictEqual(gap.versions[0].lastSeen.length, 64);
});
