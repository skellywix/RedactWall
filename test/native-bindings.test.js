'use strict';
/** Native addon checks should fail early with an actionable CI error. */
const test = require('node:test');
const assert = require('node:assert');
const {
  checkNativeBinding,
  isNativeBindingFailure,
} = require('../scripts/ensure-native-bindings');

test('better-sqlite3 native binding can construct a database', () => {
  assert.doesNotThrow(() => checkNativeBinding());
});

test('native binding failure classifier recognizes missing binding errors', () => {
  assert.strictEqual(isNativeBindingFailure(new Error('Could not locate the bindings file for better_sqlite3.node')), true);
  assert.strictEqual(isNativeBindingFailure(new Error('ordinary validation error')), false);
});
