'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const policySource = fs.readFileSync(path.join(__dirname, '..', 'console', 'src', 'views', 'Policy.tsx'), 'utf8');

function constArraySource(name) {
  const declaration = policySource.indexOf(`const ${name}`);
  assert.notStrictEqual(declaration, -1, `${name} declaration must exist`);
  const start = policySource.indexOf('[', declaration);
  assert.notStrictEqual(start, -1, `${name} must be an array`);
  let depth = 0;
  for (let index = start; index < policySource.length; index += 1) {
    if (policySource[index] === '[') depth += 1;
    if (policySource[index] !== ']') continue;
    depth -= 1;
    if (depth === 0) return policySource.slice(start, index + 1);
  }
  assert.fail(`${name} array must close`);
}

function stringLiterals(source) {
  return [...source.matchAll(/'([a-z0-9_-]+)'/g)].map((match) => match[1]);
}

test('visible Policy readiness groups partition every expected preflight check exactly once', () => {
  const expected = stringLiterals(constArraySource('EXPECTED_PREFLIGHT_CHECK_IDS'));
  const groupsSource = constArraySource('ENV_GROUPS');
  const groups = [...groupsSource.matchAll(/ids:\s*\[([\s\S]*?)\]/g)].map((match) => stringLiterals(match[1]));
  const keys = [...groupsSource.matchAll(/key:\s*'([a-z0-9-]+)'/g)].map((match) => match[1]);
  const grouped = groups.flat();
  const duplicates = grouped.filter((id, index) => grouped.indexOf(id) !== index);

  assert.strictEqual(expected.length, 43, 'the current preflight contract has 43 expected checks');
  assert.strictEqual(new Set(expected).size, expected.length, 'expected readiness contract must not contain duplicates');
  assert.ok(groups.length > 0, 'at least one visible readiness group must exist');
  assert.ok(groups.every((ids) => ids.length > 0), 'visible readiness groups must not be empty');
  assert.strictEqual(keys.length, groups.length, 'every visible readiness group must have a stable key');
  assert.strictEqual(new Set(keys).size, keys.length, 'visible readiness group keys must be unique');
  assert.deepStrictEqual([...new Set(duplicates)], [], 'a readiness check must not appear in multiple visible groups');
  assert.deepStrictEqual(grouped.slice().sort(), expected.slice().sort(), 'visible groups must cover the exact expected readiness contract');
});
