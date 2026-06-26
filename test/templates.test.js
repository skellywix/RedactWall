'use strict';
/** Regulation policy templates (src/templates.js). node --test */
const test = require('node:test');
const assert = require('node:assert');
const T = require('../src/templates');

test('every template is well-formed', () => {
  const list = T.list();
  assert.ok(list.length >= 5);
  for (const t of list) {
    assert.ok(t.id && t.label && t.description, 'has id/label/description');
    assert.ok(t.policy && typeof t.policy.enforcementMode === 'string', 'has enforcement mode');
    assert.ok(Array.isArray(t.policy.alwaysBlock) && t.policy.alwaysBlock.length, 'has hard-stops');
  }
});
test('NCUA/GLBA hard-stops member NPI (SSN, routing, DOB)', () => {
  const p = T.get('ncua_glba').policy;
  for (const e of ['US_SSN', 'ROUTING_NUMBER', 'DOB']) assert.ok(p.alwaysBlock.includes(e), 'blocks ' + e);
});
test('all templates hard-stop planted canary tokens', () => {
  for (const t of T.list()) assert.ok(t.policy.alwaysBlock.includes('CANARY_TOKEN'), t.id);
});
test('redact-first template uses redact mode', () => {
  assert.strictEqual(T.get('redact_first').policy.enforcementMode, 'redact');
});
test('unknown template id returns null', () => {
  assert.strictEqual(T.get('nope'), null);
});
