'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  DEPLOYMENT_ID_RE,
  isDeploymentId,
} = require('../server/deployment-identity');

const DEPLOYMENT_A = 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DEPLOYMENT_B = 'dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

test('deployment identity accepts only the frozen exact production shape', () => {
  assert.equal(isDeploymentId(DEPLOYMENT_A), true);
  assert.equal(isDeploymentId(DEPLOYMENT_B), true);
  assert.equal(DEPLOYMENT_ID_RE.source, '^dep_[a-f0-9]{32}$');

  for (const value of [
    'deployment_alpha_001',
    'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'dep_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-',
    'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n',
    '', null, undefined, 1, {},
  ]) assert.equal(isDeploymentId(value), false, String(value));
});

test('exact sibling deployment identities remain distinct', () => {
  assert.notEqual(DEPLOYMENT_A, DEPLOYMENT_B);
  assert.equal(isDeploymentId(DEPLOYMENT_A), true);
  assert.equal(isDeploymentId(DEPLOYMENT_B), true);
});
