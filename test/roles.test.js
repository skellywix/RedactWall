'use strict';
/** Role helpers enforce approval ownership without relying on display casing. */
const test = require('node:test');
const assert = require('node:assert');

const roles = require('../server/roles');

test('approver ownership compares assigned users as normalized principals', () => {
  const user = { user: 'Reviewer@Example.Test', role: roles.APPROVER };
  const assigned = { assignedRole: roles.APPROVER, assignedUser: ' reviewer@example.test ' };
  const otherReviewer = { assignedRole: roles.APPROVER, assignedUser: 'other@example.test' };

  assert.strictEqual(roles.canDecideQuery(user, assigned), true);
  assert.strictEqual(roles.canDecideQuery(user, otherReviewer), false);
});

test('security admins can decide any assigned record and unknown roles cannot decide', () => {
  const query = { assignedRole: roles.SECURITY_ADMIN, assignedUser: 'other@example.test' };

  assert.strictEqual(roles.canDecideQuery({ user: 'admin', role: roles.SECURITY_ADMIN }, query), true);
  assert.strictEqual(roles.canDecideQuery({ user: 'operator', role: roles.OPERATOR }, query), false);
  assert.strictEqual(roles.canDecideQuery({ user: 'auditor', role: roles.AUDITOR }, query), false);
});
