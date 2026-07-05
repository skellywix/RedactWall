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

test('approvers can decide unassigned records in the shared pool', () => {
  const approver = { user: 'reviewer@example.test', role: roles.APPROVER };

  assert.strictEqual(roles.canDecideQuery(approver, { assignedRole: roles.APPROVER }), true, 'pooled record with no assignee');
  assert.strictEqual(roles.canDecideQuery(approver, { assignedRole: roles.APPROVER, assignedUser: '' }), true, 'empty assignee counts as pooled');
  assert.strictEqual(roles.canDecideQuery(approver, { assignedRole: roles.SECURITY_ADMIN }), false, 'record routed to admins is off limits');
  assert.strictEqual(roles.canDecideQuery(approver, {}), false, 'record with no assigned role is off limits');
});

test('normalizeRole accepts only known roles regardless of casing and whitespace', () => {
  assert.strictEqual(roles.normalizeRole(' Approver '), roles.APPROVER);
  assert.strictEqual(roles.normalizeRole('SECURITY_ADMIN'), roles.SECURITY_ADMIN);
  assert.strictEqual(roles.normalizeRole('superuser'), '');
  assert.strictEqual(roles.normalizeRole(null), '');
});

test('loginAuditAction maps each role to its audit action and falls back to LOGIN', () => {
  assert.strictEqual(roles.loginAuditAction(roles.SECURITY_ADMIN), 'ADMIN_LOGIN');
  assert.strictEqual(roles.loginAuditAction(roles.APPROVER), 'APPROVER_LOGIN');
  assert.strictEqual(roles.loginAuditAction(roles.AUDITOR), 'AUDITOR_LOGIN');
  assert.strictEqual(roles.loginAuditAction(roles.OPERATOR), 'OPERATOR_LOGIN');
  assert.strictEqual(roles.loginAuditAction('unknown-role'), 'LOGIN');
  assert.strictEqual(roles.loginAuditAction(undefined), 'LOGIN');
});
