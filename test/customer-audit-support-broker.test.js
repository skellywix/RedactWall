'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  CustomerAuditSupportBroker,
} = require('../server/customer-audit-support-broker');

test('legacy positional decision and caller-summary APIs are absent', () => {
  assert.equal(CustomerAuditSupportBroker.prototype.decide.length, 1);
  assert.equal(CustomerAuditSupportBroker.prototype.respond.length, 1);
  assert.equal(CustomerAuditSupportBroker.prototype.receive.length, 1);
});

test('broker construction fails closed before accepting ungoverned dependencies', () => {
  assert.throws(() => new CustomerAuditSupportBroker({
    customerId: 'customer_alpha',
    deploymentId: 'dep_11111111111111111111111111111111',
    publicKeys: {},
    summaries: [],
    assurance: 'production',
    productionReady: true,
  }), (error) => error && error.code === 'audit_authority_manifest_required');
});
