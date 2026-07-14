'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const verifier = require('../server/audit-support-control-verifier');
const vendorFacade = require('../server/audit-support-control-artifacts');

const root = path.join(__dirname, '..');

test('vendor audit-support facade preserves the protocol API', () => {
  for (const name of [
    'assertAuditSupportCancellation', 'assertAuditSupportRequest', 'payloadDigest',
    'signAuditSupportCancellation', 'signAuditSupportRequest', 'signingInput',
    'verifyAuditSupportCancellation', 'verifyAuditSupportRequest',
  ]) {
    assert.equal(typeof vendorFacade[name], 'function', name);
  }
  assert.equal(vendorFacade.verifyAuditSupportRequest, verifier.verifyAuditSupportRequest);
  assert.equal(
    vendorFacade.verifyAuditSupportCancellation,
    verifier.verifyAuditSupportCancellation,
  );
});

test('customer audit-support modules import only the public verifier', () => {
  const verifierSource = source('server/audit-support-control-verifier.js');
  const brokerSource = source('server/customer-audit-support-broker.js');
  const storeSource = source('server/customer-audit-support-store.js');

  assert.doesNotMatch(verifierSource, /createPrivateKey\s*\(/);
  assert.doesNotMatch(verifierSource, /crypto\.sign\s*\(/);
  assert.doesNotMatch(verifierSource, /audit-support-control-artifacts/);
  assert.match(brokerSource, /require\('\.\/audit-support-control-verifier'\)/);
  assert.match(storeSource, /require\('\.\/audit-support-control-verifier'\)/);
  assert.doesNotMatch(brokerSource, /require\('\.\/audit-support-control-artifacts'\)/);
  assert.doesNotMatch(storeSource, /require\('\.\/audit-support-control-artifacts'\)/);
});

function source(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}
