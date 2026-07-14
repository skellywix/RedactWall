'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_ID,
  createCustomerDiagnosticIntegrityAuthority,
  customerDiagnosticIntegrityStatus,
} = require('../server/customer-diagnostic-integrity');

const SECRET = Buffer.alloc(32, 0x51).toString('base64');

test('customer diagnostic integrity uses one fixed customer-only HMAC identity', () => {
  const authority = createCustomerDiagnosticIntegrityAuthority({
    secret: SECRET,
    env: {},
  });
  const proof = authority.sign('redactwall.customer-diagnostic.test\0message');
  assert.deepEqual(Object.keys(proof), ['keyId', 'mac']);
  assert.equal(proof.keyId, CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_ID);
  assert.match(proof.mac, /^[a-f0-9]{64}$/);
  assert.equal(authority.verify('redactwall.customer-diagnostic.test\0message', proof), true);
  assert.equal(authority.verify('redactwall.customer-diagnostic.test\0changed', proof), false);
  assert.equal(Object.hasOwn(authority, 'secret'), false);
});

test('customer diagnostic integrity requires canonical Base64 for exactly 32 bytes', () => {
  for (const secret of [
    undefined,
    '',
    ' '.repeat(44),
    Buffer.alloc(31).toString('base64'),
    Buffer.alloc(33).toString('base64'),
    SECRET.replace(/=$/, ''),
    `${SECRET}\n`,
    '-----BEGIN PRIVATE KEY-----',
  ]) {
    assert.throws(
      () => createCustomerDiagnosticIntegrityAuthority({ secret, env: {} }),
      (error) => error && error.code === 'CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_INVALID'
        && !String(error.message).includes(String(secret || 'missing-secret-marker')),
    );
  }
});

test('customer diagnostic integrity refuses every configured channel or customer authority collision', () => {
  const collisionNames = [
    'REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN',
    'REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN',
    'REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN',
    'REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN',
    'REDACTWALL_AUDIT_KEY',
    'REDACTWALL_SECRET',
    'REDACTWALL_DATA_KEY',
    'REDACTWALL_DATA_KEY_PREVIOUS',
    'REDACTWALL_CUSTOMER_POLICY_INTEGRITY_KEY',
    'REDACTWALL_CUSTOMER_AUDIT_WITNESS_KEY',
  ];
  for (const name of collisionNames) {
    assert.throws(
      () => createCustomerDiagnosticIntegrityAuthority({
        secret: SECRET,
        env: { [name]: SECRET },
      }),
      (error) => error && error.code === 'CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY_REUSED',
      name,
    );
  }
  const distinct = createCustomerDiagnosticIntegrityAuthority({
    secret: SECRET,
    env: { REDACTWALL_AUDIT_KEY: crypto.randomBytes(32).toString('base64') },
  });
  assert.equal(distinct.verify('x', distinct.sign('x')), true);
});

test('preflight status only requires the integrity key when diagnostics consent is exact true', () => {
  assert.deepEqual(customerDiagnosticIntegrityStatus({
    REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED: 'false',
  }), { enabled: false, ok: true, reason: null });
  assert.equal(customerDiagnosticIntegrityStatus({
    REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED: 'true',
  }).ok, false);
  assert.deepEqual(customerDiagnosticIntegrityStatus({
    REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED: 'true',
    REDACTWALL_CUSTOMER_DIAGNOSTIC_INTEGRITY_KEY: SECRET,
  }), { enabled: true, ok: true, reason: null });
});
