'use strict';

const {
  ACKNOWLEDGEMENT_DOMAIN,
  acknowledgementError,
  acknowledgementMac,
  checkedReceiptCore,
  checkedRecord,
  deepFreeze,
} = require('./audit-support-acknowledgement-protocol');

const SIGNER_BRAND = Symbol('audit-support-acknowledgement-signer');

function createReferenceAuditAcknowledgementSigner(options = {}) {
  assertReferenceRuntime();
  const record = checkedRecord(options);
  const signer = {
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    keyId: record.keyId,
    attest(rawReceipt) {
      const receipt = checkedReceiptCore(rawReceipt);
      if (receipt.customerId !== record.customerId
          || receipt.deploymentId !== record.deploymentId) {
        throw acknowledgementError('audit_acknowledgement_scope_mismatch');
      }
      return deepFreeze({
        ...receipt,
        acknowledgementKeyId: record.keyId,
        acknowledgementMac: acknowledgementMac(record.secret, record.keyId, receipt),
      });
    },
  };
  Object.defineProperty(signer, SIGNER_BRAND, { value: true });
  return Object.freeze(signer);
}

function isAuditAcknowledgementSigner(value) {
  return Boolean(value && value[SIGNER_BRAND] === true && typeof value.attest === 'function');
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw acknowledgementError('audit_acknowledgement_reference_runtime_forbidden');
  }
}

module.exports = Object.freeze({
  ACKNOWLEDGEMENT_DOMAIN,
  createReferenceAuditAcknowledgementSigner,
  isAuditAcknowledgementSigner,
});
