'use strict';

const {
  ACKNOWLEDGEMENT_DOMAIN,
  acknowledgementError,
  checkedReceipt,
  checkedRecord,
  deepFreeze,
  exactKeys,
  plainObject,
  receiptCore,
  scopeKey,
  secretFingerprint,
  verifyAcknowledgementMac,
} = require('./audit-support-acknowledgement-protocol');
const {
  createReferenceAuditAcknowledgementSigner,
  isAuditAcknowledgementSigner,
} = require('./customer-audit-support-acknowledgement');

const REGISTRY_BRAND = Symbol('audit-support-acknowledgement-registry');

function createReferenceAuditAcknowledgementRegistry(options = {}) {
  assertReferenceRuntime();
  if (!plainObject(options) || !exactKeys(options, ['records'])
      || !Array.isArray(options.records) || options.records.length < 1
      || options.records.length > 100_000) {
    throw acknowledgementError('audit_acknowledgement_registry_invalid');
  }
  const records = new Map();
  const keyIds = new Set();
  const secretFingerprints = new Set();
  for (const raw of options.records) {
    const record = checkedRecord(raw);
    const scope = scopeKey(record.customerId, record.deploymentId, record.keyId);
    const fingerprint = secretFingerprint(record.secret);
    if (records.has(scope) || keyIds.has(record.keyId)
        || secretFingerprints.has(fingerprint)) {
      throw acknowledgementError('audit_acknowledgement_registry_invalid');
    }
    records.set(scope, record);
    keyIds.add(record.keyId);
    secretFingerprints.add(fingerprint);
  }
  const registry = {
    verify(rawReceipt) {
      const receipt = checkedReceipt(rawReceipt);
      const record = records.get(scopeKey(
        receipt.customerId, receipt.deploymentId, receipt.acknowledgementKeyId,
      ));
      if (!record) throw acknowledgementError('audit_acknowledgement_unknown_key');
      const core = receiptCore(receipt);
      if (!verifyAcknowledgementMac(
        record.secret, record.keyId, core, receipt.acknowledgementMac,
      )) throw acknowledgementError('audit_acknowledgement_invalid');
      return deepFreeze(core);
    },
  };
  Object.defineProperty(registry, REGISTRY_BRAND, { value: true });
  return Object.freeze(registry);
}

function createProductionAuditAcknowledgementRegistry() {
  throw acknowledgementError('audit_acknowledgement_production_adapter_unavailable');
}

function isAuditAcknowledgementRegistry(value) {
  return Boolean(value && value[REGISTRY_BRAND] === true && typeof value.verify === 'function');
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw acknowledgementError('audit_acknowledgement_reference_runtime_forbidden');
  }
}

module.exports = Object.freeze({
  ACKNOWLEDGEMENT_DOMAIN,
  createProductionAuditAcknowledgementRegistry,
  createReferenceAuditAcknowledgementRegistry,
  createReferenceAuditAcknowledgementSigner,
  isAuditAcknowledgementRegistry,
  isAuditAcknowledgementSigner,
});
