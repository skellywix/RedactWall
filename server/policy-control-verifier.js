'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');

const POLICY_KEY_PURPOSE = 'policy';

const GLOBAL_POLICY_KIND = 'policy.global-release.v1';
const GLOBAL_POLICY_SIGNATURE_DOMAIN = 'redactwall.vendor-global-policy.v1';
const OWNER_APPROVAL_KIND = 'policy.owner-approval.v1';
const OWNER_APPROVAL_SIGNATURE_DOMAIN = 'redactwall.owner-policy-approval.v1';
const POLICY_CONTROL_SCHEMA_VERSION = 2;
const MAX_GLOBAL_POLICY_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_POLICY_KEY_ID_BYTES = 64;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const POLICY_KEY_ID_RE = /^rw-policy-[a-z0-9][a-z0-9_.-]{0,53}$/;
const OWNER_APPROVAL_KEY_ID_RE = /^rw-owner-policy-approval-[a-z0-9][a-z0-9_.-]{0,38}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function policyGlobalSigningInput(payload, keyId) {
  const checked = assertGlobalPolicyPayload(payload);
  const normalizedKeyId = checkedPolicyKeyId(keyId);
  return Buffer.from(
    `${GLOBAL_POLICY_SIGNATURE_DOMAIN}\0${normalizedKeyId}\0${protocol.canonicalJson(checked)}`,
    'utf8',
  );
}

function verifyGlobalPolicyRelease(artifact, trust) {
  const snapshot = checkedArtifact(artifact);
  const checkedTrust = normalizePolicyTrust(trust);
  const key = resolveFreshPolicyKey(checkedTrust, snapshot.keyId);
  assertTrustedPolicyKey(snapshot.keyId, key, snapshot.payload.keyEpoch, checkedTrust);
  assertRegistryPolicyKey(checkedTrust.authorityRegistry, snapshot.keyId, key, false);
  return verifyGlobalSignature(snapshot, key);
}

function verifyPersistedGlobalPolicyRelease(artifact, trust) {
  const snapshot = checkedArtifact(artifact);
  const checkedTrust = normalizePolicyTrust(trust);
  const key = resolveHistoricalPolicyKey(checkedTrust.authorityRegistry, snapshot.keyId);
  assertTrustedPolicyKey(snapshot.keyId, key, snapshot.payload.keyEpoch, checkedTrust);
  return verifyGlobalSignature(snapshot, key);
}

function verifyGlobalSignature(snapshot, key) {
  const signature = strictBase64(snapshot.signature, 64, 'policy_global_signature_invalid');
  if (!crypto.verify(null, policyGlobalSigningInput(snapshot.payload, snapshot.keyId), key, signature)) {
    throw fault('policy_global_signature_invalid');
  }
  return deepFreeze({
    keyId: snapshot.keyId,
    payload: snapshot.payload,
    artifactDigest: policyGlobalArtifactDigest(snapshot),
  });
}

function ownerApprovalSigningInput(payload, keyId) {
  const checked = assertOwnerApprovalPayload(payload);
  const normalizedKeyId = checkedOwnerApprovalKeyId(keyId);
  return Buffer.from(
    `${OWNER_APPROVAL_SIGNATURE_DOMAIN}\0${normalizedKeyId}\0${protocol.canonicalJson(checked)}`,
    'utf8',
  );
}

function verifyOwnerApproval(artifact, trust) {
  return verifyOwnerApprovalWithTrust(artifact, trust);
}

function verifyPersistedOwnerApproval(artifact, trust) {
  return verifyOwnerApprovalWithTrust(artifact, trust);
}

function verifyOwnerApprovalWithTrust(artifact, trust) {
  const snapshot = checkedOwnerApprovalArtifact(artifact);
  const checkedTrust = normalizeOwnerApprovalTrust(trust);
  const key = resolvePublicKey(checkedTrust.publicKeys, snapshot.keyId);
  assertTrustedKeyEpoch(snapshot.keyId, key, snapshot.payload.keyEpoch, checkedTrust,
    OWNER_APPROVAL_KEY_ID_RE, 'owner_approval');
  const signature = strictBase64(snapshot.signature, 64, 'owner_approval_signature_invalid');
  if (!crypto.verify(null, ownerApprovalSigningInput(snapshot.payload, snapshot.keyId), key, signature)) {
    throw fault('owner_approval_signature_invalid');
  }
  return deepFreeze({
    keyId: snapshot.keyId,
    payload: snapshot.payload,
    artifactDigest: digestCanonical(snapshot),
  });
}

function policyGlobalArtifactDigest(artifact) {
  const snapshot = checkedArtifact(artifact);
  return digestCanonical(snapshot);
}

function assertGlobalPolicyPayload(value) {
  assertPlainTree(value, 'policy_global_payload_invalid');
  if (!plainRecord(value) || !exactKeys(value, [
    'approvalAttestationDigest', 'bundleDigest', 'globalReleaseId', 'globalVersion',
    'historyEpoch', 'issuedAt', 'keyEpoch', 'kind', 'mandatoryControlsDigest',
    'previousGlobalVersion', 'rollbackOfGlobalVersion', 'schemaVersion',
  ]) || value.schemaVersion !== POLICY_CONTROL_SCHEMA_VERSION
      || value.kind !== GLOBAL_POLICY_KIND
      || !UUID_RE.test(String(value.globalReleaseId || ''))
      || !safeVersion(value.globalVersion, 1)
      || !safeVersion(value.previousGlobalVersion, 0)
      || value.previousGlobalVersion !== value.globalVersion - 1
      || !safeVersion(value.historyEpoch, 1)
      || !safeVersion(value.keyEpoch, 1)
      || !SHA256_RE.test(String(value.approvalAttestationDigest || ''))
      || !SHA256_RE.test(String(value.bundleDigest || ''))
      || !SHA256_RE.test(String(value.mandatoryControlsDigest || ''))
      || !canonicalIso(value.issuedAt)) {
    throw fault('policy_global_payload_invalid');
  }
  if (value.rollbackOfGlobalVersion !== null
      && (!safeVersion(value.rollbackOfGlobalVersion, 1)
        || value.rollbackOfGlobalVersion >= value.globalVersion)) {
    throw fault('policy_global_payload_invalid');
  }
  return clone(value);
}

function assertOwnerApprovalPayload(value) {
  assertPlainTree(value, 'owner_approval_payload_invalid');
  if (!plainRecord(value) || !exactKeys(value, [
    'approvalId', 'approvedAt', 'approverActorId', 'expiresAt', 'keyEpoch', 'kind',
    'operationDigest', 'purpose', 'schemaVersion',
  ]) || value.schemaVersion !== POLICY_CONTROL_SCHEMA_VERSION
      || value.kind !== OWNER_APPROVAL_KIND || !UUID_RE.test(String(value.approvalId || ''))
      || !/^[a-z0-9][a-z0-9_.:-]{0,127}$/.test(String(value.approverActorId || ''))
      || !['policy_global_publish', 'policy_global_rollback', 'policy_deployment_rollback']
        .includes(value.purpose)
      || !SHA256_RE.test(String(value.operationDigest || ''))
      || !safeVersion(value.keyEpoch, 1) || !canonicalIso(value.approvedAt)
      || !canonicalIso(value.expiresAt) || Date.parse(value.expiresAt) <= Date.parse(value.approvedAt)) {
    throw fault('owner_approval_payload_invalid');
  }
  return clone(value);
}

function policyDeliveryDigest(binding) {
  return digestCanonical(assertPolicyDeliveryBinding(binding));
}

function assertPolicyDeliveryBinding(value) {
  assertPlainTree(value, 'policy_delivery_binding_invalid');
  if (!plainRecord(value) || !exactKeys(value, [
    'customerId', 'deploymentId', 'desiredOverlayDigest', 'distributionSequence',
    'effectivePolicyDigest', 'emergencyDenyDigest', 'expiresAt', 'globalArtifactDigest',
    'globalBundleDigest', 'globalKeyEpoch', 'globalReleaseId', 'globalVersion', 'historyEpoch', 'issuedAt',
    'mandatoryControlsDigest', 'messageId', 'previousDistributionSequence', 'rollout',
    'policyKeyEpoch', 'rollbackOfDistributionSequence', 'schemaVersion', 'supersession',
  ]) || value.schemaVersion !== POLICY_CONTROL_SCHEMA_VERSION
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !UUID_RE.test(String(value.messageId || ''))
      || !safeVersion(value.distributionSequence, 1)
      || !safeVersion(value.previousDistributionSequence, 0)
      || value.previousDistributionSequence !== value.distributionSequence - 1
      || !safeVersion(value.historyEpoch, 1) || !safeVersion(value.policyKeyEpoch, 1)
      || !safeVersion(value.globalKeyEpoch, 1)
      || !UUID_RE.test(String(value.globalReleaseId || ''))
      || !safeVersion(value.globalVersion, 1)
      || !['preview', 'staged', 'required'].includes(value.rollout)
      || !canonicalIso(value.issuedAt) || !canonicalIso(value.expiresAt)
      || Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    throw fault('policy_delivery_binding_invalid');
  }
  for (const key of [
    'desiredOverlayDigest', 'effectivePolicyDigest', 'emergencyDenyDigest',
    'globalArtifactDigest', 'globalBundleDigest', 'mandatoryControlsDigest',
  ]) {
    if (!SHA256_RE.test(String(value[key] || ''))) throw fault('policy_delivery_binding_invalid');
  }
  if (value.rollbackOfDistributionSequence !== null
      && (!safeVersion(value.rollbackOfDistributionSequence, 1)
        || value.rollbackOfDistributionSequence >= value.distributionSequence)) {
    throw fault('policy_delivery_binding_invalid');
  }
  assertSupersession(value.supersession, value.distributionSequence);
  return clone(value);
}

function assertSupersession(value, distributionSequence) {
  if (value === null) return null;
  assertPlainTree(value, 'policy_supersession_invalid');
  if (!plainRecord(value) || !exactKeys(value, [
    'deliveryDigest', 'disposition', 'rejectionDigest', 'targetDigest', 'targetVersion',
  ]) || !safeVersion(value.targetVersion, 1) || value.targetVersion >= distributionSequence
      || !SHA256_RE.test(String(value.targetDigest || ''))
      || !SHA256_RE.test(String(value.deliveryDigest || ''))
      || !['expired', 'customer_rejected', 'recovery'].includes(value.disposition)
      || (value.disposition === 'customer_rejected') !== SHA256_RE.test(String(value.rejectionDigest || ''))
      || (value.disposition !== 'customer_rejected' && value.rejectionDigest !== null)) {
    throw fault('policy_supersession_invalid');
  }
  return clone(value);
}

function createPolicyControlEnvelope(value) {
  assertPlainTree(value, 'policy_control_envelope_invalid');
  if (!plainRecord(value) || !exactKeys(value, [
    'deliveryBinding', 'deliveryDigest', 'desiredOverlay', 'emergencyDenyOverlay',
    'globalArtifact', 'globalPolicy', 'schemaVersion',
  ]) || value.schemaVersion !== POLICY_CONTROL_SCHEMA_VERSION) {
    throw fault('policy_control_envelope_invalid');
  }
  const deliveryBinding = assertPolicyDeliveryBinding(value.deliveryBinding);
  if (value.deliveryDigest !== policyDeliveryDigest(deliveryBinding)) {
    throw fault('policy_delivery_digest_mismatch');
  }
  checkedArtifact(value.globalArtifact);
  assertPlainTree(value.globalPolicy, 'policy_control_envelope_invalid');
  assertPlainTree(value.desiredOverlay, 'policy_control_envelope_invalid');
  assertPlainTree(value.emergencyDenyOverlay, 'policy_control_envelope_invalid');
  return deepFreeze(clone(value));
}

function assertArtifactSize(artifact) {
  let bytes;
  try { bytes = Buffer.byteLength(protocol.canonicalJson(artifact), 'utf8'); }
  catch { throw fault('policy_global_artifact_invalid'); }
  if (bytes > MAX_GLOBAL_POLICY_ARTIFACT_BYTES) throw fault('policy_global_artifact_too_large');
}

function checkedArtifact(value) {
  assertPlainTree(value, 'policy_global_artifact_invalid');
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'payload', 'signature'])) {
    throw fault('policy_global_artifact_invalid');
  }
  const artifact = {
    keyId: checkedPolicyKeyId(value.keyId),
    payload: assertGlobalPolicyPayload(value.payload),
    signature: String(value.signature || ''),
  };
  strictBase64(artifact.signature, 64, 'policy_global_artifact_invalid');
  assertArtifactSize(artifact);
  return clone(artifact);
}

function checkedOwnerApprovalArtifact(value) {
  assertPlainTree(value, 'owner_approval_artifact_invalid');
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'payload', 'signature'])) {
    throw fault('owner_approval_artifact_invalid');
  }
  const artifact = {
    keyId: checkedOwnerApprovalKeyId(value.keyId),
    payload: assertOwnerApprovalPayload(value.payload),
    signature: String(value.signature || ''),
  };
  strictBase64(artifact.signature, 64, 'owner_approval_artifact_invalid');
  return clone(artifact);
}

function resolvePublicKey(value, keyId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fault('policy_public_keys_invalid');
  }
  const raw = value instanceof Map ? value.get(keyId) : value[keyId];
  if (!raw) throw fault('unknown_policy_signing_key');
  if (containsPrivateTrustPin(raw)) throw fault('policy_private_trust_pin_rejected');
  let key;
  try { key = raw instanceof crypto.KeyObject ? raw : crypto.createPublicKey(raw); }
  catch { throw fault('policy_public_keys_invalid'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw fault('policy_public_keys_invalid');
  }
  return key;
}

function containsPrivateTrustPin(value) {
  if (value instanceof crypto.KeyObject) return value.type === 'private';
  if (typeof value === 'string' || Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    const text = Buffer.from(value).toString('utf8');
    return /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/.test(text);
  }
  if (!plainRecord(value)) return false;
  if (Object.hasOwn(value, 'd')) return true;
  if (value.format === 'der' && value.type === 'pkcs8') return true;
  return Object.hasOwn(value, 'key') && containsPrivateTrustPin(value.key);
}

function checkedPolicyKeyId(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_POLICY_KEY_ID_BYTES
      || !POLICY_KEY_ID_RE.test(value)) throw fault('policy_key_id_invalid');
  return value;
}

function checkedOwnerApprovalKeyId(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_POLICY_KEY_ID_BYTES
      || !OWNER_APPROVAL_KEY_ID_RE.test(value)) throw fault('owner_approval_key_id_invalid');
  return value;
}

function normalizePolicyTrust(value) {
  return normalizeTrust(value, POLICY_KEY_ID_RE, 'policy', {
    allowHistoricalEpochs: true,
    authorityRegistry: true,
  });
}

function normalizeOwnerApprovalTrust(value) {
  return normalizeTrust(value, OWNER_APPROVAL_KEY_ID_RE, 'owner_approval');
}

function normalizeTrust(value, keyIdPattern, purpose, options = {}) {
  const keys = [
    'currentEpoch', 'forbiddenPublicKeyFingerprints', 'keyEpochs', 'offlineKeyFingerprint', 'publicKeys',
    ...(options.authorityRegistry ? ['authorityRegistry'] : []),
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || !safeVersion(value.currentEpoch, 1)
      || !SHA256_RE.test(String(value.offlineKeyFingerprint || ''))
      || !Array.isArray(value.forbiddenPublicKeyFingerprints)
      || !value.forbiddenPublicKeyFingerprints.every((item) => SHA256_RE.test(String(item || '')))
      || new Set([value.offlineKeyFingerprint, ...value.forbiddenPublicKeyFingerprints]).size
        !== value.forbiddenPublicKeyFingerprints.length + 1
      || !plainRecord(value.keyEpochs)) throw fault(`${purpose}_trust_invalid`);
  const entries = value.publicKeys instanceof Map ? [...value.publicKeys.entries()]
    : plainRecord(value.publicKeys) ? Object.entries(value.publicKeys) : [];
  if (!entries.length || entries.length > 2) throw fault(`${purpose}_trust_invalid`);
  const epochKeys = Object.keys(value.keyEpochs).sort();
  const publicKeyIds = entries.map(([id]) => id).sort();
  if ((!options.allowHistoricalEpochs && epochKeys.join(',') !== publicKeyIds.join(','))
      || (options.allowHistoricalEpochs && (epochKeys.length > 32
        || publicKeyIds.some((keyId) => !Object.hasOwn(value.keyEpochs, keyId))))) {
    throw fault(`${purpose}_trust_invalid`);
  }
  for (const keyId of epochKeys) {
    if (!keyIdPattern.test(String(keyId || ''))) throw fault(`${purpose}_trust_invalid`);
    const epoch = value.keyEpochs[keyId];
    if (!plainRecord(epoch) || !exactKeys(epoch, ['retireAfterEpoch', 'validFromEpoch'])
        || !safeVersion(epoch.validFromEpoch, 1)
        || (epoch.retireAfterEpoch !== null
          && (!safeVersion(epoch.retireAfterEpoch, epoch.validFromEpoch)))) {
      throw fault(`${purpose}_trust_invalid`);
    }
  }
  if (options.authorityRegistry && !validAuthorityRegistry(value.authorityRegistry)) {
    throw fault(`${purpose}_trust_invalid`);
  }
  return value;
}

function validAuthorityRegistry(value) {
  return value && ['assertHistoricalPublicKey', 'assertPublicKey', 'verificationPublicKey']
    .every((method) => typeof value[method] === 'function');
}

function resolveFreshPolicyKey(trust, keyId) {
  try { return resolvePublicKey(trust.publicKeys, keyId); }
  catch (error) {
    if (error?.code !== 'unknown_policy_signing_key') throw error;
    try { resolveHistoricalPolicyKey(trust.authorityRegistry, keyId); }
    catch { throw error; }
    throw fault('policy_key_not_active');
  }
}

function resolveHistoricalPolicyKey(registry, keyId) {
  let keys;
  try { keys = registry.verificationPublicKey(POLICY_KEY_PURPOSE, keyId); }
  catch { throw fault('policy_historical_key_invalid'); }
  const entries = keys instanceof Map ? [...keys] : [];
  if (entries.length !== 1 || entries[0][0] !== keyId) throw fault('policy_historical_key_invalid');
  const key = resolvePublicKey(keys, keyId);
  assertRegistryPolicyKey(registry, keyId, key, true);
  return key;
}

function assertRegistryPolicyKey(registry, keyId, key, historical) {
  const method = historical ? 'assertHistoricalPublicKey' : 'assertPublicKey';
  try { registry[method](POLICY_KEY_PURPOSE, keyId, publicKeyFingerprint(key)); }
  catch { throw fault(historical ? 'policy_historical_key_invalid' : 'policy_key_not_active'); }
}

function assertTrustedPolicyKey(keyId, key, keyEpoch, trust) {
  assertTrustedKeyEpoch(keyId, key, keyEpoch, trust, POLICY_KEY_ID_RE, 'policy');
}

function assertTrustedKeyEpoch(keyId, key, keyEpoch, trust, keyIdPattern, purpose) {
  if (!keyIdPattern.test(keyId)) throw fault(`${purpose}_key_purpose_mismatch`);
  const fingerprint = publicKeyFingerprint(key);
  const forbidden = new Set([trust.offlineKeyFingerprint, ...trust.forbiddenPublicKeyFingerprints]);
  if (forbidden.has(fingerprint)) throw fault(`${purpose}_key_identity_reused`);
  const epoch = trust.keyEpochs[keyId];
  if (!epoch || keyEpoch < epoch.validFromEpoch || keyEpoch > trust.currentEpoch
      || (epoch.retireAfterEpoch !== null && keyEpoch > epoch.retireAfterEpoch)) {
    throw fault(`${purpose}_key_epoch_invalid`);
  }
}

function publicKeyFingerprint(key) {
  return crypto.createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}

function strictBase64(value, expectedBytes, code) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw fault(code);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== expectedBytes || decoded.toString('base64') !== value) throw fault(code);
  return decoded;
}

function safeVersion(value, minimum) {
  return Number.isSafeInteger(value) && value >= minimum;
}

function canonicalIso(value) {
  if (typeof value !== 'string' || !ISO_MS_RE.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function digestCanonical(value) {
  assertPlainTree(value, 'policy_digest_input_invalid');
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function assertPlainTree(value, code, seen = new Set(), depth = 0) {
  if (depth > 64) throw fault(code);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value) && !Object.is(value, -0)) return;
  if (!value || typeof value !== 'object' || seen.has(value)) throw fault(code);
  seen.add(value);
  if (Array.isArray(value)) {
    const names = Object.getOwnPropertyNames(value);
    if (Object.getOwnPropertySymbols(value).length || names.length !== value.length + 1) throw fault(code);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw fault(code);
      assertPlainTree(descriptor.value, code, seen, depth + 1);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if ((prototype !== Object.prototype && prototype !== null)
        || Object.getOwnPropertySymbols(value).length) throw fault(code);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (FORBIDDEN_KEYS.has(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw fault(code);
      }
      assertPlainTree(descriptor.value, code, seen, depth + 1);
    }
  }
  seen.delete(value);
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function clone(value) {
  return JSON.parse(protocol.canonicalJson(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}

function fault(code) {
  const error = new Error('vendor policy protocol rejected');
  error.code = code;
  return error;
}

module.exports = {
  GLOBAL_POLICY_KIND,
  GLOBAL_POLICY_SIGNATURE_DOMAIN,
  OWNER_APPROVAL_KIND,
  OWNER_APPROVAL_SIGNATURE_DOMAIN,
  POLICY_CONTROL_SCHEMA_VERSION,
  assertGlobalPolicyPayload,
  assertOwnerApprovalPayload,
  assertPolicyDeliveryBinding,
  createPolicyControlEnvelope,
  digestCanonical,
  policyDeliveryDigest,
  policyGlobalArtifactDigest,
  policyGlobalSigningInput,
  ownerApprovalSigningInput,
  verifyGlobalPolicyRelease,
  verifyPersistedGlobalPolicyRelease,
  verifyPersistedOwnerApproval,
  verifyOwnerApproval,
};
