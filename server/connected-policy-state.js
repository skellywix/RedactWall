'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const {
  DEFAULT_POLICY,
  normalizeDestination,
  normalizeMcpToolList,
} = require('./policy');
const {
  KEY_PURPOSES,
  keyFingerprint,
  normalizePublicKeys,
  verifySignedArtifact,
} = require('./vendor-signed-artifact');
const policyProtocol = require('./policy-control-verifier');

const STATE_VERSION = 2;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_POLICY_BUNDLE_BYTES = 4 * 1024 * 1024;
const MAX_POLICY_DOCUMENT_DEPTH = 32;
const MAX_POLICY_DOCUMENT_NODES = 50_000;
const MAX_RELEASE_HISTORY = 32;
const MAX_ROLLOUT_HISTORY = 64;
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const DETECTOR_RE = /^[A-Z][A-Z0-9_]{0,79}$/;
const DESTINATION_RE = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_OVERRIDE_LIST_ITEMS = 200;
const OVERRIDE_FIELDS = new Set([
  'alwaysBlockAdd',
  'blockMinSeverity',
  'blockRiskScore',
  'blockUnapprovedAiDestinations',
  'blockedDestinationsAdd',
  'blockedFileUploadDestinationsAdd',
  'enforcementMode',
  'mcpApprovalRequiredToolsAdd',
  'mcpBlockedToolsAdd',
  'responseScanMode',
  'unmanagedInstalls',
]);
const VENDOR_POLICY_FIELDS = new Set([
  'alwaysBlock', 'audit', 'blockMinSeverity', 'blockRiskScore',
  'blockUnapprovedAiDestinations', 'blockedDestinations',
  'blockedFileUploadDestinations', 'enforcementMode', 'licensing',
  'mcpApprovalRequiredTools', 'mcpBlockedTools', 'responseScanMode', 'unmanagedInstalls',
]);
const EMPTY_OVERRIDE_DIGEST = digestPolicyDocument({});
const ZERO_DIGEST = '0'.repeat(64);
const ENFORCEMENT_MODE_RANK = Object.freeze({ warn: 1, redact: 2, justify: 2, block: 3 });
const RESPONSE_SCAN_MODE_RANK = Object.freeze({ flag: 1, redact: 2, block: 3 });
const UNMANAGED_INSTALL_MODE_RANK = Object.freeze({ allow: 1, flag: 2, block: 3 });

const MANDATORY_ALWAYS_BLOCK = Object.freeze([...new Set(DEFAULT_POLICY.alwaysBlock)].sort());
const MANDATORY_CONTROLS_DIGEST = digestPolicyDocument(MANDATORY_ALWAYS_BLOCK);

function initialState(customerId, deploymentId) {
  assertBinding(customerId, deploymentId);
  return {
    stateVersion: STATE_VERSION,
    customerId,
    deploymentId,
    policyVersion: 0,
    desiredStateDigest: null,
    signingKeyId: null,
    desiredState: null,
    bundleDigest: null,
    mandatoryControlsDigest: null,
    localOverrideDigest: null,
    effectivePolicyDigest: null,
    validationDigest: null,
    rollbackOfVersion: null,
    appliedAt: null,
    lastContactAt: null,
    trustedTimeMs: 0,
    releases: [],
  };
}

function restoreState(value, expected = {}) {
  const state = checkedState(value);
  if (expected.customerId && state.customerId !== expected.customerId) throw stateError('customer_mismatch');
  if (expected.deploymentId && state.deploymentId !== expected.deploymentId) throw stateError('deployment_mismatch');
  if (state.policyVersion === 0) return state;
  const desired = protocol.assertChannel(state.desiredState, protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE);
  assertDesiredStateBinding(state, desired);
  if (protocol.payloadDigest(desired, desired.kind) !== state.desiredStateDigest
      || desired.policyVersion !== state.policyVersion
      || desired.bundleDigest !== state.bundleDigest
      || desired.mandatoryControlsDigest !== state.mandatoryControlsDigest) {
    throw stateError('state_high_water_invalid');
  }
  assertReleaseHistory(state);
  return { ...state, desiredState: desired, releases: state.releases.map((release) => ({ ...release })) };
}

function applySignedPolicy(stateValue, signedArtifact, options = {}) {
  const state = restoreState(stateValue);
  const verified = verifyPolicyArtifact(signedArtifact, options);
  const desired = verified.payload;
  assertDesiredStateBinding(state, desired);
  const nowMs = checkedNow(options.nowMs);
  assertTrustedTime(state, nowMs);
  assertFresh(desired, nowMs);
  const bundle = checkedPolicyDocument(options.vendorBundle, 'policy_bundle_invalid');
  const bundleDigest = digestCheckedDocument(bundle);
  if (bundleDigest !== desired.bundleDigest) throw stateError('bundle_digest_mismatch');
  if (desired.mandatoryControlsDigest !== MANDATORY_CONTROLS_DIGEST) {
    throw stateError('mandatory_controls_digest_mismatch');
  }
  const versionDecision = decideVersion(state, desired, verified.payloadDigest);
  if (versionDecision === 'idempotent') return idempotentResult(state, verified, nowMs);
  const localOverride = checkedTenantOverride(options.tenantLocalOverride || {});
  const localOverrideDigest = digestCheckedDocument(localOverride);
  const resolvedBundle = resolveVendorPolicyBundle(bundle, desired, options.policyTrust);
  if (resolvedBundle.control) throw stateError('explicit_rollout_api_required');
  const vendorPolicy = resolvedBundle.vendorPolicy;
  const validation = buildEffectivePolicy(vendorPolicy, localOverride);
  const rollbackOfVersion = validateRollback(state, desired, bundleDigest);
  const next = committedState(state, verified, desired, validation, {
    nowMs, localOverrideDigest, rollbackOfVersion,
  });
  return {
    state: next,
    idempotent: false,
    rollbackOfVersion,
    effectivePolicy: validation.effectivePolicy,
  };
}

function verifyPolicyArtifact(signedArtifact, options = {}) {
  const trust = options.policyTrust || options;
  assertPolicyTrust(trust, false);
  try {
    const keyring = normalizePublicKeys(trust.publicKeys, {
      authorityRegistry: trust.authorityRegistry,
      offlineKeyFingerprint: trust.offlineKeyFingerprint,
      forbiddenPublicKeyFingerprints: trust.forbiddenPublicKeyFingerprints,
      purpose: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
      strictPurpose: true,
    });
    return verifySignedArtifact(signedArtifact, keyring, protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE);
  } catch (error) {
    if (error?.code === 'unknown_signing_key' && retainedPolicyKey(trust, signedArtifact?.keyId)) {
      throw stateError('policy_key_not_active');
    }
    if (error && error.code) throw error;
    throw stateError('invalid_signature');
  }
}

function verifyPersistedPolicyArtifact(signedArtifact, options = {}) {
  const trust = options.policyTrust || options;
  assertPolicyTrust(trust, true);
  const keyId = signedArtifact?.keyId;
  if (!KEY_ID_RE.test(String(keyId || ''))) throw stateError('policy_artifact_invalid');
  try {
    const publicKeys = trust.authorityRegistry.verificationPublicKey(KEY_PURPOSES.POLICY, keyId);
    const historicalRegistry = {
      assertPublicKey(purpose, candidateKeyId, identity) {
        trust.authorityRegistry.assertHistoricalPublicKey(purpose, candidateKeyId, identity);
      },
    };
    const keyring = normalizePublicKeys(publicKeys, {
      authorityRegistry: historicalRegistry,
      offlineKeyFingerprint: trust.offlineKeyFingerprint,
      forbiddenPublicKeyFingerprints: trust.forbiddenPublicKeyFingerprints,
      purpose: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
      strictPurpose: true,
    });
    return verifySignedArtifact(signedArtifact, keyring, protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE);
  } catch (error) {
    throw stateError(error?.code || 'policy_historical_key_invalid');
  }
}

function assertPolicyTrust(trust, historical) {
  if (!trust || !trust.publicKeys || !SHA256_RE.test(String(trust.offlineKeyFingerprint || ''))
      || !Array.isArray(trust.forbiddenPublicKeyFingerprints)
      || !trust.forbiddenPublicKeyFingerprints.every((item) => SHA256_RE.test(String(item || '')))
      || (historical && (!trust.authorityRegistry
        || typeof trust.authorityRegistry.verificationPublicKey !== 'function'
        || typeof trust.authorityRegistry.assertHistoricalPublicKey !== 'function'))) {
    throw stateError('policy_trust_required');
  }
}

function retainedPolicyKey(trust, keyId) {
  if (!KEY_ID_RE.test(String(keyId || '')) || !trust.authorityRegistry
      || typeof trust.authorityRegistry.verificationPublicKey !== 'function') return false;
  try { return trust.authorityRegistry.verificationPublicKey(KEY_PURPOSES.POLICY, keyId) instanceof Map; }
  catch { return false; }
}

function buildEffectivePolicy(vendorBundle, tenantLocalOverride) {
  const vendorPolicy = checkedVendorPolicy(vendorBundle);
  const effective = cloneDocument(vendorPolicy);
  effective.alwaysBlock = unionLists(vendorPolicy.alwaysBlock, tenantLocalOverride.alwaysBlockAdd);
  effective.blockedDestinations = unionLists(
    vendorPolicy.blockedDestinations,
    tenantLocalOverride.blockedDestinationsAdd,
  );
  effective.blockedFileUploadDestinations = unionLists(
    vendorPolicy.blockedFileUploadDestinations,
    tenantLocalOverride.blockedFileUploadDestinationsAdd,
  );
  effective.mcpBlockedTools = unionLists(vendorPolicy.mcpBlockedTools, tenantLocalOverride.mcpBlockedToolsAdd);
  effective.mcpApprovalRequiredTools = unionLists(
    vendorPolicy.mcpApprovalRequiredTools,
    tenantLocalOverride.mcpApprovalRequiredToolsAdd,
  );
  applyRankedOverride(effective, vendorPolicy, tenantLocalOverride, 'enforcementMode', ENFORCEMENT_MODE_RANK);
  applyRankedOverride(effective, vendorPolicy, tenantLocalOverride, 'responseScanMode', RESPONSE_SCAN_MODE_RANK);
  applyRankedOverride(effective, vendorPolicy, tenantLocalOverride, 'unmanagedInstalls', UNMANAGED_INSTALL_MODE_RANK);
  applyMaximumOverride(effective, vendorPolicy, tenantLocalOverride, 'blockMinSeverity');
  applyMaximumOverride(effective, vendorPolicy, tenantLocalOverride, 'blockRiskScore');
  if (tenantLocalOverride.blockUnapprovedAiDestinations !== undefined) {
    if (tenantLocalOverride.blockUnapprovedAiDestinations !== true) throw stateError('policy_weakening');
    effective.blockUnapprovedAiDestinations = true;
  }
  effective.licensing = { ...(effective.licensing || {}), failClosed: true };
  effective.audit = { ...(effective.audit || {}), required: true };
  assertStrengthenOnly(vendorPolicy, effective);
  const effectivePolicy = deepFreeze(checkedPolicyDocument(effective, 'effective_policy_invalid'));
  assertMandatoryControls(effectivePolicy);
  const effectivePolicyDigest = digestCheckedDocument(effectivePolicy);
  const validationDigest = digestPolicyDocument({
    auditRequired: true,
    effectivePolicyDigest,
    licensingFailClosed: true,
    localOverridePrecedence: 'strengthen-only',
  });
  return { effectivePolicy, effectivePolicyDigest, validationDigest };
}

function normalizeVendorPolicy(value) {
  return deepFreeze(checkedVendorPolicy(value));
}

function normalizePolicyOverlay(value) {
  return deepFreeze(checkedTenantOverride(value));
}

function mergePolicyOverlays(...values) {
  const overlays = values.map((value) => checkedTenantOverride(value || {}));
  const merged = {};
  const listFields = [
    'alwaysBlockAdd', 'blockedDestinationsAdd', 'blockedFileUploadDestinationsAdd',
    'mcpApprovalRequiredToolsAdd', 'mcpBlockedToolsAdd',
  ];
  for (const field of listFields) {
    const combined = overlays.flatMap((overlay) => overlay[field] || []);
    if (combined.length) merged[field] = [...new Set(combined)].sort();
  }
  mergeRankedOverlay(overlays, merged, 'enforcementMode', ENFORCEMENT_MODE_RANK);
  mergeRankedOverlay(overlays, merged, 'responseScanMode', RESPONSE_SCAN_MODE_RANK);
  mergeRankedOverlay(overlays, merged, 'unmanagedInstalls', UNMANAGED_INSTALL_MODE_RANK);
  mergeMinimumOverlay(overlays, merged, 'blockMinSeverity');
  mergeMinimumOverlay(overlays, merged, 'blockRiskScore');
  if (overlays.some((overlay) => overlay.blockUnapprovedAiDestinations === true)) {
    merged.blockUnapprovedAiDestinations = true;
  }
  return deepFreeze(checkedTenantOverride(merged));
}

function mergeRankedOverlay(overlays, target, field, ranks) {
  const candidates = overlays.map((overlay) => overlay[field]).filter((value) => value !== undefined);
  if (!candidates.length) return;
  target[field] = candidates.reduce((left, right) => ranks[right] > ranks[left] ? right : left);
}

function mergeMinimumOverlay(overlays, target, field) {
  const candidates = overlays.map((overlay) => overlay[field]).filter((value) => value !== undefined);
  if (candidates.length) target[field] = Math.min(...candidates);
}

function resolveVendorPolicyBundle(bundle, desired, policyTrust, options = {}) {
  if (!Object.hasOwn(bundle, 'vendorControl')) {
    return { vendorPolicy: bundle, control: null };
  }
  const control = policyProtocol.createPolicyControlEnvelope(bundle.vendorControl);
  const binding = control.deliveryBinding;
  if (binding.customerId !== desired.customerId || binding.deploymentId !== desired.deploymentId
      || binding.messageId !== desired.messageId
      || binding.distributionSequence !== desired.policyVersion
      || binding.previousDistributionSequence !== desired.previousVersion
      || binding.rollout !== desired.rollout || binding.issuedAt !== desired.issuedAt
      || binding.expiresAt !== desired.expiresAt
      || binding.mandatoryControlsDigest !== desired.mandatoryControlsDigest) {
    throw stateError('policy_delivery_binding_mismatch');
  }
  let global;
  try {
    global = options.persisted === true
      ? policyProtocol.verifyPersistedGlobalPolicyRelease(control.globalArtifact, policyTrust)
      : policyProtocol.verifyGlobalPolicyRelease(control.globalArtifact, policyTrust);
  }
  catch (error) { throw stateError(error && error.code ? error.code : 'policy_global_signature_invalid'); }
  if (global.artifactDigest !== binding.globalArtifactDigest
      || global.payload.globalReleaseId !== binding.globalReleaseId
      || global.payload.globalVersion !== binding.globalVersion
      || global.payload.keyEpoch !== binding.globalKeyEpoch
      || global.payload.bundleDigest !== binding.globalBundleDigest
      || global.payload.mandatoryControlsDigest !== binding.mandatoryControlsDigest
      || digestCheckedDocument(checkedVendorPolicy(control.globalPolicy)) !== binding.globalBundleDigest
      || digestCheckedDocument(control.desiredOverlay) !== binding.desiredOverlayDigest
      || digestCheckedDocument(control.emergencyDenyOverlay) !== binding.emergencyDenyDigest) {
    throw stateError('policy_delivery_binding_mismatch');
  }
  const desiredOverlay = checkedTenantOverride(control.desiredOverlay);
  const emergencyOverlay = checkedTenantOverride(control.emergencyDenyOverlay);
  const combinedOverlay = mergePolicyOverlays(desiredOverlay, emergencyOverlay);
  const composed = buildEffectivePolicy(control.globalPolicy, combinedOverlay).effectivePolicy;
  const vendorPolicy = cloneDocument(bundle);
  delete vendorPolicy.vendorControl;
  const normalizedVendorPolicy = checkedVendorPolicy(vendorPolicy);
  if (digestCheckedDocument(composed) !== binding.effectivePolicyDigest
      || digestCheckedDocument(normalizedVendorPolicy) !== binding.effectivePolicyDigest
      || protocol.canonicalJson(composed) !== protocol.canonicalJson(normalizedVendorPolicy)) {
    throw stateError('policy_effective_digest_mismatch');
  }
  return { vendorPolicy: normalizedVendorPolicy, control };
}

function checkedVendorPolicy(vendorBundle) {
  const input = checkedPolicyDocument(vendorBundle, 'vendor_policy_invalid');
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).some((key) => !VENDOR_POLICY_FIELDS.has(key))) {
    throw stateError('vendor_policy_unknown_field');
  }
  if (!input.licensing || typeof input.licensing !== 'object' || Array.isArray(input.licensing)
      || Object.keys(input.licensing).sort().join(',') !== 'failClosed'
      || input.licensing.failClosed !== true
      || !input.audit || typeof input.audit !== 'object' || Array.isArray(input.audit)
      || Object.keys(input.audit).sort().join(',') !== 'required'
      || input.audit.required !== true) throw stateError('vendor_policy_invalid');
  const normalized = {
    enforcementMode: input.enforcementMode,
    blockMinSeverity: input.blockMinSeverity,
    blockRiskScore: input.blockRiskScore,
    alwaysBlock: input.alwaysBlock,
    blockedDestinations: input.blockedDestinations || [],
    blockedFileUploadDestinations: input.blockedFileUploadDestinations || [],
    mcpBlockedTools: input.mcpBlockedTools || [],
    mcpApprovalRequiredTools: input.mcpApprovalRequiredTools || [],
    blockUnapprovedAiDestinations: input.blockUnapprovedAiDestinations,
    responseScanMode: input.responseScanMode,
    unmanagedInstalls: input.unmanagedInstalls,
    licensing: { failClosed: true },
    audit: { required: true },
  };
  normalized.enforcementMode = checkedMode(
    normalized.enforcementMode,
    ENFORCEMENT_MODE_RANK,
    'vendor_policy_invalid',
  );
  normalized.responseScanMode = checkedMode(
    normalized.responseScanMode,
    RESPONSE_SCAN_MODE_RANK,
    'vendor_policy_invalid',
  );
  normalized.unmanagedInstalls = checkedMode(
    normalized.unmanagedInstalls,
    UNMANAGED_INSTALL_MODE_RANK,
    'vendor_policy_invalid',
  );
  normalized.blockMinSeverity = checkedInteger(normalized.blockMinSeverity, 1, 4, 'vendor_policy_invalid');
  normalized.blockRiskScore = checkedInteger(normalized.blockRiskScore, 0, 100, 'vendor_policy_invalid');
  if (typeof normalized.blockUnapprovedAiDestinations !== 'boolean') throw stateError('vendor_policy_invalid');
  normalized.alwaysBlock = unionLists(
    checkedStringList(normalized.alwaysBlock, checkedDetector, 'vendor_policy_invalid'),
    MANDATORY_ALWAYS_BLOCK,
  );
  normalized.blockedDestinations = checkedStringList(
    normalized.blockedDestinations,
    checkedDestination,
    'vendor_policy_invalid',
  );
  normalized.blockedFileUploadDestinations = checkedStringList(
    normalized.blockedFileUploadDestinations,
    checkedDestination,
    'vendor_policy_invalid',
  );
  normalized.mcpBlockedTools = checkedStringList(
    normalized.mcpBlockedTools,
    checkedMcpTool,
    'vendor_policy_invalid',
  );
  normalized.mcpApprovalRequiredTools = checkedStringList(
    normalized.mcpApprovalRequiredTools,
    checkedMcpTool,
    'vendor_policy_invalid',
  );
  normalized.licensing = { ...(normalized.licensing || {}), failClosed: true };
  normalized.audit = { ...(normalized.audit || {}), required: true };
  return checkedPolicyDocument(normalized, 'vendor_policy_invalid');
}

function checkedTenantOverride(value) {
  const override = checkedPolicyDocument(value, 'local_override_invalid');
  if (!override || typeof override !== 'object' || Array.isArray(override)) throw stateError('local_override_invalid');
  if (Object.keys(override).some((key) => !OVERRIDE_FIELDS.has(key))) {
    throw stateError('local_override_unknown_field');
  }
  const normalized = {};
  if (override.alwaysBlockAdd !== undefined) {
    normalized.alwaysBlockAdd = checkedStringList(override.alwaysBlockAdd, checkedDetector, 'local_override_invalid');
  }
  if (override.blockedDestinationsAdd !== undefined) {
    normalized.blockedDestinationsAdd = checkedStringList(
      override.blockedDestinationsAdd,
      checkedDestination,
      'local_override_invalid',
    );
  }
  if (override.blockedFileUploadDestinationsAdd !== undefined) {
    normalized.blockedFileUploadDestinationsAdd = checkedStringList(
      override.blockedFileUploadDestinationsAdd,
      checkedDestination,
      'local_override_invalid',
    );
  }
  if (override.mcpBlockedToolsAdd !== undefined) {
    normalized.mcpBlockedToolsAdd = checkedStringList(
      override.mcpBlockedToolsAdd,
      checkedMcpTool,
      'local_override_invalid',
    );
  }
  if (override.mcpApprovalRequiredToolsAdd !== undefined) {
    normalized.mcpApprovalRequiredToolsAdd = checkedStringList(
      override.mcpApprovalRequiredToolsAdd,
      checkedMcpTool,
      'local_override_invalid',
    );
  }
  copyMode(override, normalized, 'enforcementMode', ENFORCEMENT_MODE_RANK);
  copyMode(override, normalized, 'responseScanMode', RESPONSE_SCAN_MODE_RANK);
  copyMode(override, normalized, 'unmanagedInstalls', UNMANAGED_INSTALL_MODE_RANK);
  copyInteger(override, normalized, 'blockMinSeverity', 1, 4);
  copyInteger(override, normalized, 'blockRiskScore', 0, 100);
  if (override.blockUnapprovedAiDestinations !== undefined) {
    if (override.blockUnapprovedAiDestinations !== true) throw stateError('policy_weakening');
    normalized.blockUnapprovedAiDestinations = true;
  }
  return normalized;
}

function copyMode(source, target, field, ranks) {
  if (source[field] !== undefined) target[field] = checkedMode(source[field], ranks, 'local_override_invalid');
}

function copyInteger(source, target, field, minimum, maximum) {
  if (source[field] !== undefined) {
    target[field] = checkedInteger(source[field], minimum, maximum, 'local_override_invalid');
  }
}

function checkedMode(value, ranks, code) {
  if (typeof value !== 'string' || !Object.hasOwn(ranks, value)) throw stateError(code);
  return value;
}

function checkedInteger(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw stateError(code);
  return value;
}

function checkedStringList(value, normalize, code) {
  if (!Array.isArray(value) || value.length > MAX_OVERRIDE_LIST_ITEMS) throw stateError(code);
  const normalized = [];
  for (const item of value) {
    if (typeof item !== 'string') throw stateError(code);
    let candidate;
    try { candidate = normalize(item); } catch { throw stateError(code); }
    if (!candidate) throw stateError(code);
    normalized.push(candidate);
  }
  return [...new Set(normalized)].sort();
}

function checkedDetector(value) {
  return DETECTOR_RE.test(value) ? value : null;
}

function checkedDestination(value) {
  const candidate = value.trim().toLowerCase();
  if (candidate === '*') return candidate;
  if (candidate.length > 253 || !DESTINATION_RE.test(candidate)) return null;
  return normalizeDestination(candidate) === candidate ? candidate : null;
}

function checkedMcpTool(value) {
  const candidate = value.trim();
  const normalized = normalizeMcpToolList([candidate]);
  return normalized.length === 1 && normalized[0] === candidate ? candidate : null;
}

function unionLists(left = [], right = []) {
  return [...new Set([...(left || []), ...(right || [])])].sort();
}

function applyRankedOverride(effective, vendorPolicy, override, field, ranks) {
  if (override[field] === undefined) return;
  const currentRank = ranks[vendorPolicy[field]];
  const candidateRank = ranks[override[field]];
  if (candidateRank < currentRank || (candidateRank === currentRank && override[field] !== vendorPolicy[field])) {
    throw stateError('policy_weakening');
  }
  effective[field] = override[field];
}

function applyMaximumOverride(effective, vendorPolicy, override, field) {
  if (override[field] === undefined) return;
  if (override[field] > vendorPolicy[field]) throw stateError('policy_weakening');
  effective[field] = override[field];
}

function assertStrengthenOnly(vendorPolicy, effectivePolicy) {
  assertSuperset(vendorPolicy.alwaysBlock, effectivePolicy.alwaysBlock);
  assertSuperset(vendorPolicy.blockedDestinations, effectivePolicy.blockedDestinations);
  assertSuperset(vendorPolicy.blockedFileUploadDestinations, effectivePolicy.blockedFileUploadDestinations);
  assertSuperset(vendorPolicy.mcpBlockedTools, effectivePolicy.mcpBlockedTools);
  assertSuperset(vendorPolicy.mcpApprovalRequiredTools, effectivePolicy.mcpApprovalRequiredTools);
  assertRankNotLower(vendorPolicy, effectivePolicy, 'enforcementMode', ENFORCEMENT_MODE_RANK);
  assertRankNotLower(vendorPolicy, effectivePolicy, 'responseScanMode', RESPONSE_SCAN_MODE_RANK);
  assertRankNotLower(vendorPolicy, effectivePolicy, 'unmanagedInstalls', UNMANAGED_INSTALL_MODE_RANK);
  if (effectivePolicy.blockMinSeverity > vendorPolicy.blockMinSeverity
      || effectivePolicy.blockRiskScore > vendorPolicy.blockRiskScore
      || (vendorPolicy.blockUnapprovedAiDestinations && !effectivePolicy.blockUnapprovedAiDestinations)
      || effectivePolicy.licensing?.failClosed !== true
      || effectivePolicy.audit?.required !== true) {
    throw stateError('policy_weakening');
  }
}

function assertSuperset(required, candidate) {
  const candidateSet = new Set(candidate || []);
  if ((required || []).some((value) => !candidateSet.has(value))) throw stateError('policy_weakening');
}

function assertRankNotLower(vendorPolicy, effectivePolicy, field, ranks) {
  const vendorRank = ranks[vendorPolicy[field]];
  const effectiveRank = ranks[effectivePolicy[field]];
  if (effectiveRank < vendorRank || (effectiveRank === vendorRank && effectivePolicy[field] !== vendorPolicy[field])) {
    throw stateError('policy_weakening');
  }
}

function assertMandatoryControls(effectivePolicy) {
  const controls = effectivePolicy && effectivePolicy.alwaysBlock;
  if (!Array.isArray(controls) || controls.some((item) => typeof item !== 'string')) {
    throw stateError('policy_weakening');
  }
  const effective = new Set(controls);
  if (MANDATORY_ALWAYS_BLOCK.some((control) => !effective.has(control))) throw stateError('policy_weakening');
}

function decideVersion(state, desired, digest) {
  if (state.policyVersion === 0) {
    if (desired.policyVersion !== 1 || desired.previousVersion !== 0) throw stateError('version_gap');
    return 'apply';
  }
  if (desired.policyVersion < state.policyVersion) throw stateError('stale_version');
  if (desired.policyVersion === state.policyVersion) {
    if (digest !== state.desiredStateDigest) throw stateError('version_conflict');
    return 'idempotent';
  }
  if (desired.previousVersion !== state.policyVersion) throw stateError('version_gap');
  return 'apply';
}

function committedState(state, verified, desired, validation, metadata) {
  const release = {
    policyVersion: desired.policyVersion,
    desiredStateDigest: verified.payloadDigest,
    bundleDigest: desired.bundleDigest,
    mandatoryControlsDigest: desired.mandatoryControlsDigest,
    localOverrideDigest: metadata.localOverrideDigest,
    effectivePolicyDigest: validation.effectivePolicyDigest,
    validationDigest: validation.validationDigest,
    rollbackOfVersion: metadata.rollbackOfVersion,
  };
  return {
    ...state,
    policyVersion: desired.policyVersion,
    desiredStateDigest: verified.payloadDigest,
    signingKeyId: verified.keyId,
    desiredState: desired,
    bundleDigest: desired.bundleDigest,
    mandatoryControlsDigest: desired.mandatoryControlsDigest,
    localOverrideDigest: metadata.localOverrideDigest,
    effectivePolicyDigest: validation.effectivePolicyDigest,
    validationDigest: validation.validationDigest,
    rollbackOfVersion: metadata.rollbackOfVersion,
    appliedAt: new Date(metadata.nowMs).toISOString(),
    lastContactAt: new Date(metadata.nowMs).toISOString(),
    trustedTimeMs: Math.max(state.trustedTimeMs, metadata.nowMs, Date.parse(desired.issuedAt)),
    releases: [...state.releases, release].slice(-MAX_RELEASE_HISTORY),
  };
}

function idempotentResult(state, verified, nowMs) {
  const next = {
    ...state,
    signingKeyId: verified.keyId,
    lastContactAt: new Date(nowMs).toISOString(),
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs, Date.parse(verified.payload.issuedAt)),
  };
  return {
    state: next,
    idempotent: true,
    rollbackOfVersion: state.rollbackOfVersion,
    effectivePolicy: null,
  };
}

function validateRollback(state, desired, bundleDigest) {
  if (desired.rollbackOfVersion === null) return null;
  if (desired.rollbackOfVersion >= desired.previousVersion) {
    throw stateError('rollback_target_not_prior');
  }
  const target = state.releases.find((release) => release.policyVersion === desired.rollbackOfVersion);
  if (!target) throw stateError('rollback_target_unknown');
  if (target.bundleDigest !== bundleDigest) throw stateError('rollback_content_mismatch');
  return target.policyVersion;
}

function checkedState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw stateError('state_invalid');
  const allowed = new Set(Object.keys(initialState(value.customerId, value.deploymentId)));
  if (Object.keys(value).some((key) => !allowed.has(key))) throw stateError('state_unknown_field');
  if (value.stateVersion !== STATE_VERSION || !Number.isSafeInteger(value.policyVersion) || value.policyVersion < 0) {
    throw stateError('state_invalid');
  }
  if (!Number.isSafeInteger(value.trustedTimeMs) || value.trustedTimeMs < 0) throw stateError('state_invalid');
  if (!Array.isArray(value.releases) || value.releases.length > MAX_RELEASE_HISTORY) throw stateError('state_invalid');
  if (value.policyVersion === 0) assertEmptyState(value); else assertPopulatedState(value);
  return { ...value, releases: value.releases.map((release) => ({ ...release })) };
}

function assertEmptyState(state) {
  const nullable = [
    'desiredStateDigest', 'signingKeyId', 'desiredState', 'bundleDigest',
    'mandatoryControlsDigest', 'localOverrideDigest', 'effectivePolicyDigest',
    'validationDigest', 'rollbackOfVersion', 'appliedAt', 'lastContactAt',
  ];
  if (nullable.some((key) => state[key] !== null) || state.releases.length !== 0 || state.trustedTimeMs !== 0) {
    throw stateError('state_high_water_invalid');
  }
}

function assertPopulatedState(state) {
  const digests = [
    state.desiredStateDigest, state.bundleDigest, state.mandatoryControlsDigest,
    state.localOverrideDigest, state.effectivePolicyDigest, state.validationDigest,
  ];
  if (digests.some((value) => !SHA256_RE.test(String(value || '')))
      || state.mandatoryControlsDigest !== MANDATORY_CONTROLS_DIGEST
      || !KEY_ID_RE.test(String(state.signingKeyId || ''))
      || !canonicalTime(state.appliedAt)
      || !canonicalTime(state.lastContactAt)
      || (state.rollbackOfVersion !== null && (!Number.isSafeInteger(state.rollbackOfVersion)
        || state.rollbackOfVersion < 1 || state.rollbackOfVersion >= state.policyVersion))) {
    throw stateError('state_invalid');
  }
}

function assertReleaseHistory(state) {
  if (!state.releases.length) throw stateError('state_high_water_invalid');
  let previous = 0;
  for (const release of state.releases) {
    assertRelease(release);
    if (release.policyVersion <= previous) throw stateError('state_high_water_invalid');
    previous = release.policyVersion;
  }
  const latest = state.releases[state.releases.length - 1];
  const keys = [
    'policyVersion', 'desiredStateDigest', 'bundleDigest', 'mandatoryControlsDigest',
    'localOverrideDigest', 'effectivePolicyDigest', 'validationDigest', 'rollbackOfVersion',
  ];
  if (keys.some((key) => latest[key] !== state[key])) throw stateError('state_high_water_invalid');
}

function assertRelease(release) {
  const expected = [
    'bundleDigest', 'desiredStateDigest', 'effectivePolicyDigest', 'localOverrideDigest',
    'mandatoryControlsDigest', 'policyVersion', 'rollbackOfVersion', 'validationDigest',
  ].sort().join(',');
  if (!release || typeof release !== 'object' || Array.isArray(release)
      || Object.keys(release).sort().join(',') !== expected
      || !Number.isSafeInteger(release.policyVersion) || release.policyVersion < 1) {
    throw stateError('state_high_water_invalid');
  }
  const digestKeys = [
    'bundleDigest', 'desiredStateDigest', 'effectivePolicyDigest', 'localOverrideDigest',
    'mandatoryControlsDigest', 'validationDigest',
  ];
  if (digestKeys.some((key) => !SHA256_RE.test(String(release[key] || '')))) {
    throw stateError('state_high_water_invalid');
  }
  if (release.rollbackOfVersion !== null && (!Number.isSafeInteger(release.rollbackOfVersion)
      || release.rollbackOfVersion < 1 || release.rollbackOfVersion >= release.policyVersion)) {
    throw stateError('state_high_water_invalid');
  }
}

function assertBinding(customerId, deploymentId) {
  protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: '00000000-0000-4000-8000-000000000000',
    customerId,
    deploymentId,
    kind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
    policyVersion: 1,
    previousVersion: 0,
    rollbackOfVersion: null,
    bundleDigest: '0'.repeat(64),
    mandatoryControlsDigest: '0'.repeat(64),
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T00:01:00.000Z',
    rollout: 'preview',
  }, protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE);
}

function assertDesiredStateBinding(state, desired) {
  if (state.customerId !== desired.customerId) throw stateError('customer_mismatch');
  if (state.deploymentId !== desired.deploymentId) throw stateError('deployment_mismatch');
}

function assertTrustedTime(state, nowMs) {
  if (nowMs + MAX_CLOCK_SKEW_MS < state.trustedTimeMs) throw stateError('clock_rollback');
}

function assertFresh(desired, nowMs) {
  if (Date.parse(desired.issuedAt) > nowMs + MAX_CLOCK_SKEW_MS) throw stateError('future_policy');
  if (Date.parse(desired.expiresAt) <= nowMs) throw stateError('expired');
}

function checkedNow(value) {
  const nowMs = value === undefined ? Date.now() : value;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw stateError('time_invalid');
  return nowMs;
}

function digestPolicyDocument(value) {
  return digestCheckedDocument(checkedPolicyDocument(value, 'policy_document_invalid'));
}

function digestCheckedDocument(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function checkedPolicyDocument(value, code) {
  try {
    const budget = { nodes: 0, seen: new Set() };
    validateDocumentNode(value, 0, budget, code);
    const serialized = protocol.canonicalJson(value);
    const bytes = Buffer.byteLength(serialized, 'utf8');
    if (bytes > MAX_POLICY_BUNDLE_BYTES) throw stateError(code);
    const snapshot = JSON.parse(serialized);
    validateDocumentNode(snapshot, 0, { nodes: 0, seen: new Set() }, code);
    return snapshot;
  } catch (error) {
    if (error && error.code === code) throw error;
    throw stateError(code);
  }
}

function validateDocumentNode(value, depth, budget, code) {
  budget.nodes += 1;
  if (budget.nodes > MAX_POLICY_DOCUMENT_NODES || depth > MAX_POLICY_DOCUMENT_DEPTH) throw stateError(code);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value) && !Object.is(value, -0)) return;
  if (!value || typeof value !== 'object' || budget.seen.has(value)) throw stateError(code);
  budget.seen.add(value);
  if (Array.isArray(value)) validateDocumentArray(value, depth, budget, code);
  else validateDocumentObject(value, depth, budget, code);
  budget.seen.delete(value);
}

function validateDocumentArray(value, depth, budget, code) {
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length || names.length !== value.length + 1) throw stateError(code);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw stateError(code);
    validateDocumentNode(descriptor.value, depth + 1, budget, code);
  }
}

function validateDocumentObject(value, depth, budget, code) {
  assertPlainDataObject(value, code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (FORBIDDEN_KEYS.has(key)) throw stateError(code);
    validateDocumentNode(descriptor.value, depth + 1, budget, code);
  }
}

function assertPlainDataObject(value, code) {
  const prototype = Object.getPrototypeOf(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
      || Object.getOwnPropertySymbols(value).length
      || Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))) {
    throw stateError(code);
  }
}

function cloneDocument(value) {
  return JSON.parse(protocol.canonicalJson(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}

function canonicalTime(value) {
  const parsed = Date.parse(value);
  return typeof value === 'string' && Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function initialRolloutState(customerId, deploymentId) {
  assertBinding(customerId, deploymentId);
  return {
    stateVersion: STATE_VERSION,
    customerId,
    deploymentId,
    distributionSequence: 0,
    trustedTimeMs: 0,
    lastContactAt: null,
    localOverride: {},
    localOverrideRevision: 0,
    localOverrideDigest: EMPTY_OVERRIDE_DIGEST,
    localOverrideUpdatedAt: null,
    candidate: null,
    active: null,
    history: [],
    historyCheckpoint: {
      throughSequence: 0,
      entryCount: 0,
      headDigest: ZERO_DIGEST,
    },
  };
}

function restoreRolloutState(value, options = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw stateError('rollout_state_invalid');
  const expectedKeys = Object.keys(initialRolloutState(value.customerId, value.deploymentId)).sort().join(',');
  if (Object.keys(value).sort().join(',') !== expectedKeys || value.stateVersion !== STATE_VERSION
      || !Number.isSafeInteger(value.distributionSequence) || value.distributionSequence < 0
      || !Number.isSafeInteger(value.trustedTimeMs) || value.trustedTimeMs < 0
      || !Number.isSafeInteger(value.localOverrideRevision) || value.localOverrideRevision < 0
      || !SHA256_RE.test(String(value.localOverrideDigest || ''))
      || !Array.isArray(value.history) || value.history.length > MAX_ROLLOUT_HISTORY
      || (value.lastContactAt !== null && !canonicalTime(value.lastContactAt))
      || (value.localOverrideUpdatedAt !== null && !canonicalTime(value.localOverrideUpdatedAt))) {
    throw stateError('rollout_state_invalid');
  }
  if (options.customerId && options.customerId !== value.customerId) throw stateError('customer_mismatch');
  if (options.deploymentId && options.deploymentId !== value.deploymentId) throw stateError('deployment_mismatch');
  const state = cloneDocument(value);
  state.localOverride = checkedTenantOverride(state.localOverride);
  if (digestCheckedDocument(state.localOverride) !== state.localOverrideDigest
      || (state.localOverrideRevision === 0) !== (state.localOverrideUpdatedAt === null)) {
    throw stateError('local_override_state_invalid');
  }
  validateHistoryCheckpoint(state.historyCheckpoint);
  validateRolloutHistory(state);
  if (state.candidate !== null) validateRolloutCandidate(state, state.candidate, options);
  if (state.active !== null) validateActivePolicy(state.active);
  const latest = state.history.at(-1);
  if (state.distributionSequence === 0) {
    if (state.history.length || state.candidate !== null || state.active !== null
        || state.lastContactAt !== null
        || (state.localOverrideRevision === 0 && state.trustedTimeMs !== 0)
        || (state.localOverrideRevision > 0
          && state.trustedTimeMs < Date.parse(state.localOverrideUpdatedAt))
        || state.historyCheckpoint.throughSequence !== 0) {
      throw stateError('rollout_high_water_invalid');
    }
  } else if (!latest || latest.distributionSequence !== state.distributionSequence) {
    throw stateError('rollout_high_water_invalid');
  }
  return state;
}

function setLocalPolicyOverride(stateValue, command, options = {}) {
  const state = restoreRolloutState(stateValue, options);
  if (!command || typeof command !== 'object' || Array.isArray(command)
      || Object.keys(command).sort().join(',') !== [
        'expectedRevision', 'override', 'updatedAt',
      ].sort().join(',')
      || command.expectedRevision !== state.localOverrideRevision
      || !canonicalTime(command.updatedAt)) throw stateError('local_override_command_invalid');
  const nowMs = checkedNow(options.nowMs === undefined ? Date.parse(command.updatedAt) : options.nowMs);
  assertTrustedTime(state, nowMs);
  if (Date.parse(command.updatedAt) > nowMs + MAX_CLOCK_SKEW_MS) throw stateError('future_policy');
  const override = checkedTenantOverride(command.override);
  const next = {
    ...state,
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs),
    localOverride: override,
    localOverrideRevision: state.localOverrideRevision + 1,
    localOverrideDigest: digestCheckedDocument(override),
    localOverrideUpdatedAt: command.updatedAt,
  };
  if (state.active) next.active = rebuildActiveForOverride(state.active, override, next.localOverrideRevision);
  return { state: next, localOverride: override, idempotent: false };
}

function receiveSignedPolicyRollout(stateValue, signedArtifact, options = {}) {
  const state = restoreRolloutState(stateValue, {
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    policyTrust: options.policyTrust,
  });
  const verified = verifyPolicyArtifact(signedArtifact, options.policyTrust || options);
  const desired = verified.payload;
  assertDesiredStateBinding(state, desired);
  const nowMs = checkedNow(options.nowMs);
  assertTrustedTime(state, nowMs);
  assertFresh(desired, nowMs);
  const targetDigest = verified.payloadDigest;
  if (desired.policyVersion < state.distributionSequence) throw stateError('stale_version');
  if (desired.policyVersion === state.distributionSequence) {
    const existing = state.candidate || state.active;
    if (!existing || existing.distributionSequence !== desired.policyVersion
        || existing.targetDigest !== targetDigest) throw stateError('version_conflict');
    return {
      state: updateRolloutContact(state, nowMs, desired),
      candidate: state.candidate,
      idempotent: true,
      activationRequired: state.candidate?.rollout === 'required',
      activePolicy: state.active?.effectivePolicy || null,
    };
  }
  if (desired.policyVersion !== state.distributionSequence + 1
      || desired.previousVersion !== state.distributionSequence) throw stateError('version_gap');
  const vendorBundle = checkedPolicyDocument(options.vendorBundle, 'policy_bundle_invalid');
  if (digestCheckedDocument(vendorBundle) !== desired.bundleDigest) throw stateError('bundle_digest_mismatch');
  if (desired.mandatoryControlsDigest !== MANDATORY_CONTROLS_DIGEST) {
    throw stateError('mandatory_controls_digest_mismatch');
  }
  const resolved = resolveVendorPolicyBundle(vendorBundle, desired, options.policyTrust);
  if (!resolved.control) throw stateError('policy_control_envelope_required');
  assertPolicyKeyEpoch(verified.keyId, resolved.control.deliveryBinding.policyKeyEpoch,
    options.policyTrust);
  if (state.candidate?.rollout === 'required') {
    assertCandidateSupersession(state.candidate, resolved.control.deliveryBinding.supersession, nowMs);
  } else if (resolved.control.deliveryBinding.supersession !== null) {
    throw stateError('policy_supersession_target_mismatch');
  }
  const candidateCore = {
    artifact: cloneDocument(signedArtifact),
    vendorBundle,
    distributionSequence: desired.policyVersion,
    targetDigest,
    deliveryDigest: resolved.control.deliveryDigest,
    rollout: desired.rollout,
    globalReleaseId: resolved.control.deliveryBinding.globalReleaseId,
    globalVersion: resolved.control.deliveryBinding.globalVersion,
    expiresAt: desired.expiresAt,
    signingKeyId: verified.keyId,
    policyKeyEpoch: resolved.control.deliveryBinding.policyKeyEpoch,
    rejectionDigest: null,
    rejectionMessageId: null,
    receivedAt: new Date(nowMs).toISOString(),
  };
  const candidate = { ...candidateCore, candidateDigest: digestCheckedDocument(candidateCore) };
  const entry = {
    distributionSequence: candidate.distributionSequence,
    targetDigest,
    deliveryDigest: candidate.deliveryDigest,
    rollout: candidate.rollout,
    receivedAt: candidate.receivedAt,
    activatedAt: null,
  };
  const next = {
    ...state,
    distributionSequence: desired.policyVersion,
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs, Date.parse(desired.issuedAt)),
    lastContactAt: new Date(nowMs).toISOString(),
    candidate,
    ...appendRolloutHistory(state, entry),
  };
  return {
    state: next,
    candidate,
    idempotent: false,
    activationRequired: desired.rollout === 'required',
    activePolicy: state.active?.effectivePolicy || null,
  };
}

function activateRequiredPolicy(stateValue, command, options = {}) {
  const state = restoreRolloutState(stateValue, {
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    policyTrust: options.policyTrust,
  });
  if (!command || typeof command !== 'object' || Array.isArray(command)
      || Object.keys(command).sort().join(',') !== [
        'deliveryDigest', 'distributionSequence', 'targetDigest',
      ].sort().join(',')
      || !Number.isSafeInteger(command.distributionSequence) || command.distributionSequence < 1
      || !SHA256_RE.test(String(command.targetDigest || ''))
      || !SHA256_RE.test(String(command.deliveryDigest || ''))) {
    throw stateError('activation_command_invalid');
  }
  if (state.active && state.active.distributionSequence === command.distributionSequence
      && state.active.targetDigest === command.targetDigest
      && state.active.deliveryDigest === command.deliveryDigest) {
    return { state, effectivePolicy: deepFreeze(cloneDocument(state.active.effectivePolicy)), idempotent: true };
  }
  const candidate = state.candidate;
  if (!candidate || candidate.distributionSequence !== command.distributionSequence
      || candidate.targetDigest !== command.targetDigest
      || candidate.deliveryDigest !== command.deliveryDigest) throw stateError('activation_target_mismatch');
  if (candidate.rollout !== 'required') throw stateError('activation_not_required');
  const verified = verifyPersistedPolicyArtifact(candidate.artifact, options.policyTrust || options);
  const nowMs = checkedNow(options.nowMs);
  assertTrustedTime(state, nowMs);
  assertFresh(verified.payload, nowMs);
  const resolved = resolveVendorPolicyBundle(
    candidate.vendorBundle,
    verified.payload,
    options.policyTrust,
    { persisted: true },
  );
  assertPolicyKeyEpoch(verified.keyId, candidate.policyKeyEpoch, options.policyTrust, true);
  const localOverride = checkedTenantOverride(state.localOverride);
  if (options.tenantLocalOverride !== undefined
      && digestCheckedDocument(checkedTenantOverride(options.tenantLocalOverride)) !== state.localOverrideDigest) {
    throw stateError('local_override_state_mismatch');
  }
  const validation = buildEffectivePolicy(resolved.vendorPolicy, localOverride);
  const activeCore = {
    distributionSequence: candidate.distributionSequence,
    targetDigest: candidate.targetDigest,
    deliveryDigest: candidate.deliveryDigest,
    globalReleaseId: candidate.globalReleaseId,
    globalVersion: candidate.globalVersion,
    vendorPolicy: resolved.vendorPolicy,
    vendorPolicyDigest: digestCheckedDocument(resolved.vendorPolicy),
    effectivePolicy: validation.effectivePolicy,
    effectivePolicyDigest: validation.effectivePolicyDigest,
    localOverrideDigest: digestCheckedDocument(localOverride),
    localOverrideRevision: state.localOverrideRevision,
    activatedAt: new Date(nowMs).toISOString(),
  };
  const active = { ...activeCore, activeDigest: digestCheckedDocument(activeCore) };
  const history = state.history.map((entry) => entry.distributionSequence === candidate.distributionSequence
    ? { ...entry, activatedAt: active.activatedAt } : entry);
  const next = {
    ...state,
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs, Date.parse(verified.payload.issuedAt)),
    lastContactAt: new Date(nowMs).toISOString(),
    candidate: null,
    active,
    history,
  };
  return { state: next, effectivePolicy: validation.effectivePolicy, idempotent: false };
}

function buildPolicyAcknowledgement(stateValue, options = {}) {
  const state = restoreRolloutState(stateValue);
  const target = options.target === 'candidate' ? state.candidate : state.active;
  if (!target) throw stateError('acknowledgement_target_missing');
  if (!UUID_RE.test(String(options.messageId || '')) || !canonicalTime(options.recordedAt)
      || !['success', 'rejected'].includes(options.outcome)) throw stateError('acknowledgement_invalid');
  if (options.outcome === 'success' && options.target === 'candidate') {
    throw stateError('acknowledgement_before_activation');
  }
  const value = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: options.messageId,
    customerId: state.customerId,
    deploymentId: state.deploymentId,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
    targetVersion: target.distributionSequence,
    targetDigest: target.targetDigest,
    lifecycleStage: 'applied',
    outcome: options.outcome,
    reasonCode: options.reasonCode,
    recordedAt: options.recordedAt,
  };
  return deepFreeze(protocol.assertChannel(value, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT));
}

function recordCandidateRejection(stateValue, acknowledgement, options = {}) {
  const state = restoreRolloutState(stateValue, options);
  let checked;
  try { checked = protocol.assertChannel(acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT); }
  catch { throw stateError('acknowledgement_invalid'); }
  const candidate = state.candidate;
  if (!candidate || checked.customerId !== state.customerId || checked.deploymentId !== state.deploymentId
      || checked.targetKind !== protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE
      || checked.targetVersion !== candidate.distributionSequence
      || checked.targetDigest !== candidate.targetDigest || checked.outcome !== 'rejected'
      || checked.lifecycleStage !== 'applied') throw stateError('rejection_target_mismatch');
  const rejectionDigest = digestCheckedDocument(checked);
  if (candidate.rejectionDigest !== null) {
    if (candidate.rejectionDigest !== rejectionDigest) throw stateError('rejection_conflict');
    return { state, rejectionDigest, idempotent: true };
  }
  const candidateCore = { ...candidate, rejectionDigest, rejectionMessageId: checked.messageId };
  delete candidateCore.candidateDigest;
  const nextCandidate = { ...candidateCore, candidateDigest: digestCheckedDocument(candidateCore) };
  return { state: { ...state, candidate: nextCandidate }, rejectionDigest, idempotent: false };
}

function buildPolicyValidationReceipt(stateValue, options = {}) {
  const state = restoreRolloutState(stateValue);
  const candidate = state.candidate;
  if (!candidate || !['preview', 'staged'].includes(candidate.rollout)
      || !UUID_RE.test(String(options.messageId || '')) || !canonicalTime(options.recordedAt)) {
    throw stateError('validation_receipt_invalid');
  }
  return deepFreeze({
    schemaVersion: 1,
    kind: 'policy.cached-validation-receipt.v1',
    messageId: options.messageId,
    customerId: state.customerId,
    deploymentId: state.deploymentId,
    targetVersion: candidate.distributionSequence,
    targetDigest: candidate.targetDigest,
    deliveryDigest: candidate.deliveryDigest,
    lifecycleStage: 'cached',
    outcome: 'validated',
    candidateDigest: candidate.candidateDigest,
    recordedAt: options.recordedAt,
  });
}

function updateRolloutContact(state, nowMs, desired) {
  return {
    ...state,
    lastContactAt: new Date(nowMs).toISOString(),
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs, Date.parse(desired.issuedAt)),
  };
}

function assertPolicyKeyEpoch(keyId, keyEpoch, trust, historical = false) {
  if (!trust || !plainTrustRecord(trust.keyEpochs) || !Number.isSafeInteger(trust.currentEpoch)
      || trust.currentEpoch < 1 || !keyId.startsWith('rw-policy-')) throw stateError('policy_trust_required');
  const record = trust.keyEpochs[keyId];
  if (!record || !Number.isSafeInteger(record.validFromEpoch) || record.validFromEpoch < 1
      || (record.retireAfterEpoch !== null && (!Number.isSafeInteger(record.retireAfterEpoch)
        || record.retireAfterEpoch < record.validFromEpoch))
      || keyEpoch < record.validFromEpoch || keyEpoch > trust.currentEpoch
      || (record.retireAfterEpoch !== null && keyEpoch > record.retireAfterEpoch)) {
    throw stateError('policy_key_epoch_invalid');
  }
  let rawKey = trust.publicKeys instanceof Map ? trust.publicKeys.get(keyId) : trust.publicKeys[keyId];
  if (!rawKey && historical && trust.authorityRegistry) {
    try { rawKey = trust.authorityRegistry.verificationPublicKey(KEY_PURPOSES.POLICY, keyId).get(keyId); }
    catch { throw stateError('unknown_signing_key'); }
  }
  if (!rawKey) throw stateError('unknown_signing_key');
  const fingerprint = keyFingerprint(rawKey);
  const forbidden = new Set([trust.offlineKeyFingerprint, ...(trust.forbiddenPublicKeyFingerprints || [])]);
  if (forbidden.has(fingerprint)) throw stateError('vendor_key_identity_reused');
}

function assertCandidateSupersession(candidate, supersession, nowMs) {
  if (!supersession || supersession.targetVersion !== candidate.distributionSequence
      || supersession.targetDigest !== candidate.targetDigest
      || supersession.deliveryDigest !== candidate.deliveryDigest) {
    throw stateError('required_activation_pending');
  }
  const expired = Date.parse(candidate.expiresAt) <= nowMs;
  const rejected = candidate.rejectionDigest !== null;
  if (supersession.disposition === 'expired' && !expired) throw stateError('policy_supersession_invalid');
  if (supersession.disposition === 'customer_rejected'
      && (!rejected || supersession.rejectionDigest !== candidate.rejectionDigest)) {
    throw stateError('policy_supersession_invalid');
  }
  if (supersession.disposition === 'recovery' && !expired && !rejected) {
    throw stateError('policy_supersession_invalid');
  }
}

function appendRolloutHistory(state, entry) {
  const values = [...state.history, entry];
  const checkpoint = { ...state.historyCheckpoint };
  while (values.length > MAX_ROLLOUT_HISTORY) {
    const removed = values.shift();
    checkpoint.throughSequence = removed.distributionSequence;
    checkpoint.entryCount += 1;
    checkpoint.headDigest = digestPolicyDocument({ previousDigest: checkpoint.headDigest, entry: removed });
  }
  return { history: values, historyCheckpoint: checkpoint };
}

function validateHistoryCheckpoint(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'entryCount,headDigest,throughSequence'
      || !Number.isSafeInteger(value.throughSequence) || value.throughSequence < 0
      || !Number.isSafeInteger(value.entryCount) || value.entryCount < 0
      || value.entryCount !== value.throughSequence
      || !SHA256_RE.test(String(value.headDigest || ''))
      || (value.throughSequence === 0) !== (value.headDigest === ZERO_DIGEST)) {
    throw stateError('rollout_checkpoint_invalid');
  }
}

function rebuildActiveForOverride(active, override, revision) {
  const validation = buildEffectivePolicy(active.vendorPolicy, override);
  const core = {
    ...active,
    effectivePolicy: validation.effectivePolicy,
    effectivePolicyDigest: validation.effectivePolicyDigest,
    localOverrideDigest: digestCheckedDocument(override),
    localOverrideRevision: revision,
  };
  delete core.activeDigest;
  return { ...core, activeDigest: digestCheckedDocument(core) };
}

function plainTrustRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateRolloutCandidate(state, candidate, options) {
  const keys = [
    'artifact', 'candidateDigest', 'deliveryDigest', 'distributionSequence', 'expiresAt',
    'globalReleaseId', 'globalVersion', 'policyKeyEpoch', 'receivedAt', 'rejectionDigest',
    'rejectionMessageId', 'rollout', 'signingKeyId', 'targetDigest', 'vendorBundle',
  ];
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
      || Object.keys(candidate).sort().join(',') !== keys.sort().join(',')
      || !Number.isSafeInteger(candidate.distributionSequence) || candidate.distributionSequence < 1
      || candidate.distributionSequence !== state.distributionSequence
      || !SHA256_RE.test(String(candidate.targetDigest || ''))
      || !SHA256_RE.test(String(candidate.deliveryDigest || ''))
      || !SHA256_RE.test(String(candidate.candidateDigest || ''))
      || !UUID_RE.test(String(candidate.globalReleaseId || ''))
      || !Number.isSafeInteger(candidate.globalVersion) || candidate.globalVersion < 1
      || !Number.isSafeInteger(candidate.policyKeyEpoch) || candidate.policyKeyEpoch < 1
      || !/^rw-policy-/.test(String(candidate.signingKeyId || ''))
      || !['preview', 'staged', 'required'].includes(candidate.rollout)
      || !canonicalTime(candidate.receivedAt) || !canonicalTime(candidate.expiresAt)
      || (candidate.rejectionDigest === null) !== (candidate.rejectionMessageId === null)
      || (candidate.rejectionDigest !== null
        && (!SHA256_RE.test(String(candidate.rejectionDigest || ''))
          || !UUID_RE.test(String(candidate.rejectionMessageId || ''))))) {
    throw stateError('rollout_candidate_invalid');
  }
  const core = { ...candidate };
  delete core.candidateDigest;
  if (digestCheckedDocument(core) !== candidate.candidateDigest) throw stateError('rollout_candidate_invalid');
  if (options.policyTrust) {
    const verified = verifyPersistedPolicyArtifact(candidate.artifact, options.policyTrust);
    if (verified.payloadDigest !== candidate.targetDigest
        || verified.payload.policyVersion !== candidate.distributionSequence) {
      throw stateError('rollout_candidate_invalid');
    }
    const bundle = checkedPolicyDocument(candidate.vendorBundle, 'rollout_candidate_invalid');
    if (digestCheckedDocument(bundle) !== verified.payload.bundleDigest) throw stateError('rollout_candidate_invalid');
    const resolved = resolveVendorPolicyBundle(bundle, verified.payload, options.policyTrust, {
      persisted: true,
    });
    if (!resolved.control || resolved.control.deliveryDigest !== candidate.deliveryDigest
        || resolved.control.deliveryBinding.globalReleaseId !== candidate.globalReleaseId
        || resolved.control.deliveryBinding.globalVersion !== candidate.globalVersion) {
      throw stateError('rollout_candidate_invalid');
    }
  }
}

function validateActivePolicy(active) {
  const keys = [
    'activatedAt', 'activeDigest', 'deliveryDigest', 'distributionSequence', 'effectivePolicy',
    'effectivePolicyDigest', 'globalReleaseId', 'globalVersion', 'localOverrideDigest',
    'localOverrideRevision', 'targetDigest', 'vendorPolicy', 'vendorPolicyDigest',
  ];
  if (!active || typeof active !== 'object' || Array.isArray(active)
      || Object.keys(active).sort().join(',') !== keys.sort().join(',')
      || !Number.isSafeInteger(active.distributionSequence) || active.distributionSequence < 1
      || !Number.isSafeInteger(active.globalVersion) || active.globalVersion < 1
      || !Number.isSafeInteger(active.localOverrideRevision) || active.localOverrideRevision < 0
      || !UUID_RE.test(String(active.globalReleaseId || '')) || !canonicalTime(active.activatedAt)) {
    throw stateError('active_policy_invalid');
  }
  for (const key of ['activeDigest', 'deliveryDigest', 'effectivePolicyDigest', 'localOverrideDigest', 'targetDigest']) {
    if (!SHA256_RE.test(String(active[key] || ''))) throw stateError('active_policy_invalid');
  }
  const effective = checkedVendorPolicy(active.effectivePolicy);
  const vendorPolicy = checkedVendorPolicy(active.vendorPolicy);
  if (digestCheckedDocument(effective) !== active.effectivePolicyDigest
      || digestCheckedDocument(vendorPolicy) !== active.vendorPolicyDigest) {
    throw stateError('active_policy_invalid');
  }
  const core = { ...active };
  delete core.activeDigest;
  if (digestCheckedDocument(core) !== active.activeDigest) throw stateError('active_policy_invalid');
}

function validateRolloutHistory(state) {
  let previous = state.historyCheckpoint.throughSequence;
  for (const entry of state.history) {
    const keys = [
      'activatedAt', 'deliveryDigest', 'distributionSequence', 'receivedAt', 'rollout', 'targetDigest',
    ];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || Object.keys(entry).sort().join(',') !== keys.sort().join(',')
        || !Number.isSafeInteger(entry.distributionSequence) || entry.distributionSequence <= previous
        || !SHA256_RE.test(String(entry.targetDigest || ''))
        || !SHA256_RE.test(String(entry.deliveryDigest || ''))
        || !['preview', 'staged', 'required'].includes(entry.rollout)
        || !canonicalTime(entry.receivedAt)
        || (entry.activatedAt !== null && !canonicalTime(entry.activatedAt))) {
      throw stateError('rollout_high_water_invalid');
    }
    previous = entry.distributionSequence;
  }
  if (state.active && state.active.distributionSequence > state.historyCheckpoint.throughSequence) {
    const entry = state.history.find((item) => item.distributionSequence === state.active.distributionSequence);
    if (entry && (entry.activatedAt !== state.active.activatedAt
        || entry.targetDigest !== state.active.targetDigest
        || entry.deliveryDigest !== state.active.deliveryDigest)) throw stateError('rollout_high_water_invalid');
  }
}

function stateError(code) {
  const error = new Error('connected policy state rejected');
  error.code = code;
  return error;
}

module.exports = {
  STATE_VERSION,
  MAX_CLOCK_SKEW_MS,
  MAX_RELEASE_HISTORY,
  MAX_ROLLOUT_HISTORY,
  MANDATORY_ALWAYS_BLOCK,
  MANDATORY_CONTROLS_DIGEST,
  initialState,
  restoreState,
  applySignedPolicy,
  activateRequiredPolicy,
  buildEffectivePolicy,
  buildPolicyAcknowledgement,
  buildPolicyValidationReceipt,
  digestPolicyDocument,
  initialRolloutState,
  mergePolicyOverlays,
  normalizePolicyOverlay,
  normalizeVendorPolicy,
  recordCandidateRejection,
  receiveSignedPolicyRollout,
  resolveVendorPolicyBundle,
  restoreRolloutState,
  setLocalPolicyOverride,
  verifyPersistedPolicyArtifact,
};
