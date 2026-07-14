'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const policyState = require('../server/connected-policy-state');
const { DEFAULT_POLICY } = require('../server/policy');
const protocol = require('../server/vendor-control-protocol');
const { keyFingerprint } = require('../server/vendor-signed-artifact');

const CUSTOMER_ID = 'cu-policy-1';
const DEPLOYMENT_ID = 'dep_66666666666666666666666666666666';
const SIBLING_DEPLOYMENT_ID = 'dep_77777777777777777777777777777777';
const KEY_ID = 'rw-policy-current';
const NOW = Date.parse('2026-07-12T12:01:00.000Z');
const keys = crypto.generateKeyPairSync('ed25519');
const offlineKeys = crypto.generateKeyPairSync('ed25519');
const unrelatedKeys = crypto.generateKeyPairSync('ed25519');
const publicKeys = { [KEY_ID]: keys.publicKey };
const policyTrust = Object.freeze({
  publicKeys,
  offlineKeyFingerprint: keyFingerprint(offlineKeys.publicKey),
  forbiddenPublicKeyFingerprints: [keyFingerprint(unrelatedKeys.publicKey)],
});

function bundle(name, alwaysBlock = policyState.MANDATORY_ALWAYS_BLOCK, overrides = {}) {
  return {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 70,
    alwaysBlock: [...alwaysBlock],
    blockedDestinations: [`${name}.example`],
    blockedFileUploadDestinations: [],
    mcpBlockedTools: [],
    mcpApprovalRequiredTools: [],
    blockUnapprovedAiDestinations: true,
    responseScanMode: 'block',
    unmanagedInstalls: 'block',
    licensing: { failClosed: true },
    audit: { required: true },
    ...overrides,
  };
}

function desired(version = 1, vendorBundle = bundle('first'), overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: `00000000-0000-4000-8000-${String(version).padStart(12, '0')}`,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
    policyVersion: version,
    previousVersion: version - 1,
    rollbackOfVersion: null,
    bundleDigest: policyState.digestPolicyDocument(vendorBundle),
    mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:10:00.000Z',
    rollout: 'required',
    ...overrides,
  };
}

function signed(payload, keyId = KEY_ID, privateKey = keys.privateKey) {
  return {
    keyId,
    payload,
    signature: crypto.sign(null, protocol.signingInput(payload, keyId), privateKey).toString('base64'),
  };
}

function apply(state, vendorBundle, payload = desired(1, vendorBundle), options = {}) {
  return policyState.applySignedPolicy(state, signed(payload), {
    policyTrust,
    vendorBundle,
    tenantLocalOverride: {},
    nowMs: NOW,
    ...options,
  });
}

test('signed genesis release commits an internally derived effective policy', () => {
  const vendorBundle = bundle('genesis');
  const result = apply(
    policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    vendorBundle,
    desired(1, vendorBundle),
  );
  assert.equal(result.state.policyVersion, 1);
  assert.equal(result.state.signingKeyId, KEY_ID);
  assert.equal(result.state.bundleDigest, policyState.digestPolicyDocument(vendorBundle));
  assert.equal(result.state.mandatoryControlsDigest, policyState.MANDATORY_CONTROLS_DIGEST);
  assert.equal(result.state.releases.length, 1);
  assert.equal(result.idempotent, false);
  assert.equal(policyState.MANDATORY_ALWAYS_BLOCK.length, 21);
  assert.equal(Object.isFrozen(result.effectivePolicy), true);
  assert.equal(result.effectivePolicy.licensing.failClosed, true);
  assert.equal(result.effectivePolicy.audit.required, true);
  assert.equal(
    result.state.effectivePolicyDigest,
    policyState.digestPolicyDocument(result.effectivePolicy),
  );
});

test('signature and customer/deployment binding are verified before policy merge', () => {
  const vendorBundle = bundle('bound');
  const state = policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  const options = {
    policyTrust,
    vendorBundle,
    nowMs: NOW,
  };
  const artifact = signed(desired(1, vendorBundle));
  artifact.signature = `${artifact.signature[0] === 'A' ? 'B' : 'A'}${artifact.signature.slice(1)}`;
  assert.throws(() => policyState.applySignedPolicy(state, artifact, options), (error) => error.code === 'invalid_signature');
  assert.throws(
    () => policyState.applySignedPolicy(state, signed(desired(1, vendorBundle, { customerId: 'cu-policy-2' })), options),
    (error) => error.code === 'customer_mismatch',
  );
  assert.throws(
    () => policyState.applySignedPolicy(state, signed(desired(1, vendorBundle, { deploymentId: SIBLING_DEPLOYMENT_ID })), options),
    (error) => error.code === 'deployment_mismatch',
  );
  assert.throws(
    () => policyState.applySignedPolicy(state, signed(desired(1, vendorBundle)), {
      ...options,
      policyTrust: { ...policyTrust, offlineKeyFingerprint: keyFingerprint(keys.publicKey) },
    }),
    (error) => error.code === 'vendor_key_identity_reused',
  );
});

test('genesis and every later release require exact linked monotonic versions', () => {
  const firstBundle = bundle('one');
  const empty = policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.throws(
    () => apply(empty, firstBundle, desired(2, firstBundle, { previousVersion: 0 })),
    (error) => error.code === 'version_gap',
  );
  const first = apply(empty, firstBundle);
  const thirdBundle = bundle('three');
  assert.throws(
    () => apply(first.state, thirdBundle, desired(3, thirdBundle, { previousVersion: 2 })),
    (error) => error.code === 'version_gap',
  );
  assert.throws(
    () => apply(first.state, firstBundle, desired(1, firstBundle, { previousVersion: 0, rollout: 'preview' })),
    (error) => error.code === 'version_conflict',
  );
});

test('same signed version is idempotent, but altered same-version content conflicts', () => {
  const vendorBundle = bundle('idempotent');
  const payload = desired(1, vendorBundle);
  const first = apply(policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID), vendorBundle, payload);
  let callbackCalls = 0;
  const duplicate = apply(first.state, vendorBundle, payload, {
    validateCandidate: () => { callbackCalls += 1; throw new Error('must never run'); },
    nowMs: NOW + 1000,
  });
  assert.equal(duplicate.idempotent, true);
  assert.equal(duplicate.state.policyVersion, first.state.policyVersion);
  assert.equal(duplicate.state.trustedTimeMs, NOW + 1000);
  assert.equal(duplicate.state.appliedAt, first.state.appliedAt);
  assert.equal(duplicate.state.lastContactAt, new Date(NOW + 1000).toISOString());
  assert.equal(callbackCalls, 0);
  const changed = desired(1, vendorBundle, { rollout: 'preview' });
  assert.throws(() => apply(first.state, vendorBundle, changed), (error) => error.code === 'version_conflict');
});

test('expired, future-dated, and rolled-back clocks fail closed', () => {
  const vendorBundle = bundle('time');
  const empty = policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.throws(
    () => apply(empty, vendorBundle, desired(1, vendorBundle, { expiresAt: '2026-07-12T12:00:59.999Z' })),
    (error) => error.code === 'expired',
  );
  assert.throws(
    () => apply(empty, vendorBundle, desired(1, vendorBundle, {
      issuedAt: '2026-07-12T12:06:00.001Z', expiresAt: '2026-07-12T12:07:00.001Z',
    })),
    (error) => error.code === 'future_policy',
  );
  const first = apply(empty, vendorBundle);
  const nextBundle = bundle('clock-two');
  assert.throws(
    () => apply(first.state, nextBundle, desired(2, nextBundle), { nowMs: NOW - 5 * 60 * 1000 - 1 }),
    (error) => error.code === 'clock_rollback',
  );
});

test('rollback republishes an earlier exact bundle under a newer linked release', () => {
  const firstBundle = bundle('stable');
  const secondBundle = bundle('regression');
  const first = apply(policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID), firstBundle);
  const second = apply(first.state, secondBundle, desired(2, secondBundle));
  const rollback = apply(second.state, firstBundle, desired(3, firstBundle, { rollbackOfVersion: 1 }));
  assert.equal(rollback.state.policyVersion, 3);
  assert.equal(rollback.rollbackOfVersion, 1);
  assert.equal(rollback.state.rollbackOfVersion, 1);
  assert.equal(rollback.state.bundleDigest, first.state.bundleDigest);
  assert.throws(
    () => apply(rollback.state, firstBundle, desired(1, firstBundle)),
    (error) => error.code === 'stale_version',
  );
  assert.throws(
    () => apply(second.state, secondBundle, desired(3, secondBundle, { rollbackOfVersion: 1 })),
    (error) => error.code === 'rollback_content_mismatch',
  );
  assert.throws(
    () => apply(second.state, secondBundle, desired(3, secondBundle, { rollbackOfVersion: 2 })),
    (error) => error.code === 'rollback_target_not_prior',
  );
  assert.throws(
    () => apply(
      { ...second.state, releases: [second.state.releases[1]] },
      firstBundle,
      desired(3, firstBundle, { rollbackOfVersion: 1 }),
    ),
    (error) => error.code === 'rollback_target_unknown',
  );
});

test('bundle and mandatory-control digests must match exact committed inputs', () => {
  const vendorBundle = bundle('digest');
  const state = policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.throws(
    () => apply(state, bundle('different'), desired(1, vendorBundle)),
    (error) => error.code === 'bundle_digest_mismatch',
  );
  assert.throws(
    () => apply(state, vendorBundle, desired(1, vendorBundle, { mandatoryControlsDigest: 'f'.repeat(64) })),
    (error) => error.code === 'mandatory_controls_digest_mismatch',
  );
});

test('policy documents reject cyclic, sparse, accessor, and prototype-bearing inputs', () => {
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => policyState.digestPolicyDocument(cyclic), (error) => error.code === 'policy_document_invalid');
  const sparse = [];
  sparse.length = 2;
  sparse[1] = 'value';
  assert.throws(() => policyState.digestPolicyDocument(sparse), (error) => error.code === 'policy_document_invalid');
  const accessor = {};
  Object.defineProperty(accessor, 'secret', { enumerable: true, get() { throw new Error('must not run'); } });
  assert.throws(() => policyState.digestPolicyDocument(accessor), (error) => error.code === 'policy_document_invalid');
  const arrayAccessor = [];
  Object.defineProperty(arrayAccessor, '0', { enumerable: true, get() { throw new Error('must not run'); } });
  arrayAccessor.length = 1;
  assert.throws(() => policyState.digestPolicyDocument(arrayAccessor), (error) => error.code === 'policy_document_invalid');
  assert.throws(
    () => policyState.digestPolicyDocument(Object.assign(Object.create({ inherited: true }), { value: true })),
    (error) => error.code === 'policy_document_invalid',
  );
});

test('mandatory controls are derived exactly from the policy source of truth', () => {
  const expected = [...new Set(DEFAULT_POLICY.alwaysBlock)].sort();
  assert.deepEqual(policyState.MANDATORY_ALWAYS_BLOCK, expected);
  assert.equal(policyState.MANDATORY_CONTROLS_DIGEST, policyState.digestPolicyDocument(expected));

  const incompleteBundle = bundle('incomplete', []);
  const applied = apply(
    policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    incompleteBundle,
    desired(1, incompleteBundle),
  );
  assert.deepEqual(applied.effectivePolicy.alwaysBlock, expected);
  assert.equal(applied.effectivePolicy.licensing.failClosed, true);
  assert.equal(applied.effectivePolicy.audit.required, true);
});

test('tenant-local overrides use a narrow deterministic strengthen-only merge', () => {
  const vendorBundle = bundle('tenant', policyState.MANDATORY_ALWAYS_BLOCK, {
    enforcementMode: 'warn',
    blockMinSeverity: 3,
    blockRiskScore: 40,
    blockUnapprovedAiDestinations: false,
    blockedDestinations: ['blocked.vendor.example'],
    blockedFileUploadDestinations: ['uploads.vendor.example'],
    mcpBlockedTools: ['vendor.read'],
    mcpApprovalRequiredTools: ['vendor.approval'],
    responseScanMode: 'flag',
    unmanagedInstalls: 'allow',
  });
  const localOverride = {
    alwaysBlockAdd: ['CUSTOM_SECRET'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 20,
    blockUnapprovedAiDestinations: true,
    blockedDestinationsAdd: ['blocked.tenant.example'],
    blockedFileUploadDestinationsAdd: ['uploads.tenant.example'],
    mcpBlockedToolsAdd: ['tenant.write'],
    mcpApprovalRequiredToolsAdd: ['tenant.approval'],
    responseScanMode: 'block',
    unmanagedInstalls: 'block',
  };
  const result = apply(
    policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    vendorBundle,
    desired(1, vendorBundle),
    { tenantLocalOverride: localOverride },
  );
  assert.equal(result.effectivePolicy.alwaysBlock.includes('CUSTOM_SECRET'), true);
  assert.deepEqual(result.effectivePolicy.blockedDestinations, [
    'blocked.tenant.example', 'blocked.vendor.example',
  ]);
  assert.deepEqual(result.effectivePolicy.blockedFileUploadDestinations, [
    'uploads.tenant.example', 'uploads.vendor.example',
  ]);
  assert.deepEqual(result.effectivePolicy.mcpBlockedTools, ['tenant.write', 'vendor.read']);
  assert.deepEqual(result.effectivePolicy.mcpApprovalRequiredTools, ['tenant.approval', 'vendor.approval']);
  assert.equal(result.effectivePolicy.enforcementMode, 'block');
  assert.equal(result.effectivePolicy.blockMinSeverity, 2);
  assert.equal(result.effectivePolicy.blockRiskScore, 20);
  assert.equal(result.effectivePolicy.blockUnapprovedAiDestinations, true);
  assert.equal(result.effectivePolicy.responseScanMode, 'block');
  assert.equal(result.effectivePolicy.unmanagedInstalls, 'block');
  assert.notEqual(result.state.localOverrideDigest, result.state.bundleDigest);
});

test('weakening attempts and non-schema tenant fields fail closed', () => {
  const vendorBundle = bundle('strict', policyState.MANDATORY_ALWAYS_BLOCK, {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 25,
    blockUnapprovedAiDestinations: true,
    responseScanMode: 'redact',
    unmanagedInstalls: 'flag',
  });
  const state = policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID);
  const payload = desired(1, vendorBundle);
  const weakeningAttempts = [
    { enforcementMode: 'warn' },
    { enforcementMode: 'justify' },
    { blockMinSeverity: 3 },
    { blockRiskScore: 26 },
    { blockUnapprovedAiDestinations: false },
    { responseScanMode: 'flag' },
    { unmanagedInstalls: 'allow' },
  ];
  for (const tenantLocalOverride of weakeningAttempts) {
    assert.throws(
      () => apply(state, vendorBundle, payload, { tenantLocalOverride }),
      (error) => error.code === 'policy_weakening',
    );
  }
  for (const tenantLocalOverride of [
    { alwaysBlock: ['CUSTOM_SECRET'] },
    { allowedDestinations: ['bypass.example'] },
    { disabledDetectors: ['US_SSN'] },
    { ignore: ['US_SSN'] },
    { policyExceptions: [{ action: 'allow' }] },
    { licensing: { failClosed: false } },
    { audit: { required: false } },
  ]) {
    assert.throws(
      () => apply(state, vendorBundle, payload, { tenantLocalOverride }),
      (error) => error.code === 'local_override_unknown_field',
    );
  }
});

test('caller callbacks cannot self-attest a weaker effective policy', () => {
  const vendorBundle = bundle('callback', policyState.MANDATORY_ALWAYS_BLOCK, {
    blockUnapprovedAiDestinations: true,
  });
  let callbackCalls = 0;
  const result = apply(
    policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    vendorBundle,
    desired(1, vendorBundle),
    {
      validateCandidate: () => {
        callbackCalls += 1;
        return {
          effectivePolicy: { enforcementMode: 'warn', blockUnapprovedAiDestinations: false },
          licensingFailClosed: false,
          auditRequired: false,
          localOverridePrecedence: 'replace',
        };
      },
    },
  );
  assert.equal(callbackCalls, 0);
  assert.equal(result.effectivePolicy.enforcementMode, 'block');
  assert.equal(result.effectivePolicy.blockUnapprovedAiDestinations, true);
  assert.equal(result.effectivePolicy.licensing.failClosed, true);
  assert.equal(result.effectivePolicy.audit.required, true);
});

test('semantically identical additive overrides produce one canonical digest', () => {
  const vendorBundle = bundle('canonical');
  const left = apply(
    policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    vendorBundle,
    desired(1, vendorBundle),
    { tenantLocalOverride: { alwaysBlockAdd: ['ZETA_SECRET', 'ALPHA_SECRET', 'ZETA_SECRET'] } },
  );
  const right = apply(
    policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID),
    vendorBundle,
    desired(1, vendorBundle),
    { tenantLocalOverride: { alwaysBlockAdd: ['ALPHA_SECRET', 'ZETA_SECRET'] } },
  );
  assert.equal(left.state.localOverrideDigest, right.state.localOverrideDigest);
  assert.equal(left.state.effectivePolicyDigest, right.state.effectivePolicyDigest);
  assert.deepEqual(left.effectivePolicy, right.effectivePolicy);
});

test('state restore detects desired-state, release-history, and unknown-field tamper', () => {
  const vendorBundle = bundle('restore');
  const applied = apply(policyState.initialState(CUSTOMER_ID, DEPLOYMENT_ID), vendorBundle);
  assert.throws(
    () => policyState.restoreState({ ...applied.state, bundleDigest: '0'.repeat(64) }),
    (error) => error.code === 'state_high_water_invalid',
  );
  assert.throws(
    () => policyState.restoreState({ ...applied.state, releases: [] }),
    (error) => error.code === 'state_high_water_invalid',
  );
  assert.throws(
    () => policyState.restoreState({ ...applied.state, prompt: 'must never persist here' }),
    (error) => error.code === 'state_unknown_field',
  );
  assert.equal(policyState.restoreState(applied.state, {
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID,
  }).policyVersion, 1);
});
